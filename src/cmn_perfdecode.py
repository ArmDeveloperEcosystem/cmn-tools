#!/usr/bin/python3

"""
Decode CMN watchpoint perf event strings.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This is intended to be usable as a small filter, in the same spirit as a
symbol demangler. It scans text for Linux perf event strings such as:

  arm_cmn/watchpoint_up,wp_chn_sel=0,wp_val=0x4,wp_mask=...,wp_grp=0/

and annotates them with the CHI channel, direction and visible field
matches.
"""

from __future__ import print_function

import re
import sys

import chi_spec
import cmn_config
import cmn_json
import cmnwatch


_EVENT_RE = re.compile(r'arm_cmn(?:_[0-9]+)?/[^/\s]*/')


class PerfDecodeError(ValueError):
    pass


class DecodeContext:
    def __init__(self, cmn_version=None, system=None):
        self.cmn_version = cmn_version
        self.system = system


def _split_quoted(s, sep=','):
    fields = []
    cur = []
    quoted = False
    esc = False
    for ch in s:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == '\\':
            cur.append(ch)
            esc = True
        elif ch == '"':
            cur.append(ch)
            quoted = not quoted
        elif ch == sep and not quoted:
            fields.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append(''.join(cur))
    return fields


def _parse_int(s):
    return int(s, 0)


def parse_perf_event(event):
    """
    Parse a perf event string into (pmu, event_name, attrs).
    attrs maps attribute names to string values. Flags such as watchpoint_up
    are returned as the event name.
    """
    if "/" not in event:
        raise PerfDecodeError("not a perf event: %s" % event)
    if event.endswith("/"):
        event = event[:-1]
    (pmu, body) = event.split("/", 1)
    parts = _split_quoted(body)
    event_name = None
    attrs = {}
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if "=" in p:
            (k, v) = p.split("=", 1)
            attrs[k.strip()] = v.strip().strip('"')
        elif event_name is None:
            event_name = p
        else:
            attrs[p] = "1"
    return (pmu, event_name, attrs)


def _event_cmn_instance(pmu):
    if pmu == "arm_cmn":
        return None
    prefix = "arm_cmn_"
    if pmu.startswith(prefix):
        try:
            return int(pmu[len(prefix):])
        except ValueError:
            return None
    return None


def _cmn_for_instance(system, instance):
    if system is None:
        return None
    if instance is None:
        if len(system.CMNs) == 1:
            instance = 0
        else:
            return None
    if instance < 0 or instance >= len(system.CMNs):
        return None
    return system.CMNs[instance]


def _node_type_list(nodes):
    nts = []
    for n in nodes:
        ts = n.type_str()
        if n.logical_id() is not None:
            ts += "#%u" % n.logical_id()
        nts.append(ts)
    return nts


def _cpu_list(dev):
    cpus = []
    for cpu in dev.cpus:
        cpus.append("CPU#%u" % cpu.cpu)
    return cpus


def _describe_port(port, dev=None):
    desc = "%s port%u %s" % (port.XP().path_str(), port.port_number, port.connected_type_s)
    if port.cal:
        desc += " CAL%u" % port.cal
    if dev is not None:
        desc += " device%u" % dev.device_number
        nts = _node_type_list(dev.device_nodes)
        if nts:
            desc += " " + "/".join(nts)
        cpus = _cpu_list(dev)
        if cpus:
            desc += " " + ",".join(cpus)
    return desc


def _describe_topology(system, instance, attrs):
    C = _cmn_for_instance(system, instance)
    if C is None or "nodeid" not in attrs:
        return None
    try:
        nodeid = _parse_int(attrs["nodeid"])
    except ValueError:
        return None
    if nodeid in C.id_xp:
        xp = C.id_xp[nodeid]
        if "wp_dev_sel" in attrs:
            try:
                dev_sel = _parse_int(attrs["wp_dev_sel"])
            except ValueError:
                dev_sel = None
            if dev_sel is not None:
                port = xp.port(dev_sel)
                if port is not None:
                    return _describe_port(port)
        return "%s XP" % xp.path_str()
    port = C.port_at_id(nodeid)
    if port is not None:
        dev = port.device_at_id(nodeid, create=False)
        return _describe_port(port, dev=dev)
    if nodeid in C.id_nodes:
        nodes = []
        for t in sorted(C.id_nodes[nodeid].keys()):
            nodes.append(C.id_nodes[nodeid][t])
        nts = _node_type_list(nodes)
        if nts:
            return "nodeid 0x%x %s" % (nodeid, "/".join(nts))
    return None


def _lookup_name(lookup, v, dontcare):
    if dontcare != 0 or lookup is None or callable(lookup):
        return None
    if v < 0:
        return None
    try:
        name = lookup[v]
    except Exception:
        return None
    if name is None or name.startswith("?"):
        return None
    return name


def _field_display_value(field, lookup, v, dontcare, chn):
    name = _lookup_name(lookup, v, dontcare)
    if name is not None:
        return "%s" % name
    if field == "addr" and chn == cmnwatch.SNP:
        v = v << 3
        dontcare = dontcare << 3
    hs = _unconvert_hex_value_mask(v, dontcare)
    if hs is not None:
        return hs
    val = cmnwatch.unconvert_value_mask(v, dontcare)
    if isinstance(val, int):
        return "0x%x" % val
    return str(val)


def _unconvert_hex_value_mask(v, m):
    """
    If a value/mask pair can be represented cleanly with hex wildcard
    digits, return it as 0x...; otherwise return None.
    """
    if m == 0:
        return None
    s = ""
    while m or v:
        mn = m & 0xf
        vn = v & 0xf
        if mn == 0:
            s = ("%x" % vn) + s
        elif mn == 0xf:
            s = "x" + s
        else:
            return None
        m >>= 4
        v >>= 4
    s = s.lstrip("0")
    if not s:
        s = "0"
    return "0x" + s


def _field_candidates(chn, grp, val, mask, cmn_version):
    fields = cmnwatch._fields[chn]
    mix = cmnwatch.field_selector_for_product(cmn_version)
    candidates = []
    for (field, meta) in fields.items():
        poses = cmnwatch.field_positions(meta, mix)
        for (fgrp, pos, width) in poses:
            if fgrp != grp:
                continue
            bits = (1 << width) - 1
            care = ((~mask) >> pos) & bits
            if care == 0:
                continue
            fval = (val >> pos) & bits
            dontcare = (~care) & bits
            candidates.append({
                "field": field,
                "lookup": meta[0],
                "pos": pos,
                "width": width,
                "care": care,
                "value": fval,
                "dontcare": dontcare,
            })
    return candidates


def _same_field_shape(a, b):
    return a["pos"] == b["pos"] and a["width"] == b["width"] and a["care"] == b["care"]


def _alias_name(fields, up):
    fs = sorted(fields)
    if fs == ["srcid", "tgtid"]:
        if up is True:
            return "tgtid"
        if up is False:
            return "srcid"
        return "srcid/tgtid"
    if fs == ["excl", "snoopme"]:
        return "excl/snoopme"
    if fs == ["datasrc", "fwdstate"]:
        return "fwdstate/datasrc"
    if fs == ["datasrc", "fwdstate", "stash"]:
        return "fwdstate/datasrc/stash"
    if fs == ["mecid", "streamid"]:
        return "mecid/streamid"
    return "/".join(fs)


def _opcode_value(candidates):
    for c in candidates:
        if c["field"] == "opcode" and c["dontcare"] == 0:
            return c["value"]
    return None


def _is_dvm_opcode(chn, opcode):
    if chn == cmnwatch.REQ:
        return opcode == 0x14
    if chn == cmnwatch.SNP:
        return opcode == 0x0d
    return False


def _filter_candidates(candidates, chn, up, force_dvm=False):
    opcode = _opcode_value(candidates)
    show_dvm = force_dvm or _is_dvm_opcode(chn, opcode)
    filtered = []
    for c in candidates:
        f = c["field"]
        if f.startswith("dvm") and not show_dvm:
            continue
        if f == "addr" and show_dvm:
            continue
        if f == "srcid" and up is True:
            continue
        if f == "tgtid" and up is False:
            continue
        filtered.append(c)
    return filtered


def _coalesce_aliases(candidates, up):
    out = []
    used = [False] * len(candidates)
    for i in range(0, len(candidates)):
        if used[i]:
            continue
        c = candidates[i]
        aliases = [c["field"]]
        used[i] = True
        for j in range(i + 1, len(candidates)):
            if used[j]:
                continue
            d = candidates[j]
            if (_same_field_shape(c, d) and c["value"] == d["value"]
                    and c["dontcare"] == d["dontcare"]):
                aliases.append(d["field"])
                used[j] = True
        c = dict(c)
        c["field"] = _alias_name(aliases, up)
        out.append(c)
    return out


def _candidate_sort_key(c):
    return (c["pos"], -c["width"], c["field"])


def decode_watchpoint_fields(attrs, cmn_version, force_dvm=False):
    """
    Return a list of decoded field strings for one watchpoint perf event.
    """
    try:
        chn = _parse_int(attrs["wp_chn_sel"])
        grp = _parse_int(attrs.get("wp_grp", "0"))
        val = _parse_int(attrs.get("wp_val", "0"))
        mask = _parse_int(attrs["wp_mask"])
    except KeyError as e:
        raise PerfDecodeError("missing watchpoint attribute: %s" % e)
    except ValueError as e:
        raise PerfDecodeError("bad numeric watchpoint attribute: %s" % e)
    up = None
    if attrs.get("_event_name") == "watchpoint_up":
        up = True
    elif attrs.get("_event_name") == "watchpoint_down":
        up = False
    candidates = _field_candidates(chn, grp, val, mask, cmn_version)
    candidates = _filter_candidates(candidates, chn, up, force_dvm=force_dvm)
    candidates = _coalesce_aliases(candidates, up)
    fields = []
    for c in sorted(candidates, key=_candidate_sort_key):
        value = _field_display_value(c["field"].split("/")[0], c["lookup"], c["value"], c["dontcare"], chn)
        fields.append("%s=%s" % (c["field"], value))
    return fields


def decode_perf_event(event, cmn_version, force_dvm=False, system=None):
    """
    Decode a single CMN perf event string. Return None for non-watchpoint
    CMN events so callers can use this as a broad CMN-event scanner.
    """
    (pmu, event_name, attrs) = parse_perf_event(event)
    if pmu != "arm_cmn" and not pmu.startswith("arm_cmn_"):
        return None
    if event_name not in ["watchpoint_up", "watchpoint_down"]:
        return None
    attrs["_event_name"] = event_name
    chn = _parse_int(attrs.get("wp_chn_sel", "0"))
    direction = {"watchpoint_up": "upload", "watchpoint_down": "download"}[event_name]
    parts = []
    inst = _event_cmn_instance(pmu)
    if inst is not None:
        parts.append("CMN#%u" % inst)
    parts.append("%s %s" % (direction, chi_spec.channel[chn]))
    if "wp_dev_sel" in attrs:
        parts.append("dev=%s" % attrs["wp_dev_sel"])
    if "nodeid" in attrs:
        parts.append("nodeid=%s" % attrs["nodeid"])
    topology = _describe_topology(system, inst, attrs)
    if topology is not None:
        parts.append(topology)
    if "wp_grp" in attrs:
        parts.append("grp=%s" % attrs["wp_grp"])
    if "wp_combine" in attrs:
        parts.append("combine=%s" % attrs["wp_combine"])
    if attrs.get("wp_exclusive", "0") not in ["0", "false", "False"]:
        parts.append("exclusive")
    fields = decode_watchpoint_fields(attrs, cmn_version, force_dvm=force_dvm)
    if fields:
        parts.append(", ".join(fields))
    else:
        parts.append("all flits")
    return "CMN watchpoint: " + "; ".join(parts)


def _combined_key(pmu, event_name, attrs):
    combine = attrs.get("wp_combine")
    if combine is None:
        return None
    return (pmu, event_name, attrs.get("wp_chn_sel"), combine,
            attrs.get("wp_dev_sel"), attrs.get("nodeid"), attrs.get("name"))


def _event_has_dvm_opcode(attrs, cmn_version):
    try:
        chn = _parse_int(attrs["wp_chn_sel"])
        grp = _parse_int(attrs.get("wp_grp", "0"))
        val = _parse_int(attrs.get("wp_val", "0"))
        mask = _parse_int(attrs["wp_mask"])
    except Exception:
        return False
    return _is_dvm_opcode(chn, _opcode_value(_field_candidates(chn, grp, val, mask, cmn_version)))


def annotate_line(line, cmn_version, system=None):
    parsed_events = []
    dvm_keys = {}
    for m in _EVENT_RE.finditer(line):
        try:
            (pmu, event_name, attrs) = parse_perf_event(m.group(0))
        except PerfDecodeError:
            continue
        key = _combined_key(pmu, event_name, attrs)
        parsed_events.append((m, pmu, event_name, attrs, key))
        if key is not None and event_name in ["watchpoint_up", "watchpoint_down"]:
            if _event_has_dvm_opcode(attrs, cmn_version):
                dvm_keys[key] = True
    notes = []
    for (m, _pmu, _event_name, _attrs, key) in parsed_events:
        note = decode_perf_event(m.group(0), cmn_version, force_dvm=(key in dvm_keys), system=system)
        if note is not None:
            notes.append(note)
    if notes:
        return line.rstrip("\n") + "  # " + " | ".join(notes)
    return line.rstrip("\n")


def _context_from_opts(opts):
    system = None
    if opts.cmn_json is not None:
        system = cmn_json.system_from_json_file(fn=opts.cmn_json)
    elif opts.cmn_version is not None:
        system = cmn_json.system_from_json_file(exit_if_not_found=False)
    else:
        system = cmn_json.system_from_json_file()
    try:
        cmn_version = opts.cmn_version
        if cmn_version is None and system is not None:
            cmn_version = system.cmn_version()
            assert cmn_version is not None
        if cmn_version is None:
            raise PerfDecodeError("cannot discover CMN product version: use --cmn-version or --cmn-json")
        return DecodeContext(cmn_version=cmn_version, system=system)
    except Exception:
        raise PerfDecodeError("cannot discover CMN product version: use --cmn-version or --cmn-json")


def _arg_cmn_version(s):
    try:
        return cmn_config.cmn_version(s)
    except KeyError:
        raise argparse.ArgumentTypeError("invalid CMN product identifier")


def main(argv):
    global argparse
    import argparse
    parser = argparse.ArgumentParser(description="decode CMN watchpoint perf event strings")
    parser.add_argument("--cmn-version", type=_arg_cmn_version, help="CMN version")
    parser.add_argument("--cmn-json", type=str, help="CMN JSON description")
    parser.add_argument("text", nargs="*", help="text or perf event strings to annotate; defaults to stdin")
    opts = parser.parse_args(argv)
    try:
        context = _context_from_opts(opts)
    except PerfDecodeError as e:
        print(str(e), file=sys.stderr)
        return 1
    if opts.text:
        for line in opts.text:
            print(annotate_line(line, context.cmn_version, system=context.system))
    else:
        for line in sys.stdin:
            print(annotate_line(line, context.cmn_version, system=context.system))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
