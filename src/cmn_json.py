#!/usr/bin/python3

"""
JSON serialization for CMN interconnect descriptions

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys
import os
import time
import json
import uuid

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError      # Python2

import app_data
import cmn_base
import cmn_config
import cmn_enum


def cmn_config_filename():
    return app_data.app_data_cache("cmn-system.json")


def cmn_config_default(fn):
    if fn is None:
        fn = cmn_config_filename()
        if not os.path.exists(fn):
            print("Need CMN configuration in %s" % fn, file=sys.stderr)
            sys.exit(1)
    return fn


def boot_time():
    """
    Get the boot time of the current system
    """
    t = time.time() - float(open("/proc/uptime").read().split()[0])
    return t


def cmn_from_json(j, S):
    """
    Construct a CMN object from its JSON representation.
    """
    assert isinstance(S, cmn_base.System)
    assert j["product"] == "CMN"
    jc = j["config"]
    C = S.create_CMN(dimX=jc["X"], dimY=jc["Y"], extra_ports=jc.get("extra_ports", False))
    if "version" in j:
        v = j["version"]
        if isinstance(v, int):
            v = "CMN-" + str(v)
        revision_code = j.get("revision", None)
        C.product_config = cmn_config.CMNConfig(product_name=v, revision_code=revision_code)
    C.product_config.mpam_enabled = jc.get("mpam_enabled", False)
    C.product_config.chi_version = jc.get("chi_version", None)
    C.frequency = j.get("frequency", None)
    if "base" in jc:
        C.periphbase = int(jc["base"], 16)
        if "rootnode_offset" in jc:
            C.rootnode_offset = int(jc["rootnode_offset"], 16)
    if "skiplist" in j:
        C.node_skiplist = [int(se, 16) for se in j["skiplist"]]
    for jxp in jc["xps"]:
        np = jxp.get("n_ports", None)
        if np is None:
            np = len(jxp["ports"])
        xp = C.create_xp(jxp["X"], jxp["Y"], n_ports=np, id=jxp["id"], logical_id=jxp.get("logical_id", None))
        if "dtc" in jxp:
            xp.dtc = jxp["dtc"]
        if "skipped" in jxp:
            xp.skipped_nodes = jxp["skipped"]
        if "mcs_east" in jxp:
            xp.mcs_east = jxp["mcs_east"]
        if "mcs_north" in jxp:
            xp.mcs_north = jxp["mcs_north"]
        for jp in jxp["ports"]:
            p = jp["port"]
            p_type = jp["type"]
            # We now omit unconnected ports in the JSON, but some old files had "null" here
            if p_type is None:
                continue        # unconnected port
            po = xp.create_port(port_number=p, type=p_type, type_s=jp["type_s"])
            po.cal = jp.get("cal", 0)
            if isinstance(po.cal, bool):
                # handle older JSON schema, pre CAL4
                po.cal = 2 if po.cal else 0
            po.cal_credited_slices = jp.get("ccs", None)
            if "devices" in jp:
                for jd in jp["devices"]:
                    n = C.create_node(type=jd["type"], type_s=jd["type_s"], xp=xp, port_number=p, id=jd["id"], logical_id=jd.get("logical_id", None))
            if "pdevices" in jp:
                for jd in jp["pdevices"]:
                    dn = jd["device_number"]
                    if dn in po.pdevices:
                        if "dcs" in jd:
                            po.pdevices[dn].device_credited_slices = jd["dcs"]
            if "attached" in jp:
                for ja in jp["attached"]:
                    if ja["type"] == "cpu":
                        S.set_cpu(ja["cpu"], po, id=ja.get("id", None), lpid=ja.get("lpid", 0))
    return C


def check_system_description_time(S):
    """
    Check and warn if the current system has rebooted since the
    system description was created.
    """
    if S.timestamp is not None:
        t_boot = boot_time()
        if S.timestamp < t_boot:
            print("Warning: system description dates from %s but system rebooted %s" %
                  (time.ctime(S.timestamp), time.ctime(t_boot)),
                  file=sys.stderr)


def dmi_system_type():
    """
    Get the system type from DMI strings.
    Because we might not be root, we use the kernel's DMI strings in sysfs.
    """
    try:
        return " ".join([open(os.path.join("/sys/class/dmi/id", s)).read().strip()
                         for s in ["sys_vendor", "product_name", "product_version"]]).strip()
    except FileNotFoundError:
        return None


def system_from_json(j, filename=None):
    """
    Create a system description object from a JSON structure.
    """
    S = cmn_base.System(filename=filename)
    S.system_type = j.get("system_type", None)
    if S.system_type is not None:
        S.system_type = S.system_type.strip()
    S.system_uuid = uuid.UUID(j["system_uuid"]) if "system_uuid" in j else None
    S.processor_type = j.get("processor_type", None)
    if S.system_type is not None and S.processor_type is not None:
        os_type = dmi_system_type()
        if os_type is not None and os_type != S.system_type:
            print("CMN file might be for different system:", file=sys.stderr)
            print("  This system:    '%s'" % os_type, file=sys.stderr)
            print("  System in file: '%s'" % S.system_type, file=sys.stderr)
    if "date" in j and j["date"] is not None:
        # Currently a float as per time.time()
        S.timestamp = float(j["date"])
    elif filename is not None:
        S.timestamp = os.path.getmtime(filename)
    for e in j["elements"]:
        if e["type"] == "interconnect" and e["product"] == "CMN":
            cmn_from_json(e, S)   # this will add it to the System object
    return S


def system_from_json_file(fn=None, check_timestamp=False, exit_if_not_found=True):
    """
    Get the system description from a given file name or the standard cached location.
    """
    if fn is None:
        fn = cmn_config_filename()
    try:
        with open(fn) as f:
            S = system_from_json(json.load(f), filename=fn)
            if check_timestamp:
                check_system_description_time(S)
            return S
    except FileNotFoundError:
        # Typically, whoever's calling this really needs the topology,
        # and there's no point continuing if it's not there.
        if exit_if_not_found:
            print("%s: file not found: run cmn_discover" % fn, file=sys.stderr)
            sys.exit(1)
        return None


def json_from_cpu(co):
    j = {
        "type": "cpu",
        "cpu": co.cpu,     # CPU number as known to Linux
        "mseq": co.port.CMN().seq,   # mesh sequence number in the system
        "id": co.id,       # CHI SRCID - includes port and device bits
        "lpid": co.lpid    # CHI LPID, generally zero or assigned by DSU
    }
    return j


def json_from_device_node(d):
    jd = {
        "id": d.node_id(),
        "type": d.type(),
        "type_s": d.type_str(),
    }
    if d.logical_id() is not None:
        jd["logical_id"] = d.logical_id()
    return jd


def json_from_port(p):
    jp = {
        "port": p.port_number,
        "type": p.connected_type,
        "type_s": p.connected_type_s,
    }
    if p.cal:
        jp["cal"] = p.cal
        if p.cal_credited_slices is not None:
            jp["ccs"] = p.cal_credited_slices
    jp["pdevices"] = []
    for dn in p.device_numbers():
        jd = {
            "device_number": dn,
            "id": p.base_id() + dn,
        }
        if p.device_credited_slices(dn):
            jd["dcs"] = p.device_credited_slices(dn)
        jp["pdevices"].append(jd)
    return jp


def json_from_xp(xp):
    (x, y) = xp.XY()
    j = {
        "X": x,
        "Y": y,
        "n_ports": xp.n_device_ports(),
        "id": xp.node_id(),
        "logical_id": xp.logical_id(),
        "ports": [],
    }
    if xp.logical_id() is None:
        del j["logical_id"]
    if xp.dtc_domain() is not None:
        j["dtc"] = xp.dtc_domain()
    if xp.skipped_nodes is not None:
        j["skipped"] = xp.skipped_nodes
    emcs = xp.mesh_credited_slices(0)
    if emcs:
        j["mcs_east"] = emcs
    nmcs = xp.mesh_credited_slices(1)
    if nmcs:
        j["mcs_north"] = nmcs
    for i in range(xp.n_device_ports()):
        p = xp.port_object(i)
        if p is None:
            continue
        jp = json_from_port(p)
        if list(xp.port_nodes(i)):
            jp["devices"] = [json_from_device_node(d) for d in xp.port_nodes(i)]
            assert jp["devices"]
        try:
            if xp.port[i].cpus:
                jp["attached"] = [json_from_cpu(co) for co in xp.port[i].cpus]
        except AttributeError:
            # this won't work for the CMN objects built from /dev/mem discovery
            pass
        j["ports"].append(jp)
    return j


def json_from_cmn(C):
    j = {
        "type": "interconnect",
        "product": "CMN",
        "version": C.product_config.product_name(),
        "revision": C.product_config.revision_code,
        "config": {
            "mpam_enabled": C.product_config.mpam_enabled,
            "chi_version": C.product_config.chi_version,
            "X": C.dimX,
            "Y": C.dimY,
            "extra_ports": C.extra_ports,
            "xps": [json_from_xp(xp) for xp in C.XPs()],
        }
    }
    if C.periphbase is not None:
        j["config"]["base"] = "0x%x" % C.periphbase
        j["config"]["rootnode_offset"] = "0x%x" % C.rootnode_offset
    if C.node_skiplist is not None:
        j["skiplist"] = [("0x%x" % se) for se in C.node_skiplist]
    if hasattr(C, "frequency") and C.frequency is not None:
        j["frequency"] = C.frequency
    return j


def json_from_system(S):
    j = {
        "version": S.version,
        "generator": os.path.basename(__file__),
        "date": S.timestamp,     # currently a float
        "elements": []
    }
    if S.system_type is not None:
        j["system_type"] = S.system_type
    if S.system_uuid is not None:
        j["system_uuid"] = str(S.system_uuid)
    if S.processor_type is not None:
        j["processor_type"] = S.processor_type
    for C in S.CMNs:
        jc = json_from_cmn(C)
        j["elements"].append(jc)
    if S.has_cpu_mappings():
        j["cpus"] = [json_from_cpu(S.cpu_node[c]) for c in sorted(S.cpu_node.keys())]
    return j


def json_dump_file_from_system(S, fn):
    """
    Dump the system description into a JSON file.
    This might be run after initial topology discovery,
    or after CPU discovery.
    If it's the special cache file, check if we're running as sudo,
    and update the permissions to the 'real' user in that case.
    """
    if fn is None:
        fn = cmn_config_filename()
    j = json_from_system(S)
    if fn == "-":
        json.dump(j, sys.stdout, indent=4)
    else:
        with open(fn, "w") as f:
            json.dump(j, f, indent=4)
        if fn == cmn_config_filename():
            app_data.change_to_real_user_if_sudo(fn)


def file_print_summary_info(fn, opts):
    """
    Print a summary of JSON contents, as controlled by options
    """
    S = system_from_json_file(fn)
    system_print_summary_info(S, opts)
    return S


def system_print_summary_info(S, opts):
    """
    Print summary information about a system.
    """
    if opts.verbose:
        print("System type: %s" % S.system_type)
        print("CMN version: %s" % S.cmn_version())
        print("System has HN-S: %s" % S.has_HNS())
    if S.cmn_version() is None:
        print("%s: CMN interconnect not found" % (S.filename), file=sys.stderr)
        sys.exit(1)
    if not (opts.filename or (opts.nodeid is not None) or
            opts.nodes or opts.ports or opts.home_nodes or opts.cpus or opts.xps or
            opts.summary or opts.output):
        print(S)
    if opts.summary:
        """
        Print a single-line summary of the system, with some alignment of fields
        so that we can compare systems.
        """
        C0 = S.CMNs[0]
        vsn = S.cmn_version()
        print("%-40s " % S.filename, end="")
        if C0.has_cpu_mappings():
            print(" %3u CPUs" % len(S.cpu_node), end="")
        else:
            print("         ", end="")
        print("  ", end="")
        if len(S.CMNs) != 1:
            print("%u x " % len(S.CMNs), end="")
        else:
            print("    ", end="")
        print("%-12s %2ux%-2u " % (vsn.product_name(revision=True), C0.dimX, C0.dimY), end="")
        print(" %s" % vsn.chi_version_str(), end="")
        if vsn.mpam_enabled:
            print(" MPAM", end="")
        else:
            print("     ", end="")
        max_cal = 0
        max_port_number = 0
        for p in S.ports():
            max_cal = max(max_cal, p.cal)
            max_port_number = max(max_port_number, p.port_number)
        if max_cal:
            print(" CAL%u" % max_cal, end="")
        else:
            print("     ", end="")
        print(" P%u" % max_port_number, end="")
        ports_sparse = False
        for xp in S.XPs():
            pos = list(xp.ports())
            if pos and pos[0].port_number != 0:
                ports_sparse = True
        if ports_sparse:
            print(" sp", end="")
        if S.has_HNS():
            print(" HN-S", end="")
        if S.system_type:
            print(" -- %s" % S.system_type, end="")
        print()
        return
    if opts.filename:
        print(S.filename)
    if opts.xps:
        for C in S.CMNs:
            print("  %s" % C)
            for xp in C.XPs():
                print("    %s" % xp)
                for p in xp.ports():
                    print("      %s" % p, end="")
                    if p.cal:
                        print(" (CAL)", end="")
                    print()
                    for d in p.devices:
                        print("        %s" % d)
                    for co in p.cpus:
                        print("        %s" % co)
    if opts.cpus:
        if S.has_cpu_mappings():
            print("CPUs:")
            for cpu in S.cpus():
                print("  %s" % cpu)
                assert cpu.CMN().cpu_from_id(cpu.id, cpu.lpid) == cpu
        else:
            print("This CMN description does not have CPU mappings yet", file=sys.stderr)
    def property_str(x):
        s = []
        for (k, p) in cmn_enum.__dict__.items():
            if k.startswith("CMN_PROP_") and k != "CMN_PROP_none":
                if x.has_properties(p):
                    s.append(k[9:])
        return ' '.join(s)
    if opts.nodes:
        print("Nodes:")
        for node in S.nodes():
            print("  %s: %s" % (node, property_str(node)))
    if opts.ports:
        print("Ports:")
        for port in S.ports():
            print("  %s: %s" % (port, property_str(port)))
    if opts.requesters:
        """
        Show all requesters in the mesh. There are three things we could do here:
          - show all CMN device nodes classed as requesters. This will miss RN-Fs,
            which are external and have no device nodes.
          - show all XP ports which have requester type (or RN-F type specifically).
            This will pick up RN-F ports, but won't list actual requester nodes
            with their node ids.
          - scan the XP RN-F ports and CAL information to produce a list of
            RN-Fs with their node ids.
        """
        print("Requester nodes:")
        for node in S.nodes(properties=cmn_enum.CMN_PROP_RN):
            print("  %s" % node)
        # RN-Fs aren't nodes in CMN, but we can list RN-F ports
        print("RN-F ports:")
        for port in S.ports(properties=cmn_enum.CMN_PROP_RNF):
            print("  %s" % port)
        print("RN-Fs:")
        for port in S.ports(properties=cmn_enum.CMN_PROP_RNF):
            nd = port.cal if port.cal else 1
            for d in range(nd):
                print("  RN-F 0x%x" % (port.base_id() + d))
    if opts.home_nodes:
        print("Home node ports:")
        for port in S.ports():
            if port.has_properties(cmn_enum.CMN_PROP_HN):
                print("  %s" % port, end="")
                if port.has_properties(cmn_enum.CMN_PROP_HNF):
                    print(" (HN-F)", end="")
                if port.has_properties(cmn_enum.CMN_PROP_HNI):
                    print(" (HN-I)", end="")
                if port.has_properties(cmn_enum.CMN_PROP_HND):
                    print(" (HN-D)", end="")
                print()
        print("Home nodes:")
        for node in S.home_nodes():
            print("  %s" % node)
    if opts.nodeid is not None:
        # Look up node by CHI srcid/tgtid
        if opts.cmn_instance is None:
            if S.has_multiple_cmn():
                print("Defaulting to CMN#0, use --cmn-instance to specify instance",
                      file=sys.stderr)
            opts.cmn_instance = 0
        C = S.CMNs[opts.cmn_instance]
        p = C.port_at_id(opts.nodeid)
        if p is not None:
            print(p)
        else:
            print("No port matching ID 0x%02x" % opts.nodeid)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN mesh interconnect model")
    parser.add_argument("-i", "--input", type=str, help="input JSON")
    parser.add_argument("-o", "--output", type=str, help="output JSON")
    parser.add_argument("--filename", action="store_true", help="display filename")
    parser.add_argument("--summary", action="store_true", help="print single-line summary")
    parser.add_argument("--nodes", action="store_true", help="list all nodes")
    parser.add_argument("--nodeid", type=(lambda s: int(s, 16)), help="look up node id")
    parser.add_argument("--ports", action="store_true", help="list all ports")
    parser.add_argument("--xps", action="store_true", help="list all crosspoints")
    parser.add_argument("--requesters", action="store_true", help="list requesters")
    parser.add_argument("--home-nodes", action="store_true", help="list home nodes")
    parser.add_argument("--cpus", action="store_true", help="list CPUs")
    parser.add_argument("--cmn-instance", type=int, help="select CMN instance")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("all_inputs", type=str, nargs="*", help="input JSON")
    opts = parser.parse_args()
    if opts.all_inputs:
        if opts.input is not None:
            opts.all_inputs.insert(0, opts.input)
    else:
        opts.all_inputs = [cmn_config_default(opts.input)]
    if len(opts.all_inputs) > 1:
        if opts.output:
            print("-o can only be used with a single input", file=sys.stderr)
            sys.exit(1)
        opts.filename = True
    for fn in opts.all_inputs:
        S = file_print_summary_info(fn, opts)
        if opts.output is not None and S is not None:
            json_dump_file_from_system(S, opts.output)
