#!/usr/bin/python

"""
JSON serialization for CMN interconnect descriptions

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys
import os
import time
import calendar
import datetime
import errno
import json
import math
import uuid

try:
    basestring
except NameError:
    basestring = str

import app_data
import cmn_base
import cmn_config
import cmn_enum


def _json_object(value, required, description):
    """
    Check a JSON object and its required fields before interpreting it.
    Unknown fields remain allowed for compatibility with other producers.
    """
    if not isinstance(value, dict):
        raise TypeError("%s must be a JSON object" % description)
    for field in required:
        if field not in value:
            raise ValueError("%s is missing '%s'" % (description, field))


def _json_array(value, description):
    """
    Check a JSON array before iterating over its entries.
    """
    if not isinstance(value, list):
        raise TypeError("%s must be a JSON array" % description)
    return value


def _integer_fields(j, fields):
    """
    Check optional nonnegative integer fields, allowing null for unknowns.
    Required fields are also checked by their model constructors.
    """
    for field in fields:
        if j.get(field) is not None:
            cmn_config.check_integer(j[field], field)


def _string_fields(j, fields):
    """
    Check optional descriptive strings, allowing null for unknowns.
    """
    for field in fields:
        if j.get(field) is not None and not isinstance(j[field], basestring):
            raise TypeError("%s must be a string" % field)


def _hex_address(value, description):
    """
    Decode a nonnegative address from the JSON hexadecimal string format.
    """
    if not isinstance(value, basestring):
        raise TypeError("%s must be a hexadecimal string" % description)
    address = int(value, 16)
    return cmn_config.check_integer(address, description)


def _json_number(value, description):
    """
    Reject non-numeric and non-finite values, including JSON NaN/Infinity.
    """
    if isinstance(value, bool) or not isinstance(value, cmn_config.integer_types + (float,)):
        raise TypeError("%s must be a number" % description)
    try:
        number = float(value)
        finite = not (math.isnan(number) or math.isinf(number))
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError("%s must be finite" % description)
    return value


def cmn_config_filename():
    return app_data.app_data_cache("cmn-system.json")


def cmn_config_default(fn):
    """
    Resolve an optional filename without checking whether the file exists.
    """
    return cmn_config_filename() if fn is None else fn


def boot_time():
    """
    Get the boot time of the current system
    """
    with open("/proc/uptime") as f:
        t = time.time() - float(f.read().split()[0])
    return t


def json_timestamp(t=None):
    if t is None:
        t = time.time()
    dt = datetime.datetime.utcfromtimestamp(float(t))
    stamp = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        stamp += ".%06u" % dt.microsecond
    return stamp + "Z"


def timestamp_from_json(v):
    if v is None:
        return None
    if isinstance(v, cmn_config.integer_types + (float,)):
        return float(_json_number(v, "timestamp"))
    if isinstance(v, basestring):
        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"]:
            try:
                dt = datetime.datetime.strptime(v, fmt)
                return calendar.timegm(dt.utctimetuple()) + (float(dt.microsecond) / 1000000.0)
            except ValueError:
                pass
    raise ValueError("bad JSON timestamp: %r" % (v,))


def product_config_from_json(j):
    """
    Construct a CMNConfig object from its JSON representation.
    """
    _json_object(j, ["config", "version"], "CMN product")
    jc = j["config"]
    _json_object(jc, [], "CMN configuration")
    v = j["version"]
    if isinstance(v, cmn_config.integer_types) and not isinstance(v, bool):
        v = "CMN-" + str(v)
    if not isinstance(v, basestring):
        raise TypeError("CMN product version must be a string or integer")
    return cmn_config.CMNConfig(
        product_name=v, revision_code=j.get("revision", None),
        mpam_enabled=jc.get("mpam_enabled", None),
        mpam_partid_width=jc.get("mpam_partid_width", None),
        mte_enabled=jc.get("mte_enabled", None),
        chi_version=jc.get("chi_version", None),
        pa_width=jc.get("pa_width", None),
        req_pa_width=jc.get("req_pa_width", None),
        rsvdc_width=jc.get("rsvdc_width", None))


def _check_cmn_json(j):
    """
    Validate JSON containers and scalar fields before creating mesh objects.
    Topology relationships and duplicates are checked by model constructors.
    Legacy null ports, boolean CAL and absent optional fields remain supported.
    """
    _json_object(j, ["product", "config"], "CMN element")
    if j["product"] != "CMN":
        raise ValueError("expected CMN product, got %r" % j["product"])
    jc = j["config"]
    _json_object(jc, ["X", "Y", "xps"], "CMN configuration")
    for field in ["X", "Y"]:
        cmn_config.check_integer(jc[field], "CMN %s dimension" % field, minimum=1, maximum=16)
    if jc.get("extra_ports") is not None and not isinstance(jc["extra_ports"], bool):
        raise TypeError("extra_ports must be a boolean")
    if j.get("frequency") is not None and _json_number(j["frequency"], "CMN frequency") <= 0:
        raise ValueError("CMN frequency must be positive")
    for field in ["base", "rootnode_offset"]:
        if field in jc:
            _hex_address(jc[field], field)
    for entry in _json_array(j.get("skiplist", []), "skiplist"):
        _hex_address(entry, "skiplist address")
    for jxp in _json_array(jc["xps"], "CMN XPs"):
        _json_object(jxp, ["X", "Y", "id", "ports"], "XP")
        for field in ["X", "Y", "id"]:
            cmn_config.check_integer(jxp[field], "XP %s" % field)
        _integer_fields(jxp, ["n_ports", "logical_id", "dtc", "skipped", "mcs_east", "mcs_north"])
        if jxp.get("is_external") is not None and not isinstance(jxp["is_external"], bool):
            raise TypeError("XP is_external must be a boolean")
        if not isinstance(jxp.get("disabled", False), bool):
            raise TypeError("XP disabled must be a boolean")
        for jp in _json_array(jxp["ports"], "XP ports"):
            _json_object(jp, ["port"], "port")
            if "type" not in jp and "base_id" not in jp:
                raise ValueError("port is missing 'type' or 'base_id'")
            cmn_config.check_integer(jp["port"], "port number")
            if jp.get("type") is None and jp.get("base_id") is None:
                continue
            _integer_fields(jp, ["type"])
            _string_fields(jp, ["type_s"])
            _integer_fields(jp, ["base_id", "ccs"])
            if jp.get("cal") is not None and not isinstance(jp["cal"], bool):
                cmn_config.check_integer(jp.get("cal", 0), "CAL count", maximum=8)
            for jd in _json_array(jp.get("devices", []), "port device nodes"):
                _json_object(jd, ["id", "type"], "device node")
                cmn_config.check_integer(jd["id"], "node ID")
                cmn_config.check_integer(jd["type"], "node type")
                _integer_fields(jd, ["logical_id"])
                _string_fields(jd, ["type_s"])
                if jd.get("is_external") is not None and not isinstance(jd["is_external"], bool):
                    raise TypeError("node is_external must be a boolean")
                if not isinstance(jd.get("disabled", False), bool):
                    raise TypeError("node disabled must be a boolean")
            for jd in _json_array(jp.get("pdevices", []), "port devices"):
                _json_object(jd, ["id", "device_number"], "port device")
                cmn_config.check_integer(jd["id"], "device node ID")
                cmn_config.check_integer(jd["device_number"], "device number", maximum=7)
                _integer_fields(jd, ["dcs"])
            for ja in _json_array(jp.get("attached", []), "attached devices"):
                _json_object(ja, ["type"], "attached device")
                if ja["type"] == "cpu":
                    _json_object(ja, ["cpu"], "attached CPU")
                    cmn_config.check_integer(ja["cpu"], "CPU number")
                    _integer_fields(ja, ["id", "lpid"])


def cmn_from_json(j, S, warnings=None):
    """
    Construct a CMN object from its JSON representation.
    If supplied, append descriptions of ignored legacy devices to warnings.
    """
    if not isinstance(S, cmn_base.System):
        raise TypeError("CMN owner must be a System")
    _check_cmn_json(j)
    n_bad_structure_warnings = 0
    jc = j["config"]
    config = product_config_from_json(j)
    C = S.create_CMN(dimX=jc["X"], dimY=jc["Y"], config=config, extra_ports=jc.get("extra_ports", None))
    C.frequency = j.get("frequency", None)
    if "base" in jc:
        C.periphbase = _hex_address(jc["base"], "CMN base")
    if "rootnode_offset" in jc:
        C.rootnode_offset = _hex_address(jc["rootnode_offset"], "rootnode_offset")
    if "skiplist" in j:
        C.node_skiplist = [_hex_address(se, "skiplist address") for se in j["skiplist"]]
    for jxp in jc["xps"]:
        np = jxp.get("n_ports", None)
        if np is None:
            np = len(jxp["ports"])
        xp = C.create_xp(jxp["X"], jxp["Y"], n_ports=np, id=jxp["id"],
                         logical_id=jxp.get("logical_id", None), dtc=jxp.get("dtc", None))
        xp.is_external = jxp.get("is_external")
        xp.disabled = jxp.get("disabled", False)
        if "skipped" in jxp:
            xp.skipped_nodes = jxp["skipped"]
        if "mcs_east" in jxp:
            xp.mcs_east = jxp["mcs_east"]
        if "mcs_north" in jxp:
            xp.mcs_north = jxp["mcs_north"]
        port_numbers = set()
        for jp in jxp["ports"]:
            p = jp["port"]
            cmn_config.check_integer(p, "port number", maximum=np - 1)
            if p in port_numbers:
                raise ValueError("%s: duplicate port P%u" % (xp, p))
            port_numbers.add(p)
            p_type = jp.get("type")
            # We now omit unconnected ports in the JSON, but some old files had "null" here
            if p_type is None and jp.get("base_id") is None:
                continue        # legacy unconnected port
            cal = jp.get("cal", None)
            if isinstance(cal, bool):
                # handle older JSON schema, pre CAL4
                cal = 2 if cal else 0
            base_id = jp.get("base_id", None)
            if base_id is None and "pdevices" in jp and jp["pdevices"]:
                # Explicit slot numbers also identify the base when D0 was
                # not captured. Node-only legacy descriptions cannot do this.
                base_id = min(jd["id"] - jd["device_number"] for jd in jp["pdevices"])
            if base_id is None and jp.get("devices"):
                base_id = min(jd["id"] for jd in jp["devices"])
            if base_id is None:
                # Port has no nodes - e.g. SN-F. Legacy schema does not record the base id
                # of the port, so we calculate it.
                db = 1 if (np > 2) else 2
                base_id = xp.node_id() + (p << db)
                #print("assuming: %s port %u type %s base id 0x%x" % (xp, p, jp["type_s"], base_id))
            po = xp.create_port(port_number=p, type=p_type, type_s=jp.get("type_s"), cal=cal, base_id=base_id)
            po.cal_credited_slices = jp.get("ccs", None)
            if "devices" in jp:
                for jd in jp["devices"]:
                    n = C.create_node(type=jd["type"], type_s=jd.get("type_s"), xp=xp, port_number=p, id=jd["id"], logical_id=jd.get("logical_id", None))
                    n.is_external = jd.get("is_external")
                    n.disabled = jd.get("disabled", False)
            if "pdevices" in jp:
                device_numbers = set()
                for jd in jp["pdevices"]:
                    dn = jd["device_number"]
                    id = jd["id"]
                    if dn in device_numbers:
                        raise ValueError("%s: duplicate device number %u" % (po, dn))
                    device_numbers.add(dn)
                    if id != po.base_id() + dn:
                        raise ValueError("%s: device D%u ID does not match its base ID" % (po, dn))
                    try:
                        pdo = po.device(dn, create=True)
                    except cmn_base.CMNBadStructure:
                        n_bad_structure_warnings += 1
                        if warnings is not None:
                            if n_bad_structure_warnings <= 3:
                                warnings.append("%s: ignoring device D%u" % (po, dn))
                            elif n_bad_structure_warnings == 4:
                                warnings.append("(... further warnings suppressed ...)")
                        continue
                    if "dcs" in jd:
                        pdo.device_credited_slices = jd["dcs"]
            if "attached" in jp:
                for ja in jp["attached"]:
                    if ja["type"] == "cpu":
                        S.set_cpu(ja["cpu"], po, id=ja.get("id", None),
                                  lpid=ja.get("lpid", None))
    return C


def dmi_system_type():
    """
    Get the system type from DMI strings.
    Because we might not be root, we use the kernel's DMI strings in sysfs.
    """
    try:
        strings = []
        for s in ["sys_vendor", "product_name", "product_version"]:
            with open(os.path.join("/sys/class/dmi/id", s)) as f:
                strings.append(f.read().strip())
        return " ".join(strings).strip()
    except (IOError, OSError) as e:
        if e.errno == errno.ENOENT:
            return None
        raise


def system_description_warnings(S, check_system=True, check_timestamp=False):
    """
    Compare a description with the current host and return warning strings.
    These optional checks read local OS information, not CMN registers.
    Keep them separate from loading so offline clients need not inspect the host.
    """
    warnings = []
    if check_system and S.system_type is not None and S.processor_type is not None:
        os_type = dmi_system_type()
        if os_type is not None and os_type != S.system_type:
            warnings.extend([
                "CMN file might be for different system:",
                "  This system:    '%s'" % os_type,
                "  System in file: '%s'" % S.system_type,
            ])
    if check_timestamp and S.timestamp is not None:
        t_boot = boot_time()
        if S.timestamp < t_boot:
            warnings.append("Warning: system description dates from %s but system rebooted %s" %
                            (time.ctime(S.timestamp), time.ctime(t_boot)))
    return warnings


def c2c_links_from_json(jlinks, system, warnings=None):
    """Bind recorded links after all meshes have been loaded, without probing."""
    for jl in _json_array(jlinks, "C2C links"):
        _json_object(jl, ["id", "endpoints"], "C2C link")
        for field in ["protocol", "description"]:
            if field in jl and not isinstance(jl[field], basestring):
                raise TypeError("C2C %s must be a string" % field)
        jes = _json_array(jl["endpoints"], "C2C endpoints")
        if len(jes) != 2:
            raise ValueError("C2C link must have exactly two endpoints")
        endpoints = []
        for je in jes:
            _json_object(je, ["mseq", "id"], "C2C endpoint")
            for field in ["type", "interface"]:
                if field in je:
                    cmn_config.check_integer(je[field], "C2C endpoint %s" % field)
            endpoints.append(cmn_base.C2CLinkEndpoint(
                system, je["mseq"], je["id"],
                node_type=je.get("type"), interface=je.get("interface")))
        link = system.create_c2c_link(jl["id"], endpoints,
                                     protocol=jl.get("protocol"),
                                     description=jl.get("description"))
        if warnings is not None:
            for endpoint in link.endpoints:
                if endpoint.node_type is not None and endpoint.node is None:
                    warnings.append("C2C link %s: %s" % (link.id, endpoint))


def system_from_json(j, filename=None, warnings=None):
    """
    Create a system description object from a JSON structure.
    filename is source metadata only: this function does not access files or
    inspect the current host. If supplied, warnings is a list to append to.
    """
    _json_object(j, ["elements"], "system description")
    _json_array(j["elements"], "system elements")
    _string_fields(j, ["system_type", "system_uuid", "processor_type"])
    if "version" in j:
        cmn_config.check_integer(j["version"], "system description version", minimum=1)
    S = cmn_base.System(filename=filename)
    S.system_type = j.get("system_type", None)
    if S.system_type is not None:
        S.system_type = S.system_type.strip()
    S.system_uuid = uuid.UUID(j["system_uuid"]) if j.get("system_uuid") is not None else None
    S.processor_type = j.get("processor_type", None)
    if "date" in j and j["date"] is not None:
        S.timestamp = timestamp_from_json(j["date"])
    if "topology_discovery_time" in j and j["topology_discovery_time"] is not None:
        S.timestamp = timestamp_from_json(j["topology_discovery_time"])
    if "cpu_discovery_time" in j and j["cpu_discovery_time"] is not None:
        S.cpu_timestamp = timestamp_from_json(j["cpu_discovery_time"])
    for e in j["elements"]:
        _json_object(e, ["type", "product"], "system element")
        if e["type"] == "interconnect" and e["product"] == "CMN":
            cmn_from_json(e, S, warnings=warnings)   # this will add it to the System object
    # CPU mappings may be supplied either beside their port or in the system
    # index. Accept matching copies, but reject contradictory descriptions.
    for jc in _json_array(j.get("cpus", []), "CPUs"):
        _json_object(jc, ["cpu", "mseq", "id"], "CPU")
        cmn_config.check_integer(jc["cpu"], "CPU number")
        cmn_config.check_integer(jc["mseq"], "CPU mesh", maximum=len(S.CMNs) - 1)
        cmn_config.check_integer(jc["id"], "CPU node ID")
        _integer_fields(jc, ["lpid"])
        C = S.CMNs[jc["mseq"]]
        lpid = jc.get("lpid")
        if jc["cpu"] in S.cpu_node:
            cpu = S.cpu_node[jc["cpu"]]
            if (cpu.CMN(), cpu.id, cpu.lpid) != (C, jc["id"], lpid):
                raise ValueError("conflicting mappings for CPU %u" % jc["cpu"])
        else:
            device = C.device_at_id(jc["id"], create=True)
            if device is None:
                raise ValueError("CPU %u refers to an unknown device" % jc["cpu"])
            S.set_cpu(jc["cpu"], device.port, id=jc["id"], lpid=lpid)
    if "c2c_links" in j:
        c2c_links_from_json(j["c2c_links"], S, warnings=warnings)
    if "io_address_map" in j:
        ja = j["io_address_map"]
        _json_object(ja, ["homes"], "I/O address map")
        homes = []
        for jh in _json_array(ja["homes"], "I/O homes"):
            _json_object(jh, ["mseq", "id", "type_s", "regions"], "I/O home")
            regions = []
            for jr in _json_array(jh["regions"], "I/O regions"):
                _json_object(jr, ["start", "end"], "I/O region")
                resources = []
                for js in _json_array(jr.get("resources", []), "I/O resources"):
                    _json_object(js, ["start", "end", "name"], "I/O resource")
                    resources.append(cmn_base.IOAddressResource(
                        _hex_address(js["start"], "resource start"),
                        _hex_address(js["end"], "resource end"), js["name"]))
                regions.append(cmn_base.IOAddressRegion(
                    _hex_address(jr["start"], "region start"),
                    _hex_address(jr["end"], "region end"),
                    status=jr.get("status", "ok"), resources=resources))
            homes.append(cmn_base.IOAddressHome(
                jh["mseq"], jh["id"], jh["type_s"], regions=regions))
        S.io_address_map = cmn_base.IOAddressMap(
            discovery_time=timestamp_from_json(
                ja.get("discovery_time", None)), homes=homes)
    return S


def system_from_json_file(fn=None, missing_ok=False, warnings=None):
    """
    Get the system description from a given file name or the standard cached location.
    No host checks, printing or process exits occur here. missing_ok allows a
    missing input file to return None; other I/O errors still propagate.
    If supplied, append conversion warnings to the caller's list.
    """
    fn = cmn_config_default(fn)
    try:
        f = open(fn)
    except (IOError, OSError) as e:
        # Catch only failure to open the input, not errors from reading,
        # conversion or metadata. IOError also covers non-missing files on
        # Python 2, so checking errno is essential on every interpreter.
        if missing_ok and e.errno == errno.ENOENT:
            return None
        raise
    with f:
        S = system_from_json(json.load(f), filename=fn, warnings=warnings)
        if S.timestamp is None:
            S.timestamp = os.path.getmtime(fn)
    return S


def load_system_for_cli(fn=None, check_timestamp=False, missing_ok=False,
                        check_system=True):
    """
    Load a description for a command-line tool and print its warnings.
    Report a missing required file and exit. An optional missing file returns
    None; all other loading errors propagate. Host checks are enabled here,
    but can be disabled for reporting on descriptions from other systems.
    """
    fn = cmn_config_default(fn)
    warnings = []
    S = system_from_json_file(fn, missing_ok=True, warnings=warnings)
    if S is None:
        if not missing_ok:
            print("%s: file not found: run cmn_discover" % fn, file=sys.stderr)
            sys.exit(1)
        return None
    warnings.extend(system_description_warnings(
        S, check_system=check_system, check_timestamp=check_timestamp))
    for warning in warnings:
        print(warning, file=sys.stderr)
    return S


def json_from_cpu(co, mesh_numbers=None):
    j = {
        "type": "cpu",
        "cpu": co.cpu,     # CPU number as known to Linux
        "mseq": co.CMN().cmn_seq if mesh_numbers is None else mesh_numbers[co.CMN()],
        "id": co.id,       # CHI SRCID - includes port and device bits
    }
    if co.lpid is not None:
        j["lpid"] = co.lpid    # CHI LPID, generally zero or assigned by DSU
    return j


def cmn_label(C):
    return "CMN#%u" % C.cmn_seq


def json_from_device_node(d):
    jd = {
        "id": d.node_id(),
        "type": d.type(),
        "type_s": d.type_str(),
    }
    if d.logical_id() is not None:
        jd["logical_id"] = d.logical_id()
    if d.is_external is not None:
        jd["is_external"] = bool(d.is_external)
    if d.is_disabled():
        jd["disabled"] = True
    return jd


def json_from_port(p):
    jp = {
        "port": p.port_number,
        "type": p.connected_type,
        "type_s": p.connected_type_s,
        "base_id": p.base_id(),
    }
    jp["cal"] = p.cal
    if p.cal_credited_slices is not None:
        jp["ccs"] = p.cal_credited_slices
    jp["pdevices"] = []
    for dn in p.device_numbers():
        pdo = p.device(dn, create=True)
        if pdo is None:
            raise TypeError("%s reports device number %u but did not materialize a device object" % (p, dn))
        jd = {
            "device_number": dn,
            "id": p.base_id() + dn,
        }
        dcs = p.device_credited_slices(dn)
        if dcs is not None:
            jd["dcs"] = dcs
        jp["pdevices"].append(jd)
    return dict((name, value) for name, value in jp.items() if value is not None)


def json_from_xp(xp, mesh_numbers=None):
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
    if xp.is_external is not None:
        j["is_external"] = bool(xp.is_external)
    if xp.is_disabled():
        j["disabled"] = True
    # JSON has only one DTC domain per XP. Both models provide the domains
    # through the same topology query; reject values that cannot be represented.
    dtc_domains = xp.dtc_domains()
    dtc_domain = dtc_domains[0]
    for i, domain in enumerate(dtc_domains):
        if domain != dtc_domain:
            raise ValueError("unsupported configuration: %s has different DTC domains "
                             "(DTM0=%s, DTM%u=%s); JSON supports only one DTC domain per XP" %
                             (xp, dtc_domain, i, domain))
    if dtc_domain is not None:
        j["dtc"] = dtc_domain
    if xp.skipped_nodes is not None:
        j["skipped"] = xp.skipped_nodes
    emcs = xp.mesh_credited_slices(0)
    if emcs is not None:
        j["mcs_east"] = emcs
    nmcs = xp.mesh_credited_slices(1)
    if nmcs is not None:
        j["mcs_north"] = nmcs
    for p in xp.ports():
        jp = json_from_port(p)
        pnodes = list(p.nodes())
        if pnodes:
            jp["devices"] = [json_from_device_node(d) for d in pnodes]
            assert jp["devices"]
        try:
            if p.cpus:
                jp["attached"] = [json_from_cpu(co, mesh_numbers=mesh_numbers) for co in p.cpus]
        except AttributeError:
            # this won't work for the CMN objects built from /dev/mem discovery
            pass
        j["ports"].append(jp)
    return j


def json_from_cmn(C, mesh_numbers=None):
    j = {
        "type": "interconnect",
        "product": "CMN",
        "version": C.product_config.product_name(),
        "revision": C.product_config.revision_code,
        "config": {
            "mpam_enabled": C.product_config.mpam_enabled,
            "mpam_partid_width": C.product_config.mpam_partid_width,
            "mte_enabled": C.product_config.mte_enabled,
            "chi_version": C.product_config.chi_version,
            "pa_width": C.product_config.pa_width,
            "req_pa_width": C.product_config.req_pa_width,
            "rsvdc_width": C.product_config.rsvdc_width,
            "X": C.dimX,
            "Y": C.dimY,
            "extra_ports": C.extra_ports,
            "xps": [json_from_xp(xp, mesh_numbers=mesh_numbers) for xp in C.XPs()],
        }
    }
    if C.product_config.revision_code is None:
        del j["revision"]
    j["config"] = dict((name, value) for name, value in j["config"].items() if value is not None)
    if C.periphbase is not None:
        j["config"]["base"] = "0x%x" % C.periphbase
    if C.rootnode_offset is not None:
        j["config"]["rootnode_offset"] = "0x%x" % C.rootnode_offset
    if C.node_skiplist is not None:
        j["skiplist"] = [("0x%x" % se) for se in C.node_skiplist]
    if C.frequency is not None:
        j["frequency"] = C.frequency
    return j


def json_from_io_address_map(amap, mesh_indices=None):
    j = {"homes": []}
    if amap.discovery_time is not None:
        j["discovery_time"] = json_timestamp(amap.discovery_time)
    for home in amap.homes:
        jh = {
            "mseq": home.mseq if mesh_indices is None else mesh_indices.get(home.mseq, home.mseq),
            "id": home.node_id,
            "type_s": home.type_s,
            "regions": [],
        }
        for region in home.regions:
            jr = {
                "start": "0x%x" % region.start,
                "end": "0x%x" % region.end,
                "status": region.status,
                "resources": [],
            }
            for resource in region.resources:
                jr["resources"].append({
                    "start": "0x%x" % resource.start,
                    "end": "0x%x" % resource.end,
                    "name": resource.name,
                })
            jh["regions"].append(jr)
        j["homes"].append(jh)
    return j


def json_from_c2c_link(link, mesh_numbers=None):
    """
    Serialize topology references, including unresolved node selectors.
    A system writer supplies mesh_numbers to match its CMN element order;
    live mesh sequence numbers need not be contiguous or ordered that way.
    """
    j = {"id": link.id, "endpoints": []}
    for endpoint in link.endpoints:
        cmn = endpoint.device.CMN()
        mseq = cmn.cmn_seq if mesh_numbers is None else mesh_numbers[cmn]
        je = {"mseq": mseq, "id": endpoint.device.node_id()}
        if endpoint.node_type is not None:
            je["type"] = endpoint.node_type
        if endpoint.interface is not None:
            je["interface"] = endpoint.interface
        j["endpoints"].append(je)
    if link.protocol is not None:
        j["protocol"] = link.protocol
    if link.description is not None:
        j["description"] = link.description
    return j


def json_from_system(S):
    j = {
        "version": S.version,
        "generator": os.path.basename(__file__),
        "elements": []
    }
    if S.timestamp is not None:
        j["topology_discovery_time"] = json_timestamp(S.timestamp)
    if S.cpu_timestamp is not None:
        j["cpu_discovery_time"] = json_timestamp(S.cpu_timestamp)
    if S.system_type is not None:
        j["system_type"] = S.system_type
    if S.system_uuid is not None:
        j["system_uuid"] = str(S.system_uuid)
    if S.processor_type is not None:
        j["processor_type"] = S.processor_type
    mesh_numbers = dict((cmn, i) for i, cmn in enumerate(S.CMNs))
    for C in S.CMNs:
        jc = json_from_cmn(C, mesh_numbers=mesh_numbers)
        j["elements"].append(jc)
    if S.has_cpu_mappings():
        j["cpus"] = [json_from_cpu(S.cpu_node[c], mesh_numbers=mesh_numbers) for c in sorted(S.cpu_node.keys())]
    if S.io_address_map is not None:
        mesh_indices = dict((cmn.cmn_seq, i) for i, cmn in enumerate(S.CMNs))
        j["io_address_map"] = json_from_io_address_map(S.io_address_map, mesh_indices=mesh_indices)
    if S.c2c_links:
        j["c2c_links"] = [json_from_c2c_link(link, mesh_numbers=mesh_numbers)
                          for link in sorted(S.c2c_links, key=lambda link: link.id)]
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
    S = load_system_for_cli(fn)
    system_print_summary_info(S, opts)
    return S


def home_node_type(C):
    """Describe the one recorded home-node type of a mesh."""
    node_type = C.home_node_type()
    return cmn_enum.cmn_node_type_str(node_type) if node_type is not None else "none recorded"


def system_print_summary_info(S, opts):
    """
    Print summary information about a system.
    """
    if opts.verbose:
        print("System type: %s" % S.system_type)
        print("CMN configuration: %s" % S)
        types = sorted(set(home_node_type(c) for c in S.CMNs if c.home_node_type() is not None))
        print("Home-node types: %s" % ("/".join(types) if types else "none recorded"))
    if not S.CMNs:
        print("%s: CMN interconnect not found" % (S.filename), file=sys.stderr)
        sys.exit(1)
    if not (opts.filename or (opts.nodeid is not None) or
            opts.nodes or opts.ports or opts.home_nodes or opts.cpus or opts.xps or opts.c2c_links or
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
        if S.has_cpu_mappings():
            print(" %3u CPUs" % len(S.cpu_node), end="")
        else:
            print("         ", end="")
        print("  ", end="")
        # cmn_version() uses CMNConfig equality; compare topology separately.
        topology = [(c.dimX, c.dimY, c.home_node_type()) for c in S.CMNs]
        same_meshes = vsn is not None and all(t == topology[0] for t in topology)
        if same_meshes:
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
        else:
            print("; ".join("%s: %s %ux%u %s" %
                            (c, c.product_config if c.product_config is not None else
                             "unknown configuration",
                             c.dimX, c.dimY, home_node_type(c))
                            for c in S.CMNs), end="")
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
        if same_meshes and home_node_type(C0) not in ["HN-F", "none recorded"]:
            print(" %s" % home_node_type(C0), end="")
        disabled = sum(n.is_disabled() for n in S.nodes()) + sum(xp.is_disabled() for xp in S.XPs())
        if disabled:
            print(" %u disabled node%s" % (disabled, "s" if disabled != 1 else ""), end="")
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
                        print(" (CAL%s)" % p.cal, end="")
                    print()
                    for d in p.device_nodes:
                        print("        %s" % d)
                    for co in p.cpus:
                        print("        %s" % co)
    if opts.c2c_links:
        links = [link for link in S.c2c_links
                 if opts.cmn_instance is None or any(
                     endpoint.device.CMN().cmn_seq == opts.cmn_instance
                     for endpoint in link.endpoints)]
        if not links:
            print("No C2C links recorded%s." %
                  ("" if opts.cmn_instance is None else " for CMN#%u" % opts.cmn_instance))
        else:
            print("C2C links:")
            for link in sorted(links, key=lambda link: link.id):
                print("  %s: %s <-> %s" % (link.id, link.endpoints[0], link.endpoints[1]), end="")
                if link.protocol is not None:
                    print(" protocol=%s" % link.protocol, end="")
                if link.description:
                    print(" -- %s" % link.description, end="")
                print()
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
                print("  %s RN-F 0x%x" % (cmn_label(port.CMN()), (port.base_id() + d)))
        print("RN-Fs:")
        for d in S.devices(properties=cmn_enum.CMN_PROP_RNF):
            print("  %s RN-F 0x%x" % (cmn_label(d.CMN()), d.node_id()), end="")
            for cpu in d.CMN().cpus_at_id(d.node_id()):
                print(" CPU#%u(lpid=%s)" % (cpu.cpu, cpu.lpid), end="")
            print()
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
        for C in S.cmn_instances(instance=opts.cmn_instance):
            p = C.port_at_id(opts.nodeid)
            if p is not None:
                print(p)
            else:
                print("%s: no port matching ID 0x%02x" % (cmn_label(C), opts.nodeid))


def main(argv):
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
    parser.add_argument("--c2c-links", action="store_true", help="list recorded chip-to-chip links")
    parser.add_argument("--cmn-instance", type=int, help="select CMN instance")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("all_inputs", type=str, nargs="*", help="input JSON")
    opts = parser.parse_args(argv)
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


if __name__ == "__main__":
    main(sys.argv[1:])
