#!/usr/bin/python3

"""
JSON serialization for CMN interconnect descriptions

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys, os, time
import json
import cmn_base
import cmn_enum


def cmn_config_cache(name=None):
    """
    Get the default location for CMN JSON description files,
    ensuring that the subdirectory exists.
    We allow for the fact that this script is likely to be run under 'sudo'.
    """
    user = os.environ.get("SUDO_USER", os.environ.get("USER"))
    pcache = os.path.expanduser("~" + user + "/.cache")
    if not os.path.isdir(pcache):
        os.mkdir(pcache)
        change_to_real_user_if_sudo(pcache)
    pcache = os.path.join(pcache, "arm")
    if not os.path.isdir(pcache):
        os.mkdir(pcache)
        change_to_real_user_if_sudo(pcache)
    if name is not None:
        return os.path.join(pcache, name)
    return pcache


def cmn_config_filename():
    return cmn_config_cache("cmn-system.json")


def cmn_config_default(fn):
    if fn is None:
        fn = cmn_config_filename()
        if not os.path.exists(fn):
            print("Need CMN configuration in %s" % fn, file=sys.stderr)
            sys.exit(1)
    return fn


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
        C.product_config = cmn_base.CMNConfig(product_name=v)
        if "revision" in j:
            C.product_config.revision = j["revision"]
    C.product_config.mpam_enabled = jc.get("mpam_enabled", False)
    C.product_config.chi_version = jc.get("chi_version", None)
    C.frequency = j.get("frequency", None)
    if "base" in jc:
        C.periphbase = int(jc["base"], 16)
    for jxp in jc["xps"]:
        np = jxp["n_ports"]
        xp = C.create_xp(jxp["X"], jxp["Y"], n_ports=np, id=jxp["id"], logical_id=jxp.get("logical_id", None))
        if "dtc" in jxp:
            xp.dtc = jxp["dtc"]
        for jp in jxp["ports"]:
            p = jp["port"]
            po = xp.create_port(port=p, type=jp["type"], type_s=jp["type_s"])
            po.cal = jp.get("cal", False)
            if "devices" in jp:
                for jd in jp["devices"]:
                    n = C.create_node(type=jd["type"], type_s=jd["type_s"], xp=xp, port=p, id=jd["id"], logical_id=jd.get("logical_id", None))
            if "attached" in jp:
                for ja in jp["attached"]:
                    if ja["type"] == "cpu":
                        S.set_cpu(ja["cpu"], po, id=ja.get("id", None), lpid=ja.get("lpid", 0))
    return C


def system_from_json(j, filename=None):
    S = cmn_base.System(filename=filename)
    S.system_type = j.get("system_type", None)
    for e in j["elements"]:
        if e["type"] == "interconnect" and e["product"] == "CMN":
            cmn_from_json(e, S)   # this will add it to the System object
    return S


def system_from_json_file(fn=None):
    """
    Get the system description from a given file name or the standard cached location.
    """
    if fn is None:
        fn = cmn_config_filename()
    with open(fn) as f:
        return system_from_json(json.load(f), filename=fn)


def json_from_cpu(co):
    j = {
        "type": "cpu",
        "cpu": co.cpu,     # CPU number as known to Linux
        "mseq": co.port.CMN().seq,   # mesh sequence number in the system
        "id": co.id,       # CHI SRCID - includes port and device bits
        "lpid": co.lpid    # CHI LPID, generally zero or assigned by DSU
    }
    return j


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
    for i in range(xp.n_device_ports()):
        #p = xp.port[i]
        jp = {
            "port": i,
            "type": xp.port_device_type(i),
            "type_s": xp.port_device_type_str(i),
        }
        if xp.port_has_cal(i):
            jp["cal"] = True
        if list(xp.port_nodes(i)):
            jp["devices"] = []
            for d in xp.port_nodes(i):
                jd = {
                    "id": d.node_id(),
                    "type": d.type(),
                    "type_s": d.type_str(),
                }
                if d.logical_id() is not None:
                    jd["logical_id"] = d.logical_id()
                jp["devices"].append(jd)
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
        "revision": C.product_config.revision,
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
    if C.frequency is not None:
        j["frequency"] = C.frequency
    return j


def json_from_system(S):
    j = {
        "version": S.version,
        "generator": os.path.basename(__file__),
        "date": time.time(),
        "elements": []
    }
    if S.system_type is not None:
        j["system_type"] = S.system_type
    for C in S.CMNs:
        jc = json_from_cmn(C)
        j["elements"].append(jc)
    if S.has_cpu_mappings():
        j["cpus"] = [json_from_cpu(S.cpu_node[c]) for c in sorted(S.cpu_node.keys())]
    return j


def change_to_real_user_if_sudo(fn):
    """
    When writing a file as sudo, we might want it to be owned by the "real" user
    to avoid complications when later using it as non-sudo.
    """
    if "SUDO_USER" in os.environ:
        user = os.environ["SUDO_USER"]
        if sys.version_info[0] >= 3:
            import shutil
            shutil.chown(fn, user=user, group=user)
        else:
            # Python2 shutil doesn't have chown().
            import pwd, grp
            os.chown(fn, pwd.getpwnam(user).pw_uid, grp.getgrnam(user).gr_gid)


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
            change_to_real_user_if_sudo(fn)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN mesh interconnect model")
    parser.add_argument("-i", "--input", type=str, help="input JSON")
    parser.add_argument("-o", "--output", type=str, help="output JSON")
    parser.add_argument("--filename", action="store_true", help="display filename")
    parser.add_argument("--nodes", action="store_true", help="list all nodes")
    parser.add_argument("--ports", action="store_true", help="list all ports")
    parser.add_argument("--requesters", action="store_true", help="list requesters")
    parser.add_argument("--home-nodes", action="store_true", help="list home nodes")
    parser.add_argument("--cpus", action="store_true", help="list CPUs")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    opts.input = cmn_config_default(opts.input)
    S = system_from_json_file(opts.input)
    if opts.verbose:
        print("System type: %s" % S.system_type)
        print("CMN version: %s" % S.cmn_version())
    if S.cmn_version() is None:
        print("%s: CMN interconnect not found" % (S.filename), file=sys.stderr)
        sys.exit(1)
    if not (opts.filename or opts.nodes or opts.ports or opts.home_nodes or opts.cpus or opts.output):
        print(S)
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
    if opts.filename:
        print(S.filename)
    if opts.output is not None:
        json_dump_file_from_system(S, opts.output)
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
        print("Requester nodes:")
        for node in S.nodes(properties=cmn_enum.CMN_PROP_RN):
            print("  %s" % node)
        # RN-Fs aren't nodes in CMN, but we can list RN-F ports
        print("RN-F ports:")
        for port in S.ports(properties=cmn_enum.CMN_PROP_RNF):
            print("  %s" % port)
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
