#!/usr/bin/python

"""
Generate a 2-D map of the CMN mesh in the format of the Linux PMU driver
(main author Robin Murphy). This is mainly for cross-checking
the bare-metal tools against the driver.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os
import sys

import cmn_base
import cmn_json
from cmn_enum import *


DEBUG_CMN_MAP = "/sys/kernel/debug/arm-cmn/map"


def gen_debugmap(C):
    """
    Generate a debugmap from a single CMN
    Returns a list of strings corresponding to text lines.
    """
    WIDTH = 8
    sl = []
    sl.append("     X" + ''.join([("  %3u    " % i) for i in range(0, C.dimX)]))
    sl.append("Y P D+" + (C.dimX * "--------+"))
    max_ports = max([xp.n_device_ports() for xp in C.XPs()])
    max_devices = 0
    for port in C.ports():
        dns = port.device_numbers()
        if dns:
            max_devices = max(max_devices, max(dns) + 1)
    for y in range(C.dimY-1, -1, -1):
        s = "%-5u|" % y
        xps = [C.XP_at(x, y) for x in range(0, C.dimX)]
        for xp in xps:
            s += " XP #%-3u|" % xp.logical_id()
        sl.append(s)
        sl.append("     |" + ''.join([(" DTC %-2s |" % (xp.dtc_domain() if xp.dtc_domain() is not None else "??")) for xp in xps]))
        sl.append("     |" + (C.dimX * "........|"))
        for p in range(0, max_ports):
            pos = [xp.port(p) for xp in xps]      # P<n> for all XPs in this mesh row. None if port not in use on this XP.
            def port_type_str(po):
                return cmn_port_device_type_str(po.connected_type) if po is not None else ""
            sl.append((" %2u  |" % p) + ''.join(["%s|" % port_type_str(po).center(WIDTH) for po in pos]))
            for d in range(0, max_devices):
                def port_devices(po, d):
                    if po is None or not po.is_valid_id(cmn_base.port_device_id(po, d)):
                        return []
                    pdo = po.device(d)
                    return pdo.device_nodes if pdo is not None else []
                def devlist_logical_id(dl):
                    # Find the device logical id for devices with a given (port, device) combination.
                    # Generally these are the same for all nodes in a device, so we return as soon
                    # as we find one. The one exception to this rule is on HN-D/HN-T nodes where the
                    # debug node (DTC) logical id is its DTC domain number, and may be different from
                    # the logical id of the DN and HN-I device nodes in the same device.
                    # For consistency with the Linux driver, we prefer the DN/HN-I logical id.
                    id = None
                    for dev in dl:
                        if C.id_xy(dev.id) != dev.XP().XY():
                            # Skip devices that are wrongly located (CXLA on CMN-600)
                            continue
                        nid = dev.logical_id()
                        if nid is not None and not dev.has_properties(CMN_PROP_T):
                            if id is not None and id != nid:
                                print("%s logical id mismatch %u vs %u" % (dev, id, nid), file=sys.stderr)
                            id = nid
                    return id
                def lidstr(lid):
                    return ("#%u" % lid) if lid is not None else ""
                lids = [devlist_logical_id(port_devices(po, d)) for po in pos]
                sl.append(("   %2u|" % d) + ''.join(["%s|" % lidstr(lid).center(WIDTH) for lid in lids]))
        sl.append("-----+" + (C.dimX * "--------+"))
    return sl


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="generate Linux-style CMN diagram")
    parser.add_argument("-i", "--input", type=str, default=cmn_json.cmn_config_filename(), help="CMN JSON")
    parser.add_argument("--cmn-instance", type=int, help="select CMN number")
    parser.add_argument("--diff", action="store_true", help="diff our map against the kernel's map")
    parser.add_argument("--kernel-map", type=str, default=DEBUG_CMN_MAP, help="file containing kernel debug map")
    parser.add_argument("--diff-opts", type=str, default="", help="options for 'diff' command")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("inputs", type=str, nargs="*", help="additional JSON inputs")
    opts = parser.parse_args(argv)
    if not opts.inputs:
        opts.inputs = [opts.input]
    if opts.diff and len(opts.inputs) > 1:
        print("Can't use --diff with multiple inputs", file=sys.stderr)
        sys.exit(1)
    mismatched = 0
    for fn in opts.inputs:
        if len(opts.inputs) > 1 or opts.verbose:
            print("%s:" % fn)
        S = cmn_json.system_from_json_file(fn)
        for C in S.CMNs:
            if opts.cmn_instance is not None and C.cmn_seq != opts.cmn_instance:
                continue
            m = gen_debugmap(C)
            if not opts.diff:
                print("\n".join(m))
            else:
                suffix = "_%u" % C.cmn_seq if C.cmn_seq > 0 else ""
                temp_fn = "temp.cmnmap" + suffix
                kernel_map = opts.kernel_map + suffix
                with open(temp_fn, "w") as f:
                    f.write("\n".join(m) + "\n")
                rc = os.system("diff %s %s %s" % (opts.diff_opts, kernel_map, temp_fn))
                if rc == 0:
                    print("Successfully reproduced the kernel driver map in %s" % kernel_map)
                    os.remove(temp_fn)
                else:
                    print("Maps do not match: compare %s and %s" % (temp_fn, kernel_map))
                    mismatched = rc
    if mismatched:
        sys.exit(mismatched)


if __name__ == "__main__":
    main(sys.argv[1:])
