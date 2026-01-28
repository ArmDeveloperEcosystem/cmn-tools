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
    for y in range(C.dimY-1, -1, -1):
        s = "%-5u|" % y
        xps = [C.XP_at(x, y) for x in range(0, C.dimX)]
        for xp in xps:
            s += " XP #%-3u|" % xp.logical_id()
        sl.append(s)
        sl.append("     |" + ''.join([(" DTC %-2s |" % (xp.dtc_domain() if xp.dtc_domain() is not None else "??")) for xp in xps]))
        sl.append("     |" + (C.dimX * "........|"))
        for p in range(0, max_ports):
            pos = [xp.port_object(p) for xp in xps]      # P<n> for all XPs in this mesh row. None if port not in use on this XP.
            def port_type_str(po):
                return cmn_port_device_type_str(po.connected_type) if po is not None else ""
            sl.append((" %2u  |" % p) + ''.join(["%s|" % port_type_str(po).center(WIDTH) for po in pos]))
            for d in range(0, 2):
                def port_devices(po, d):
                    return po.device_nodes(d) if po is not None else []
                def devlist_logical_id(dl):
                    for dev in dl:
                        if C.id_xy(dev.id) != dev.XP().XY():
                            # Skip devices that are wrongly located (CXLA on CMN-600)
                            continue
                        if dev.logical_id() is not None:
                            return dev.logical_id()
                    return None
                def lidstr(lid):
                    return ("#%u" % lid) if lid is not None else ""
                lids = [devlist_logical_id(port_devices(po, d)) for po in pos]
                sl.append(("   %2u|" % d) + ''.join(["%s|" % lidstr(lid).center(WIDTH) for lid in lids]))
        sl.append("-----+" + (C.dimX * "--------+"))
    return sl


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="generate Linux-style CMN diagram")
    parser.add_argument("-i", "--input", type=str, default=cmn_json.cmn_config_filename(), help="CMN JSON")
    parser.add_argument("--cmn-instance", type=int, default=0, help="select CMN number")
    parser.add_argument("--diff", action="store_true", help="diff our map against the kernel's map")
    parser.add_argument("--kernel-map", type=str, default=DEBUG_CMN_MAP, help="file containing kernel debug map")
    parser.add_argument("--diff-opts", type=str, default="", help="options for 'diff' command")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("inputs", type=str, nargs="*", help="additional JSON inputs")
    opts = parser.parse_args()
    if not opts.inputs:
        opts.inputs = [opts.input]
    if opts.diff and len(opts.inputs) > 1:
        print("Can't use --diff with multiple inputs", file=sys.stderr)
        sys.exit(1)
    for fn in opts.inputs:
        if len(opts.inputs) > 1 or opts.verbose:
            print("%s:" % fn)
        S = cmn_json.system_from_json_file(fn)
        C = S.CMNs[opts.cmn_instance]
        m = gen_debugmap(C)
        if not opts.diff:
            print("\n".join(m))
        else:
            with open("temp.cmnmap", "w") as f:
                f.write("\n".join(m) + "\n")
            rc = os.system("diff %s %s %s" % (opts.diff_opts, opts.kernel_map, "temp.cmnmap"))
            if rc == 0:
                print("Successfully reproduced the kernel driver map")
            else:
                print("Maps do not match")
                sys.exit(rc)
