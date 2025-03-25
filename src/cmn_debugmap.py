#!/usr/bin/python

"""
Generate a 2-D map of the CMN mesh in the format of the Linux PMU driver
(main author Robin.Murphy@arm.com). This is mainly for cross-checking
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


def port_device_type_str(xp, p):
    ptype = xp.port_device_type(p)
    return cmn_port_device_type_str(ptype) if ptype is not None else ""


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
            sl.append((" %2u  |" % p) + ''.join(["%s|" % port_device_type_str(xp, p).center(WIDTH) for xp in xps]))
            for d in range(0, 2):
                def port_devices(xp, p, d):
                    if xp.port_device_type(p) is not None:
                        return xp.port_nodes_by_device(p, d)
                    else:
                        return []
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
                lids = [devlist_logical_id(port_devices(xp, p, d)) for xp in xps]
                sl.append(("   %2u|" % d) + ''.join(["%s|" % lidstr(lid).center(WIDTH) for lid in lids]))
        sl.append("-----+" + (C.dimX * "--------+"))
    return sl


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="generate Linux-style CMN diagram")
    parser.add_argument("-i", "--input", type=str, default=cmn_json.cmn_config_filename(), help="CMN JSON")
    parser.add_argument("--cmn-instance", type=int, default=0, help="select CMN number")
    parser.add_argument("--diff", action="store_true")
    parser.add_argument("--diff-opts", type=str, default="", help="options for 'diff' command")
    opts = parser.parse_args()
    S = cmn_json.system_from_json_file(opts.input)
    C = S.CMNs[opts.cmn_instance]
    m = gen_debugmap(C)
    if not opts.diff:
        print("\n".join(m) + "\n")
    else:
        with open("temp.cmnmap", "w") as f:
            f.write("\n".join(m) + "\n")
        rc = os.system("diff %s %s %s" % (opts.diff_opts, DEBUG_CMN_MAP, "temp.cmnmap"))
        if rc == 0:
            print("Successfully reproduced the kernel driver map")
        else:
            print("Maps do not match")
            sys.exit(rc)
