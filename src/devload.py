#!/usr/bin/python3

"""
Generate a stream of accesses from a CPU to device space,
to test CMN top-down analysis.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

We expect to see a stream of accesses to the HN-D node.
Because this is Python, the access rate will be fairly modest and unlikely
to compete with data accesses or I/O accesses from a real application.
"""

from __future__ import print_function

import cmn_devmem
import cmn_devmem_find


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="generate device traffic")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    C = cmn_devmem.CMN(cmn_devmem.cmn_instance(opts), verbose=opts.verbose)
    xp = list(C.XPs())[0]
    print(xp)
    # Endless loop to read a device register - node_info register is a safe one to read
    while True:
        x = xp.read64(cmn_devmem.CMN_any_NODE_INFO)
