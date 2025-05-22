#!/usr/bin/python

"""
Print CMN frequency estimated from the CMN cycle counter.
Does not require CMN kernel PMU driver.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os
import time


import cmn_devmem
import cmn_devmem_find


class VarTracker:
    def __init__(self):
        self.n_samples = 0
        self.v_last = None
        self.v_max = None
        self.v_min = None

    def add(self, v):
        self.n_samples += 1
        self.v_max = max(v, self.v_max) if self.v_max is not None else v
        self.v_min = min(v, self.v_min) if self.v_min is not None else v
        self.v_last = v


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN frequency")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--td", type=float, help="frequency measurement time")
    parser.add_argument("--watch", type=float, help="watch interval")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    Cs = cmn_devmem.cmn_from_opts(opts)
    for C in Cs:
        C.freq_var = VarTracker()
    while True:
        for C in Cs:
            if opts.td is not None:
                f = C.estimate_frequency(td=opts.td)
            else:
                f = C.estimate_frequency()
            print("%s: %.2f GHz" % (C, f/1e9), end="")
            fv = C.freq_var
            vl = fv.v_last
            fv.add(f)
            if fv.n_samples >= 2:
                print("  %.2f..%.2f" % (fv.v_min/1e9, fv.v_max/1e9), end="")
                print("  %5.2f" % ((f - vl)/1e9), end="")
            # end with some blank spaces to avoid artefacts
            print("        ")
        if not opts.watch:
            # Finish now
            break
        # Step the cursor back up to the first line
        # n.b. --watch only makes sense if output is to tty
        print("\x1b[%uA" % len(Cs), end="")
        time.sleep(opts.watch)
