#!/usr/bin/python

"""
Write to Secure-writeable-only security override registers,
to allow NonSecure reading of SLC/SF, RN-SAM etc.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import os
import sys


import cmn_devmem_find
import cmn_devmem


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN lock/unlock")
    gex = parser.add_mutually_exclusive_group()
    gex.add_argument("--unlock", action="store_true", help="unlock CMN secure registers")
    gex.add_argument("--lock", action="store_true", help="lock CMN secure registers")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    clocs = list(cmn_devmem_find.cmn_locators(opts))
    CS = [cmn_devmem.CMN(cl, verbose=opts.verbose) for cl in clocs]
    for c in CS:
        if opts.verbose or not (opts.lock or opts.unlock):
            print("%s:" % c)
            print("  global security: 0x%08x" % c.rootnode.read64(cmn_devmem.CMN_any_SECURE_ACCESS))
        if opts.lock or opts.unlock:
            if not c.secure_accessible:
                c.rootnode.set_secure_access(c.root_security)
            v = 0x00 if opts.lock else 0x01
            c.rootnode.write64(cmn_devmem.CMN_any_SECURE_ACCESS, v, check=True)
            if opts.verbose:
                print("              now: 0x%08x" % c.rootnode.read64(cmn_devmem.CMN_any_SECURE_ACCESS))
