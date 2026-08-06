#!/usr/bin/python

"""
Generate a string representing a memory size.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

There are several ways the caller can tune the output:

  - decimal vs. binary, e.g. 1000000 bytes might be "1MB" or "977KiB"
  - whether binary is printed as "977KiB" (as per IEC 80000) or "977KB" (legacy)
"""

from __future__ import print_function


import sys


def memsize_str(n, decimal=False, legacy=False, unit="B"):
    """
    Given a memory size in bytes, return a descriptive string.
    """
    if not decimal:
        suf = ("" if legacy else "i")
        for u in range(4, 0, -1):
            # For values which are over 1000* one unit, but not quite at the next unit,
            # we want to avoid scientific notation - so we force use of the next unit.
            if n >= 1000*(1 << ((u-1)*10)):
                return "%.3g%s%s%s" % ((float(n) / (1 << (u*10))), "?KMGT"[u], suf, unit)
    else:
        for (i, u) in enumerate([1000000000000, 1000000000, 1000000, 1000]):
            if n >= u:
                return "%.3g%s%s" % ((float(n) / u), "TGMK"[i], unit)
    return ("%.3g%s" % (n, unit))


assert memsize_str(1024*1024, legacy=False) == "1MiB"
assert memsize_str(1024*1024, legacy=True) == "1MB"
assert memsize_str(1040000) == "0.992MiB"


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="memsize_str test")
    parser.add_argument("--decimal", action="store_true", help="output in decimal")
    parser.add_argument("--po2", dest="decimal", action="store_false", help="output in powers of 2")
    parser.add_argument("--legacy", action="store_true", help="for powers of 2, use legacy (non SI) format")
    parser.add_argument("--unit", type=str, default="B", help="unit (default B for byte)")
    parser.add_argument("size", type=(lambda x: int(x, 0)), nargs="+", help="size in bytes")
    opts = parser.parse_args(argv)
    for sz in opts.size:
        print("%10u: %10s" % (sz, memsize_str(sz, decimal=opts.decimal, legacy=opts.legacy, unit=opts.unit)))


if __name__ == "__main__":
    main(sys.argv[1:])
