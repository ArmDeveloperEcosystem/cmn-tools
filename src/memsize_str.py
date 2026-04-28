#!/usr/bin/python

"""
Generate a string representing a memory size.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

There are several ways the caller can tune the output:

  - decimal vs. binary, e.g. 1000000 bytes might be "1MB" or "977KiB"
  - whether binary is printed as "977KiB" or "977KB"
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
            if n >= (1 << (u*10)):
                return "%.3g%s%s%s" % ((float(n) / (1 << (u*10))), "BKMGT"[u], suf, unit)
    else:
        for (i, u) in enumerate([1000000000000, 1000000000, 1000000, 1000]):
            if n >= u:
                return "%.3g%s%s" % ((float(n) / u), "TGMK"[i], unit)
    return ("%.3g%s" % (n, unit))


assert memsize_str(1024*1024, legacy=True) == "1MB"


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="memsize_str test")
    parser.add_argument("--decimal", action="store_true")
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("size", type=(lambda x: int(x, 0)), nargs="+", help="size in bytes")
    opts = parser.parse_args(argv)
    for sz in opts.size:
        print("%10u: %10s" % (sz, memsize_str(sz, decimal=opts.decimal, legacy=opts.legacy)))


if __name__ == "__main__":
    main(sys.argv[1:])
