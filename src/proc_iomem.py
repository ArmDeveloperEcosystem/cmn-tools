#!/usr/bin/python

"""
Read and query the Linux /proc/iomem map.

Copyright (C) Arm Ltd. 2024-2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import argparse
import bisect
import re
import sys

from address_map import ranges_overlap


PROC_IOMEM = "/proc/iomem"


class IOmem_region:
    """A descriptor of one (inclusive) address range in /proc/iomem."""

    def __init__(self, addr, aend, name=None, level=0):
        self.addr = addr
        self.aend = aend
        self.name = name
        self.level = level

    def size(self):
        return self.aend + 1 - self.addr

    def contains(self, addr):
        return self.addr <= addr and addr <= self.aend

    def overlaps(self, addr, aend):
        return ranges_overlap(self.addr, self.aend, addr, aend)

    def contains_range(self, desc):
        return self.addr <= desc.addr and desc.aend <= self.aend

    def is_address_missing(self):
        return self.addr == 0 and self.aend == 0

    def describe(self, addr):
        """
        Describe an address in this region, including its offset.
        """
        assert self.contains(addr)
        s = self.name
        if addr > self.addr:
            s += "[0x%x]" % (self.addr)
            s += "+0x%x" % (addr - self.addr)
        return s

    def __str__(self):
        s = "%x-%x : %s" % (self.addr, self.aend, self.name)
        return ("  " * self.level) + s


_iomem_line_re = re.compile(
    r"^(\s*)([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*?)\s*$")


def iomem_regions(iomem=None):
    """Yield IOmem_region objects from a /proc/iomem-format file."""
    if iomem is None:
        iomem = PROC_IOMEM
    with open(iomem) as f:
        for ln in f:
            m = _iomem_line_re.match(ln)
            if m is None:
                if not ln.strip():
                    continue
                raise ValueError("invalid /proc/iomem line: %s" % ln.rstrip())
            indent, addr, aend, name = m.groups()
            level = len(indent.expandtabs(8)) // 2
            yield IOmem_region(int(addr, 16), int(aend, 16), name, level)


class IOmemAddressUnavailable(Exception):
    """Physical addresses have been hidden in /proc/iomem."""


class IOmem_map:
    """A searchable snapshot of /proc/iomem."""

    def __init__(self, regions=None, iomem=None):
        if regions is not None and iomem is not None:
            raise ValueError("specify regions or iomem, not both")
        if regions is None:
            regions = iomem_regions(iomem=iomem)
        self.regions = list(regions)
        self.addresses_valid = bool(self.regions) and any(
            not r.is_address_missing() for r in self.regions)
        self._by_addr = sorted(self.regions,
                               key=lambda r: (r.addr, r.aend, r.level))
        self._starts = [r.addr for r in self._by_addr]

    def __iter__(self):
        return iter(self.regions)

    def lookup(self, addr):
        """Return the most specific region containing addr, or None.

        Raise IOmemAddressUnavailable when /proc/iomem hid all addresses.
        """
        if not self.addresses_valid:
            raise IOmemAddressUnavailable(
                "/proc/iomem does not expose physical addresses")
        ix = bisect.bisect_right(self._starts, addr)
        best = None
        ix -= 1
        while ix >= 0:
            r = self._by_addr[ix]
            if r.contains(addr):
                if best is None or r.level > best.level or (
                        r.level == best.level and r.size() < best.size()):
                    best = r
            ix -= 1
        return best

    def overlapping_regions(self, addr, aend):
        """Yield regions overlapping an inclusive address range."""
        if not self.addresses_valid:
            raise IOmemAddressUnavailable(
                "/proc/iomem does not expose physical addresses")
        for r in self.regions:
            if not r.is_address_missing() and r.overlaps(addr, aend):
                yield r

    def describe(self, addr):
        """Return a region-and-offset description, or the bare address."""
        r = self.lookup(addr)
        if r is None:
            return "0x%x" % addr
        return r.describe(addr)


_default_iomem_map = None


def get_iomem_map():
    """Return the process-wide, lazily created /proc/iomem snapshot."""
    global _default_iomem_map
    if _default_iomem_map is None:
        _default_iomem_map = IOmem_map()
    return _default_iomem_map


def iomem_region_at(addr):
    """Look up an address in the cached /proc/iomem map."""
    return get_iomem_map().lookup(addr)


def describe_iomem_address(addr):
    """Describe an address using the cached /proc/iomem map."""
    return get_iomem_map().describe(addr)


def _address(s):
    try:
        return int(s, 0)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid physical address: %s" % s)


def main(argv):
    parser = argparse.ArgumentParser(
        description="list or query Linux /proc/iomem regions")
    parser.add_argument("--iomem", default=PROC_IOMEM,
                        help="/proc/iomem-format file (default: %(default)s)")
    parser.add_argument("-l", "--list", action="store_true",
                        help="list regions as well as performing lookups")
    parser.add_argument("address", type=_address, nargs="*",
                        help="physical address, in decimal or 0x-prefixed hex")
    opts = parser.parse_args(argv)

    iomap = IOmem_map(iomem=opts.iomem)
    if not iomap.addresses_valid:
        print("physical addresses are unavailable; only region names are valid",
              file=sys.stderr)
    if opts.list or not opts.address:
        for r in iomap:
            print(r)
    if opts.address and not iomap.addresses_valid:
        return 1
    for addr in opts.address:
        r = iomap.lookup(addr)
        if r is None:
            print("0x%x: not found" % addr)
        else:
            print("0x%x: %s" % (addr, r.describe(addr)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
