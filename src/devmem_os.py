#!/usr/bin/python3

"""
Map physical devices, using /dev/mem.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import os
import sys
import struct

import iommap as mmap
from devmem_base import DevMapFactory, DevMap, DevMemNoSecure


class DevMemFactory(DevMapFactory):
    """
    Access to the physical address space generally,
    and owner of a file handle to /dev/mem.
    """
    def __init__(self, write=False, check=True):
        DevMapFactory.__init__(self, write=write, check=check)
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.fd = None
        try:
            self.fd = open("/dev/mem", "r+b")
        except PermissionError:
            print("cannot open /dev/mem: try running as sudo", file=sys.stderr)
            sys.exit(1)

    def __del__(self):
        if self.fd is not None:
            self.fd.close()

    def mmap(self, pa, size, write=False):
        assert (size % self.page_size) == 0
        if write:
            prot = (mmap.PROT_READ | mmap.PROT_WRITE)
        else:
            prot = mmap.PROT_READ
        m = mmap.mmap(self.fd.fileno(), size, mmap.MAP_SHARED, prot, offset=pa)
        return m

    def map(self, pa, size, name=None, write=False):
        """
        Create a physical mapping directly from the /dev/mem object.
        The result is a DevMap object. Often, a caller will want to
        create one or more subclasses of DevMap, representing different
        device types, and have the mapping created by the constructor.
        """
        assert (pa % self.page_size) == 0, "unaligned address: 0x%x" % pa
        return DevMemDevMap(pa, size, owner=self, name=name, write=write)


def align_down(a, size):
    return a & -size

assert align_down(0x12345678, 0x1000) == 0x12345000

def page_align_down(pa):
    return align_down(pa, os.sysconf("SC_PAGE_SIZE"))


class DevMemDevMap(DevMap):
    """
    Mapping for a particular region of physical memory,
    within which registers can be accessed by offset.

    Normally, a caller would create this with a DevMem object and a physical address,
    and the mmap mapping would be created by the constructor below.
    Sometimes, the caller might want to create the mapping first, e.g. to
    discover device type, and then create a subclass object of the required type,
    providing the mapping via the 'map' object.

    TBD: it would be useful to handle sub-page sizes, e.g. 4K device in a 16K page.
    """
    def __init__(self, pa, size, name=None, owner=None, write=False, verbose=0):
        assert isinstance(owner, DevMapFactory)
        DevMap.__init__(self, pa, size, name=name, owner=owner, write=write)
        self.verbose_level = verbose
        self.m = None
        self.m = owner.mmap(pa, size, write=self.writing)
        assert self.m is not None

    def verbose(self):
        return self.verbose_level

    def _ensure_writeable(self):
        self.m.mprotect(mmap.PROT_READ | mmap.PROT_WRITE)

    def _set_secure_access(self, secure):
        if secure != "NS":
            raise DevMemNoSecure(self, secure)

    def _read(self, off, n, fmt=None):
        if fmt is None:
            fmt = {1:"B", 2:"H", 4:"I", 8:"Q"}[n]
        if self.verbose():
            print("%s: read 0x%x" % (self, off), end="")
        assert (off % n) == 0, "%s: invalid offset: 0x%x" % (self, off)
        raw = self.m[off:off+n]
        x = struct.unpack(fmt, raw)[0]
        if self.verbose():
            print(" => 0x%x" % (x))
        return x

    def _write(self, off, n, data, fmt=None, check=None):
        if fmt is None:
            fmt = {1:"B", 2:"H", 4:"I", 8:"Q"}[n]
        if self.verbose():
            print("%s: write 0x%x := 0x%x" % (self, off, data))
        assert (off % n) == 0, "%s: invalid offset: 0x%x" % (self, off)
        self.m[off:off+n] = struct.pack(fmt,data)

    def _read8(self, off):
        return self._read(off, 1)

    def _read16(self, off):
        return self._read(off, 2)

    def _read32(self, off):
        return self._read(off, 4)

    def _read64(self, off):
        return self._read(off, 8)

    def _write8(self, off, data, check=None):
        self._write(off, 1, data, check=check)

    def _write16(self, off, data, check=None):
        self._write(off, 2, data, check=check)

    def _write32(self, off, data, check=None):
        self._write(off, 4, data, check=check)

    def _write64(self, off, data, check=None):
        self._write(off, 8, data, check=check)


if __name__ == "__main__":
    import argparse
    def hexstr(s):
        return int(s,16)
    parser = argparse.ArgumentParser(description="physical memory access")
    parser.add_argument("address", type=hexstr, help="physical address")
    parser.add_argument("width", choices=["b","h","w","d"], help="width")
    parser.add_argument("value", nargs="?", type=hexstr, help="data to be written")
    opts = parser.parse_args()
    base = page_align_down(opts.address)
    off = opts.address - base
    width = {"b":1, "h":2, "w":4, "d":8}[opts.width]
    m = DevMap(base, os.sysconf("SC_PAGE_SIZE"), write=(opts.value is not None))
    if not opts.value:
        print("0x%x" % m._read(off, width))
    else:
        m._write(off, width, opts.value)
