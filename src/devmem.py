#!/usr/bin/python3

"""
Map physical devices, using /dev/mem.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import iommap as mmap

import os
import sys
import struct


class DevMemWriteFailed(Exception):
    def __init__(self, dev, addr, data, ndata):
        self.dev = dev
        self.addr = addr
        self.data = data
        self.ndata = ndata

    def __str__(self):
        return "%s: at 0x%04x wrote 0x%x, read back 0x%x" % (self.dev, self.addr, self.data, self.ndata)


class DevMem:
    """
    Access to the physical address space generally,
    and owner of a file handle to /dev/mem.
    """
    def __init__(self):
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

    def map(self, pa, size, write=False):
        """
        Create a physical mapping directly from the /dev/mem object.
        The result is a DevMap object. Often, a caller will want to
        create one or more subclasses of DevMap, representing different
        device types, and have the mapping created by the constructor.
        """
        return DevMap(self, pa, m)


def align_down(a, size):
    return a & -size

assert align_down(0x12345678, 0x1000) == 0x12345000

def page_align_down(pa):
    return align_down(pa, os.sysconf("SC_PAGE_SIZE"))


class DevMap:
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
    def __init__(self, pa, size, name=None, write=False, map=None, mem=None, verbose=1, check=None):
        if mem is None:
            mem = DevMem()
        assert (pa % mem.page_size) == 0, "unaligned address: 0x%x" % pa
        self.mem = mem
        self.verbose_level = verbose
        self.pa = pa
        self.size = size
        self.writing = write
        self.checking = check
        if name is None:
            name = "dev@0x%x" % pa
        self.name = name
        if map is None:
            map = self.mem.mmap(pa, size, write=self.writing)
        self.m = map
        assert self.m is not None

    def __str__(self):
        return self.name

    def verbose(self):
        return self.verbose_level

    def _read(self, off, n, fmt=None):
        if fmt is None:
            fmt = {1:"B",2:"H",4:"I",8:"Q"}[n]
        if self.verbose():
            print("%s: read 0x%x" % (self, off), end="")
        assert (off % n) == 0, "%s: invalid offset: 0x%x" % (self, off)
        raw = self.m[off:off+n]
        x = struct.unpack(fmt, raw)[0]
        if self.verbose():
            print(" => 0x%x" % (x))
        return x

    def _write(self, off, n, data, fmt=None, check=None):
        if check is None:
            check = self.checking
        if fmt is None:
            fmt = {1:"B",2:"H",4:"I",8:"Q"}[n]
        if self.verbose():
            print("%s: write 0x%x := 0x%x" % (self, off, data))
        assert self.writing, "%s: not opened for writing" % (self)
        assert (off % n) == 0, "%s: invalid offset: 0x%x" % (self, off)
        self.m[off:off+n] = struct.pack(fmt,data)
        if check:
            ndata = self._read(off, n, fmt)
            if ndata != data:
                raise DevMemWriteFailed(self, off, data, ndata)

    def read8(self, off):
        return self._read(off, 1)

    def read32(self, off):
        return self._read(off, 4)

    def read64(self, off):
        return self._read(off, 8)

    def write8(self, off, data, check=None):
        self._write(off, 1, data, check=check)

    def write32(self, off, data, check=None):
        self._write(off, 4, data, check=check)

    def write64(self, off, data, check=None):
        self._write(off, 8, data, check=check)

    def set32(self, off, val, check=None):
        self.write32(off, self.read32(off) | val, check=check)

    def clr32(self, off, val, check=None):
        self.write32(off, self.read32(off) & ~val, check=check)


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
    width = {"b":1,"h":2,"w":4,"d":8}[opts.width]
    m = DevMap(base, os.sysconf("SC_PAGE_SIZE"), write=(opts.value is not None))
    if not opts.value:
        print("0x%x" % m._read(off, width))
    else:
        m._write(off, width, opts.value)
