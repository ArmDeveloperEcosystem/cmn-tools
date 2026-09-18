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
import operator

import iommap as mmap
from devmem_base import DevMapFactory, DevMap, DevMemNoSecure
import devmem_memap
import devmem_phys


class DevMemFactory(DevMapFactory):
    """
    Access to the physical address space generally,
    and owner of a file handle to /dev/mem.
    """
    def __init__(self, write=False, check=True, space=None):
        DevMapFactory.__init__(self, write=write, check=check, is_local=True)
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.fd = None
        try:
            self.fd = open("/dev/mem", "r+b")
        except PermissionError:
            print("cannot open /dev/mem: try running as sudo", file=sys.stderr)
            sys.exit(1)
        self.memif = None
        if devmem_memap.memory_interface_available():
            self.memif = devmem_memap.MemoryInterface()
        elif devmem_phys.memory_interface_available():
            self.memif = devmem_phys.MemoryInterface()

    def __str__(self):
        return "native"

    def __del__(self):
        if self.fd is not None:
            self.fd.close()
        DevMapFactory.__del__(self)

    def mmap(self, pa, size, write=False):
        if (size % self.page_size) != 0:
            raise ValueError("mapping size must be a multiple of the page size")
        if write:
            prot = (mmap.PROT_READ | mmap.PROT_WRITE)
        else:
            prot = mmap.PROT_READ
        m = mmap.mmap(self.fd.fileno(), size, mmap.MAP_SHARED, prot, offset=pa)
        return m

    def map(self, pa, size, name=None, write=False, verbose=0):
        """
        Create a physical mapping directly from the /dev/mem object.
        The result is a DevMap object. Often, a caller will want to
        create one or more subclasses of DevMap, representing different
        device types, and have the mapping created by the constructor.
        """
        pa = operator.index(pa)
        if (pa % self.page_size) != 0:
            raise ValueError("unaligned mapping address: 0x%x" % pa)
        return DevMemDevMap(pa, size, owner=self, name=name, write=write, verbose=verbose)


def align_down(a, size):
    return a & -size

assert align_down(0x12345678, 0x1000) == 0x12345000


def align_up(a, size):
    return align_down(a + (size - 1), size)

assert align_up(0x1000, 0x1000) == 0x1000
assert align_up(0x1, 0x1000) == 0x1000


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

    Sub-page sizes are handled by mapping a whole page and offsetting within it.
    """
    def __init__(self, pa, size, name=None, owner=None, write=False, verbose=0, check=None):
        DevMap.__init__(self, pa, size, name=name, owner=owner, write=write, verbose=verbose, check=check)
        self.m = None
        aligned_pa = align_down(self.pa, owner.page_size)
        self.offset_in_page = self.pa - aligned_pa
        aligned_size = align_up(self.offset_in_page + self.size, owner.page_size)
        self.m = owner.mmap(aligned_pa, aligned_size, write=self.writing)
        assert self.m is not None

    def _ensure_writeable(self):
        self.m.mprotect(mmap.PROT_READ | mmap.PROT_WRITE)

    def _set_secure_access(self, secure):
        if (self.owner.memif is None) and secure != "NS":
            raise DevMemNoSecure(self, secure)

    def adjust_offset(self, off):
        return off + self.offset_in_page

    def _read(self, off, n, fmt=None):
        if self.secure != "NS":
            pa = self.pa + off
            return self.owner.memif.read(pa, n, sec=self.secure)
        off = self.adjust_offset(off)
        if fmt is None:
            fmt = {1:"B", 2:"H", 4:"I", 8:"Q"}[n]
        if self.verbose():
            print("%s: read 0x%x" % (self, off), end="")
        raw = self.m[off:off+n]
        x = struct.unpack(fmt, raw)[0]
        if self.verbose():
            print(" => 0x%x" % (x))
        return x

    def _write(self, off, n, data, fmt=None):
        if self.secure != "NS":
            pa = self.pa + off
            return self.owner.memif.write(pa, n, data, sec=self.secure)
        off = self.adjust_offset(off)
        if fmt is None:
            fmt = {1:"B", 2:"H", 4:"I", 8:"Q"}[n]
        if self.verbose():
            print("%s: write 0x%x := 0x%x" % (self, off, data))
        self.m[off:off+n] = struct.pack(fmt,data)

    def _read8(self, off):
        return self._read(off, 1)

    def _read16(self, off):
        return self._read(off, 2)

    def _read32(self, off):
        return self._read(off, 4)

    def _read64(self, off):
        return self._read(off, 8)

    def _write8(self, off, data):
        self._write(off, 1, data)

    def _write16(self, off, data):
        self._write(off, 2, data)

    def _write32(self, off, data):
        self._write(off, 4, data)

    def _write64(self, off, data):
        self._write(off, 8, data)


def main(argv):
    import argparse
    def hexstr(s):
        return int(s,16)
    parser = argparse.ArgumentParser(description="physical memory access")
    parser.add_argument("address", type=hexstr, help="physical address")
    parser.add_argument("width", choices=["b","h","w","d"], help="width")
    parser.add_argument("value", nargs="?", type=hexstr, help="data to be written")
    opts = parser.parse_args(argv)
    base = page_align_down(opts.address)
    off = opts.address - base
    width = {"b":1, "h":2, "w":4, "d":8}[opts.width]
    m = DevMap(base, os.sysconf("SC_PAGE_SIZE"), write=(opts.value is not None))
    if opts.value is None:
        print("0x%x" % m._read(off, width))
    else:
        m._write(off, width, opts.value)


if __name__ == "__main__":
    main(sys.argv[1:])
