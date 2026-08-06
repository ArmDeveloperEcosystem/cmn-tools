#!/usr/bin/python

"""
Physical memory access via CoreSight MEM-AP.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import sys
import os
import struct


import iommap as mmap


ENV_MEMAP = "CMN_MEMAP"

def memory_interface_available():
    return ENV_MEMAP in os.environ


def BITS(x, p, n):
    return (x >> p) & ((1 << n) - 1)


def BIT(x, p):
    return (x >> p) & 1


def align_down(a, size):
    return a & -size


def align_up(a, size):
    return align_down(a + (size - 1), size)


MEMAP_SIZE = 4096


class MemoryInterface:
    """
    Implement memory access via AXI-AP.
    """
    def __init__(self, memap_addr=None, verbose=0):
        self.verbose = verbose
        self.fd = None
        self.memap_addr = memap_addr or int(os.environ[ENV_MEMAP], 16)
        assert (self.memap_addr & 0xfff) == 0
        try:
            self.fd = open("/dev/mem", "r+b")
        except PermissionError:
            print("cannot open /dev/mem: try running as sudo", file=sys.stderr)
            sys.exit(1)
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.mmap_base = align_down(self.memap_addr, self.page_size)
        memap_end = self.memap_addr + MEMAP_SIZE
        self.mmap_size = align_up(memap_end, self.page_size) - self.mmap_base
        self.offset_in_page = self.memap_addr - self.mmap_base
        prot = (mmap.PROT_READ | mmap.PROT_WRITE)
        self.m = mmap.mmap(self.fd.fileno(), self.mmap_size, mmap.MAP_SHARED, prot, offset=self.mmap_base)
        devarch = self.int_read32(0xFBC)
        assert (devarch & 0xfff00fff) == 0x47700a17, "DEVARCH 0x%08x does not indicate MEM-AP" % devarch
        cfg = self.int_read32(0xDF4)
        csw = self.int_read32(0xD00)
        if verbose:
            print("%s:" % self)
            print("  CFG = 0x%08x" % cfg)
            print("  CSW = 0x%08x" % csw)
        assert BIT(csw, 6), "%s: MEM-AP is not enabled" % self
        assert BITS(cfg, 4, 4) == 10, "%s: expected 10-bit DAR space" % self
        self.n_bytes = None
        self.tar = None
        self.da_mask = 0x3ff
        self.sec = None

    def __del__(self):
        if self.fd is not None:
            self.fd.close()

    def __str__(self):
        return "MEM-AP at 0x%x" % (self.memap_addr)

    def int_read32(self, addr):
        """
        MEM-AP register read
        """
        off = self.offset_in_page + addr
        return struct.unpack("I", self.m[off:off+4])[0]

    def int_read64(self, addr):
        lo = self.int_read32(addr)
        hi = self.int_read32(addr + 4)
        return (hi << 32) | lo

    def int_write32(self, addr, value):
        """
        MEM-AP register write
        """
        off = self.offset_in_page + addr
        self.m[off:off+4] = struct.pack("I", value)

    def int_write64(self, addr, value):
        self.int_write32(addr, (value & 0xffffffff))
        self.int_write32(addr + 4, (value >> 32))

    def ensure_n_bytes(self, n_bytes):
        if n_bytes != self.n_bytes:
            csw = self.int_read32(0xD00)
            csw &= ~7
            csw |= {1: 0, 2: 1, 4: 2, 8: 3}[n_bytes]
            if self.verbose:
                print("%s: CSW := 0x%08x for width=%d" % (self, csw, n_bytes))
            self.int_write32(0xD00, csw)
            self.n_bytes = n_bytes

    def set_TAR(self, addr):
        ntar = addr & ~self.da_mask
        if ntar != self.tar:
            if self.verbose:
                print("%s: TAR := 0x%x" % (self, ntar))
            self.int_write64(0xD04, ntar)    # TARH is 0xD08
            self.tar = ntar

    def set_security(self, sec):
        if sec != self.sec:
            nse_ns = {"S": 0, "NS": 1, "ROOT": 2, "REALM": 3}[sec]
            nse = BIT(nse_ns, 1)
            ns = BIT(nse_ns, 0)
            csw = self.int_read32(0xD00)
            csw &= 0xdfffefff
            csw |= (ns << 29) | (nse << 12)
            if self.verbose:
                print("%s: CSW := 0x%08x for sec=%s" % (self, csw, sec))
            self.int_write32(0xD00, csw)
            self.sec = sec

    def setup(self, addr, n_bytes, sec):
        assert n_bytes in [4, 8]
        self.ensure_n_bytes(n_bytes)
        self.set_TAR(addr)
        self.set_security(sec)

    def read(self, addr, n_bytes, sec="NS"):
        self.setup(addr, n_bytes, sec)
        if n_bytes == 4:
            return self.int_read32(0x000 + (addr & 0x3fc))
        elif n_bytes == 8:
            return self.int_read64(0x000 + (addr & 0x3f8))
        else:
            assert False

    def write(self, addr, n_bytes, value, sec="NS"):
        self.setup(addr, n_bytes, sec)
        if n_bytes == 4:
            self.int_write32(0x000 + (addr & 0x3fc), value)
        elif n_bytes == 8:
            self.int_write64(0x000 + (addr & 0x3f8), value)


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="MEM-AP test")
    parser.add_argument("--memap", type=(lambda x:int(x, 16)), help="MEM-AP address")
    parser.add_argument("--addr", type=(lambda x:int(x, 16)), help="address to read")
    parser.add_argument("--security", type=str, default="NS", help="security (S, NS, ROOT, REALM)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    M = MemoryInterface(memap_addr=opts.memap, verbose=opts.verbose)
    print(M)
    if opts.addr:
        print("read 0x%x => 0x%x" % (opts.addr, M.read(opts.addr, 8, sec=opts.security)))


if __name__ == "__main__":
    main(sys.argv[1:])
