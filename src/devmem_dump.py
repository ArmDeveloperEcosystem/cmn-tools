#!/usr/bin/python

"""
Emulated memory access to a target, using a previously collected dump file.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os


from devmem_base import DevMapFactory, DevMap, DevMemWriteProtected


class Dump:
    """
    Memory contents read from a dump file.
    """
    def __init__(self, fn):
        self.fn = fn
        self.locs = {}
        self.read()

    def read(self):
        with open(self.fn, "r") as f:
            for ln in f:
                if ln.startswith("R "):
                    (_, addr, val) = ln.strip().split()
                    addr = int(addr, 16)
                    if val == "ERROR":
                        val = None
                    else:
                        val = int(val, 16)
                    self.locs[addr] = val

    def __str__(self):
        return "dump(\"%s\")" % self.fn


class DumpBusError(Exception):
    def __init__(self, dump, addr):
        self.dump = dump
        self.addr = addr

    def __str__(self):
        return "Simulated bus error in %s at 0x%x" % (self.dump, self.addr)


class DumpMemFactory(DevMapFactory):
    def __init__(self, write=False, check=True, space=None):
        DevMapFactory.__init__(self, write=write, check=check, is_local=False)
        self.dump = Dump(os.environ["CMN_DUMP"])

    def map(self, pa, size, name=None, write=False):
        return DumpMemDevMap(pa, size, owner=self, name=name, write=write)

    def __str__(self):
        return str(self.dump)


class DumpMemDevMap(DevMap):
    def __init__(self, pa, size, name=None, owner=None, write=False, check=None):
        DevMap.__init__(self, pa, size, owner=owner, write=write, check=check)

    def _read64(self, off):
        addr = self.pa + off
        val = self.owner.dump.locs.get(addr, 0)
        if val is None:
            raise DumpBusError(self.owner, addr)
        return val

    def _write64(self, off, val):
        # Dumps are not writeable
        raise DevMemWriteProtected(self, off, val)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN dump test")
    parser.add_argument("file", type=str)
    opts = parser.parse_args()
    D = Dump(opts.file)
