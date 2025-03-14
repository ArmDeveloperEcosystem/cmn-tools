#!/usr/bin/python

"""
Map physical devices using DS

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os


from arm_ds.debugger_v1 import Debugger
from devmem_base import DevMapFactory, DevMap


def default_address_space():
    return os.environ.get("ARMDS_CMN_SPACE", "AXI")


class DSMemFactory(DevMapFactory):
    def __init__(self, write=False, check=True, space=None):
        DevMapFactory.__init__(self, write=write, check=check)
        self.dbg = Debugger()
        if space is None:
            space = default_address_space()
        self.space = space

    def map(self, pa, size, name=None, write=False):
        return DSMemDevMap(pa, size, owner=self, name=name, write=write)


class DSMemDevMap(DevMap):
    """
    Implement memory access using the DS API.
    """
    def __init__(self, pa, size, name=None, owner=None, write=False, check=None, secure=False):
        assert isinstance(owner, DSMemFactory)
        DevMap.__init__(self, pa, size, owner=owner, write=write, check=check)
        self.secure = secure

    def dsaddr(self, off):
        return "%s:0x%x" % (self.owner.space, self.pa + off)

    def _read64(self, off):
        dsa = self.dsaddr(off)
        if self.secure:
            return self.owner.dbg.readMemoryValue(dsa, size=64, memParams={"PROT": 1})
        else:
            return self.owner.dbg.readMemoryValue(dsa, size=64)

    def _write64(self, off, val):
        dsa = self.dsaddr(off)
        if self.secure:
            self.owner.dbg.writeMemoryValue(dsa, val, size=64, memParams={"PROT": 1})
        else:
            self.owner.dbg.writeMemoryValue(dsa, val, size=64)
