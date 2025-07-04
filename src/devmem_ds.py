#!/usr/bin/python

"""
Memory access to targets using Arm Debugger (DS).

Target might be a physical device accessed via JTAG, or a
Fast Models virtual platform (FVP).

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os
import sys


from arm_ds.debugger_v1 import Debugger
from devmem_base import DevMapFactory, DevMap

# In the DS environment, output to stderr is highlighted and reformatted.
# This is undesirable for minor warnings and information messages.
# See discussion in README-arm-ds.md.
sys.stderr = sys.stdout


def default_address_space():
    return os.environ.get("ARMDS_CMN_SPACE", "AXI")


class DSMemFactory(DevMapFactory):
    """
    Factory class for mapping memory ranges using DS.
    """
    def __init__(self, write=False, check=True, space=None):
        DevMapFactory.__init__(self, write=write, check=check, is_local=False)
        self.dbg = Debugger()
        if space is None:
            space = default_address_space()
        self.space = space
        self.is_model = (space in ["NP", "SP", "RTP", "RLP"])

    def map(self, pa, size, name=None, write=False):
        return DSMemDevMap(pa, size, owner=self, name=name, write=write)


_prot_map = { "NS": 0, "S": 1, "ROOT": 2, "REALM": 3 }

_space_map = { "NS": "NP", "S": "SP", "ROOT": "RTP", "REALM": "RLP" }


class DSMemDevMap(DevMap):
    """
    Implement memory access to an address range using the DS API.

    Because we're a debugger, we support Secure/Root access.
    Handling depends on the type of target:
      - does the target support CCA?
        - if not, access is Non-Secure or Secure
        - if so, access can also be Root or Realm
      - is the target JTAG or Fast Model?
        - if JTAG, access is indicated via memParams but might also
          be indicated via address space
        - if Fast Model, access is indicated only via address space
          (NP, SP, RTP, RLP)
    """
    def __init__(self, pa, size, name=None, owner=None, write=False, check=None, secure="NS"):
        assert isinstance(owner, DSMemFactory)
        DevMap.__init__(self, pa, size, owner=owner, write=write, check=check, secure=secure)
        self.secure = secure

    def dsaddr(self, off):
        space = _space_map[self.secure] if self.owner.is_model else self.owner.space
        return "%s:0x%x" % (space, self.pa + off)

    def memParams(self):
        return {} if self.owner.is_model else {"PROT": _prot_map[self.secure]}

    def _read64(self, off):
        dsa = self.dsaddr(off)
        return self.owner.dbg.readMemoryValue(dsa, size=64, memParams=self.memParams())

    def _write64(self, off, val):
        dsa = self.dsaddr(off)
        self.owner.dbg.writeMemoryValue(dsa, val, size=64, memParams=self.memParams())
