#!/usr/bin/python

"""
CMN address mapa

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


def BITS(x,p,n):
    return (x >> p) & ((1 << n)-1)


def BIT(x,p):
    return (x >> p) & 1


class AddressRegion:
    """
    A single range of physical addresses.
    """
    def __init__(self, index=None, hashed=False, secure=None):
        self.index = index
        self.hashed = hashed
        self.secure = secure
        self.base = None
        self.size = None
        self.end = None
        self.nodeid = None    # unique node id, for non-hashed
        self.nodeids = None   # list of node ids, for hashed

    def range_str(self):
        s = "0x%016x" % self.base
        if self.end is not None:
            s += "-0x%016x" % self.end
        s += " size=0x%08x" % self.size
        return s

    def __str__(self):
        s = "#%u %s" % (self.index, self.range_str())
        if self.hashed:
            s += " hashed"
        if self.nodeid is not None:
            s += " nodeid:0x%x" % self.nodeid
        return s


_target_type_str_map_600 = ["HN-F", "HN-I", "CXRA", "?3"]

def _region_600(r, info, nodeid=None, hashed=False):
    reg = AddressRegion(r, hashed=hashed)
    reg.target_type = BITS(info, 2, 2)
    reg.target_type_str = _target_type_str_map_600[reg.target_type]
    reg.base = BITS(info, 9, 22) << 26
    reg.size = 1 << (26 + BITS(info, 4, 5))
    reg.end = None
    reg.nodeid = nodeid
    return reg


_target_type_str_map_700 = ["HN-F", "HN-I", "CXRA", "HN-P", "PCI-CXRA", "HN-S", "?6", "?7"]

def _region_700(r, info, einfo, nodeid=None, hashed=False):
    reg = AddressRegion(r, hashed=hashed)
    reg.target_type = BITS(info, 2, 3)
    reg.target_type_str = _target_type_str_map_700[reg.target_type]
    reg.secure = BITS(info, 6, 2)
    reg.base = BITS(info, 16, 36) << 16
    reg.size = 1 << (16 + BITS(info, 56, 7))
    if einfo is not None:
        reg.end = BITS(einfo, 16, 36) << 16
    reg.nodeid = nodeid
    return reg


def arr_read(n, offs, width, ix, fields_per_reg=None):
    offs = list(offs)
    if fields_per_reg is None:
        fields_per_reg = 64 // width
    rix = ix // fields_per_reg
    v = n.read64(offs[rix])
    fix = ix % fields_per_reg
    return BITS(v, fix*width, width)


def hn_sam_regions(n):
    """
    Yield all address regions for a home node.
    """
    if not n.C.part_ge_700():
        for (i, r) in enumerate(range(0xD08, 0xD18, 8)):
            info = n.read64(r)
            if BIT(info, 63):
                # The address and size field aren't clearly documented,
                # but it seems that the address is pre-aligned to 64MB (i.e. bit 26),
                # and the size is a right-shift to be applied before comparing.
                reg = AddressRegion(i)
                reg.base = BITS(info, 26, 22) << 26
                reg.size = (1 << (26+BITS(info, 12, 5)))
                reg.nodeid = BITS(info, 0, 11)
                yield reg
    else:
        for (i, r) in enumerate(range(0xD08, 0xD18, 8)):
            info = n.read64(r)
            einfo = n.read64(0xD38 + (i*8))
            if BIT(info, 63):
                reg = AddressRegion(i)
                reg.base = BITS(info, 20, 32) << 20
                reg.size = (1 << (20+BITS(info, 12, 7)))
                reg.nodeid = BITS(info, 0, 11)
                reg.end = BITS(einfo, 20, 32) << 20
                yield reg


def rn_sam_nonhash_regions(n):
    """
    Yield all nonhash regions for a RN-SAM.
    """
    if not n.C.part_ge_700():
        nhm = [0xC08, 0xC10, 0xC18, 0xC20, 0xC28, 0xCA0, 0xCA8, 0xCB0, 0xCB8, 0xCC0]
        nhn = [0xC30, 0xC38, 0xC40, 0xCE0, 0xCE8]
        for r in range(0, 20):
            info = arr_read(n, nhm, 32, r)
            nodeid = arr_read(n, nhn, 12, r, fields_per_reg=4)
            if info & 1:
                yield _region_600(r, info, nodeid=nodeid)
    else:
        for r in range(0, 64):
            ir = (0xC00 if r < 24 else 0x2000) + r*8
            info = n.read64(ir)
            nr = 0xD80 + (r // 4) * 8
            n4 = n.read64(nr)
            nodeid = BITS(n4, (r & 3)*12, 11)
            if info & 1:
                er = (0xCC0 if r < 24 else 0x2400) + r*8
                ev = n.read64(er)
                yield _region_700(r, info, ev, nodeid=nodeid)


def rn_sam_hashed_regions(n):
    """
    Yield all hashed regions for an RN-SAM, or more precisely, all entries
    from the hashed region table. These an be used as nonhash regions.
    """
    next_hnf = 0
    if not n.C.part_ge_700():
        scgs_cal_mode = n.read64(0xF10)
        scgs_nonhash_node = n.read64(0xC98)
        scgs_hn_count = n.read64(0xD00)
        scgs_sn_attr = n.read64(0xD60)
        nodeids_reg = list(range(0xC58, 0xC98, 8)) + list(range(0xF58, 0xF98, 8))
        for (i, r) in enumerate(range(0xC48, 0xC58, 4)):
            odd = (i & 1)
            info = BITS(n.read64(r & ~7), odd*32, 32)
            if info & 1:
                reg = _region_600(i, info, hashed=(not BIT(info, 1)))
                reg.CAL = 2 * BIT(scgs_cal_mode, i*16)
                reg.hn_count = BITS(scgs_hn_count, i*8, 8)
                if reg.hashed:
                    reg.nodeids = [arr_read(n, nodeids_reg, 12, ix, fields_per_reg=4) for ix in range(next_hnf, next_hnf+reg.hn_count)]
                    next_hnf += reg.hn_count
                scg_sn_attr = BITS(scgs_sn_attr, i*16, 16)
                reg.sn_mode = [1, 3, 6, 0][BITS(scg_sn_attr, 4, 2)]
                if i >= 1 and not reg.hashed:
                    reg.nodeid = BITS(scgs_nonhash_node, (i-1)*12, 11)
                yield reg
    else:
        scgs_cal_mode = n.read64(0x1120)
        scgs_nonhash_node = n.read64(0xEC0)
        nonhash_reg = [0xEC0, 0xEC8, 0xED0, 0xED8, 0xEE0, 0xEE8, 0x3800]
        hn_count_reg = [0xEA0, 0xEA8, 0x3710, 0x3718]
        sn_attr_reg = [0xEB0, 0xEB8]
        next_hnp = 0
        # Four system cache group ranges, then additional hashed groups
        for (i, r) in enumerate(list(range(0xE00, 0xE40, 8)) + list(range(0x3040, 0x3100, 8))):
            info = n.read64(r)
            if info & 1:
                einfo = n.read64(0x3100 + (i*8))
                reg = _region_700(i, info, einfo, hashed=(not BIT(info, 1)))
                if i < 4:
                    reg.CAL = [0, 2, 0, 4][BITS(scgs_cal_mode, i*16, 2)]
                if i < 32:
                    reg.hn_count = arr_read(n, hn_count_reg, 8, i)
                    if reg.hashed:
                        hash_cntl = n.read64(0x3400+i*8)
                        if not BIT(hash_cntl, 24):
                            reg.nodeids = [arr_read(n, range(0xF00, 0x1000, 8), 12, ix, fields_per_reg=4) for ix in range(next_hnf, next_hnf+reg.hn_count)]
                            next_hnf += reg.hn_count
                        else:
                            reg.nodeids = [arr_read(n, range(0x3600, 0x3680, 8), 12, ix, fields_per_reg=4) for ix in range(next_hnp, next_hnp+reg.hn_count)]
                            next_hnp += reg.hn_count
                if i < 8:
                    scg_sn_attr = arr_read(n, sn_attr_reg, 16, i)
                    reg.sn_mode = [1, 3, 6, 5, 2, 4, 8, 0][BITS(scg_sn_attr, 4, 3)]
                else:
                    reg.sn_mode = 1
                if i >= 1 and not reg.hashed:
                    reg.nodeid = arr_read(n, nonhash_reg, 12, i-1)
                yield reg
