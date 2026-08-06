#!/usr/bin/python

"""
CMN address mapa

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys


def BITS(x,p,n):
    return (x >> p) & ((1 << n)-1)


def BIT(x,p):
    return (x >> p) & 1


class AddressRegion:
    """
    A single range of physical addresses.
    """
    def __init__(self, index=None, hashed=False, secure=None):
        self.index = index       # Region index in SAM
        self.hashed = hashed     # Hashed region? Distributes addresses across multiple nodes
        self.secure = secure
        self.base = None         # Base address
        self.size = None
        self.end = None          # End address (ending ...FFFF)
        self.hier_n_clusters = None      # hierarchical cacheing: number of clusters
        self.nodeid = None       # Unique node id, for non-hashed
        self.nodeids = None      # List of node ids, for hashed
        self.CAL = None          # CAL in use: multiplies home nodes
        self.n_cpa = 1           # Number of possible CPA outcomes for this region
        self.cpag = []

    def range_end(self):
        if self.end is not None:
            return self.end
        return self.base + self.size - 1

    def range_str(self):
        s = "0x%016x" % self.base
        if self.end is not None:
            s += "-0x%016x" % self.end
        s += " size=0x%08x" % self.size
        return s

    def target_str(self, cpa=0):
        """
        String describing the target(s) of this region.
        May be quite long, if a list of HN node ids.
        """
        s = ""
        if self.nodeid is not None:
            s += "HN:0x%x" % self.nodeid
        else:
            if self.cpag and self.cpag[cpa] is not None:
                s += "CPAG#%u" % self.cpag[cpa]
            else:
                s += "HNs:" + ','.join(["0x%x" % n for n in self.nodeids])
                if self.CAL:
                    s += " CAL%u" % self.CAL
        return s

    def __str__(self):
        #s = "#%u "
        s = ""
        s += self.range_str()
        if self.hashed:
            s += " hashed"
        if self.hier_n_clusters:
            s += " hierarchical (%uc x %un)" % (self.hier_n_clusters, self.hier_n_nodes)
        if self.cpag:
            s += " cpag:%s" % str(self.cpag)
        if not self.hashed:
            s += " " + self.target_str()
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

def _region_700(r, info, einfo, nodeid=None, hashed=False, min_region_size=0):
    reg = AddressRegion(r, hashed=hashed)
    reg.target_type = BITS(info, 2, 3)
    reg.target_type_str = _target_type_str_map_700[reg.target_type]
    reg.secure = BITS(info, 6, 2)
    reg.base = BITS(info, 16, 36) << 16
    reg.size = 1 << (16 + BITS(info, 56, 7))
    if einfo is not None:
        reg.end = (BITS(einfo, 16, 36) << 16) + min_region_size - 1
        reg.size = reg.end + 1 - reg.base
    reg.nodeid = nodeid
    return reg


def arr_read(n, offs, width, ix, fields_per_reg=None):
    """
    Read a value from an array of values, packed into a range (not necessarily
    contiguous) of registers. The caller supplies a list of register offsets,
    and also the value width.
    """
    offs = list(offs)
    if fields_per_reg is None:
        fields_per_reg = 64 // width
    assert (width * fields_per_reg) <= 64, "bad register array: can't have %u %u-bit values" % (fields_per_reg, width)
    rix = ix // fields_per_reg
    assert rix < len(offs), "bad index %u: array %u regs, %u %u-bit values per reg, %u values" % (ix, len(offs), fields_per_reg, width, fields_per_reg*len(offs))
    v = n.read64(offs[rix])
    fix = ix % fields_per_reg
    return BITS(v, fix*width, width)


def reg_range(base, n):
    return list(range(base, base+(n*8), 8))


def compact_n_cpa(r):
    """
    Given a value of compact_cpag_ctrl, find the number of possible CPA hash output values.
    For each of the 3 bit selectors that is not 7 (zero), multiply by 2.
    """
    n = 1
    for p in [46, 50, 54]:
        if BITS(r, p, 3) != 7:
            n *= 2
    return n


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
        s3r2 = n.C.part_ge_S3r2()
        hns_unit_info1 = n.read64(0x908) if s3r2 else None
        rcomp = BIT(hns_unit_info1, 29) if s3r2 else True
        min_region_size = ((1 << BITS(hns_unit_info1, 30, 5))
                           if rcomp and s3r2 else (1 << 26))
        for (i, r) in enumerate(range(0xD08, 0xD18, 8)):
            info = n.read64(r)
            einfo = n.read64(0xD38 + (i*8)) if rcomp else None
            if BIT(info, 63):
                reg = AddressRegion(i)
                reg.base = BITS(info, 20, 32) << 20
                reg.size = (1 << (20+BITS(info, 12, 7)))
                reg.nodeid = BITS(info, 0, 11)
                if einfo is not None:
                    reg.end = BITS(einfo, 20, 32) << 20
                    if s3r2:
                        reg.end += min_region_size - 1
                    reg.size = reg.end + 1 - reg.base
                yield reg


def hn_sam_default_region(n):
    """Return the S3 r2 HN-S default hashed region, if configured."""
    if not n.C.part_ge_S3r2():
        return None
    unit_info1 = n.read64(0x908)
    if not BIT(unit_info1, 28):
        return None
    info = n.read64(0xD48)
    if not BIT(info, 63):
        return None
    rcomp = BIT(unit_info1, 29)
    min_region_size = ((1 << BITS(unit_info1, 30, 5))
                       if rcomp else (1 << 26))
    einfo = n.read64(0xD50) if rcomp else None
    reg = AddressRegion("default", hashed=True)
    reg.base = BITS(info, 20, 32) << 20
    reg.size = 1 << (20 + BITS(info, 56, 7))
    if einfo is not None:
        reg.end = ((BITS(einfo, 20, 32) << 20) + min_region_size - 1)
        reg.size = reg.end + 1 - reg.base
    return reg


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
        rnsam_unit_info = n.read64(0x900)
        rnsam_unit_info1 = n.read64(0x908)
        nonhash_rcomp = BIT(rnsam_unit_info, 31)
        nonhash_min_region_size = ((1 << BITS(rnsam_unit_info1, 5, 5))
                                   if nonhash_rcomp else (1 << 26))
        n_nonhash_regions = BITS(rnsam_unit_info, 32, 8)
        for r in range(0, n_nonhash_regions):
            ir = (0xC00 if r < 24 else 0x2000) + r*8
            info = n.read64(ir)
            if r < 64:
                nr = 0xD80 + (r // 4) * 8
            else:
                nr = 0x2880 + ((r - 64) // 4) * 8
            n4 = n.read64(nr)
            nodeid = BITS(n4, (r & 3)*12, 11)
            if info & 1:
                er = (0xCC0 if r < 24 else 0x2400) + r*8
                ev = n.read64(er) if nonhash_rcomp else None
                yield _region_700(r, info, ev, nodeid=nodeid, min_region_size=nonhash_min_region_size)


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
        cal_mode_reg = reg_range(0x1120, 4) + reg_range(0x37A0, 4)
        scgs_nonhash_node = n.read64(0xEC0)
        nonhash_reg = [0xEC0, 0xEC8, 0xED0, 0xED8, 0xEE0, 0xEE8, 0x3800]
        hn_count_reg = [0xEA0, 0xEA8, 0x3710, 0x3718]
        sn_attr_reg = [0xEB0, 0xEB8]
        hnf_table = list(range(0xF00, 0x1000, 8))
        hnp_table = list(range(0x3600, 0x3680, 8))
        misc_table = list(range(0x1900, 0x1940, 8))
        rnsam_unit_info = n.read64(0x900)
        rnsam_unit_info1 = n.read64(0x908)
        rnsam_unit_info2 = n.read64(0x910)
        htg_rcomp_lsb = BITS(rnsam_unit_info1, 0, 5)
        htg_rcomp = BIT(rnsam_unit_info, 27)
        htg_min_region_size = ((1 << htg_rcomp_lsb)
                               if htg_rcomp else (1 << 26))
        nonhash_rcomp = BIT(rnsam_unit_info, 31)
        nonhash_min_region_size = ((1 << BITS(rnsam_unit_info1, 5, 5))
                                   if nonhash_rcomp else (1 << 26))
        # compact_en = n.C.unit_info1 is not None and BIT(n.C.unit_info1, 29)
        compact_en = BIT(rnsam_unit_info2, 47)
        next_hnp = 0
        next_misc = 0
        # Four system cache group ranges, then additional (4+24) hashed groups
        # "Each SCG with multiple HN-F targets consumes hashed target ID table entries
        #  from a base index for that SCG, up to the number of HN-F nodes that are
        #  assigned to that SCG. The table base index of each SCG is derived in a
        #  linked list appraoch, based on the SCG programming:
        #    SCG[n] base index = (SCG[n-1] base index) + (SCG[n-1] number of HN-Fs).
        if False:
            print("HTG HN-F node ids:")
            for i in range(0, 128):
                print("  %3x" % arr_read(n, hnf_table, 12, i, fields_per_reg=4), end="")
                if ((i+1) % 16) == 0:
                    print()
            print("CPAGs:")
            for i in range(0, 5*6):
                cpag = arr_read(n, list(range(0x1208, 0x1240, 8)), 12, i)
                bix = arr_read(n, list(range(0x2B00, 0x2B20, 8)), 8, i)
                if BIT(cpag, 3):
                    ncx = [1, 2, 4, 8, 16, 32, 3, 0][BITS(cpag, 0, 3)]
                    print("  CPAG #%u: n=%u %s base=0x%x" % (i, ncx, ["CXL", "CMLSMP"][BIT(cpag, 5)], bix))
        for (i, r) in enumerate(list(range(0xE00, 0xE40, 8)) + list(range(0x3040, 0x3100, 8))):
            info = n.read64(r)
            if info & 1:        # region valid
                einfo = n.read64(0x3100 + (i*8)) if htg_rcomp else None
                compact = n.read64(0x3B00 + (i*8)) if compact_en else None
                # If addresses are hashed across local and CPA, the HN count needs to be scaled
                cpa_hash_n = compact_n_cpa(compact) if compact is not None else 1
                cpag = n.read64(0x3A00 + (i*8)) if compact_en else 0
                hashed = not BIT(info, 1)
                reg = _region_700(i, info, einfo, hashed=hashed, min_region_size=(htg_min_region_size if hashed else nonhash_min_region_size))
                if i < 32:
                    cal_mode = arr_read(n, cal_mode_reg, 16, i)
                    reg.CAL = [0, 2, 0, 4][BITS(cal_mode, 0, 2)]
                    reg.hn_count = arr_read(n, hn_count_reg, 8, i)
                    local_hn_count = reg.hn_count // cpa_hash_n
                    if reg.hashed:
                        hash_cntl = n.read64(0x3400+i*8)
                        reg.hier_n_clusters = BITS(hash_cntl, 8, 6) if BIT(hash_cntl, 2) else 0
                        reg.hier_n_nodes = BITS(hash_cntl, 16, 6) if BIT(hash_cntl, 2) else 0
                        reg.n_cpa = cpa_hash_n
                        if cpa_hash_n == 1 and BIT(cpag, 0):
                            # Only one CPA hash outcome, and CPA is always enabled: it's always remote
                            local_hn_count = 0
                        if not BIT(hash_cntl, 24) and not BIT(hash_cntl, 23):
                            # Select from HN-F target table
                            bix = BITS(compact, 0, 8) if compact_en else next_hnf
                            reg.nodeids = [arr_read(n, hnf_table, 12, ix, fields_per_reg=4) for ix in range(bix, bix+local_hn_count)]
                            next_hnf += reg.hn_count
                        elif BIT(hash_cntl, 24):
                            # Select from HN-P target table
                            bix = BITS(compact, 0, 8) if compact_en else next_hnp
                            reg.nodeids = [arr_read(n, hnp_table, 12, ix, fields_per_reg=4) for ix in range(bix, bix+reg.hn_count)]
                            next_hnp += reg.hn_count
                        else:
                            # Select from Misc target table
                            bix = BITS(compact, 0, 8) if compact_en else next_misc
                            reg.nodeids = [arr_read(n, misc_table, 12, ix,
                                                    fields_per_reg=4)
                                           for ix in range(bix, bix+reg.hn_count)]
                            next_misc += reg.hn_count
                        reg.cpag = []
                        for j in range(0, cpa_hash_n):
                            if BIT(cpag, j*8):
                                # CPA enabled for this CPA hash output value
                                cp = BITS(cpag, j*8+1, 5)
                            else:
                                cp = None
                            reg.cpag.append(cp)
                        if False:
                            print("Region #%u: info = 0x%x, einfo = 0x%x, control = 0x%016x, compact = 0x%016x, cpag = 0x%x: %s" % (i, info, einfo, hash_cntl, compact, cpag, reg))
                        if len(reg.nodeids) != len(set(reg.nodeids)):
                            print("Unexpected duplicate node ids: %s" % reg,
                                  file=sys.stderr)
                if i < 8:
                    scg_sn_attr = arr_read(n, sn_attr_reg, 16, i)
                    reg.sn_mode = [1, 3, 6, 5, 2, 4, 8, 0][BITS(scg_sn_attr, 4, 3)]
                else:
                    reg.sn_mode = 1
                if i >= 1 and not reg.hashed:
                    reg.nodeid = arr_read(n, nonhash_reg, 12, i-1)
                yield reg
