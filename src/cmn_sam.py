#!/usr/bin/python

"""
CMN address maps

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys

from cmn_config import PART_CMN700, PART_CMN_S3


class CPAG(object):
    """A CML Port Aggregation Group selecting gateway target IDs."""

    def __init__(self, index, nodeids=None, port_type=None, axid=False,
                 valid=None, error=None):
        self.index = index
        self.nodeids = tuple(nodeids) if nodeids is not None else None
        self.port_type = port_type
        self.axid = axid
        self.valid = valid
        self.error = error

    def key(self):
        return (self.index, self.nodeids or (), self.nodeids is not None,
                self.port_type or "", self.axid,
                -1 if self.valid is None else int(self.valid), self.error or "")

    def description(self):
        if self.valid is False:
            return "disabled CPAG"
        if self.nodeids is None:
            return "gateway membership unknown%s" % (": " + self.error if self.error else "")
        return "%s; %u gateway(s); %s hashing" % (
            self.port_type or "CML", len(self.nodeids), "AXID" if self.axid else "address")


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
        self.hier_n_nodes = None
        self.hier_n_clusters = None      # hierarchical cacheing: number of clusters
        self.nodeid = None       # Unique node id, for non-hashed
        self.nodeids = None      # List of node ids, for hashed
        self.target_table = None
        self.target_indexes = None
        self.target_cpags = None     # Per-target CPA substitution, if decoded
        self.cpa_error = None        # Selection may substitute remote targets
        self.cal_node_offsets = None
        self.CAL = None          # CAL in use: multiplies home nodes
        self.n_cpa = 1           # Number of possible CPA outcomes for this region
        self.cpag = []
        self.table_name = None
        self.priority = 0
        self.selection_details = ""

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
    reg.size = 1 << (26 + BITS(info, 56, 7))
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
                reg.size = (1 << (26+BITS(info, 12, 7)))
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
    reg.size = 1 << (26 + BITS(info, 56, 7))
    if einfo is not None:
        reg.end = ((BITS(einfo, 20, 32) << 20) + min_region_size - 1)
        reg.size = reg.end + 1 - reg.base
    return reg


def hn_sam_target_regions(n):
    """Decode HN-to-SN ranges, including HTGs and the default target set.

    This is an optional scan: callers must explicitly request HN SAM access.
    Cache register values for this scan, particularly shared target-ID words.
    Use the implemented region counts before reading configurable tables.

    References: CMN-700 TRM (102308), HN-F SAM; CMN-700 r3 addendum
    (108055), sections 3.4.3 and 5.2.4; CMN S3 TRM (107858), HN-F SAM,
    SAM memory region size configuration, and cmn_hns_sam_* registers.
    S3 r2 adds arithmetic-modulo SN modes and explicit HTG base indexes.
    """
    values = {}

    def read(offset):
        if offset not in values:
            values[offset] = n.read64(offset)
        return values[offset]

    def region(info, end_info, index, table, priority, size_pos=56):
        reg = AddressRegion(index)
        reg.table_name = table
        reg.priority = priority
        reg.target_type_str = "SN-F"
        reg.base = BITS(info, 20, 32) << 20
        if end_info is not None:
            reg.end = (BITS(end_info, 20, 32) << 20) + (1 << lsb) - 1
            reg.size = reg.end - reg.base + 1
        else:
            # Size encoding 0 is 64MB, not the base-address field's LSB.
            size = BITS(info, size_pos, 7)
            if size > 26 and not (table == "default" and size == 127):
                raise ValueError("HN SAM %s#%s has invalid size %u" %
                                 (table, index, size))
            reg.size = 1 << min(26 + size, 52)
        if reg.size <= 0 or reg.range_end() >= (1 << 52):
            raise ValueError("HN SAM %s#%s has invalid address bounds" %
                             (table, index))
        return reg

    def set_targets(reg, ids, detail=""):
        reg.hashed = len(ids) > 1
        if reg.hashed:
            reg.nodeids = ids
        else:
            reg.nodeid = ids[0]
        reg.selection_details = detail
        return reg

    s3r2 = n.C.part_ge_S3r2()
    lsb = 26
    default = None
    regions = []
    if n.C.part_ge_700():
        # CMN-700 r0/r1 have a four-bit HTG count; r2+ and S3 have five.
        early_700 = (not n.C.part_ge_S3() and
                     n.C.product_config.revision_major < 2)
        count_width = 4 if early_700 else 5
        unit = read(0x908)
        nonhash_count = BITS(unit, 16, 7)
        htg_count = BITS(unit, 23, count_width)
        default_en = BIT(unit, 23 + count_width)
        rcomp = BIT(unit, 24 + count_width)
        if rcomp:
            lsb = BITS(unit, 25 + count_width, 5)
            if lsb < 20 or lsb > 26:
                raise ValueError("HN SAM has invalid comparison LSB %u" % lsb)
        max_htg = 8 if early_700 else 16
        if nonhash_count > 64 or htg_count > max_htg:
            raise ValueError("HN SAM implemented region counts exceed table bounds")
        # A masked range can describe disjoint aliases. Do not report it as
        # an ordinary contiguous range until masked comparisons are decoded.
        if not (nonhash_count or htg_count or default_en):
            return []
        compare_mask = read(0xCF8)
        address_mask = ((1 << 52) - 1) & ~((1 << lsb) - 1)
        if compare_mask & address_mask != address_mask:
            raise ValueError("HN SAM uses masked address comparisons; "
                             "SN address ranges are not decoded")
        for i in range(nonhash_count):
            offset = 0xD08 + i*8 if i < 2 else 0x5000 + i*8
            info = read(offset)
            if not BIT(info, 63):
                continue
            end_offset = 0xD38 + i*8 if i < 2 else 0x5200 + i*8
            end_info = read(end_offset) if rcomp else None
            reg = region(info, end_info, i, "NHMR", 0,
                         size_pos=12 if i < 2 else 56)
            regions.append(set_targets(reg, [BITS(info, 0, 11)]))
        next_sn = 0
        next_sa = 0
        for i in range(htg_count):
            info = read(0x5400 + i*8)
            control = read(0x5500 + i*8)
            mode = BITS(control, 25, 4 if s3r2 else 3)
            count = {0: 0, 1: 3, 2: 6, 3: 5, 4: 2, 5: 4, 6: 8}.get(mode)
            table_base, table_size = 0x5600, 64
            base = next_sn
            target_type = "SN-F"
            if mode == 7 and not s3r2:
                count = [1, 2, 4, 8, 16, 3, 6, 12][BITS(control, 40, 3)]
                table_base, table_size = 0x5700, 16
                base = next_sa
                next_sa += count
                target_type = "CCG-SA"
            elif s3r2 and mode in [8, 9]:
                count = 3 if mode == 8 else 6
            if target_type == "SN-F" and count is not None:
                next_sn += count
            if not BIT(info, 63):
                continue
            if not count:
                raise ValueError("HN HTG#%u has unsupported SN mode %u" % (i, mode))
            if s3r2:
                base = BITS(control, 56, 8)
            if base + count > table_size:
                raise ValueError("HN HTG#%u targets exceed the SN table" % i)
            ids = [BITS(read(table_base + (j // 4)*8), (j % 4)*16, 11)
                   for j in range(base, base + count)]
            end_info = read(0x5480 + i*8) if rcomp else None
            reg = region(info, end_info, i, "HTG", 1)
            reg.target_type_str = target_type
            detail = "%u-SN mode" % count
            if mode in [8, 9]:
                detail += "; arithmetic modulo"
            elif mode == 7:
                detail = "aggregated SA interleave"
            regions.append(set_targets(reg, ids, detail))
        if default_en:
            info = read(0xD48)
            if BIT(info, 63):
                end_info = read(0xD50) if rcomp else None
                default = region(info, end_info, None, "default", 2)
    else:
        for reg in hn_sam_regions(n):
            reg.table_name = "NHMR"
            reg.target_type_str = "SN-F"
            reg.priority = 0
            regions.append(reg)
        default = AddressRegion()
        default.base = 0
        default.size = 1 << 48
        default.table_name = "default"
        default.priority = 2
        default.target_type_str = "SN-F"
    if default is not None:
        control = read(0xD00)
        control2 = read(0xD28) if n.C.part_ge_700() else 0
        modes = [(BIT(control, 36), 3), (BIT(control, 37), 6),
                 (BIT(control, 38), 5), (BIT(control2, 0), 2),
                 (BIT(control2, 1), 4), (BIT(control2, 2), 8)]
        if s3r2:
            modes += [(BIT(control2, 3), 3), (BIT(control2, 4), 6)]
        counts = [count for enabled, count in modes if enabled]
        if len(counts) > 1:
            raise ValueError("HN SAM has multiple default SN modes enabled")
        count = counts[0] if counts else 1
        ids = [BITS(control if i < 3 else read(0xD20),
                    (i if i < 3 else i - 3)*12, 11) for i in range(count)]
        detail = "%u-SN mode" % count if count > 1 else ""
        if s3r2 and BITS(control2, 3, 2):
            detail += "; arithmetic modulo"
        regions.append(set_targets(default, ids, detail))
    return regions


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
                    if reg.CAL and n.C.part_ge_S3r2():
                        # CMN S3 TRM (107858), HN-F with CAL support and
                        # sys_cache_grp_cal_mode_reg/hashed_target_grp_cal_mode.
                        # RN-SAM IP-XACT makes the override-map fields
                        # conditional on num_misc > 0. Otherwise they are
                        # reserved and CAL uses the fixed identity map.
                        if BITS(rnsam_unit_info2, 9, 8):
                            reg.cal_node_offsets = [BITS(cal_mode, 4 + j*3, 3)
                                                    for j in range(reg.CAL)]
                        else:
                            reg.cal_node_offsets = list(range(reg.CAL))
                    reg.hn_count = arr_read(n, hn_count_reg, 8, i)
                    local_hn_count = reg.hn_count // cpa_hash_n
                    if reg.hashed:
                        hash_cntl = n.read64(0x3400+i*8)
                        if BIT(hash_cntl, 2):
                            reg.selection_details = "hierarchical hashing"
                        elif BIT(hash_cntl, 1):
                            reg.selection_details = "non-power-of-two hashing"
                        else:
                            reg.selection_details = "power-of-two hashing"
                        if BIT(hash_cntl, 0):
                            reg.selection_details += "; AXID participates in selection"
                        if BIT(hash_cntl, 31):
                            reg.selection_details += "; NUCA enabled"
                        reg.hier_n_clusters = BITS(hash_cntl, 8, 6) if BIT(hash_cntl, 2) else 0
                        reg.hier_n_nodes = BITS(hash_cntl, 16, 6) if BIT(hash_cntl, 2) else 0
                        reg.n_cpa = cpa_hash_n
                        if cpa_hash_n == 1 and BIT(cpag, 0):
                            # Only one CPA hash outcome, and CPA is always enabled: it's always remote
                            local_hn_count = 0
                        if not BIT(hash_cntl, 24) and not BIT(hash_cntl, 23):
                            # Select from HN-F target table
                            bix = BITS(compact, 0, 8) if compact_en else next_hnf
                            reg.target_table = "HN-F"
                            reg.target_indexes = list(range(bix, bix+local_hn_count))
                            reg.nodeids = [arr_read(n, hnf_table, 12, ix, fields_per_reg=4) for ix in reg.target_indexes]
                            next_hnf += reg.hn_count
                        elif BIT(hash_cntl, 24):
                            # Select from HN-P target table
                            bix = BITS(compact, 0, 8) if compact_en else next_hnp
                            reg.target_table = "HN-P"
                            reg.target_indexes = list(range(bix, bix+reg.hn_count))
                            reg.nodeids = [arr_read(n, hnp_table, 12, ix, fields_per_reg=4) for ix in reg.target_indexes]
                            next_hnp += reg.hn_count
                        else:
                            # Select from Misc target table
                            bix = BITS(compact, 0, 8) if compact_en else next_misc
                            reg.target_table = "misc"
                            reg.target_indexes = list(range(bix, bix+reg.hn_count))
                            reg.nodeids = [arr_read(n, misc_table, 12, ix,
                                                    fields_per_reg=4)
                                           for ix in reg.target_indexes]
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



def rn_sam_cpa_groups(n, nonhash_regions, hashed_regions):
    """Decode RN-SAM CPAG membership and annotate regions with CPA selection.

    Only the explicit hashed-group scan calls this function. All table reads
    are cached and bounded by the implemented group count and target capacity.
    Unsupported layouts raise ValueError before reading their CPA tables.

    References: CMN-700 TRM (102308), RN SAM; r3 addendum (108055),
    section 3.4.2, CML port aggregation; CMN S3 TRM (107858), RN SAM,
    cml_port_aggr_* and cml_cpag_base_indx_* registers. Compact tables select
    CPAGs directly; other HN-F tables use the per-target CPA enable bitmap.
    """
    config = n.C.product_config
    revision = config.revision_major
    if (config.product_id not in [PART_CMN700, PART_CMN_S3] or
            revision is None or revision > (3 if config.product_id == PART_CMN700 else 2)):
        raise ValueError("CPAG decoding is unavailable for this CMN product/revision")
    values = {}

    def read(offset):
        if offset not in values:
            values[offset] = n.read64(offset)
        return values[offset]

    count = BITS(read(0x908), 10, 7)
    if count == 0:
        return []
    if count > 32:
        raise ValueError("RN SAM CPAG count exceeds the 32-group table")
    # The older layout has no unit_info2 register or programmable base indexes.
    indexed = config.product_id == PART_CMN_S3 or revision >= 2
    target_limit = 32
    if n.C.part_ge_S3r2():
        unit2 = read(0x910)
        if not BIT(unit2, 45):
            return []
        target_limit = BITS(unit2, 18, 8)
        if not 0 < target_limit <= 64:
            raise ValueError("RN SAM CPAG target count exceeds the 64-entry table")
    cpags = {}
    next_target = 0
    for i in range(count):
        control = BITS(read(0x1208 + (i // 5)*8), (i % 5)*12, 6)
        group = CPAG(i, valid=bool(BIT(control, 3)))
        cpags[i] = group
        mode = BITS(control, 0, 3)
        n_targets = [1, 2, 4, 8, 16, 32, 3, None][mode]
        if mode == 6 and not indexed:
            n_targets = None
        if not group.valid:
            group.nodeids = ()
            # Do not infer subsequent linked-list positions through an
            # inactive entry. Explicit base indexes can still be resolved.
            next_target = None
            continue
        group.port_type = ("CML SMP" if BIT(control, 5) else "CXL") if indexed else "CML"
        group.axid = bool(BIT(control, 4)) if indexed else False
        if n_targets is None:
            group.error = "reserved gateway-count encoding"
            next_target = None
            continue
        base = BITS(read(0x2B00 + (i // 8)*8), (i % 8)*8, 6) if indexed else 63
        if base == 63:
            # The TRM specifies linked-list allocation and an all-ones
            # reset value for the programmable override. Interpret that
            # reset value as retaining the linked-list base.
            base = next_target
        next_target = None if base is None else base + n_targets
        if base is None:
            group.error = "linked-list base depends on an undecoded or inactive CPAG"
            continue
        if base + n_targets > target_limit:
            group.error = "target indexes exceed the implemented CPAG table"
            continue
        try:
            ids = []
            for j in range(base, base + n_targets):
                word = j // 5
                offset = (0x11F0 if word < 3 else 0x2C00) + word*8
                ids.append(BITS(read(offset), (j % 5)*12, 11))
            group.nodeids = tuple(ids)
        except OSError as ex:
            group.error = str(ex)
    # CMN S3 r2 TRM (107858_0200), sections 2.4.5.6 and 8.3.17.11:
    # 128 non-hashed regions, with CPA controls through mode_ctrl_reg12.
    # Earlier supported revisions have 64 regions, through mode_ctrl_reg6.
    nonhash_limit = 128 if n.C.part_ge_S3r2() else 64
    # Region indexes originate in the bounded SAM decoders. Validate them
    # again before deriving offsets into the additional CPA control tables.
    for reg in nonhash_regions:
        if reg.index is None or not 0 <= reg.index < nonhash_limit:
            raise ValueError("RN SAM non-hashed region index %s is outside the CPA table "
                             "(%u entries, valid indexes 0..%u)" %
                             (reg.index, nonhash_limit, nonhash_limit - 1))
        word = reg.index // 10
        offset = (0x11A0 if word < 4 else 0x2A00) + word*8
        control = BITS(read(offset), (reg.index % 10)*6, 6)
        if BIT(control, 0):
            reg.cpag = [BITS(control, 1, 5)]
    for reg in hashed_regions:
        if reg.index is None or not 0 <= reg.index < 32:
            raise ValueError("RN SAM hashed region index %s is outside the CPA table "
                             "(32 entries, valid indexes 0..31)" % reg.index)
        # Compact mode has already decoded the explicit CPAG outcomes. The
        # compact decoder leaves cpa empty only for non-hashed operation.
        if not reg.hashed or any([c is not None for c in reg.cpag]):
            continue
        if n.C.part_ge_S3r2() and BIT(read(0x910), 47):
            continue
        if reg.target_table == "misc":
            continue
        if reg.target_table != "HN-F":
            # HN-P CPA has a different table layout on some revisions.
            if reg.target_table == "HN-P":
                reg.cpa_error = "HN-P CPA selection is not decoded"
            continue
        indexes = reg.target_indexes or []
        if any([i < 0 or i >= 128 for i in indexes]):
            raise ValueError("HN-F CPA target index exceeds the 128-entry bitmap")
        enabled = [bool(BIT(read(0x1180 + (i // 64)*8), i % 64)) for i in indexes]
        if not any(enabled):
            continue
        word = reg.index // 4
        offset = (0x1190 if word < 2 else 0x3740) + word*8
        control = BITS(read(offset), (reg.index % 4)*16, 6)
        per_target = []
        for i, use_cpa in zip(indexes, enabled):
            if not use_cpa:
                per_target.append(None)
            elif indexed and BIT(control, 5):
                per_target.append(BITS(read(0x3900 + (i // 8)*8), (i % 8)*8, 5))
            else:
                per_target.append(BITS(control, 0, 5))
        reg.target_cpags = per_target
        reg.cpag = per_target
    referenced = set([c for reg in nonhash_regions + hashed_regions
                      for c in reg.cpag if c is not None])
    for i in referenced:
        if i not in cpags:
            cpags[i] = CPAG(i, error="reference exceeds the implemented CPAG count")
    return [cpags[i] for i in sorted(cpags) if cpags[i].valid or i in referenced]
