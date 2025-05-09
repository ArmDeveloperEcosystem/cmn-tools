#!/usr/bin/python3

"""
Decode CHI flit data as captured by Arm CMN interconnect

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys

import chi_spec


REQ = 0
RSP = 1
SNP = 2
DAT = 3

CHI_VC_strings = ["REQ", "RSP", "SNP", "DAT"]


# CHI opcode decodes for REQ, RSP, SNP and DAT.
# Note that opcode 0x00 (link credit return) should not be traced by CMN,
# so its appearance in a decode would be an error.

# The 4-character mnemonics are our own, and make trace output more compact.

# CHI 5 IHI0050F Table 13-12, "REQ channel opcodes":
CHI_REQ_opcodes = {
    0x00: "crtn",
    0x01: "RShr",   # ReadShared
    0x02: "RCln",   # ReadClean
    0x03: "ROnc",   # ReadOnce
    0x04: "RNSp",   # ReadNoSnp
    0x05: "PCrt",   # PCrdReturn
    0x07: "RUnq",   # ReadUnique
    0x08: "CShr",   # CleanShared
    0x09: "CInv",   # CleanInvalid
    0x0A: "MkIn",   # MakeInvalid
    0x0B: "CUnq",   # CleanUnique
    0x0C: "MUnq",   # MakeUnique
    0x0D: "Evic",   # Evict
    0x11: "RNSS",   # ReadNoSnpSep
    0x14: "DVMO",   # DVMOp
    0x15: "WEFu",   # WriteEvictFull
    0x17: "WCFu",   # WriteCleanFull
    0x18: "WUnP",   # WriteUniquePartial
    0x19: "WUnF",   # WriteUniqueFull
    0x1A: "WBPt",   # WriteBackPtl
    0x1B: "WBFu",   # WriteBackFull
    0x1C: "WNSP",
    0x1D: "WNSF",   # WriteNoSnpFull
    0x20: "WUFS",   # WriteUniqueFullStash
    0x22: "StOS",   # StashOnceShared
    0x23: "StOU",   # StashOnceUnique
    0x24: "ROCI",   # ReadOnceCleanInvalid
    0x25: "ROMI",   # ReadOnceMakeInvalid
    0x26: "RNSD",   # ReadNotSharedDirty
    0x28: "Sadd",
    0x29: "Sclr",
    0x2A: "Seor",
    0x2B: "Sset",
    0x2C: "Ssmx",
    0x2D: "Ssmn",
    0x2E: "Sumx",
    0x2F: "Sumn",
    0x30: "Ladd",
    0x31: "Lclr",
    0x32: "Leor",
    0x33: "Lset",
    0x34: "Lsmx",
    0x35: "Lsmn",
    0x36: "Lumx",
    0x37: "Lumn",
    0x38: "Aswp",   # AtomicSwap
    0x39: "Acmp",   # AtomicCompare
    0x3a: "PfTg",   # PrefetchTarget
    # later CHI with opcode[6]=1; includes combined Write+CMO
    0x41: "MRUn",   # MakeReadUnique
    0x42: "WEoE",   # WriteEvictOrEvict
    0x43: "WrUZ",   # WriteUniqueZero
    0x44: "WNSZ",   # WriteNoSnoopZero
}


CHI_RSP_opcodes = {
    0x00: "crtn",
    0x01: "SnRe",   # SnpResp
    0x02: "CAck",   # CompAck
    0x03: "RAck",   # RetryAck
    0x04: "Comp",   # Comp
    0x05: "CDBR",   # CompDBIDResp
    0x06: "DBIR",   # DBIDResp
    0x07: "PCrd",   # PCrdGrant
    0x08: "RRcp",   # ReadReceipt
    0x09: "SRFw",   # SnpRespFwded
    0x0a: "TagM",   # TagMatch
    0x0b: "RSpD",   # RespSepData
    0x0c: "Pers",   # Persist
    0x0d: "CoPe",   # CompPersist
    0x0e: "DBRO",   # DBIDRespOrd
    0x11: "CStD",   # CompStashDone
    0x14: "CCMO",   # CompCMO
}

CHI_SNP_opcodes = {
    0x00: "crtn",
    0x01: "SnSh",   # SnpShared
    0x02: "SnCl",   # SnpClean
    0x03: "SnOn",   # SnpOnce
    0x04: "SNSD",   # SnpNotSharedDirty
    0x05: "SUnS",
    0x06: "SMIS",
    0x07: "SnUn",   # SnpUnique
    0x08: "SnCS",   # SnpCleanShared
    0x09: "SnCI",   # SnpCleanInvalid
    0x0A: "SnMI",   # SnpMakeInvalid
    0x0D: "SDVM",   # SnpDVMOp
    0x13: "SOnF",   # SnpOnceFwd
    0x14: "SNDF",   # SnpNotSharedDirtyFwd
    0x15: "SPrU",   # SnpPreferUnique
    0x16: "SPUF",   # SnpPreferUniqueFwd
    0x17: "SUnF",   # SnpUniqueFwd
}

CHI_DAT_opcodes = {
    0x00: "crtn",
    0x01: "SnRD",   # SnpRespData
    0x02: "CBWD",   # CopyBackWriteData
    0x03: "NCWD",   # NonCopyBackWriteData
    0x04: "CoDa",   # CompData
    0x05: "SRDP",   # SnpRespDataPtl
    0x06: "SRDF",   # SnpRespDataFwded
    0x07: "WDaC",   # WriteDataCancel
    # later CHI onwards: CMN-600 only has 3-bit DAT opcodes
    0x0b: "DaSR",   # DataSepResp
    0x0c: "NWCA",   # NCBWrDataCompAck
}

CHI_opcodes = [
    CHI_REQ_opcodes,
    CHI_RSP_opcodes,
    CHI_SNP_opcodes,
    CHI_DAT_opcodes,
]


def CHI_op_str(vc, n, short=False):
    if short:
        if n in CHI_opcodes[vc]:
            return CHI_opcodes[vc][n]
        else:
            #assert False, "unknown %s opcode 0x%02x" % (CHI_VC_strings[vc], n)
            return "*%02x*" % n
    else:
        if n < len(chi_spec.opcodes[vc]):
            return chi_spec.opcodes[vc][n]
        else:
            return "*%02x" % n


# CHI-F Table 13-35.
# The Resp value is context-sensitive - we really need to know
# whether it's a Snoop response, a Comp response etc.
def CHI_DAT_resp_str_nonsnoop(n):
    return ["I", "SC", "UC", "?3", "?4", "?5", "UD_PD", "SD_PD"][n]


def CHI_DAT_resp_str_snoop(n):
    return ["I", "SC", "UC/UD", "SD", "I_PD", "SC_PD", "UC_PD", "?7"][n]


def CHI_DAT_resp_str(opcode, resp):
    if opcode in [1, 5, 6]:
        rs = CHI_DAT_resp_str_snoop(resp)
    else:
        rs = CHI_DAT_resp_str_nonsnoop(resp)
    return rs


def CHI_memattr_str(ma, order, snpattr):
    """
    Return a short string that summarizes the various memory attribute fields.
    """
    Device = BIT(ma, 1)
    Allocate = BIT(ma, 3)
    Cacheable = BIT(ma, 2)
    EWA = BIT(ma, 0)
    s = None
    if Device and not Allocate and not Cacheable:
        if not EWA and order == 3:
            s = "dev-nRnE"
        elif EWA and order == 3:
            s = "dev-nRE"
        elif EWA:
            s = "dev-RE"
    elif not Device:
        if not EWA:
            s = "nCnB"
        elif not Cacheable:
            s = "nCB"
        else:
            s = ["nS", "S"][snpattr] + "WB" + ["nA", "A"][Allocate]
        if order != 0:
            s += ":ord%u" % order
    if s is None:
        s = "attr=0x%x/%u" % (ma, order)
    return s


# DVM operation type.
# This has the same encoding in REQ DVMop and SNP SnpDVMOp.
# See CHI-E page 305 Table 8-7.
DVM_op_str = [
    "TLBI",      # TLB Invalidate
    "BPI",       # Branch Predictor Invalidate
    "PICI",      # Physical Instruction Cache Invalidate
    "VICI",      # Virtual Instruction Cache Invalidate
    "SYNC",      # Synchronization
    "?5",
    "?6",
    "?7",
]

DVM_EL_str = ["EL21", "EL3", "EL1", "EL2"]


# Following are DEVEVENT encodings from CMN HN-F.
_HNF_devevent_str = ["miss/no-snoop", "miss/directed-snoop", "miss/broadcast-snoop", "hit"]


def devevent_str(de):
    return _HNF_devevent_str[de]


class CMNFlit:
    """
    Data about a flit. Ranges from just the TXNID, up to some of the payload,
    depending on the trace format requested at the watchpoint.
    """
    def __init__(self, txnid=None, opcode=None, srcid=None, tgtid=None, tracetag=None, data=None, group=None):
        self.group = group         # will be a CMNFlitGroup
        self.txnid = txnid         # CHI transaction id, always present: 8, 10 or 12 bits
        self.opcode = opcode       # meaning depends on channel
        self.srcid = srcid         # CHI source, 11 bits
        self.lpid = None
        self.tgtid = tgtid         # CHI target, 11 bits
        self.tracetag = tracetag
        self.data = data

    def is_DVM(self):
        return (self.group.VC == REQ and self.opcode == 0x14) or (self.group.VC == SNP and self.opcode == 0x0d)

    def opcode_str(self, short=False):
        """
        Return a string for the opcode.
        """
        if self.opcode is not None:
            return CHI_op_str(self.group.VC, self.opcode, short=short)
        else:
            return None

    def resp_str(self):
        if self.group.VC == DAT and self.opcode is not None and self.resp is not None:
            return CHI_DAT_resp_str(self.opcode, self.resp)
        else:
            return None

    def DVM_opcode(self):
        if self.is_DVM():
            if self.group.VC == REQ:
                return BITS(self.addr, 11, 3)
            elif self.group.VC == SNP and BIT(self.addr, 0) == 0:
                return BITS(self.addr, 8, 3)
        return None

    def DVM_opcode_str(self):
        dvm_op = self.DVM_opcode()
        return DVM_op_str[dvm_op] if dvm_op is not None else None

    def mpam_str(self, mpam):
        # 11-bit MPAM field is 1-bit PerfMonGroup, 9-bit PartID, 1-bit MPAMNS.
        # See e.g. CHI-E 11.3.
        # "A Requester that supports MPAM includes in each request it sends a label,
        #  identifying the partition to which it belongs, together with the
        #  performance monitoring group within that partition."
        if False:
            # For now, just decode as hex.
            return "mpam=0x%x" % mpam
        else:
            mb = self.group.cfg._MPAM_bits
            assert mb != 0
            sb = 2 if mb >= 12 else 1
            pb = mb - 1 - sb
            mpam_space = BITS(mpam, 0, sb)  # Separate to main NS bit
            partid = BITS(mpam, sb, pb)     # either 9 or 11 bits
            pmg = BIT(mpam, mb-1)           # top bit is PerfMonGroup
            # PMG is within partition, so print the partition first
            s = "partid=%u:pmg=%u" % (partid, pmg)
            if mpam_space != 1:
                s += "/" + (["S", "NS", "RT", "RL"][mpam_space])
            return s

    def short_str(self):
        """
        Source, target, opcode and transaction id
        """
        s = self.group.txnid_fmt % self.txnid
        if self.opcode is not None:
            s = self.opcode_str(short=True) + ":" + s
        if self.srcid is not None:
            src_lpid = self.lpid if self.group.VC == 0 else 0
            rs = self.group.id_str(self.srcid, lpid=src_lpid) + "->"
            if self.tgtid is not None:
                rs = rs + self.group.id_str(self.tgtid)
            else:
                rs = rs + "..."
            s = rs + ":" + s
        return s

    def long_str(self):
        """
        Full CHI flit decode (of information captured by CMN format 4) to a string.
        We focus on presenting the most relevant information in a concise way.
        Generally, decode is determined by the CHI architecture. There are a few
        fields (RSVDC, DEVEVENT) whose interpretation may be specific to CMN,
        or a CMN node type, or even an implementation of CMN.
        """
        s = self.short_str()
        if self.group.format == 4:
            if self.group.VC == 3:
                s += ".%u" % self.dataid
            s += (" %x" % self.qos) if self.qos else "  "
            s += " %02x:%-20s" % (self.opcode, CHI_op_str(self.group.VC, self.opcode))
            if self.group.VC == 0:
                s += " lpid=%02x" % self.lpid
                s += " ret=%03x:" % self.returnnid
                s += self.group.txnid_fmt % self.returntxnid
                s += " %17s %3u" % (self.group.addr_str(self.addr, self.NS), (1 << self.size))
                if self.mpam is not None and self.mpam != 0x01:     # present and interesting
                    s += " %s" % self.mpam_str(self.mpam)
                if self.opcode != 0x14:
                    s += " %s" % (CHI_memattr_str(self.memattr, self.order, self.snpattr))
                else:
                    # DVMOp REQ is special, and encodes the operation in the address
                    # (as well as in the lower 8 bytes of data in a DAT packet,
                    # which we don't have access to).
                    # See "DVM message payload" in the CHI spec,
                    # particularly the "DVM message packing" section.
                    # See also SnpDVMOp below.
                    addr = self.addr
                    sec = BITS(addr,7,2)
                    EL = BITS(addr,9,2)
                    dvmop = BITS(addr,11,3)
                    addr_valid = BIT(addr,4)
                    vmid_valid = BIT(addr,5)
                    asid_valid = BIT(addr,6)
                    range = BIT(addr,41)
                    s += " %s %s" % (DVM_op_str[dvmop], DVM_EL_str[EL])
                    if addr_valid:
                        s += " addr"
                    if range:
                        s += " range"
                    if vmid_valid:
                        s += " vmid=0x%x" % BITS(addr,14,8)
                    if asid_valid:
                        s += " asid=0x%x" % BITS(addr,22,16)
                if self.excl_snoopme:
                    s += " excl"
                if self.expcompack:
                    s += " eca"
                if self.rsvdc != 0:
                    s += " rsvdc=0x%02x" % (self.rsvdc)
                if self.likelyshared:
                    s += " lshr"
                if not self.allowretry:
                    s += " no-retry:%u" % (self.pcrdtype)
            elif self.group.VC == 1:
                # RSP
                s += " resp=%u/%u dbid=0x%02x" % (self.resp, self.resperr, self.dbid)
                if self.opcode in [3, 7]:
                    s += " pcrdtype=%u" % (self.pcrdtype)
                if self.cbusy:
                    s += " cbusy=0x%x" % (self.cbusy)
                if self.devevent != 0:
                    s += " %s" % devevent_str(self.devevent)
            elif self.group.VC == 2:
                # SNP
                s += " fwdnid=0x%03x %s0x%012x" % (self.fwdnid, ["S:","  "][self.NS], self.addr)
                if self.mpam is not None and self.mpam != 0x01:
                    s += " %s" % self.mpam_str(self.mpam)
                if self.opcode == 0x0d:
                    # SnpDVMOp is special: meaning is encoded in address field (and always S)
                    addr = self.addr >> 3    # recover original field
                    part = BIT(addr, 0)
                    s += " #%u" % part
                    if part == 0:
                        # SnpDVMOp part 0: same info as REQ DVMOp, but at different offset
                        addr_valid = BIT(addr,1)
                        vmid_valid = BIT(addr,2)
                        asid_valid = BIT(addr,3)
                        sec = BITS(addr,4,2)
                        EL = BITS(addr,6,2)
                        dvmop = BITS(addr,8,3)
                        s += " %s %s" % (DVM_op_str[dvmop], DVM_EL_str[EL])
                        if addr_valid:
                            s += " addr"
                        if vmid_valid:
                            s += " vmid=0x%x" % BITS(addr,11,8)
                        if asid_valid:
                            s += " asid=0x%x" % BITS(addr,19,16)
                    else:
                        # SnpDVMOp part 1: often address[:6], but sometimes low
                        # bits are used for other purposes e.g. IS, TTL, TG
                        # Wthout seeing part 0, our heuristic is that if any bits
                        # from bit 7 on are set, it's an address.
                        if (addr >> 7) != 0:
                            address = (addr >> 1) << 6
                            s += " address=0x%x" % address
                        elif addr != 0x1:
                            s += " ?=0x%x" % addr
            elif self.group.VC == DAT:
                s += " resp=%s" % (self.resp_str())
                s += " dbid=0x%02x" % (self.dbid)
                if self.ccid != 0:
                    s += " ccid=%u" % (self.ccid)
                if self.homenid != 0:
                    # only valid for some opcodes
                    s += " homenid=0x%02x" % (self.homenid)
                if self.cbusy:
                    s += " cbusy=0x%x" % (self.cbusy)
                if self.devevent != 0:
                    s += " %s" % devevent_str(self.devevent)
                if self.poison != 0:
                    s += " poison=0x%x" % (self.poison)
            else:
                assert False
            if self.tracetag:
                s += " TAG"
        return s

    def __str__(self):
        return self.short_str()


def BITS(x,p,n):
    return (x >> p) & ((1 << n)-1)


def BIT(x,p):
    return (x >> p) & 1


def bytes_hex(x):
    s = ""
    for b in x:
        try:
            b = ord(b)
        except TypeError:
            pass
        s += ("%02x" % b)
    return s


def bytes_as_int(s):
    """
    Given a byte string or byte-producing iterator
    (Python2: str or bytearray, Python3: bytes or bytearray),
    form an integer such that the later bytes in
    the string appear at the highest positions.
    """
    if sys.version_info[0] >= 3:
        return int.from_bytes(s, byteorder="little")
    n = 0
    for (i, b) in enumerate(s):
        try:
            b = ord(b)
        except TypeError:
            pass
        n |= (b << (i*8))
    return n


assert bytes_as_int(b"\x12\x34\x56\x78\x9a") == 0x9a78563412
assert bytes_as_int(bytearray(b"\x12\x34\x56\x78\x9a")) == 0x9a78563412


def bytes_as_chunks(payload, size):
    n_chunks = (len(payload)*8) // size
    x = bytes_as_int(payload)
    for i in range(n_chunks):
        yield BITS(x, (n_chunks-i-1)*size, size)


PART_CMN600   = 0x434
PART_CMN650   = 0x436
PART_CMN700   = 0x43c
PART_CI700    = 0x43a
PART_CMN_S3   = 0x43e

_cmn_product_names = {
    0x434: "CMN-600",
    0x436: "CMN-650",
    0x43c: "CMN-700",
    0x43a: "CI-700",
    0x43e: "CMN S3",
}


class CMNTraceConfig:
    """
    CMN configuration details, sufficient to decode trace.
    The CMN tools have their own class for CMN configuration,
    but we keep this one separate so we can use the flit decoder
    independently as part of a CoreSight trace decoder.
    """
    def __init__(self, cmn_product_id, has_MPAM):
        if cmn_product_id in [600, 650, 700]:
            # legacy compatibility
            cmn_product_id = {600: PART_CMN600, 650: PART_CMN650, 700: PART_CMN700}[cmn_product_id]
        assert cmn_product_id in _cmn_product_names, "unexpected CMN product id: %s" % cmn_product_id
        self.cmn_product_id = cmn_product_id
        self.has_MPAM = has_MPAM
        # Mostly we can treat CMN S3 like CMN-700
        self._cmn_base_type = {PART_CMN600: 0, PART_CMN650: 1, PART_CMN700: 2, PART_CI700: 2, PART_CMN_S3: 3}[self.cmn_product_id]
        # Assume CMN S3 MPAM is 15-bit not 12-bit
        self._MPAM_bits = 0 if not self.has_MPAM else [0, 11, 11, 15][self._cmn_base_type]

    def __str__(self):
        s = _cmn_product_names[self.cmn_product_id]
        if self.has_MPAM:
            s += "+MPAM"
        return s


def trace_size_bits(cfg):
    return [144, 160, 176, 176][cfg._cmn_base_type]


class CMNFlitGroup:
    """
    A group of flits sharing the same trace configuration.

    We allow mixing of CHI channels, devices etc. within a flit group.
    So it's not necessary to specify these when creating the group.
    But they will need to be specified by the time we call decode() to
    decode a payload from CMN trace stream, watchpoint FIFO etc.
    """
    def __init__(self, cfg, format=None, VC=None, payload=None, WP=None, DEV=None, cmn_seq=None, nodeid=None, lossy=False, cc=None, debug=False):
        self.cfg = cfg
        self.txnid_bits = [8, 10, 12, 12][self.cfg._cmn_base_type]
        self.txnid_fmt = "%02x" if self.txnid_bits <= 8 else "%03x"
        self.format = format    # CMN flit encoding format, needed for decode
        self.VC = VC            # REQ/RSP/SNP/DAT, needed for decode
        self.flits = []
        self.payload = payload
        self.cmn_seq = cmn_seq  # CMN instance number, or None if not needed or not known
        self.nodeid = nodeid    # XP node id where flit was captured
        self.WP = WP            # Watchpoint number
        self.DEV = DEV          # Device number (= port number)
        self.cc = cc            # Cycle count, or None if not recorded
        self.lossy = lossy      # Trace indicated that packets were lost (ATB only)
        self.debug = debug
        if payload is not None:
            self.decode(payload)

    def add_flit(self, flit):
        assert isinstance(flit, CMNFlit)
        assert flit.group is None or flit.group == self
        flit.group = self
        flit.VC = self.VC
        self.flits.append(flit)
        return flit

    def __iter__(self):
        for flit in self.flits:
            yield flit

    def context_str(self):
        """
        Return a string indicating where the data was captured.
        """
        s = ""
        if self.cmn_seq is not None:
            s += "C%u" % self.cmn_seq
        if self.nodeid is not None:
            s += "@0x%03x " % self.nodeid
        if self.DEV is not None:
            s += "DEV=%u " % self.DEV
        if self.WP is not None:
            s += "WP=%u " % self.WP
        return s.strip()

    def id_str(self, id, lpid=0):
        """
        Return a string representation of source or target id. Subclass can override.
        lpid is provided for the subclass override (e.g. to map to a CPU identifier).
        """
        return "%03x" % id

    def addr_str(self, addr, NS=1):
        return "%s0x%012x" % (["S:","  "][NS], addr)

    def __str__(self):
        """
        Return a string for the flit group as a whole. Where only basic
        details have been captured (CMN formats 0, 1, 2), several flits
        can be printed on one line.
        """
        s = ""
        if self.cc is not None:
            s += "%08x " % self.cc
        s += self.context_str()
        s += "! " if self.lossy else "  "
        if self.debug and self.payload is not None:
            s += "%36s  " % bytes_hex(reversed(self.payload))
        if self.VC is not None:
            s += "%s " % CHI_VC_strings[self.VC]
        if self.payload is not None:
            if self.flits:
                sep = "  " if self.format == 2 else " "
                if self.format == 0:
                    s += "TXNID: "
                s += sep.join([f.long_str() for f in self.flits])
            elif self.format in [5, 6]:
                s += "DATA(%s): %36s" % (["lo", "hi"][self.format-5], bytes_hex(reversed(self.payload)))
            else:
                s += "raw: %s (format=%s)" % (bytes_hex(self.payload), self.format)
        return s

    def decode(self, payload):
        """
        Unpack the payload and add some flits to this flit group.
        """
        # "Trace data is packed into a DTM FIFO buffer entry
        # such that the higher order bytes contain older trace data".
        assert not self.flits, "for now, only decode one payload per flit group"
        self.payload = payload
        assert self.format is not None, "flit capture format must be known for decode"
        if self.format == 0:
            # TXNID only. CMN-600: 18 x 8-bit; CMN-650: 16 x 10-bit; CMN-700: 14 x 12-bit.
            for txnid in bytes_as_chunks(payload, self.txnid_bits):
                self.add_flit(CMNFlit(txnid=txnid))
        elif self.format == 1:
            # TXNID + opcode up to 9 times
            # Note for fuzzing: the opcode field is wider than might make sense for the CHI channel
            osize = [6, 6, 7, 7][self.cfg._cmn_base_type]
            csize = [16, 16, 19, 19][self.cfg._cmn_base_type]
            for bb in bytes_as_chunks(payload, csize):
                txnid = BITS(bb, 0, self.txnid_bits)
                opcode = BITS(bb, self.txnid_bits, osize)
                self.add_flit(CMNFlit(txnid=txnid, opcode=opcode))
        elif self.format == 2:
            # TXNID + opcode + source ID + target ID, up to 4 times
            osize = [6, 6, 7, 7][self.cfg._cmn_base_type]
            csize = [36, 40, 44, 44][self.cfg._cmn_base_type]
            for p in bytes_as_chunks(payload, csize):
                txnid = BITS(p, 0, self.txnid_bits)
                opcode = BITS(p, self.txnid_bits, osize)
                srcid = BITS(p, self.txnid_bits+osize, 11)
                tgtid = BITS(p, self.txnid_bits+osize+11, 11)
                self.add_flit(CMNFlit(txnid=txnid, opcode=opcode, srcid=srcid, tgtid=tgtid))
        elif self.format == 4:
            # decode according to "Trace data formats" table:
            #   CMN-600 Table 5-8 etc.
            #   CMN-700 Table 6-9 etc.
            #   CMN S3 is identical to CMN-700
            x = bytes_as_int(payload)
            f = CMNFlit()
            f.qos = BITS(x,0,4)
            assert self.VC is not None, "CHI channel must be known for format-4 decode"
            if self.VC == 0:
                # REQ
                f.tgtid = BITS(x,4,11)
                f.srcid = BITS(x,15,11)
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.txnid = BITS(x,26,8)
                    f.opcode = BITS(x,54,6)
                    f.tracetag = BIT(x,84)
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.txnid = BITS(x,26,10)
                    f.opcode = BITS(x,58,6)
                    f.tracetag = BIT(x,88)
                elif self.cfg.cmn_product_id != PART_CMN_S3:
                    f.txnid = BITS(x,26,12)
                    f.opcode = BITS(x,62,7)
                    f.tracetag = BIT(x,98)
                else:
                    f.txnid = BITS(x,26,12)
                    f.opcode = BITS(x,62,7)
                    f.tracetag = BIT(x,99)
            elif self.VC == 1:
                # RSP
                f.tgtid = BITS(x,4,11)
                f.srcid = BITS(x,15,11)
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.txnid = BITS(x,26,8)
                    f.opcode = BITS(x,34,4)
                    f.tracetag = BIT(x,58)
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.txnid = BITS(x,26,10)
                    f.opcode = BITS(x,36,4)
                    f.tracetag = BIT(x,65)
                else:
                    f.txnid = BITS(x,26,12)
                    f.opcode = BITS(x,38,5)
                    f.tracetag = BIT(x,70)
            elif self.VC == 2:
                # SNP
                f.srcid = BITS(x,4,11)
                f.tgtid = None
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.txnid = BITS(x,15,8)
                    f.opcode = BITS(x,42,5)
                    f.tracetag = BIT(x,50)
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.txnid = BITS(x,15,10)
                    f.opcode = BITS(x,46,5)
                    f.tracetag = BIT(x,54)
                elif self.cfg.cmn_product_id != PART_CMN_S3:
                    f.txnid = BITS(x,15,12)
                    f.opcode = BITS(x,50,5)
                    f.tracetag = BIT(x,58)
                else:
                    f.txnid = BITS(x,15,12)
                    f.opcode = BITS(x,50,5)
                    f.tracetag = BIT(x,59)
            elif self.VC == 3:
                # DAT
                f.tgtid = BITS(x,4,11)
                f.srcid = BITS(x,15,11)
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.txnid = BITS(x,26,8)
                    f.opcode = BITS(x,45,3)
                    f.tracetag = BIT(x,68)
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.txnid = BITS(x,26,10)
                    f.opcode = BITS(x,47,4)
                    f.tracetag = BIT(x,77)
                else:
                    f.txnid = BITS(x,26,12)
                    f.opcode = BITS(x,49,4)
                    f.tracetag = BIT(x,95)
            else:
                assert False, "bad CMN channel %s" % self.VC
            self.add_flit(f)
            # full
            if self.VC == 0:
                # REQ
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.returnnid = BITS(x,34,11)    # or StashNID
                    f.returntxnid = BITS(x,46,8)
                    f.size = BITS(x,60,3)
                    f.NS = BIT(x,63)
                    f.likelyshared = BIT(x,64)
                    f.allowretry = BIT(x,65)
                    f.order = BITS(x,66,2)
                    f.pcrdtype = BITS(x,68,4)
                    f.memattr = BITS(x,72,4)
                    f.snpattr = BIT(x,76)
                    f.lpid = BITS(x,77,5)
                    f.excl_snoopme = BIT(x,82)
                    f.expcompack = BIT(x,83)
                    f.tracetag = BIT(x,84)
                    f.addr = BITS(x,85,48)
                    f.rsvdc = BITS(x,133,8)
                    f.mpam = None
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.returnnid = BITS(x,36,11)    # or StashNID
                    f.returntxnid = BITS(x,48,10)
                    f.size = BITS(x,64,3)
                    f.NS = BIT(x,67)
                    f.likelyshared = BIT(x,68)
                    f.allowretry = BIT(x,69)
                    f.order = BITS(x,70,2)
                    f.pcrdtype = BITS(x,72,4)
                    f.memattr = BITS(x,76,4)
                    f.snpattr = BIT(x,80)
                    f.lpid = BITS(x,81,5)
                    f.excl_snoopme = BIT(x,86)
                    f.expcompack = BIT(x,87)
                    f.tracetag = BIT(x,88)
                    if not self.cfg.has_MPAM:
                        f.mpam = None
                        f.addr = BITS(x,89,52)
                        f.rsvdc = BITS(x,141,8)
                    else:
                        f.mpam = BITS(x,89,11)
                        f.addr = BITS(x,100,52)
                        f.rsvdc = BITS(x,152,8)
                elif self.cfg.cmn_product_id != PART_CMN_S3:
                    # CMN-700
                    f.returnnid = BITS(x,38,11)
                    f.returntxnid = BITS(x,50,12)
                    f.size = BITS(x,69,3)
                    f.NS = BIT(x,72)
                    f.likelyshared = BIT(x,73)
                    f.allowretry = BIT(x,74)
                    f.order = BITS(x,75,2)
                    f.pcrdtype = BITS(x,77,4)
                    f.memattr = BITS(x,81,4)
                    f.snpattr = BIT(x,85)
                    f.lpid = BITS(x,86,5)
                    f.excl_snoopme = BIT(x,94)
                    f.expcompack = BIT(x,95)
                    f.tracetag = BIT(x,98)
                    if not self.cfg.has_MPAM:
                        f.mpam = None
                        f.addr = BITS(x,99,52)
                        f.rsvdc = BITS(x,151,8)
                    else:
                        f.mpam = BITS(x,99,11)
                        f.addr = BITS(x,110,52)
                        f.rsvdc = BITS(x,162,8)
                else:
                    # CMN S3
                    f.returnnid = BITS(x,38,11)
                    f.returntxnid = BITS(x,50,12)
                    f.size = BITS(x,69,3)
                    f.NS = BIT(x,72)
                    f.likelyshared = BIT(x,74)
                    f.allowretry = BIT(x,75)
                    f.order = BITS(x,76,2)
                    f.pcrdtype = BITS(x,78,4)
                    f.memattr = BITS(x,82,4)
                    f.snpattr = BIT(x,86)
                    f.lpid = BITS(x,87,5)
                    f.excl_snoopme = BIT(x,95)
                    f.expcompack = BIT(x,96)
                    f.tracetag = BIT(x,99)
                    if not self.cfg.has_MPAM:
                        f.mpam = None
                        f.addr = BITS(x,121,52)
                        f.rsvdc = BITS(x,173,8)
                    else:
                        f.mpam = BITS(x,100,15)
                        f.addr = BITS(x,136,52)
                        f.rsvdc = BITS(x,188,8)
            elif self.VC == 1:
                # RSP
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.resperr = BITS(x,38,2)
                    f.resp = BITS(x,40,3)
                    f.cbusy = None
                    f.dbid = BITS(x,46,8)
                    f.pcrdtype = BITS(x,54,4)
                    f.devevent = BITS(x,59,2)
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.resperr = BITS(x,43,2)
                    f.resp = BITS(x,45,3)
                    f.cbusy = BITS(x,48,3)
                    f.dbid = BITS(x,51,10)
                    f.pcrdtype = BITS(x,61,4)
                    f.devevent = BITS(x,66,2)
                else:
                    f.resperr = BITS(x,46,2)
                    f.resp = BITS(x,48,3)
                    f.cbusy = BITS(x,51,3)
                    f.dbid = BITS(x,54,12)
                    f.pcrdtype = BITS(x,66,4)
                    f.devevent = BITS(x,71,2)
            elif self.VC == 2:
                # SNP
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.fwdnid = BITS(x,23,11)
                    f.NS = BIT(x,47)
                    f.addr = BITS(x,51,45) << 3
                    f.mpam = None
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.fwdnid = BITS(x,25,11)
                    f.NS = BIT(x,51)
                    if not self.cfg.has_MPAM:
                        f.addr = BITS(x,55,49) << 3
                        f.mpam = None
                    else:
                        f.mpam = BITS(x,55,11)
                        f.addr = BITS(x,66,49) << 3
                elif self.cfg.cmn_product_id != PART_CMN_S3:
                    f.fwdnid = BITS(x,27,11)
                    f.NS = BIT(x,55)
                    if not self.cfg.has_MPAM:
                        f.addr = BITS(x,60,49) << 3
                        f.mpam = None
                    else:
                        f.mpam = BITS(x,59,11)
                        f.addr = BITS(x,70,49) << 3
                elif self.cfg.cmn_product_id == PART_CMN_S3:
                    f.fwdnid = BITS(x,27,11)
                    f.NS = BIT(x,55)
                    if not self.cfg.has_MPAM:
                        f.addr = BITS(x,76,49) << 3
                        f.mpam = None
                    else:
                        f.mpam = BITS(x,60,15)
                        f.addr = BITS(x,91,49) << 3
                else:
                    assert False
            elif self.VC == 3:
                # DAT
                # n.b. DataSource is not available
                if self.cfg.cmn_product_id == PART_CMN600:
                    f.homenid = BITS(x,34,11)
                    f.resperr = BITS(x,48,2)
                    f.resp = BITS(x,50,3)
                    f.fwdstate = BITS(x,53,3)
                    f.cbusy = None
                    f.dbid = BITS(x,56,8)
                    f.ccid = BITS(x,64,2)
                    f.dataid = BITS(x,66,2)
                    f.poison = BITS(x,69,4)
                    f.chunkv = BITS(x,73,2)
                    f.devevent = BITS(x,75,2)
                    f.rsvdc = BITS(x,77,8)
                elif self.cfg.cmn_product_id == PART_CMN650:
                    f.homenid = BITS(x,36,11)
                    f.resperr = BITS(x,51,2)
                    f.resp = BITS(x,53,3)
                    f.fwdstate = BITS(x,56,4)
                    f.cbusy = BITS(x,60,3)
                    f.dbid = BITS(x,63,10)
                    f.ccid = BITS(x,73,2)
                    f.dataid = BITS(x,75,2)
                    f.poison = BITS(x,78,4)
                    f.chunkv = BITS(x,82,2)
                    f.devevent = BITS(x,84,2)
                    f.rsvdc = BITS(x,86,8)
                else:
                    f.homenid = BITS(x,38,11)
                    f.resperr = BITS(x,53,2)
                    f.resp = BITS(x,55,3)
                    f.fwdstate = BITS(x,58,4)
                    f.cbusy = BITS(x,62,3)
                    f.dbid = BITS(x,65,12)
                    f.ccid = BITS(x,77,2)
                    f.dataid = BITS(x,79,2)
                    f.rsvdc = BITS(x,96,8)
                    f.poison = BITS(x,104,4)
                    f.chunkv = BITS(x,108,2)
                    f.devevent = BITS(x,110,2)
            else:
                assert False


if __name__ == "__main__":
    import argparse
    import random
    parser = argparse.ArgumentParser(description="CMN CHI flit decoder (self-tests)")
    parser.add_argument("--cmn-version", type=(lambda x:int(x,16)), help="set CMN version", required=True)
    parser.add_argument("--no-mpam", action="store_true", help="indicate MPAM not present")
    parser.add_argument("--format", type=int)
    parser.add_argument("--vc", type=int, help="CHI channel (REQ/RSP/SNP/DAT)")
    parser.add_argument("--tests", type=int, default=1000, help="number of tests to run")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    cfg = CMNTraceConfig(opts.cmn_version, not opts.no_mpam)
    for i in range(opts.tests):
        g = CMNFlitGroup(cfg)
        g.VC = opts.vc if opts.vc is not None else random.randrange(4)
        g.format = opts.format if opts.format is not None else [0, 1, 2, 4][random.randrange(4)]
        wbytes = trace_size_bits(cfg) // 8
        def randbytes(n):
            x = 0
            for _ in range(n // 2):
                x = (x << 16) | random.randrange(0xffff)
            return x.to_bytes(n, 'big')
        g.decode(randbytes(wbytes))
        print(g)
