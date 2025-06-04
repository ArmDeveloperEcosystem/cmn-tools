#!/usr/bin/python3

"""
CMN watchpoint configuration

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

The basic idea is to take a set of named CHI packet fields, e.g.
  opcode=..., srcid=...
and return a watchpoint configuration as a 64-bit value/mask pair,
that can be passed to a perf command or perf_event_open call.
In some cases two value/mask pairs must be used, and the caller will
combine these with the 'combine' attribute when passing to perf.

The value/mask pairs can also be used when programming CMN
watchpoints directly, e.g. via /dev/mem.

The mapping of fields to masks depends on product version (600, 700 etc.)
and may also depend on product configuration (e.g. MPAM enabled).

This script is designed as a module, but can also be used as a
command-line tool to construct a watchpoint expression for "perf".
"""

from __future__ import print_function

import sys

import chi_spec
import cmn_base
import cmn_json


o_verbose = 0


REQ = 0
RSP = 1
SNP = 2
DAT = 3


_chi_channels = ["REQ", "RSP", "SNP", "DAT"]


class WatchpointError(ValueError):
    """
    Some error occurred when trying to construct a watchpoint.
    Since all errors detected at this stage are basically "user error",
    we make them a subclass of ValueError.
    """
    pass


class WatchpointNoDirection(WatchpointError):
    """
    Watchpoint fields are ok, but the user requested generation of "perf"
    strings without explicitly or implicitly indicating a direction.
    Currently the PMU driver needs this to be specified.
    """
    def __init__(self, wp):
        self.wp = wp

    def __str__(self):
        return "must specify up/down direction if it cannot be inferred: %s" % self.wp


class WatchpointBadValue(WatchpointError):
    def __init__(self, val, reason, field=None, chn=None):
        assert chn in [None, 0, 1, 2, 3]
        self.field = field
        self.value = val
        self.chn = chn
        self.reason = reason

    def __str__(self):
        chn_name = _chi_channels[self.chn] if self.chn is not None else "chn?"
        return "%s: %s=%s (%s)" % (self.reason, self.field, self.value, chn_name)


class WatchpointBadShort(WatchpointError):
    """
    Bad short-form watchpoint specifier
    """
    def __init__(self, spec, reason):
        self.spec = spec
        self.reason = reason

    def __str__(self):
        return "bad short-form watchpoint specifier: \"%s\" (%s)" % (self.spec, self.reason)


def convert_value(v):
    """
    Given a numeric or masked-numeric value specifier,
    return a pair of a numeric value and a don't-care mask.

    Table-lookup of enumerated values is assumed to have already been done.

    A value specifier might be a literal value, or a wildcard:
      0b1x00    -> (0x8, 0x4)
      0x4xxx    -> (0x4000, 0x0fff)
    TBD: For non-nybble-aligned fields that don't fit hex wildcards,
    it would be nice to have a way to represent them compactly.
    """
    if isinstance(v, bool):
        return (int(v), 0)
    if isinstance(v, int):
        return (v, 0)
    try:
        v = int(v, 0)
        return (v, 0)
    except Exception:
        pass
    if v.startswith("0b"):
        v0 = int(v.replace('x', '0'), 2)
        v1 = int(v.replace('x', '1'), 2)
        return (v0, v1-v0)
    elif v.startswith("0x"):
        v0 = int(v[2:].replace('x', '0'), 16)
        v1 = int(v[2:].replace('x', 'f'), 16)
        return (v0, v1-v0)
    else:
        raise WatchpointBadValue(v, "expected integer or bitmask")


def unconvert_value_mask(v, m):
    """
    Inverse of convert_value - given a (value, mask) tuple, convert it back into
    a single object - either an integer, or a string.
    """
    if m == 0:
        return v
    else:
        s = ""
        while m or v:
            if m & 1:
                s = "x" + s
            else:
                s = str(v & 1) + s
            v >>= 1
            m >>= 1
        return "0b" + s


assert convert_value(123) == (123, 0)
assert convert_value("123") == (123, 0)
assert convert_value("0x123") == (0x123, 0)
assert convert_value("0bx1xx") == (4, 0b1011)

assert unconvert_value_mask(123, 0) == 123
assert unconvert_value_mask(4, 0b1011) == "0bx1xx"


class MatchMask:
    """
    A single value/mask pair, for a single match group.
    A dont-care in the mask is indicated by a 1-bit.
    """
    def __init__(self, grp, val=0, mask=None, exclusive=False, n_bits=64):
        self.n_bits = n_bits
        self.grp = grp
        self.val = val
        self.mask = mask if mask is not None else ((1 << n_bits) - 1)
        self.exclusive = exclusive    # Succeed on non-match

    def is_open(self):
        """
        Return true if the match currently matches everything
        """
        return self.mask == (1 << self.n_bits) - 1

    def set(self, val, pos, bits=1):
        """
        Set a field in a match mask to a given value.
        The field may be specified with wildcard bits.
        """
        assert (pos + bits) <= self.n_bits, "invalid field [%u:%u] in %u-bit watchpoint" % (pos+bits-1, pos, self.n_bits)
        if val is not None:
            if o_verbose:
                print("    setting [%u:%u] to %s" % (pos+bits-1, pos, val), file=sys.stderr)
            (val, dontcare) = convert_value(val)
            if val >= (1 << bits):
                raise WatchpointBadValue(val, ("value out of range for %u-bit field" % bits))
            dontcare &= ((1 << bits) - 1)
            mask = ((1 << bits) - 1) << pos
            # Remove any previous specification for this field
            self.val = self.val & ~mask
            self.mask |= mask
            # Now apply the new value
            self.val = (self.val & ~mask) | (val << pos)
            self.mask &= ~mask
            self.mask |= (dontcare << pos)

    def __str__(self):
        """
        To describe the MatchMask, generate a perf-like string
        """
        s = "wp_grp=%u,wp_val=0x%x,wp_mask=0x%016x" % (self.grp, self.val, self.mask)
        if self.exclusive:
            s += ",wp_exclusive=1"
        return s


def _perf_sanitize_name(s):
    # perf faults certain characters in names, the rules aren't clear.
    return s.replace('=', '-')


_wp_combine = 1


def alloc_combine():
    """
    The wp_combine parameter is used by the kernel PMU to allocate
    multiple match groups in a single logical watchpoint event
    (counted to the primary event).
    Events with a wp_combine value of 0 are considered independent.
    The PMU currently defines 4 bits for wp_combine.
    """
    global _wp_combine
    next_wp_combine = _wp_combine
    _wp_combine += 1
    if _wp_combine == 16:
        _wp_combine = 1
    return next_wp_combine


class Watchpoint:
    """
    A CMN watchpoint configuration, for a specific CHI channel,
    with one or two value/mask pairs, that can be assigned to
    match-registers 0, 1 or 2.

    It may be that no CHI fields are matched at all - perhaps the user
    wants to match e.g. all REQ flits uploaded on a particular interface.
    In that case we can return an open wildcard on an arbitrary group, e.g. 0.

    TBD: currently the 'exclusive' flag is handled suboptimally.
    'exclusive' acts as a flag on an individual watchpoint, indicating
    that the condition should be negated.
    Ideally, we should allow things like "a=x and b!=y" by combining
    two watchpoints, the second one marked as 'exclusive'. The watchpoints
    might both be on the same match group. Currently, we only allow
    negation of an entire group.

    TBD: review name for the 'exclusive' mode of watchpoints, to avoid
    confusion with the 'excl' flag on CHI requests.
    """
    def __init__(self, chn=0, up=None, cmn_version=None, grp=None, mask=None, name=None, **matches):
        assert cmn_version is not None
        #assert isinstance(cmn_version, cmn_base.CMNConfig)
        try:
            chn = _chi_channels.index(chn.upper())
        except Exception:
            pass
        assert chn in [0, 1, 2, 3], "bad CHI channel, expected 0..3: %s" % chn
        self.cmn_version = cmn_version
        self.up = up
        self.chn = chn
        self.wps = {}        # {0,1,2} -> MatchMask object
        self.name = name
        if mask is not None and not mask.is_open():
            assert grp is not None
            self.wps[grp] = mask
        if matches is not None:
            apply_matches_to_watchpoint(self, **matches)

    def set(self, grp, val, pos, bits=1, exclusive=False, field=None):
        """
        Set a field in a watchpoint to a given value.
        The field is specified by group and position, i.e. the caller has
        already resolved the field name, and selected a group out of possibly
        several that could apply.
        """
        assert grp in [0, 1, 2]     # currently CMN has up to 3 watchpoint groups
        assert bits >= 1
        assert pos+bits <= 64
        if grp not in self.wps:
            if len(self.wps) == 2:
                raise WatchpointBadValue(val, "too many groups needed", field, self.chn)
            m = MatchMask(grp, exclusive=exclusive)
            self.wps[grp] = m
        else:
            m = self.wps[grp]
        m.set(val, pos, bits)
        if m.is_open():
            # group might be or have become open, e.g. "--field=0bxxxxx"
            del self.wps[grp]

    def grps(self):
        """
        Return the list of watchpoint register groups, drawn from 0, 1 or 2.
        The list might be empty, if the watchpoint is unrestricted.
        """
        return sorted(self.wps.keys())

    def finalize(self):
        """
        If the watchpoint is unrestricted, add an open filter on group 0,
        so that we have something to program the CMN with.
        """
        if not self.wps:
            self.wps[0] = MatchMask(0)

    def is_multigrp(self):
        """
        Return true if this watchpoint needs two (linked) value/mask pairs,
        each programmed to a different group. (CMN does not support matching
        all three groups at the same time.)
        """
        return len(self.wps.keys()) > 1

    def match_mask(self):
        """
        Return the single MatchMask object for this watchpoint.
        """
        assert not self.is_multigrp()
        if not self.wps:
            return MatchMask(0)
        return self.wps[self.grps()[0]]

    def perf_event_fields(self, fields=None, combine=None):
        """
        Return a list (often a singleton) of perf event field strings, configured for
        the current watchpoint. The caller will generally need to add wp_dev_sel
        and can also add nodeid to select the XP: use the 'fields' argument for this.
        """
        assert fields is None or isinstance(fields, str)
        wspec = "wp_chn_sel=%u" % self.chn
        if self.up is not None:
            wspec = ("watchpoint_%s," % ["down", "up"][self.up]) + wspec
        if fields is not None:
            wspec += "," + fields
        if not self.wps:
            # There are no match constraints on CHI fields, but the kernel PMU
            # requires us to specify a value and mask, so create an open match
            # on group 0.
            mmnul = MatchMask(0)
            wspec += "," + str(mmnul)
            return [wspec]
        if self.is_multigrp():
            if not combine:
                combine = alloc_combine()
            wspec += ",wp_combine=%u" % combine
        return [("%s," % (wspec)) + str(self.wps[grp]) for grp in self.grps()]

    def perf_events(self, fields=None, combine=None, cmn_instance=None, name=None, nodeid=None, dev=None, allow_incomplete=False):
        """
        Return a list of complete perf event specifiers, for the current watchpoint:
          "arm_cmn/watchpoint_up,.../","arm_cmn/watchpoint_up,.../"
        """
        assert fields is None or isinstance(fields, str)
        if not allow_incomplete:
            if self.up is None:
                raise WatchpointNoDirection(self)
        pmu = "arm_cmn"
        if cmn_instance is not None:
            pmu += "_" + str(cmn_instance)
        if name is None:
            name = self.name
        if name is not None or nodeid is not None or dev is not None:
            if fields is None:
                fields = ""
        if nodeid is not None:
            fields += ",nodeid=0x%x,bynodeid=1" % nodeid
        if dev is not None:
            fields += ",wp_dev_sel=%u" % dev
        if name is not None:
            fields += ',name="%s"' % _perf_sanitize_name(name)
        if fields is not None and fields.startswith(","):
            fields = fields[1:]
        return [(pmu + "/" + s + "/") for s in self.perf_event_fields(fields=fields, combine=combine)]

    def perf_event_string(self, fields=None, combine=None, cmn_instance=None, name=None, nodeid=None, dev=None, allow_incomplete=False):
        """
        Return a single string containing one, or possibly two, perf events
        in the format needed for the Linux perf tool.
        If two events are used, they are grouped with braces to ensure simultaneous scheduling.
        """
        es = self.perf_events(fields=fields, combine=combine, cmn_instance=cmn_instance, name=name,
                              nodeid=nodeid, dev=dev, allow_incomplete=allow_incomplete)
        s = ",".join(es)
        if len(es) > 1:
            s = "{" + s + "}"
        return s

    def __str__(self):
        """
        To describe the Watchpoint, generate a string similar to perf events -
        but without throwing an exception if incomplete.
        """
        return self.perf_event_string(allow_incomplete=True)

    def __repr__(self):
        return "Watchpoint(%s)" % str(self)


class _CKeys:
    pass


def _dict_to_object(kwds):
    o = _CKeys()
    for (f, v) in kwds.items():
        setattr(o, f, v)
    return o


def _object_to_dict(obj, fields):
    """
    Given an object (e.g. a class of some kind) and a list of field names,
    return a dictionary mapping field names that occur as attributes,
    to their corresponding values.
      e.g. x.a==1, x.b==2, return {"a":1, "b":2}
    Used for retrieving CHI fields from an argparse.Namespace object.
    """
    flds = {}
    for f in fields:
        v = getattr(obj, f)
        if v is not None:
            flds[f] = v
    return flds


"""
Documentation in the TRMs, from "REQ channel: primary match group" onwards
   CMN-600: 5.1, tables 5-1 on
   CMN-650: 7.1, tables 7-1 on
   CMN-700: 6.1, tables 6-1 on

Some fields may exist in multple match groups, while others only exist
in one. This gives us some flexibility in how we allocate fields.

CMN-650, CMN-700 and CI-700 appear to be the same.

For each field we define:
  (lookup, [CMN-600 positions], [CMN-650/700 positions], (optional: CMN-S3 positions))
"""

_resperr = ["OK", "EXOK", "DERR", "NDERR"]

_req_fields = {
    "tracetag":   (None,   [(0, 54, 1), (1, 59, 1)],  [(1, 63, 1)]),
    "srcid":      (None,   [(0, 0, 11)],  [(0, 0, 11), (2, 0, 11)]),
    "tgtid":      (None,   [(0, 0, 11)],  [(0, 0, 11), (2, 0, 11)]),
    "returnnid":  (None,   [(0, 11, 11)], [(0, 11, 11)]),
    "endian":     (None,   [(0, 22, 1)],  [(0, 22, 1)]),     # overlays wth stashnidvalid/deep
    "opcode":     (chi_spec.opcodes_REQ, [(0, 31, 6)],  [(0, 29, 7), (2, 11, 7)]),
    "size":       (None,   [(0, 37, 3)],  [(0, 36, 3)]),
    "ns":         (chi_spec.NS,   [(0, 40, 1)],  [(0, 39, 1)]),
    "allowretry": (None,   [(0, 41, 1)],  [(0, 40, 1)]),
    "order":      (None,   [(0, 43, 2)],  [(0, 41, 2)]),
    "pcrdtype":   (None,   [(0, 44, 4)],  [(0, 43, 4)]),
    "lpid":       (None,   [(0, 48, 5)],  [(0, 47, 5)]),
    "groupidext": (None,   None,          [(0, 52, 3)]),
    "expcompack": (None,   None,          [(0, 55, 1)]),
    "rsvdc":      (None,   [(0, 55, 8)],  [(0, 56, 8)]),
    "qos":        (None,   [(1, 0, 4)],   [(1, 0, 4)]),
    "addr":       (None,   [(1, 4, 48)],  [(1, 4, 52)]),
    "mpam":       (None,   None,          [(2, 18, 11)]),
    "likelyshared": (None, [(1, 52, 1)],  [(1, 56, 1)]),
    "memattr":    (None,   [(1, 53, 4)],  [(1, 57, 4)]),
    "snpattr":    (None,   [(1, 57, 1)],  [(1, 61, 1)]),
    "excl":       (None,   [(1, 58, 1)],  [(1, 62, 1)]),
    "snoopme":    (None,   [(1, 58, 1)],  [(1, 62, 1)]),
    "tagop":      (None,   None,          [(2, 29, 2)]),
}

_rsp_fields = {
    "tracetag":   (None,   [(0, 39, 1)],  [(0, 49, 1)]),
    "qos":        (None,   [(0, 0, 4)],   [(0, 0, 4)]),
    "srcid":      (None,   [(0, 4, 11)],  [(0, 4, 11)]),
    "tgtid":      (None,   [(0, 4, 11)],  [(0, 4, 11)]),
    "opcode":     (chi_spec.opcodes_RSP,   [(0, 15, 4)],  [(0, 15, 5)]),
    "resperr":    (_resperr,   [(0, 19, 2)], [(0, 20, 2)]),
    "resp":       (None,   [(0, 21, 3)],  [(0, 22, 3)]),
    "fwdstate":   (None,   [(0, 24, 3)],  [(0, 25, 3)]),    # SnpRespFwded
    "cbusy":      (None,   None,          [(0, 28, 3)]),
    "dbid":       (None,   [(0, 27, 8)],  [(0, 31, 12)]),
    "pcrdtype":   (None,   [(0, 35, 4)],  [(0, 43, 4)]),
    "devevent":   (None,   [(0, 40, 2)],  [(0, 50, 2)]),
    "tagop":      (None,   None,          [(0, 47, 2)]),
}


def snp_addr(s):
    """
    For convenience, we allow the user to specify a line byte address,
    which we convert to the field value in a SNP packet.
    TBD: For CMN-600, the full SNP address field is split across two match groups -
    we don't handle this yet.
    """
    (v, m) = convert_value(s)
    (v, m) = (v >> 3, m >> 3)
    return unconvert_value_mask(v, m)


assert snp_addr(0x8000) == 0x1000
assert snp_addr("0xxx40") == "0bxxxxxxxx01000"


_snp_fields = {
    "tracetag":   (None,   [(0, 27, 1)],  [(0, 38, 1)]),
    "srcid":      (None,   [(0, 0, 11), (1, 0, 11)],  [(0, 0, 11), (1, 0, 11)]),
    "opcode":     (chi_spec.opcodes_SNP,   [(0, 19, 5)],  [(0, 30, 5)]),
    "ns":         (chi_spec.NS,   [(0, 24, 1), (1, 24, 1)],  [(0, 35, 1)]),
    "donotgotosd":(None,   [(0, 25, 1), (1, 25, 1)],  [(0, 36, 1)]),
    "rettosrc":   (None,   [(0, 26, 1), (1, 26, 1)],  [(0, 37, 1)]),
    "addr":       (snp_addr,   [(0, 28, 36)], [(1, 11, 49)]),
    "addr13":     (None,   [(1, 32, 32)],  None),
    "mpam":       (None,   None,          [(0, 43, 11)]),
    "qos":        (None,   None,          [(0, 39, 4)]),
}

_resp_DAT = ["I", "SC", "UC", None, None, None, "UD_PD", "SD_PD"]

_dat_fields = {
    "tracetag":   (None,   [(0, 49, 1)],  [(1, 44, 1)]),
    "qos":        (None,   [(0, 0, 4)],   [(0, 0, 4)]),
    "srcid":      (None,   [(0, 4, 11)],  [(0, 4, 11), (1, 0, 11)]),
    "tgtid":      (None,   [(0, 4, 11)],  [(0, 4, 11), (1, 0, 11)]),
    "homenid":    (None,   [(0, 15, 11)], [(0, 15, 11)]),
    "opcode":     (chi_spec.opcodes_DAT,   [(0, 26, 3)],  [(0, 26, 4), (1, 11, 4)]),
    "resperr":    (_resperr,    [(0, 29, 2)],  [(0, 30, 2), (1, 15, 2)]),
    "resp":       (_resp_DAT,   [(0, 31, 3)],  [(0, 32, 3), (1, 17, 2)]),
    "fwdstate":   (None,   [(0, 34, 3)],  [(0, 35, 4)]),     # SnpRespDataFwded
    "datasrc":    (None,   [(0, 34, 3)],  [(0, 35, 4)]),     # CompData, DataSepResp, SnpRespData, SnpRespDataPtl
    "cbusy":      (None,   None,          [(0, 39, 3)],                [(0, 40, 3)]),
    "dbid":       (None,   [(0, 37, 8)],  [(0, 42, 12), (1, 32, 12)],  [(0, 43, 12), (1, 32, 12)]),
    "ccid":       (None,   [(0, 45, 2)],  [(0, 54, 2)]),
    "dataid":     (None,   [(0, 47, 2)],  [(0, 56, 2)],                [(0, 57, 2)]),
    "poison":     (None,   [(0, 50, 1)],  [(0, 58, 4)],                [(0, 59, 4)]),
    "chunkv":     (None,   [(0, 51, 2)],  [(1, 45, 2)]),
    "devevent":   (None,   [(0, 53, 2)],  [(0, 62, 2), (1, 47, 2)],    [(1, 47, 2)]),
    "cah":        (None,   None,          None,          [(1, 49, 1)]),
    "rsvdc":      (None,   [(0, 55, 8)],  [(1, 49, 8)]),
    "tagop":      (None,   None,          [(1, 20, 2)]),
    "tag":        (None,   None,          [(1, 22, 8)]),
    "tu":         (None,   None,          [(1, 30, 2)]),
}


# Use the product code to index into the field offset list - falling
# back to the lsat entry, if the list isn't long enough.
_field_selector = {
    cmn_base.PART_CMN600: 1,
    cmn_base.PART_CMN650: 2,
    cmn_base.PART_CMN700: 2,
    cmn_base.PART_CI700: 2,
    cmn_base.PART_CMN_S3: 3,
}


# Add DVM fields as sub-fields of the address

# DVM is encoded in the address field of REQ and SNP, regardless of CMN version
# SNP packets don't contain the lower bits of the address. The offsets here
# are relative to the address field in the packet.
# For SNP we also need to match bit 0 of the address field, to select fragment #0,
# which corresponds (mostly) to the REQ packet.
_dvm_fields = [
    ("vavalid",   None,              1, 4,  1, 0),
    ("vmidvalid", None,              1, 5,  2, 0),
    ("asidvalid", None,              1, 6,  3, 0),
    ("sec",       None,              2, 7,  4, 0),
    ("el",        chi_spec.DVM_EL,   2, 9,  6, 0),
    ("type",      chi_spec.DVM_type, 3, 11, 8, 0),
    ("vmid",      None,              8, 14, 11, 0),
    ("asid",      None,              16, 22, 19, 0),
]


def _fixdvmaddr(flds, fbits, off):
    af = flds["addr"]
    rf = []
    for f in list(af)[1:]:
        if f is not None:
            f = [(grp, pos+off, fbits) for (grp, pos, _) in f]
        rf.append(f)
    return rf


_dvm_frag = {}
for (df, dlookup, dbits, reqoff, snpoff, frag) in _dvm_fields:
    if frag == 0:
        # For REQ, some DVM fields are only visible when they are in the first fragment,
        # since in the second, they are in the DAT payload which we can't see.
        _req_fields["dvm"+df] = tuple([dlookup] + _fixdvmaddr(_req_fields, dbits, reqoff))
    _snp_fields["dvm"+df] = tuple([dlookup] + _fixdvmaddr(_snp_fields, dbits, snpoff))
    _dvm_frag["dvm"+df] = frag


# Selecting on DVM SNP fields should normally force fragment #0.
# We might also want to select fragment #0 or #1 explicitly.
_snp_fields["dvmfrag"] = tuple([None] + _fixdvmaddr(_snp_fields, 1, 0))


# Build a consolidated CHI opcodes table that maps opcodes to channel and value.
# CHI architects have indicated that opcode names will remain unique across channels.
_all_opcodes = {}
for (chn, optab) in enumerate(chi_spec.opcodes):
    for (i, op) in enumerate(optab):
        if op[0] == '?':
            continue
        assert op not in _all_opcodes, "unexpected duplicate CHI opcode: %s" % op
        _all_opcodes[op] = (chn, i)


# Fields indexed by CHI channel
_fields = [_req_fields, _rsp_fields, _snp_fields, _dat_fields]

# Consolidated list of CHI fields (including DVM fields).
# Used for e.g. constructing command-line arguments.
chi_fields = list(set([k for flds in _fields for k in flds.keys()]))

_all_fields = chi_fields + ["exclusive"]


def match_obj(o, chn=0, up=None, mask=None, cmn_version=None):
    """
    Create a watchpoint for the specified channel, direction and field values.
    """
    wp = Watchpoint(chn=chn, up=up, cmn_version=cmn_version)
    if mask is not None and not mask.is_open():
        wp.wps[0] = mask     # allow caller to set up the primary mask directly
    return apply_matches_obj_to_watchpoint(wp, o)


def fix_matches_obj_for_dvm(chn, o):
    """
    If there are any DVM fields, force the opcode and SNP fragment selector
    """
    opcode = [0x14, None, 0x0D, None][chn]
    for dvmf in _fields[chn].keys():
        if dvmf.startswith("dvm") and getattr(o, dvmf, None) is not None:
            # Force opcode
            cur_op = getattr(o, "opcode", None)
            if cur_op is None:
                o.opcode = opcode
            elif cur_op != opcode:
                #raise WatchpointBadValue(cur_op, "opcode not compatible with DVM field")
                # caller might have specified opcode as string, hex code etc.
                # only want to complain if it doesn't resolve to the right code. TBD.
                pass
            if chn == SNP and dvmf != "dvmfrag":
                # apply the fragment selector
                frag = _dvm_frag[dvmf]
                o.dvmfrag = frag


def apply_matches_obj_to_watchpoint(wp, o):
    """
    Set fields in the match group(s).
    The fields are specified as a class object (not a map).
    The channel and direction have already been specified.

    Placement of fields in match groups is specified in the
    CMN TRMs. Placement differs between CMN products.

    Some fields are present in more than one match group, so we
    go through all the fields to try to get an allocation to just
    one group, before we resort to using multiple groups.
    """
    assert wp.chn is not None, "channel (REQ/RSP/SNP/DAT) must be specified"
    exclusive = getattr(o, "exclusive", None)
    fields = _fields[wp.chn]
    # Index of this CMN's field positions in the tuple
    mix = _field_selector[wp.cmn_version.product_id]
    fix_matches_obj_for_dvm(wp.chn, o)
    for phase in [0, 1]:
        for (k, meta) in fields.items():
            val = getattr(o, k, None)
            if val is not None:
                if o_verbose:
                    print("  setting chn=%u %s = %s" % (wp.chn, k, val), file=sys.stderr)
                if k == "srcid":
                    if wp.up is True:
                        raise WatchpointBadValue(val, "can't specify SRCID on upload", k, wp.chn)
                    wp.up = False     # srcid specified, force watchpoint to "down"
                if k == "tgtid":
                    if wp.up is False:    # n.b. not None
                        raise WatchpointBadValue(val, "can't specify TGTID on download", k, wp.chn)
                    wp.up = True      # tgtid specified, force watchpoint to "up"
                # Currently, CMN-S3 is almost always the same as CMN-700, so we allow most
                # fields to not bother with a separate CMN-S3 configuration.
                eff_mix = min(mix, len(meta)-1)
                if meta[eff_mix] is None:
                    raise WatchpointBadValue(val, ("field not supported in this product (%s)" % wp.cmn_version), k, wp.chn)
                # Get the value-parsing function, so we can do e.g. "resp=UC"
                # Each channel has its own opcode lookup function.
                lookup = meta[0]
                if lookup is not None:
                    # The lookup function may be a table, or a callable.
                    if callable(lookup):
                        val = lookup(val)
                    elif val in lookup:
                        val = lookup.index(val)
                    elif wp.chn == 0 and val == "AtomicStore":
                        val = "0b101xxx"     # 0x28 to 0x2f
                    elif wp.chn == 0 and val == "AtomicLoad":
                        val = "0b110xxx"     # 0x30 to 0x37
                try:
                    _ = convert_value(val)
                except WatchpointBadValue as e:
                    if k == "opcode" and val in _all_opcodes:
                        op_chn = _all_opcodes[val][0]
                        e.reason = "opcode is for %s" % (_chi_channels[op_chn])
                    raise WatchpointBadValue(val, e.reason, k, wp.chn)
                # First do fields that only have one possible group
                try:
                    poses = meta[eff_mix]
                    if phase == 0 and len(poses) == 1:
                        # Only one possible group for this field
                        (grp, pos, width) = poses[0]
                        wp.set(grp, val, pos, width, exclusive=exclusive, field=k)
                    elif phase == 1 and len(poses) > 1:
                        # prefer a group that is already in use
                        done = False
                        for (grp, pos, width) in poses:
                            if grp in wp.wps:
                                wp.set(grp, val, pos, width, exclusive=exclusive, field=k)
                                done = True
                                break
                        if not done:
                            (grp, pos, width) = poses[0]
                            wp.set(grp, val, pos, width, exclusive=exclusive, field=k)
                except WatchpointBadValue as e:
                    raise WatchpointBadValue(val, e.reason, k, wp.chn)
    """
    Check whether the user specified any CHI fields inappropriate for the channel.
    The user might have passed in an argparse.Namespace object so there may be
    extraneous keywords, so we only check for the ones that are valid CHI fields.
    """
    for k in [k for k in dir(o) if k in _all_fields]:
        if getattr(o, k, None) is not None and k not in fields and k != "exclusive":
            raise WatchpointBadValue(getattr(o, k), "field not valid for this channel", k, wp.chn)
    return wp


def apply_matches_to_watchpoint(wp, **kwds):
    return apply_matches_obj_to_watchpoint(wp, _dict_to_object(kwds))


def match_kwd(chn=0, up=None, cmn_version=None, **kwds):
    return match_obj(_dict_to_object(kwds), chn=chn, up=up, cmn_version=cmn_version)


def _field_spec(s):
    """
    Fields can be specified as bit wildcards (Verilog-style).
    For now, just accept strings and then convert values later.
    """
    return s


def list_fields(cmn_version):
    """
    List all CHI fields that can be matched.
    """
    mix = _field_selector[cmn_version.product_id]
    for (chn, cf) in zip(_chi_channels, _fields):
        print("%s fields:" % chn)
        for (f, meta) in cf.items():
            eff_mix = min(mix, len(meta)-1)
            poses = meta[eff_mix]
            if poses is None and not o_verbose:
                continue
            print("%12s " % f, end="")
            if poses is None:
                print("- n/a", end="")
            else:
                nbits = poses[0][2]
                groups = ''.join([str(g) for (g, _, _) in poses])
                print("%2u bits  grp %-4s" % (nbits, groups), end="")
            # Print any enumerator for this CHI field
            keys = meta[0]
            if keys is not None and not o_verbose:
                keys = [k for k in keys if k is not None]
                print(', '.join(keys[:5]), end="")
                if len(keys) > 5:
                    print("...", end="")
            print()
            if keys is not None and poses is not None and o_verbose:
                for (i, k) in enumerate(keys):
                    if k is not None and not k.startswith("?") and i < (1 << nbits):
                        print("            %s (%u)" % (k, i))


def parse_short_watchpoint(ws, opts, cmn_version=None):
    """
    Parse a short-form watchpoint specifier into a Watchpoint object, e.g.

       up:req:opcode=Evict:memattr=0bxx0x

    'opts' supplies defaults as set on the command line.
    """
    try:
        (wdir, chn, spec) = ws.split(':', 2)
    except ValueError:
        try:
            (wdir, chn) = ws.split(':')
            spec = ""
        except ValueError:
            raise WatchpointBadShort(ws, "expected <dir>:<channel>:<fields>")
    up = ["down", "up"].index(wdir.lower())
    if up < 0:
        raise WatchpointBadShort(ws, "expected channel up/down")
    chn = ["req", "rsp", "snp", "dat"].index(chn.lower())
    if chn < 0:
        raise WatchpointBadShort(ws, "expected channel REQ/RSP/SNP/DAT")
    flds = {}
    if spec.startswith("not:"):
        flds["exclusive"] = True
        spec = spec[4:]
    for f in spec.split(':'):
        if f:
            try:
                (k, v) = f.split('=', 1)
            except ValueError:
                raise WatchpointBadShort(ws, "expected field=value: '%s'" % f)
            if k not in chi_fields:
                raise WatchpointBadShort(ws, "'%s' is not a CHI field" % k)
            flds[k] = v
    for k in chi_fields:
        if getattr(opts, k, None) is not None and k not in flds:
            flds[k] = getattr(opts, k)
    wp = match_kwd(chn=chn, up=up, cmn_version=cmn_version, **flds)
    return wp


def add_chi_arguments(parser):
    """
    Given an existing ArgumentParser object, add command-line arguments
    to allow the user to specify various CHI fields for matching,
    as command-line arguments.

    The default is None, meaning allow any value.

    Note: for single-bit fields like tracetag, we could define these as
    "store_true" options. But we don't want to imply a value of False if the
    option is not specified. Requiring an explicit value specification makes
    it clearer that a specific value (0 or 1) must be matched.
    """
    group = parser.add_argument_group("CHI fields")
    for f in chi_fields:
        group.add_argument("--" + f, type=_field_spec, help="match CHI field %s" % f.upper())
    group.add_argument("--exclusive", action="store_true")


if __name__ == "__main__":
    def _hexint(s):
        return int(s, 16)
    def arg_cmn_version(s):
        try:
            v = cmn_base.cmn_version(s)
            assert isinstance(v, cmn_base.CMNConfig)
        except KeyError:
            raise argparse.ArgumentTypeError("invalid CMN product identifier")
        return v
    def arg_chi_channel(s):
        if s in ["0", "1", "2", "3"]:
            return int(s)
        s = s.upper()
        if s in _chi_channels:
            return _chi_channels.index(s)
        raise argparse.ArgumentTypeError("invalid CHI channel specifier")
    import argparse
    import os
    parser = argparse.ArgumentParser(description="CMN flit matching")
    parser.add_argument("--chn", type=arg_chi_channel, default=0, help="CHI channel (REQ/RSP/SNP/DAT)")
    parser.add_argument("--REQ", action="store_const", const=0, dest="chn", help="REQ channel")
    parser.add_argument("--RSP", action="store_const", const=1, dest="chn", help="RSP channel")
    parser.add_argument("--SNP", action="store_const", const=2, dest="chn", help="SNP channel")
    parser.add_argument("--DAT", action="store_const", const=3, dest="chn", help="DAT channel")
    add_chi_arguments(parser)
    parser.add_argument("--upload", dest="up", action="store_true", default=None, help="watchpoint is upload (default download)")
    parser.add_argument("--download", dest="up", action="store_false", default=None, help="watchpoint is download")
    parser.add_argument("--dev", type=int, default=None, help="device")
    parser.add_argument("--nodeid", type=_hexint, help="XP node id")
    parser.add_argument("--at-cpu", type=int, help="CPU number")
    parser.add_argument("--cmn-instance", type=int, help="CMN instance")
    parser.add_argument("--stat", action="store_true", help="run 'perf stat' with these watchpoints")
    parser.add_argument("--sleep", type=float, default=0.5, help="sleep time for perf stat")
    parser.add_argument("--cmn-json", type=str, help="CMN JSON description")
    parser.add_argument("--cmn-version", type=arg_cmn_version, help="CMN version")
    parser.add_argument("--no-name", action="store_true", help="don't use readable names for events")
    parser.add_argument("--list", action="store_true", help="list possible fields")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("wps", type=str, nargs="*", help="watchpoint specifiers")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    S = None
    cpu = None
    if opts.cmn_version is not None:
        cmn_version = opts.cmn_version
    else:
        try:
            S = cmn_json.system_from_json_file(fn=opts.cmn_json)
            cmn_version = S.cmn_version()
            assert cmn_version is not None
        except Exception:
            print("cannot discover CMN product version: run discovery tools", file=sys.stderr)
            sys.exit(1)
    assert isinstance(cmn_version, cmn_base.CMNConfig)
    if opts.verbose:
        print("CMN version: %s" % cmn_version, file=sys.stderr)
    if opts.list:
        list_fields(cmn_version)
        sys.exit()
    if opts.at_cpu is not None:
        if S is None:
            S = cmn_json.system_from_json_file(fn=opts.cmn_json)
        cpu = S.cpu(opts.at_cpu)
        if opts.verbose:
            print("CPU: %s" % cpu, file=sys.stderr)
        assert not opts.nodeid and not opts.dev
        opts.cmn_instance = cpu.port.CMN().seq
        opts.nodeid = cpu.port.xp.node_id()
        opts.dev = cpu.port.port
        opts.lpid = cpu.lpid
    events = []
    def wp_events(wp, opts, name=None):
        es = []
        if opts.dev is not None:
            devs = [opts.dev]
        else:
            # On CMN-600, Linux driver won't catch wp_dev_sel=2 and will select device 0
            devs = [0, 1, 2, 3] if cmn_version.product_id >= cmn_base.PART_CMN650 else [0, 1]
        if opts.no_name:
            name = None
        for d in devs:
            if name is not None:
                dname = "%s.%u" % (name, d)
            else:
                dname = None
            es.append(wp.perf_event_string(cmn_instance=opts.cmn_instance, nodeid=opts.nodeid, dev=d, name=dname))
        return es
    if opts.wps:
        # Command line specified one or more "short" watchpoint specifiers
        for ws in opts.wps:
            try:
                wp = parse_short_watchpoint(ws, opts, cmn_version=cmn_version)
                events += wp_events(wp, opts, name=ws)
            except WatchpointError as wbv:
                print("** Bad value: %s" % wbv, file=sys.stderr)
                sys.exit(1)
    else:
        # Construct a watchpoint from whatever fields were on the command line
        flds = _object_to_dict(opts, _all_fields)
        try:
            wp = match_kwd(chn=opts.chn, up=opts.up, cmn_version=cmn_version, **flds)
            events += wp_events(wp, opts)
        except WatchpointError as wbv:
            print("** Bad value: %s" % wbv, file=sys.stderr)
            sys.exit(1)
        if o_verbose:
            print("Watchpoint: %s" % wp)
    if not events:
        print("no perf events!")
        sys.exit(1)
    # Print the events as a bare string, so "perf stat -e `...`" can use it
    if opts.verbose:
        print("events:", file=sys.stderr)
        for e in events:
            print("  %s" % (e), file=sys.stderr)
    print(','.join(events))
    if opts.stat:
        cmd = "perf stat "
        for e in events:
            cmd += " -e %s" % e
        cmd += " -- sleep %f" % opts.sleep
        if opts.verbose:
            print(">>> %s" % (cmd), file=sys.stderr)
        rc = os.system(cmd)
        if rc != 0:
            print("<<< rc=%d" % rc, file=sys.stderr)
    if False:
        m = match_obj(opts, chn=opts.chn, up=opts.up, cmn_version=cmn_version)
        print("Watchpoint: %s" % (m))
