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

Compiled watchpoints can also be inspected without accessing hardware.
wp.field_definitions() gives the field layouts and decoders for its product
and channel. wp.field_match_masks("opcode") gives field-sized MatchMask copies
from its configured groups, with value and mask normalized to bit zero.
The copies retain their group number and the original group's exclusive flag.

The mapping of fields to masks depends on product version (600, 700 etc.)
and may also depend on product configuration (e.g. MPAM enabled).

This script is designed as a module, but can also be used as a
command-line tool to construct a watchpoint expression for "perf".
"""

from __future__ import print_function

import sys

try:
    basestring
except NameError:
    basestring = str

import chi_spec
import cmn_base
import cmn_config
import cmn_json
import cmn_wp_fields
import value_mask


o_verbose = 0

o_default_to_up = False      # Watchpoints default to 'up' if not specified


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


class WatchpointValueOutOfRange(WatchpointBadValue):
    def __init__(self, val, reason, field=None, chn=None):
        WatchpointBadValue.__init__(self, val, reason, field=field, chn=chn)


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
    Convert a value specifier to a value_mask.ValueMask object.

    This compatibility wrapper preserves cmnwatch's WatchpointBadValue error
    type while the shared parser in value_mask raises ValueError.
    """
    try:
        return value_mask.convert_value(v)
    except ValueError as e:
        raise WatchpointBadValue(v, str(e))


def unconvert_value_mask(v, m):
    """
    Convert a value/don't-care mask pair back to an integer or wildcard string.
    """
    return value_mask.unconvert_value_mask(v, m)


assert convert_value(123).as_tuple() == (123, 0)
assert convert_value("123").as_tuple() == (123, 0)
assert convert_value("0x123").as_tuple() == (0x123, 0)
assert convert_value("0bx1xx").as_tuple() == (4, 0b1011)

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
            (val, dontcare) = convert_value(val).as_tuple()
            if val >= (1 << bits):
                raise WatchpointValueOutOfRange(val, ("value out of range for %u-bit field" % bits))
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
        if not isinstance(cmn_version, cmn_config.CMNConfig):
            raise TypeError("watchpoint requires a CMNConfig")
        if isinstance(chn, basestring):
            try:
                chn = _chi_channels.index(chn.upper())
            except ValueError:
                raise WatchpointError("unknown CHI channel: %s" % chn)
        cmn_config.check_integer(chn, "CHI channel", maximum=3)
        if up is not None:
            if not isinstance(up, cmn_config.integer_types) or up not in [0, 1]:
                raise WatchpointError("watchpoint direction must be True, False or None")
            up = bool(up)
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

    def field_definitions(self):
        """Return CHI field metadata resolved for this product and channel.

        Each entry contains ``positions`` (group, bit offset, width tuples)
        and ``lookup`` (an optional value decoder). Known fields unavailable
        on this product have an empty positions list. Treat the metadata as
        read-only; no watchpoint groups are created by this query.
        """
        return cmn_wp_fields.fields_for_product(self.cmn_version, self.chn)

    def field_match_masks(self, field):
        """Return field-sized MatchMask copies from the configured groups.

        Values and masks are shifted to bit zero and limited to the field's
        width. Each copy retains its group number and exclusive flag. A mask
        bit of one means don't-care, as in the full group. A configured group
        may contain the field without constraining it, yielding an open mask.
        Missing groups and fields unavailable on this product yield no entry.

        These are inspection results, not complete programmable groups:
        exclusive negates the entire original group, including other fields.
        Changing the copies does not change this watchpoint, and this query
        does not finalize an unrestricted watchpoint. Unknown fields or fields
        invalid for this channel raise WatchpointBadValue.
        """
        if not isinstance(field, basestring):
            raise TypeError("watchpoint field name must be a string")
        definitions = self.field_definitions()
        if field not in definitions:
            reason = "field not valid for this channel" if field in chi_fields else "unknown CHI field"
            raise WatchpointBadValue(None, reason, field, self.chn)
        matches = []
        for grp, pos, width in sorted(field_positions(definitions[field])):
            match = self.wps.get(grp)
            if match is not None:
                bits = (1 << width) - 1
                matches.append(MatchMask(grp, val=(match.val >> pos) & bits,
                                         mask=(match.mask >> pos) & bits,
                                         exclusive=match.exclusive, n_bits=width))
        return matches

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

    def grps(self, allow_empty=False):
        """
        Return the list of watchpoint register groups, drawn from 0, 1 or 2.
        The list might currently be empty, if the watchpoint is unrestricted.
        In general we're looking for at least one match group to program into
        the DTM WP registers, so ensure an open watchpoint unless allow_empty=True.
        """
        if not self.wps and not allow_empty:
            self.finalize()
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


def chi_fields_from_options(opts):
    """
    Extract explicitly supplied CHI fields and exclusive from CLI options.
    Other options control the tool, not the match. Do not use this filtering
    step on field dictionaries: the matcher must reject unknown names there.
    """
    flds = {}
    for f in _all_fields:
        v = getattr(opts, f, None)
        if v is not None:
            flds[f] = v
    return flds


"""
Documentation in the TRMs, from "REQ channel: primary match group" onwards:
   CMN-600: 5.1, tables 5-1 on
   CMN-650: 7.1, tables 7-1 on
   CMN-700: 6.1, tables 6-1 on
   CMN S3 r0: 5.1, tables 5-1 on
   CMN S3 r2: 6.1, tables 6-1 on

Watchpoint field layout tables live in cmn_wp_fields. Some fields may exist
in multiple match groups, while others only exist in one. This gives us some
flexibility in how we allocate fields.
"""


# Build a consolidated CHI opcodes table that maps opcodes to channel and value.
# CHI architects have indicated that opcode names will remain unique across channels.
_all_opcodes = {}
for (chn, optab) in enumerate(chi_spec.opcodes):
    for (i, op) in enumerate(optab):
        if op[0] == '?':
            continue
        assert op not in _all_opcodes, "unexpected duplicate CHI opcode: %s" % op
        _all_opcodes[op] = (chn, i)


# Fields indexed by CHI channel. Kept as a compatibility view for callers
# that inspect cmnwatch metadata directly.
_fields = cmn_wp_fields.all_fields_by_channel()

# Consolidated list of CHI fields (including DVM fields).
# Used for e.g. constructing command-line arguments.
chi_fields = cmn_wp_fields.chi_field_names()

_all_fields = chi_fields + ["exclusive"]


def field_positions(meta, product_key=None):
    """
    Return watchpoint bit positions from a field metadata dictionary.

    "meta" is a small dictionary created by cmn_wp_fields. It carries either
    resolved "positions" for one selected product or a compatibility
    "positions_by_product" map. The product_key argument selects an entry from
    that compatibility map. It can be omitted for resolved metadata.
    """
    return cmn_wp_fields.field_positions(meta, product_key)


def field_decoder(meta):
    """
    Return the optional value decoder from a field metadata dictionary.

    Decoders are shared across products. A decoder may be an enum table or a
    callable; None means the field value is parsed as a raw integer/wildcard.
    """
    return cmn_wp_fields.field_decoder(meta)


def match_fields(matches, chn=0, up=None, mask=None, cmn_version=None):
    """
    Create a watchpoint from a dictionary of CHI fields and exclusive.
    Unknown names are errors, even when their value is None. CLI callers
    should first extract match fields with chi_fields_from_options().
    """
    wp = Watchpoint(chn=chn, up=up, cmn_version=cmn_version)
    if mask is not None and not mask.is_open():
        wp.wps[0] = mask     # allow caller to set up the primary mask directly
    return _apply_match_fields(wp, matches)


def _fix_matches_for_dvm(chn, matches, fields):
    """
    If there are any DVM fields, force the opcode and SNP fragment selector
    """
    opcode = [0x14, None, 0x0D, None][chn]
    for dvmf in fields:
        if dvmf.startswith("dvm") and matches.get(dvmf) is not None:
            # Force opcode
            cur_op = matches.get("opcode")
            if cur_op is None:
                matches["opcode"] = opcode
            elif cur_op != opcode:
                #raise WatchpointBadValue(cur_op, "opcode not compatible with DVM field")
                # caller might have specified opcode as string, hex code etc.
                # only want to complain if it doesn't resolve to the right code. TBD.
                pass
            if chn == SNP and dvmf != "dvmfrag":
                # apply the fragment selector
                frag = cmn_wp_fields.dvm_fragment(dvmf)
                matches["dvmfrag"] = frag


def _apply_match_fields(wp, matches):
    """
    Set fields in the match group(s).
    The fields are specified in a dictionary, copied before DVM defaults
    are added so that caller-owned fields are not modified.
    The channel and direction have already been specified.

    Placement of fields in match groups is specified in the
    CMN TRMs. Placement differs between CMN products.

    Some fields are present in more than one match group, so we
    go through all the fields to try to get an allocation to just
    one group, before we resort to using multiple groups.
    """
    if not isinstance(matches, dict):
        raise TypeError("watchpoint fields must be a dictionary")
    fields = wp.field_definitions()
    # Validate every supplied name before setting any match bits. In
    # particular, opocde="ReadShared" must not become an open match just
    # because only known field names are visited during allocation below.
    for (k, val) in matches.items():
        if k not in _all_fields:
            raise WatchpointBadValue(val, "unknown CHI field", k, wp.chn)
        if val is None or k == "exclusive":
            continue
        if k not in fields:
            raise WatchpointBadValue(val, "field not valid for this channel", k, wp.chn)
        if not field_positions(fields[k]):
            raise WatchpointBadValue(val, "field not supported in this product (%s)" % wp.cmn_version, k, wp.chn)
    matches = dict(matches)
    exclusive = matches.get("exclusive")
    _fix_matches_for_dvm(wp.chn, matches, fields)
    for phase in [0, 1]:
        for (k, meta) in fields.items():
            val = matches.get(k)
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
                poses = field_positions(meta)
                if not poses:
                    raise WatchpointBadValue(val, ("field not supported in this product (%s)" % wp.cmn_version), k, wp.chn)
                # Get the value-parsing function, so we can do e.g. "resp=UC".
                lookup = field_decoder(meta)
                if lookup is not None:
                    # The lookup function may be a table, or a callable.
                    if callable(lookup):
                        try:
                            val = lookup(val)
                        except ValueError as e:
                            raise WatchpointBadValue(val, str(e), k, wp.chn)
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
                    raise type(e)(val, e.reason, k, wp.chn)
    return wp


def apply_matches_to_watchpoint(wp, **kwds):
    """
    Apply validated keyword fields to an existing watchpoint.
    """
    return _apply_match_fields(wp, kwds)


def match_kwd(chn=0, up=None, cmn_version=None, **kwds):
    """
    Create a watchpoint from validated keyword fields.
    """
    return match_fields(kwds, chn=chn, up=up, cmn_version=cmn_version)


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
    product_key = cmn_wp_fields.product_key_for_config(cmn_version)
    for (chn, cf) in zip(_chi_channels, _fields):
        print()
        print("%s fields:" % chn)
        for (f, meta) in cf.items():
            poses = field_positions(meta, product_key)
            if not poses and not o_verbose:
                # For this product, this field is not present or not observable
                continue
            print("%12s " % f, end="")
            if not poses:
                print("- n/a", end="")
            else:
                nbits = poses[0][2]
                groups = ''.join([str(g) for (g, _, _) in poses])
                print("%2u bits  grp %-4s" % (nbits, groups), end="")
            # Print any enumerator for this CHI field
            keys = field_decoder(meta)
            if keys is not None and not o_verbose:
                if callable(keys):
                    print("(special)", end="")
                else:
                    keys = [k for k in keys if k is not None]
                    print(', '.join(keys[:5]), end="")
                    if len(keys) > 5:
                        print("...", end="")
            print()
            if o_verbose:
                # print individual positions
                for (grp, pos, nbits) in poses:
                    print("%s.%s: group %u: width %u, bit range %u:%u" % (chn, f, grp, nbits, pos+nbits-1, pos))
            if keys is not None and poses is not None and o_verbose:
                if callable(keys):
                    print("        (special)")
                else:
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
    up = {"down": 0, "up": 1, "both": None}.get(wdir.lower(), -1)
    if up == -1:
        raise WatchpointBadShort(ws, "expected channel up/down")
    try:
        chn = ["req", "rsp", "snp", "dat"].index(chn.lower())
    except ValueError:
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
    for (k, v) in chi_fields_from_options(opts).items():
        if k not in flds:
            flds[k] = v
    wp = match_fields(flds, chn=chn, up=up, cmn_version=cmn_version)
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


def main(argv):
    global argparse, o_verbose
    def _hexint(s):
        return int(s, 16)
    def arg_cmn_version(s):
        try:
            v = cmn_config.cmn_version(s)
            assert isinstance(v, cmn_config.CMNConfig)
        except (KeyError, ValueError):
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
    import subprocess
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
    parser.add_argument("--perf-bin", type=str, default="perf", help="path to perf binary")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("wps", type=str, nargs="*", help="watchpoint specifiers")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    S = None
    cpu = None
    if opts.cmn_version is not None:
        cmn_version = opts.cmn_version
    else:
        try:
            S = cmn_json.load_system_for_cli(fn=opts.cmn_json)
            cmn_version = S.cmn_version()
            assert cmn_version is not None
        except Exception as e:
            print("cannot discover CMN product version (%s): run discovery tools" % e, file=sys.stderr)
            raise
            sys.exit(1)
    assert isinstance(cmn_version, cmn_config.CMNConfig)
    if opts.verbose:
        print("CMN version: %s" % cmn_version, file=sys.stderr)
    if opts.list:
        list_fields(cmn_version)
        sys.exit()
    if opts.at_cpu is not None:
        if S is None:
            S = cmn_json.load_system_for_cli(fn=opts.cmn_json)
        cpu = S.cpu(opts.at_cpu)
        if opts.verbose:
            print("CPU: %s" % cpu, file=sys.stderr)
        assert not opts.nodeid and not opts.dev
        opts.cmn_instance = cpu.port.CMN().cmn_seq
        opts.nodeid = cpu.port.xp.node_id()
        opts.dev = cpu.port.port_number
        opts.lpid = cpu.lpid
    events = []
    def wp_events(wp, opts, name=None):
        es = []
        if opts.dev is not None:
            devs = [opts.dev]
        else:
            # On CMN-600, Linux driver won't catch wp_dev_sel=2 and will select device 0
            if cmn_version.is_before_gen(cmn_config.CMN_GEN_650):
                n_devs = 2
            elif cmn_version.is_before_gen(cmn_config.CMN_GEN_S3):
                n_devs = 4
            else:
                n_devs = 8
            devs = list(range(n_devs))
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
        flds = chi_fields_from_options(opts)
        if o_default_to_up and opts.up is None:
            opts.up = True
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
        args = [opts.perf_bin, "stat"]
        for e in events:
            args += ["-e", e]
        args += ["--", "sleep", ("%f" % opts.sleep)]
        if opts.verbose:
            print(">>> %s" % (' '.join(args)), file=sys.stderr)
        rc = subprocess.call(args, shell=False)
        if rc != 0:
            print("<<< rc=%d" % rc, file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
