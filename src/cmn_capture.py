#!/usr/bin/python3

"""
CMN flit capture tool

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This tool captures CHI flits using the XP watchpoint FIFOs.

For usage details, see README-capture.md.
"""

from __future__ import print_function

import sys
import time

import cmn_base
import cmn_devmem
import cmn_devmem_find
import cmn_json
from cmn_enum import *
import cmnwatch
import cmn_select
import cmn_flits
from cmn_flits import CMNTraceConfig, CMNFlitGroup, CMNFlitGroupDeduper
import cmn_dtstat


o_verbose = 0

o_include_polling = False

o_decode_raw = False

o_decode_verbose = 0

o_deduplicate = True


class BadCaptureWatchpoint(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "bad capture specifier: %s" % self.msg


def bits(x, p, n):
    return (x >> p) & ((1 << n) - 1)


def hexstr(x):
    s = ""
    # be portable for Python2/3
    for ix in range(len(x)):
        s += ("%02x" % ord(x[ix:ix+1]))
    return s


# TBD: currently limited argument validation, while we're experimenting.
def inthex(s):
    return int(s,16)


def add_trace_arguments(parser, cc_default=False):
    parser.add_argument("--xp", type=inthex, action="append", help="crosspoint number(s)")
    parser.add_argument("--node", type=cmn_select.CMNSelect, action="append", help="node specifier(s)")
    parser.add_argument("--vc", "--chn", type=int, choices=[0,1,2,3], default=0, help="VC channel number: REQ, RSP, SNP, DAT")
    parser.add_argument("--wp-val", type=inthex, default=0, help="watchpoint value")
    parser.add_argument("--wp-mask", type=inthex, default=0xffffffffffffffff, help="watchpoint mask (don't-care bits)")
    cmnwatch.add_chi_arguments(parser)
    parser.add_argument("--uploads", dest="up", action="store_true", default=None, help="capture uploaded flits only")
    parser.add_argument("--downloads", dest="up", action="store_false", default=None, help="capture downloaded flits only")
    parser.add_argument("--cc", action="store_true", default=cc_default, help="enable cycle counts")
    parser.add_argument("--no-cc", dest="cc", action="store_false", help="disable cycle counts")
    parser.add_argument("--cross-trigger", action="store_true", help="generate cross trigger on watchpoint match")
    parser.add_argument("--debug-trigger", action="store_true", help="generate debug trigger on watchpoint match")
    parser.add_argument("--set-tracetag", action="store_true", help="set TraceTag")
    parser.add_argument("--format", type=int, choices=range(8), default=4, help="trace packet format")
    parser.add_argument("--immediate", action="store_true", help="show FIFO contents immediately")
    parser.add_argument("--samples", type=int, default=100, help="number of FIFO samples to collect")
    parser.add_argument("--cg-disable", action="store_true")
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--count", action="store_true", help="program DTM PMU to count packets")
    parser.add_argument("--sleep", type=float, default=0.01, help="wait time for packet collection")
    parser.add_argument("--no-sync", action="store_true", help="when decoding, don't look for sync packet")
    parser.add_argument("--list", action="store_true", help="list CMN nodes")
    parser.add_argument("--check-writes", action="store_true", help="check writes to CMN")
    parser.add_argument("--no-check-writes", action="store_true", help="don't check writes to CMN")
    parser.add_argument("--diag", action="store_true")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("--decode-verbose", type=int, default=0)
    parser.add_argument("watchpoint", type=str, nargs="*", help="short-form watchpoint specifier")


def cmn_desc(cmn_direct):
    """
    Given a direct-access (cmn_devmem) CMN representation, find the matching
    CMN descriptor object if it exists in our cache. The aim here is to be able
    to use the cached CPU mappings along with direct access for programming.
    """
    assert cmn_direct.periphbase, "expect CMN base address to be known: %s" % cmn_direct
    try:
        S = cmn_json.system_from_json_file()
    except Exception:
        return None
    return S.cmn_at_base(cmn_direct.periphbase)


def id_key(cmn_seq, nodeid, lpid):
    return (cmn_seq, nodeid, lpid)


class CMNFlitGroupX(CMNFlitGroup):
    """
    Subclass CMN flit decode to provide more annotation of CHI source and target ids.
    """
    def __init__(self, cfg, cmn_seq=None, nodeid=None, WP=None, DEV=None, VC=None, format=None, cc=0, vis=None):
        assert VC is not None
        assert DEV is not None
        assert format is not None
        assert cmn_seq is not None
        CMNFlitGroup.__init__(self, cfg, cmn_seq=cmn_seq, nodeid=nodeid, WP=WP, DEV=DEV, VC=VC, format=format, cc=cc, debug=o_decode_verbose)
        self.vis = vis
        self.id_map = vis.id_map

    def id_str(self, id, lpid=0):
        """
        Override, to identify nodes, using our discovered node type and CPU identity
        """
        s = CMNFlitGroup.id_str(self, id, lpid=lpid)
        ns = "????"
        ik = id_key(self.cmn_seq, id, lpid)
        if ik in self.id_map:
            ns = self.id_map[ik]
        elif lpid != 0:
            ik = id_key(self.cmn_seq, id, lpid=0)
            if ik in self.id_map:
                # e.g. RN-F where we haven't got CPU mappings for non-zero LPIDs
                ns = self.id_map[ik]
        s += "(%-4s)" % ns[:4]
        return s

    def addr_str(self, addr, NSENS):
        """
        Override default address printing, to identify CMN access itself
        """
        if self.vis.cmn_by_seq[self.cmn_seq].contains_addr(addr):
            return "<CMN:%06x>" % (addr & 0xffffff)
        return CMNFlitGroup.addr_str(self, addr, NSENS)


def xp_node_ids(xp):
    """
    Yield tuples (node_id, desc) for an XP, where all possible CHI ids are yielded,
    together with a suitable descriptive string.

    We have to deal with several cases:
     - CALs which have no device nodes (e.g. CAL for RN-F)
     - HCALs, e.g. HCAL3 is always [RN-F, RN-F, HN-I]
     - CAL-less multiple-device nodes, e.g. CCG where device 1 is an RN-I
     - devices with multiple nodes with the same device id
    """
    for port in xp.ports():
        port_desc = cmn_port_device_type_str(port.device_type())
        for dev in cmn_base.port_devices(port, create=True):
            desc = port_desc
            for n in dev.device_nodes:
                if cmn_node_type_has_properties(n.type(), CMN_PROP_CHI):
                    desc = cmn_node_type_str(n.type())
                    break
            yield (dev.node_id(), desc)


def cmn_node_ids(cmns):
    for cmn in cmns:
        cmn.discover_all_devices()
        for xp in cmn.XPs():
            for (id, desc) in xp_node_ids(xp):
                yield (cmn.cmn_seq, id, desc)


def trace_config_from_cmn_config(config):
    return CMNTraceConfig(config.product_id, has_MPAM=config.mpam_enabled, cmn_product_revision=config.revision_major)


class CMNVis:
    """
    Print CMN trace in a human-readable form, one packet per line, minimizing clutter.
    """
    def __init__(self):
        self.cmns = None
        self.deduper = CMNFlitGroupDeduper()

    def set_cmns(self, cmns):
        self.cmns = cmns
        self.cmn_by_seq = {C.cmn_seq: C for C in cmns}
        self.cfgs = {C.cmn_seq: trace_config_from_cmn_config(C.product_config) for C in cmns}
        self.last_xp = None
        self.build_id_map()

    def build_id_map(self):
        self.id_map = {}     # (cmn_seq, id, lpid) -> label
        for (cmn_seq, id, desc) in cmn_node_ids(self.cmns):
            self.id_map[(cmn_seq, id, 0)] = desc[:4]
        for C in self.cmns:
            cd = cmn_desc(C)
            if cd is not None and cd.has_cpu_mappings():
                for cpu in cd.cpus():
                    self.id_map[(C.cmn_seq, cpu.id, cpu.lpid)] = "#%-3u" % cpu.cpu
        if o_verbose:
            print("ID map:")
            n_on_line = 0
            for k in sorted(self.id_map.keys()):
                (cmn_seq, id, lpid) = k
                s = self.id_map[k]
                if n_on_line == 8:
                    print()
                    n_on_line = 0
                print("  M%u %04x[%u]: %-6s" % (cmn_seq, id, lpid, s), end="")
                n_on_line += 1
            print()

    def handle_flitgroup(self, xp, w, fg):
        """
        Flit group handler for tracing - print it out
        """
        if xp != self.last_xp:
            print("%s:" % xp)
            self.last_xp = xp
        if o_decode_raw:
            print("%s  " % hexstr(fg.payload[::-1]), end="")
        print("  %s WP%u: " % ("<>"[w.up], w.wp), end="")
        print(fg)

    def decode_packet(self, xp, w, data, cc):
        assert isinstance(w, cmn_devmem.DTMWatchpoint)
        assert 0 <= w.wp and w.wp <= 3
        cmn_seq = xp.C.cmn_seq
        fg = CMNFlitGroupX(self.cfgs[cmn_seq], cmn_seq=cmn_seq, nodeid=xp.node_id(), WP=w.wp, DEV=w.dev, VC=w.chn, format=w.type, cc=cc, vis=self)
        fg.decode(data)
        if o_deduplicate and self.deduper.is_duplicate(fg):
            return
        fg.up = w.up
        self.handle_flitgroup(xp, w, fg)


def is_cmn_polling_req(cmn, flit):
    """
    Try to reduce noise in flit capture by detecting flits we generated -
    i.e. that are from this tool polling the XP FIFO registers.
    """
    if flit.group.VC == cmn_flits.REQ and flit.opcode == 0x04 and flit.group.format == 4 and cmn.contains_addr(flit.addr):
        return True
    return False


class CMNHist(CMNVis):
    """
    Histogram to accmulate packet stats
    """
    def __init__(self, direction=False):
        CMNVis.__init__(self)
        self.hist = {}
        self.witness = {}     # a witness flit for each key
        self.n_total = 0
        self.n_discarded_self = 0
        self.direction = direction

    def handle_flitgroup(self, xp, w, fg):
        """
        Override, to accumulate histogram instead of printing
        """
        for flit in fg:
            if (not o_include_polling) and is_cmn_polling_req(xp.C, flit):
                self.n_discarded_self += 1
                continue
            key = self.flit_key(xp, flit)
            if key not in self.hist:
                self.hist[key] = 0
                self.witness[key] = flit
            self.hist[key] += 1
            self.n_total += 1

    def id_key(self, cmn_seq=None, nodeid=None, lpid=0):
        """
        Construct a key to look up a node id - actually, a unique endpoint including
        CMN mesh instance number, and possibly a device LPID.
        """
        return id_key(cmn_seq, nodeid, lpid)

    def flit_key(self, xp, flit):
        """
        Construct a key to classify the flit into a sensible group.
        We use at least the source and target type, the channel, and the opcode.
        """
        cmn_seq = xp.C.cmn_seq
        skey = self.id_key(cmn_seq, flit.srcid, 0)
        if skey not in self.id_map:
            if flit.srcid is not None:
                self.id_map[skey] = "?%03x" % flit.srcid
            else:
                self.id_map[skey] = "-"    # e.g. format-0 tracing - transaction ids only
        stype = self.id_map[skey]
        if stype.startswith("#"):
            stype = "RN-F"    # undo the CPU mapping!
        if flit.tgtid is not None:
            tkey = self.id_key(cmn_seq, flit.tgtid, 0)
            try:
                ttype = self.id_map[tkey]
                if ttype.startswith("#"):
                    ttype = "RN-F"
            except KeyError:
                # Unexpected: a target-id that we didn't know about
                ttype = "?"
        elif flit.group.VC == 2:
            ttype = "-"       # SNP expected to have no tgtid
        else:
            ttype = "?"
        op = flit.opcode_str()
        # For some opcodes, we can additionally differentiate
        if flit.group.VC == 3:
            op += "_" + flit.resp_str()
        elif flit.is_DVM():
            dop = flit.DVM_opcode_str()
            if dop is not None:
                op += "(%s)" % dop
        d = flit.group.up if self.direction else None
        key = (flit.group.VC, op, stype, ttype, d)
        return key

    def flit_key_str(self, flit_key):
        (vc, op, stype, ttype, d) = flit_key
        s = "%-5s %-5s %s %-22s" % (stype, ttype, cmnwatch._chi_channels[vc], op)
        if d is not None:
            s = "<>"[d] + " " + s
        return s

    def print_histogram(self):
        # Sort by descending order of counts
        h = sorted(self.hist.items(), key=lambda x: -x[1])
        for (key, n) in h:
            pc = (n * 100.0) / self.n_total
            print("%8u %3.0f%%  %20s" % (n, pc, self.flit_key_str(key)), end="")
            # Print the witness
            if True:
                witness = self.witness[key]
                if o_decode_raw:
                    print("  %s" % hexstr(witness.group.payload[::-1]), end="")
                print("  %s %s" % ("<>"[witness.group.up], witness.long_str()), end="")
            print()
        if o_verbose:
            print("(%u CMN polling packets captured and discarded)" % self.n_discarded_self)


"""
Setting up a trace session.

Where we want to get to is a list of DTMs involved with trace, each with a watchpoint configuration.
Each DTM should have a list of upload watchpoints and a list of download watchpoints.
These watchpoints are rotated through the physical watchpoints on the DTM.
Some watchpoints may need a pair of physical watchpoints.
"""

class WatchBind:
    """
    This represents a watchpoint specification, either up or down, on a specific DTM port.
    It might consume one, or both (in the case of pair-watchpoints) of the DTM's physical watchpoints.
    """
    def __init__(self, wp, port=None, cc=True, format=4, format2=None, ctrig=False, dbgtrig=False, tag=False, name=None):
        self.name = name
        self.dtm = port.dtm
        self.dtm_port_number = port.port_number - (port.dtm.index * 2)
        self.wp = wp
        self.format = format      # Capture format, e.g. 4 for full header
        self.format2 = format2    # or None
        self.cc = cc
        self.ctrig = ctrig
        self.dbgtrig = dbgtrig
        # In current CMN, tag-setting is a function of the DTM, not the watchpoint.
        # But we track it per watchpoint. This may restrict scheduling.
        self.tag = tag

    def n_groups(self):
        """
        Check how many physical watchpoints are needed - some combinations of CHI opcodes
        will need a combined watchpoint, and header+data will also need two watchpoints.
        """
        n = len(self.wp.grps())
        assert n in [1, 2]
        if n == 1 and self.format2 is not None:
            n += 1
        return n

    def is_multigrp(self):
        return self.n_groups() > 1

    def can_share(self):
        """
        See if this watchpoint can share a DTM pair with another watchpoint.
        It can't do this if it needs two watch groups, or has two formats.
        """
        return not self.is_multigrp()

    def __str__(self):
        s = "%s.P%u,%s" % (self.dtm, self.dtm_port_number, self.wp)
        if self.format != 4 or self.format2 is not None:
            s += ",format=%u" % self.format
        if self.format2 is not None:
            s += "&%u" % self.format2
        if self.ctrig:
            s += ",cross-trigger"
        if self.dbgtrig:
            s += ",debug-trigger"
        if self.tag:
            s += ",tracetag"
        if self.name is not None:
            s += ",name=\"%s\"" % self.name
        s = "WatchBind(%s)" % s
        return s

    def __repr__(self):
        return str(self)


class WatchRotation:
    """
    This represents a list of WatchBind objects to be scheduled on to a DTM's physical watchpoints.
    This will be specific to a direction (up or down).
    """
    def __init__(self, dtm):
        self.dtm = dtm
        self.bind_list = []
        self.index = 0

    def is_empty(self):
        return not self.bind_list

    def n_groups(self):
        return sum([wp.n_groups() for wp in self.bind_list])

    def needs_rotation(self):
        return self.n_groups() > 2         # For a given direction, each DTM has two physical watchpoints

    def append(self, wp):
        assert isinstance(wp, WatchBind)
        assert wp.dtm == self.dtm
        self.bind_list.append(wp)

    def next(self):
        if not self.bind_list:
            return None
        return self.bind_list[self.index]

    def advance(self):
        self.index += 1
        if self.index == len(self.bind_list):
            self.index = 0

    def __str__(self):
        return str(self.bind_list)


WP_UP = 0
WP_DN = 1

dir_str = ["Up", "Down"]


# Data trace configurations: (dataid, format, format2)
data_trace_mnemonic = {
    "HDR":   (None, 4, None),
    "H01":   (0,    4, None),
    "H23":   (2,    4, None),
    "D0":    (0,    5, None),
    "D1":    (0,    6, None),
    "D2":    (2,    5, None),
    "D3":    (2,    6, None),
    "HD0":   (0,    4, 5),
    "HD1":   (0,    4, 6),
    "HD2":   (2,    4, 5),
    "HD3":   (2,    4, 6),
    "DALL":  (None, 5, 6),
    "D01":   (0,    5, 6),
    "D23":   (0,    5, 6),
}


class TraceSession:
    """
    All the information we need to manage tracing flits.
    """
    def __init__(self, opts, handler=None, atb=False, init=True):
        self.opts = opts
        self.atb = atb
        self.cmns = None    # in case next line throws
        self.cmns = list(cmn_devmem.cmn_from_opts(opts))
        self.data_trace_available = any(C.part_ge_650() for C in self.CMNs())
        self.TV = handler
        if handler is not None:
            handler.set_cmns(list(self.CMNs()))        # The trace visualizer
        for dtm in self.all_dtms():
            dtm.rotation = {}
            dtm.rotation[WP_UP] = WatchRotation(dtm)
            dtm.rotation[WP_DN] = WatchRotation(dtm)
            self.reset_dtm(dtm)
        self.construct_watchpoints()
        self.dtms = [dtm for dtm in self.all_dtms() if not (dtm.rotation[WP_UP].is_empty() and dtm.rotation[WP_DN].is_empty())]
        self.move_tag_setters_first()
        if self.opts.verbose:
            print("Monitoring ports:")
            for dtm in self.dtms:
                print("  %s:" % dtm)
                for d in [WP_UP, WP_DN]:
                    if dtm.rotation[d].is_empty():
                        continue
                    print("    %s:" % dir_str[d])
                    for w in dtm.rotation[d].bind_list:
                        print("      %s" % w)
        if not self.dtms:
            print("No ports matched: %s" % (nodes), file=sys.stderr)
            sys.exit(1)
        self.dtms_rotating = [dtm for dtm in self.dtms if (dtm.rotation[WP_UP].needs_rotation() or dtm.rotation[WP_DN].needs_rotation())]
        if self.check_need_rotation():
            print("Warning: %u watchpoints will need to be dynamically rotated" % len(self.dtms_rotating))
        self.remove_unused_cmns()
        if init:
            self.init_cmn()
        self.reset_dtms(clear_fifo=True)

    def __del__(self):
        """
        Always leave DTCs enabled, to avoid kernel PMU driver reading zeroes
        """
        if self.cmns is not None:
            for C in self.CMNs():
                C.dtc_enable()

    def cmn_from_opts(self, opts):
        loc = cmn_devmem.cmn_instance(opts)
        if loc is None:
            print("Can't locate CMN")
            sys.exit(1)
        C = cmn_devmem.CMN(loc, check_writes=(not opts.no_check_writes), verbose=max(0, opts.verbose-1))
        if opts.list:
            cmn_devmem.show_cmn(C)
            sys.exit()
        if opts.diag:
            C.diag_trace |= cmn_devmem.DIAG_READS | cmn_devmem.DIAG_WRITES
        return C

    def remove_unused_cmns(self):
        """
        If we aren't monitoring anything on a mesh, we don't need to bother with DTC enable/disable etc.
        """
        is_used = {C.cmn_seq: False for C in self.cmns}
        for dtm in self.dtms:
            is_used[dtm.C.cmn_seq] = True
        self.cmns = [C for C in self.cmns if is_used[C.cmn_seq]]

    def CMNs(self):
        if self.cmns is not None:
            return self.cmns
        else:
            return []

    def DTCs(self):
        for C in self.CMNs():
            for dtc in C.DTCs():
                yield dtc

    def XPs(self):
        for C in self.CMNs():
            for xp in C.XPs():
                yield xp

    def init_cmn(self):
        """
        Iniitialize CMN for tracing
        """
        for C in self.CMNs():
            if self.opts.verbose:
                print("cmn_capture: initializing CMN %s" % C)
            # Enable all DTCs in the CMN
            if C.DTC0() is None:
                print("%s: could not discover DTC" % C, file=sys.stderr)
                sys.exit(1)
            C.dtc_enable(cc=self.opts.cc)   # need to enable CC in DTCs if we want timestamp in DTMs
            C.restore_dtc_status_on_deletion()
            # First disable all the non-involved XPs
            for dtm in C.DTMs():
                if self.opts.verbose >= 2:
                    print("cmn_capture: disable DTM %s" % dtm)
                dtm.dtm_set_control(enable=False, atb=False, tag=False)

    def construct_watchpoints(self):
        """
        Use the command-line options to construct watchpoint filters.
        Depending on the user's choice of CHI fields, each watchpoint might require
        a single physical watchpoint or a pair. Also, the user might specify multiple
        watchpoints.

        This routine doesn't program any watchpoints.
        """
        gnodes = self.get_nodes()           # Overall node restrictor from command-line options
        if not self.opts.watchpoint:
            # No watchpoint expressions provided: relying on command-line options only
            wspec = ["REQ", "RSP", "SNP", "DAT"][self.opts.vc or 0]
            if self.opts.up is not None:
                wspec = ["DOWN", "UP"][self.opts.up] + ":" + wspec
            else:
                wspec = "BOTH:" + wspec
            self.opts.watchpoint = [wspec]
        ports_checked = 0
        # Process each watchpoint expression, and expand into watchpoints bound to crosspoints
        for wspec in self.opts.watchpoint:
            # Each watchpoint expression must specify a filter and can also specify location in the mesh.
            # The filter specifies CHI channel, direction and possibly CHI fields,
            # e.g. "up:req:opcode=1", "down:rsp"
            #   <filter>
            #   <location-selector>/<filter>
            # In addition, actions (trigger, tag etc.) can be specified:
            #   <filter>#<actions>
            name = wspec
            nodes = gnodes
            actions = ""
            if '/' in wspec:
                (wnodes, wspec) = wspec.split('/')
                try:
                    nodes = cmn_select.cmn_select_merge([cmn_select.CMNSelect(wnodes)])
                except cmn_select.CMNSelectBad as e:
                    raise BadCaptureWatchpoint("bad node selector: %s" % wnodes)
            # Process actions
            if '#' in wspec:
                (wspec, actions) = wspec.split('#')
            wp_format = self.opts.format
            wp_format2 = None
            wp_cc = self.opts.cc
            wp_cross_trigger = self.opts.cross_trigger
            wp_debug_trigger = self.opts.debug_trigger
            wp_tracetag = self.opts.set_tracetag
            for act in actions.split(','):
                if act == "":
                    pass
                elif act.startswith("format="):
                    wp_format = int(act[7:])
                elif act.startswith("format2="):
                    wp_format2 = int(act[8:])
                elif act.startswith("data="):
                    if not self.data_trace_available:
                        raise BadCaptureWatchpoint("data trace not available on this product")
                    (dataid, wp_format, wp_format2) = data_trace_mnemonic.get(act[5:].upper(), (None, None, None))
                    if wp_format is None:
                        raise BadCaptureWatchpoint("unknown data trace: choose from %s" % str(data_trace_mnemonic.keys()))
                    if dataid is not None:
                        wspec += ":dataid=%u" % dataid
                elif act == "cross-trigger":
                    wp_cross_trigger = True
                elif act == "debug-trigger":
                    wp_debug_trigger = True
                elif act == "tracetag":
                    wp_tracetag = True
                elif act == "cc":
                    wp_cc = True
                else:
                    raise BadCaptureWatchpoint("unknown watchpoint action '%s'" % act)
            try:
                # Watchpoint specifications are interpreted using the configuration of the first mesh.
                # TBD: in a heterogeneous system, we might need to do better.
                wps = cmnwatch.parse_short_watchpoint(wspec, self.opts, cmn_version=self.cmns[0].product_config)
            except cmnwatch.WatchpointError as e:
                raise BadCaptureWatchpoint("can't do this watchpoint: %s" % e)
            if wp_tracetag and not wps.up:
                raise BadCaptureWatchpoint("download watchpoint can't set TraceTag")
            if self.opts.verbose:
                print("Watchpoint (groups %s) at %s" % (str(wps.grps()), nodes))
                print("  %s" % wps)
            wps.finalize()
            if wp_format2 is not None and wps.is_multigrp():
                raise BadCaptureWatchpoint("can't do DAT header+data with multi-group matching")
            for port in self.ports_matching_nodes(nodes):
                ports_checked += 1
                wb = WatchBind(wps, port, format=wp_format, format2=wp_format2, cc=wp_cc, ctrig=wp_cross_trigger, dbgtrig=wp_debug_trigger, tag=wp_tracetag, name=name)
                if wps.up is None or wps.up:
                    port.dtm.rotation[WP_UP].append(wb)
                if wps.up is None or not wps.up:
                    port.dtm.rotation[WP_DN].append(wb)
        if not ports_checked:
            print("No ports could have these watchpoints", file=sys.stderr)
            sys.exit(1)

    def move_tag_setters_first(self):
        """
        Check for DTMs that have tag-setting watchpoints, and move them last for configuration
        This helps with latency correlation. We actually put them first in the list so they
        appear before the tag receivers when printing.
        """
        dtms_tag = []
        dtms_nontag = []
        for dtm in self.dtms:
            sets_tag = False
            for wp in dtm.rotation[WP_UP].bind_list:
                if wp.tag:
                    sets_tag = True
                    break
            (dtms_tag if sets_tag else dtms_nontag).append(dtm)
        self.dtms = dtms_tag + dtms_nontag

    def ports_matching_nodes(self, nodes):
        xps = [xp for xp in self.XPs() if nodes.can_match_devices_at_xp(xp)]
        if self.opts.verbose >= 2:
            print("XPs: %s" % (','.join([str(xp) for xp in xps])))
        for xp in xps:
            for port in xp.ports():
                # Check port connected type rather than nodes, as some ports (RN-F, SN-F) have no nodes
                can_match = nodes.can_match_devices_at_port(port)
                if self.opts.verbose >= 2:
                    print("%s: check %s => %s" % (nodes, port, can_match))
                if can_match:
                    yield port

    def legacy_xp_selectors(self):
        """
        Translate legacy --xp arguments into mesh-qualified XP selectors.

        XP node ids are only unique within a mesh, so in a multi-mesh trace
        session an --xp value can match multiple XPs. Represent the result as
        selectors restricted by mesh sequence number and XP coordinates, so the
        normal device-matching fast paths can prune correctly.
        """
        sels = []
        for xp_id in self.opts.xp:
            matched = False
            for xp in self.XPs():
                if xp.node_id() == xp_id:
                    sels.append(cmn_select.CMNSelectSingle(cmn_seq=xp.C.cmn_seq, x=xp.x, y=xp.y))
                    matched = True
            if not matched:
                print("XP node id not found: 0x%x" % xp_id, file=sys.stderr)
                sys.exit(1)
        return sels

    def get_nodes(self):
        """
        Apply global restrictions to filter XPs and ports
        Four possibilities:
          no --xp, no --node: monitor all XPs
          --node, no --xp: monitor ports as selected by node selector
          --xp, no --node: monitor selected XPs
          --xp, --node: form the cross-product of the XP and node selectors.
        """
        nodes = cmn_select.cmn_select_merge(self.opts.node)     # a CMNSelect object
        if nodes is None:
            nodes = cmn_select.CMNSelect()
        if not self.opts.xp:
            pass
        elif self.opts.xp and not self.opts.node:
            if self.opts.xp == [-1]:
                pass
            else:
                for sel in self.legacy_xp_selectors():
                    nodes.append(sel)
        else:
            # Both were specified: apply the cross-product
            xp_sels = self.legacy_xp_selectors()
            nsel = []
            for s in nodes.matchers:
                for xp_sel in xp_sels:
                    ns = s.copy()
                    ns.cmn_seq = xp_sel.cmn_seq
                    ns.node_x = xp_sel.node_x
                    ns.node_y = xp_sel.node_y
                    nsel.append(ns)
            nodes.matchers = nsel
        # At this point, if we've used either --xp or --nodes, the 'nodes' selector should
        # match all ports we're interested in profiling
        if self.opts.verbose:
            print("Node selector: %s" % nodes)
        return nodes

    def all_dtms(self):
        """
        Yield all the DTMs in the system.
        TraceSession.dtms is a list of the DTMs we're actually using.
        """
        for xp in self.XPs():
            for dtm in xp.dtms:
                yield dtm

    def check_need_rotation(self, warn=True):
        """
        Check if the watchpoints need dynamic rotation in order to cover all selected ports.
        Rotation is needed:
          - for a 1-group watchpoint, if more than 2 ports are selected on an XP
          - for a 2-group watchpoint, if more than 1 port is selected on an XP
        Upload/download isn't relevant, since that is a fixed property of DTM watchpoints.
        TBD: should handle multi-DTM watchpoints.
        """
        need_rotation = False
        printed = False
        for dtm in self.dtms:
            for d in [WP_UP, WP_DN]:
                n_groups = dtm.rotation[d].n_groups()
                if n_groups > 2:
                    if warn and not printed:
                        print("%s needs %u physical watchpoints, need to rotate" % (dtm, n_groups))
                        printed = True
                    need_rotation = True
        return need_rotation

    def gen_watchpoint(self, wb, n=0):
        """
        Generate a DTMWatchpoint object from a WatchBind and an index (0 or 1) into the watchpoint's groups.
        """
        dev = wb.dtm_port_number
        wp = wb.wp
        gn = wp.grps()[n]
        M = wp.wps[gn]
        assert M.grp == gn
        combine = (wp.is_multigrp() and (n == 0))
        w = cmn_devmem.DTMWatchpoint(dtm=wb.dtm, pkt_gen=True,
                                     value=M.val, mask=M.mask,
                                     type=wb.format, cc=wb.cc,
                                     ctrig=wb.ctrig,
                                     dbgtrig=wb.dbgtrig,
                                     dev=dev, chn=wp.chn, grp=M.grp,
                                     exclusive=M.exclusive, combine=combine)
        return w

    def reset_dtm(self, dtm):
        dtm.dtm_disable()
        for wp in range(0, 4):
            dtm.dtm_wp_reset(wp)

    def reset_dtms(self, clear_fifo=False):
        if self.opts.verbose >= 2:
            print("cmn_capture: reset all DTMs")
        for dtm in self.dtms:
            self.reset_dtm(dtm)
        if clear_fifo:
            for dtm in self.dtms:
                dtm.dtm_clear_fifo()

    def configure_dtm(self, dtm):
        """
        Set up the trace configuration in the DTM.
        Each DTM has four WPs.
        This function may also rotate the port selection.
        """
        # (CMN-600 TRM 5.2.1).
        # "WP0 and WP1 are assigned to flit uploads. WP2 and WP3 are assigned to flit downloads."
        #
        # It may be that there are not enough watchpoints to monitor all
        # traffic on all ports at the same time.
        # This occur for two reasons:
        #  - the XP might have more than two ports.
        #  - some combination of fields might need two combined (paired) watchpoints
        # In those cases we would need to iterate through the ports.
        #
        # Also, matching on SRCID or TGTID restricts us to only download or upload.
        #
        if o_verbose >= 2:
            print("%s: configure trace" % dtm)
        if dtm.rotation[WP_UP].is_empty() and dtm.rotation[WP_DN].is_empty():
            dtm.dtm_disable()
            for wp in range(0, 4):
                dtm.dtm_set_watchpoint(wp, gen=False)
            return
        dtm.current_wb = {}
        # In read (non-ATB) mode, it appears that the FIFO starts filling as soon as
        # trace_no_atb is set, regardless of dtm_enable. So make sure the
        # watchpoints are configured and then clear the FIFO.
        dtm.dtm_disable()
        self.reset_dtm(dtm)
        if not self.atb:
            dtm_control = cmn_devmem.CMN_DTM_CONTROL_TRACE_NO_ATB
        else:
            dtm_control = 0
        #if opts.fifo:
        #    xp.set64(cmn_devmem.CMN_DTM_CONTROL, 0x08)
        #else:
        #    xp.clear64(cmn_devmem.CMN_DTM_CONTROL, 0x08)    # send to ATB not FIFO
        for (d, off) in [(WP_UP, 0), (WP_DN, 2)]:
            rot = dtm.rotation[d]
            if rot.is_empty():
                for wp in range(off, off+2):
                    dtm.dtm_set_watchpoint(wp, gen=False)
                continue
            wb = rot.next()
            rot.advance()
            # Try to use both physical watchpoints (for this direction)
            w = self.gen_watchpoint(wb, 0)
            if o_verbose >= 2:
                print("  WP%u := %s" % (off, wb))
            if wb.tag and d == WP_UP:
                dtm_control |= cmn_devmem.CMN_DTM_CONTROL_TRACE_TAG_ENABLE
            if dtm_control is not None:
                # Now we know whether or not this DTM is setting TraceTag, write its control
                dtm.dtm_write64(cmn_devmem.CMN_DTM_CONTROL_off, dtm_control)   # DTM is still disabled
                dtm_control = None      # so we don't write it again
            dtm.dtm_wp_set(off, w)
            dtm.current_wb[off] = wb
            if wb.format2 is not None:
                w.type = wb.format2     # Same watchpoint, but with a different capture format
            elif wb.wp.is_multigrp():
                # Do the other half of the combined match (this will not do a separate capture)
                w = self.gen_watchpoint(wb, 1)
            else:
                w = None
                # See if we can do another singleton
                # Tag setting must be common, as it's a DTM function not a WP function
                nwb = rot.next()
                if nwb != wb and nwb.can_share() and nwb.tag == wb.tag:
                    rot.advance()
                    wb = nwb
                    w = self.gen_watchpoint(wb, 0)
            if w is not None:
                if o_verbose >= 2:
                    print("+ WP%u := %s" % (off+1, wb))
                dtm.dtm_wp_set(off+1, w)
                dtm.current_wb[off+1] = wb
            else:
                # Ensure we don't see residual data on the other watchpoint
                dtm.dtm_set_watchpoint(off+1, gen=False)
                dtm.current_wb[off+1] = None
        #dtm.dtm_enable()
        if not self.atb:
            # Clearing the FIFO only works if trace_no_atb is already set
            dtm.dtm_set64(cmn_devmem.CMN_DTM_CONTROL_off, cmn_devmem.CMN_DTM_CONTROL_TRACE_NO_ATB)
            #dtm.dtm_clear_fifo()
        if self.opts.count:
            # Program the four local counters to count the four WPs (events 0..3).
            # The DTC has eight global counters which can catch rollovers from the
            # local counters. We have eight DTC counters so we might as well distribute
            # the XP rollovers between them.
            dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0)     # disable PMU while we're programming it
            dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_PMEVCNT_off, 0)    # clear the four local counters
            #dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0x0302010000000001)
            #if wp == 0:
            #    dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0x03020100642000f1)
            #else:
            #    dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0x03020100753100f1)
        # "The final step is to write 1'b1 to dtm_control.dtm_enable to enable the WP."
        if self.opts.verbose >= 2:
            print("enable DTM on %s" % dtm)
        dtm.dtm_enable()

    def trace_start(self):
        if self.opts.verbose:
            print("cmn_capture: start...")
        self.dtc_disable()
        if False:
            # Reset all the XP DTMs (even the ones we're not interested in) and stop
            # them generating ATB trace packets.
            for dtm in self.all_dtms():
                dtm.dtm_disable()
                dtm.dtm_set64(cmn_devmem.CMN_DTM_CONTROL_off, cmn_devmem.CMN_DTM_CONTROL_TRACE_NO_ATB)
                dtm.dtm_clear_fifo()
        if self.opts.verbose >= 2:
            self.show_fifos("before DTC enable")
        self.dtc_enable()
        if self.opts.verbose >= 2:
            self.show_fifos("after DTC enable")
        for dtm in reversed(self.dtms):
            # Here we are scanning just the XPs that we want to monitor.
            # The others are left disabled.
            self.configure_dtm(dtm)
            if self.opts.verbose >= 2:
                self.show_fifos("after configuring a DTM")
        if self.opts.verbose >= 2:
            self.show_fifos("after configure DTMs")

        if self.opts.count:
            # We've programmed the local PMUs in the DTMs, and even though we aren't
            # forwarding local counts to the DTC, the DTMs won't count until we set
            # the global PMU enable.
            for dtc in self.DTCs():
                dtc.pmu_clear()
                dtc.pmu_enable()

        # Start CMN generating ATB trace
        if self.opts.cg_disable:
            for dtc in self.DTCs():
                dtc.set64(cmn_devmem.CMN_DTC_CTL, cmn_devmem.CMN_DTC_CTL_CG_DISABLE)    # experimental
        self.dtc_enable()
        if False:
            # Generate some more alignment packets in the ATB stream
            for _ in range(0, 3):
                self.dtc_disable()
                self.dtc_enable()

    def trace_readout(self, fifocap=None, clear=True):
        """
        Check for trace and accumulate it into a map:
            xp -> wp# -> (w, data, cc)
        """
        if fifocap is None:
            fifocap = {}
        for dtm in self.dtms:
            if dtm not in fifocap:
                fifocap[dtm] = {}
        self.reset_dtms()
        for dtm in self.dtms:
            # Check the DTM's four FIFOs (two upload, two download)
            fe = dtm.dtm_fifo_ready()
            for e in range(0, 4):
                if fe & (1 << e):
                    wb = dtm.current_wb[e]
                    if wb is None:
                        print("** Unexpected data on %s WP%u" % (dtm, e), file=sys.stderr)
                    w = dtm.dtm_wp_config(e, value=False)
                    (data, cc) = dtm.dtm_fifo_entry(e)
                    if o_verbose >= 3:
                        print("%s WP%u (%s) captured %s" % (dtm, e, wb, data))
                    if self.opts.immediate:
                        self.TV.decode_packet(dtm.xp, w, data, cc)
                    else:
                        ee = (e - 1) if (w.type in [5, 6] and (e & 1)) else e
                        if ee not in fifocap[dtm]:
                            fifocap[dtm][ee] = []
                        fifocap[dtm][ee].append((w, data, cc))
            if clear:
                dtm.dtm_clear_fifo()
        return fifocap

    def trace(self):
        """
        Start trace, capture some FIFO packets (emptying the FIFO) and stop.
        Return a map:
            xp -> wp# -> (w, data, cc)
        """
        self.trace_start()
        # Prepare to capture FIFO packets
        fifocap = {}
        for dtm in self.dtms:
            fifocap[dtm] = {}
        for i in range(self.opts.samples):
            # Wait for a while
            time.sleep(self.opts.sleep)
            self.trace_readout(fifocap, clear=True)
            for dtm in reversed(self.dtms):
                self.configure_dtm(dtm)
            continue
            if self.dtms_rotating:
                if self.opts.verbose >= 2:
                    print("cmn_capture: rotating %u DTMs..." % len(self.dtms_rotating))
                for dtm in self.dtms_rotating:
                    self.configure_dtm(dtm)
        self.trace_stop()
        return fifocap

    def show_captured_trace(self, fifocap):
        """
        Decode and print some flits captured by trace().
        """
        if self.opts.verbose:
            print("Captured trace:")
            for dtm in self.dtms:
                print("  %s:" % dtm, end="")
                for e in sorted(fifocap[dtm].keys()):
                    print(" %s:%u" % (e, len(fifocap[dtm][e])), end="")
                print()
        for dtm in self.dtms:
            for e in sorted(fifocap[dtm].keys()):
                for (w, data, cc) in fifocap[dtm][e]:
                    self.TV.decode_packet(dtm.xp, w, data, cc)

    def dtc_enable(self):
        for C in self.CMNs():
            C.dtc_enable()

    def dtc_disable(self):
        for C in self.CMNs():
            C.dtc_disable()

    def trace_stop(self):
        # Stop generating trace, and collect it
        self.dtc_disable()
        for dtm in self.dtms:
            dtm.dtm_disable()
        if self.opts.verbose >= 3:
            self.show_all_status()
        elif self.opts.verbose >= 2:
            self.show_dtm()

    def show_watchpoint_counts(self):
        """
        Show counts of watchpoint matches - assuming we programmed the PMU.
        """
        if self.opts.count:
            # Show watchpoint counts
            for dtm in self.dtms:
                # Read the local counters
                c = dtm.dtm_read64(cmn_devmem.CMN_DTM_PMU_PMEVCNT_off)
                for wp in range(0, 4):
                    print(" %6u" % bits(c, wp*16, 16), end="")
                print()

    def show_fifos(self, msg=""):
        """
        Show DTM FIFO contents from all the DTMs
        """
        n_shown = 0
        print("FIFO contents (%s):" % msg)
        for dtm in self.dtms:
            n_shown += self.show_fifo(dtm)
        if n_shown == 0:
            print("  (all FIFOs empty)")
        print("")

    def show_fifo(self, dtm):
        n_shown = 0
        fe = dtm.dtm_fifo_ready()
        for e in range(0, 4):
            if fe & (1 << e):
                w = dtm.dtm_wp_config(e, value=False)
                (data, cc) = dtm.dtm_fifo_entry(e)
                self.TV.decode_packet(dtm.xp, w, data, cc)
                n_shown += 1
        return n_shown

    def show_all_status(self):
        """
        Show all XPs and DTCs, even non-involved
        """
        for xp in self.XPs():
            xp.show()
        for dtc in self.DTCs():
            cmn_dtstat.print_dtc(dtc)

    def show_dtm(self):
        print("DTM status:")
        for dtm in self.dtms:
            cmn_dtstat.print_dtm(dtm)
        for dtc in self.DTCs():
            cmn_dtstat.print_dtc(dtc)


def main(argv):
    global o_decode_raw, o_include_polling, o_verbose, o_decode_verbose, o_deduplicate
    import argparse
    parser = argparse.ArgumentParser(description="CMN flit capture tool")
    add_trace_arguments(parser)
    parser.add_argument("--include-polling", action="store_true", help="include CMN polling reqs from script")
    parser.add_argument("--histogram", action="store_true", help="print histogram of packet types")
    parser.add_argument("--histogram2", action="store_true", help="histogram distinguishing direction")
    parser.add_argument("--setup", action="store_true", help="set up but don't capture")
    parser.add_argument("--inspect", action="store_true", help="inspect captured data")
    parser.add_argument("--no-deduplicate", action="store_true")
    parser.add_argument("--no-clear", action="store_true", help="don't clear captured data")
    parser.add_argument("--decode-raw", action="store_true", help="show raw packet contents")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    o_decode_raw = opts.decode_raw
    o_decode_verbose = opts.decode_verbose
    o_deduplicate = (not opts.no_deduplicate)
    if opts.setup and opts.inspect:
        print("Setup and inspect mode should be used separately", file=sys.stderr)
        sys.exit(1)
    if opts.histogram2:
        opts.histogram = True
    if (opts.setup or opts.inspect) and opts.histogram:
        print("In setup/inspect mode, actions like --histogram are not available", file=sys.stderr)
        sys.exit(1)
    o_include_polling = opts.include_polling
    if opts.histogram:
        vis = CMNHist(direction=opts.histogram2)
    else:
        vis = CMNVis()
    try:
        ts = TraceSession(opts, handler=vis, init=(not opts.inspect))
    except BadCaptureWatchpoint as e:
        print("Error: %s" % e, file=sys.stderr)
        sys.exit(1)
    if opts.setup:
        # With --setup, we set up a specific configuration and then exit, so we don't
        # have the opportunity to rotate watchpoints between ports.
        if ts.check_need_rotation(warn=True):
            sys.exit(1)
        ts.trace_start()
        sys.exit()
    elif opts.inspect:
        cap = ts.trace_readout(clear=(not opts.no_clear))
        ts.show_captured_trace(cap)
        sys.exit()
    for _ in range(opts.iterations):
        cap = ts.trace()
        ts.show_captured_trace(cap)
    if opts.histogram:
        vis.print_histogram()
    del ts
    del vis


if __name__ == "__main__":
    main(sys.argv[1:])
