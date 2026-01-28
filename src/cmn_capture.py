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

import cmn_devmem
import cmn_devmem_find
import cmn_json
from cmn_enum import *
import cmnwatch
import cmn_select
import cmn_flits
from cmn_flits import CMNTraceConfig, CMNFlitGroup
import cmn_dtstat


o_verbose = 0

o_include_polling = False


def bits(x, p, n):
    return (x >> p) & ((1 << n) - 1)


# TBD: currently limited argument validation, while we're experimenting.
def inthex(s):
    return int(s,16)


def add_trace_arguments(parser):
    parser.add_argument("--xp", type=inthex, action="append", help="crosspoint number(s)")
    parser.add_argument("--node", type=cmn_select.CMNSelect, action="append", help="node specifier(s)")
    parser.add_argument("--vc", "--chn", type=int, choices=[0,1,2,3], default=0, help="VC channel number: REQ, RSP, SNP, DAT")
    parser.add_argument("--data", type=int, choices=[0,1,2,3], help="capture 16-byte data fragments with headers")
    parser.add_argument("--wp-val", type=inthex, default=0, help="watchpoint value")
    parser.add_argument("--wp-mask", type=inthex, default=0xffffffffffffffff, help="watchpoint mask (don't-care bits)")
    cmnwatch.add_chi_arguments(parser)
    parser.add_argument("--uploads", dest="up", action="store_true", default=None, help="capture uploaded flits only")
    parser.add_argument("--downloads", dest="up", action="store_false", default=None, help="capture downloaded flits only")
    parser.add_argument("--cc", action="store_true", help="enable cycle counts")
    parser.add_argument("--cross-trigger", action="store_true", help="generate cross trigger on watchpoint match")
    parser.add_argument("--debug-trigger", action="store_true", help="generate debug trigger on watchpoint match")
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
    parser.add_argument("watchpoint", type=str, nargs="?", help="short-form watchpoint specifier")


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


class CMNFlitGroupX(CMNFlitGroup):
    """
    Subclass CMN flit decode to provide more annotation of CHI source and target ids.
    """
    def __init__(self, cfg, cmn_seq=None, nodeid=None, DEV=None, VC=None, format=None, cc=0, vis=None):
        assert VC is not None
        assert DEV is not None
        assert format is not None
        CMNFlitGroup.__init__(self, cfg, cmn_seq=cmn_seq, nodeid=nodeid, DEV=DEV, VC=VC, format=format, cc=cc, debug=opts.decode_verbose)
        self.vis = vis
        self.id_map = vis.id_map

    def id_str(self, id, lpid=0):
        s = CMNFlitGroup.id_str(self, id, lpid=lpid)
        ns = "????"
        if (id, lpid) in self.id_map:
            ns = self.id_map[(id, lpid)]
        elif lpid != 0 and (id, 0) in self.id_map:
            # e.g. RN-F where we haven't got CPU mappings for non-zero LPIDs
            ns = self.id_map[(id, 0)]
        s += "(%-4s)" % ns[:4]
        return s

    def addr_str(self, addr, NSENS):
        """
        Override default address printing, to identify CMN access itself
        """
        if self.vis.cmn.contains_addr(addr):
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
    n_ports = xp.n_device_ports()
    for port in xp.ports():
        base_id = port.base_id()
        devices = {}
        port_desc = cmn_port_device_type_str(port.device_type())
        # Look at actual device nodes and have them take priority -
        # this copes with HCALs and with multiple devices where there isn't a CAL
        for n in port.nodes():
            if not cmn_node_type_has_properties(n.type(), CMN_PROP_CHI):
                continue
            id = n.node_id()
            if id not in devices:
                devices[id] = cmn_node_type_str(n.type())
        # By default use CAL multiplicity to populate the device ids with
        # the "port connected device" descriptor string
        cal = port.has_cal()
        for device_id in range(cal or 1):
            id = base_id + device_id
            if id not in devices:
                devices[id] = port_desc
        # Finally return the device ids and their descriptions
        for id in sorted(devices.keys()):
            yield (id, devices[id])


def cmn_node_ids(cmn):
    cmn.discover_all_devices()
    for xp in cmn.XPs():
        for (id, desc) in xp_node_ids(xp):
            yield (id, desc)


class CMNVis:
    """
    Print CMN trace in a human-readable form, one packet per line, minimizing clutter.
    """
    def __init__(self):
        self.cmn = None

    def set_cmn(self, cmn):
        self.cmn = cmn
        config = cmn.product_config
        self.cfg = CMNTraceConfig(config.product_id, has_MPAM=config.mpam_enabled, cmn_product_revision=config.revision_major)
        self.last_xp = None
        self.build_id_map()

    def build_id_map(self):
        self.id_map = {}     # (id, lpid) -> label
        for (id, desc) in cmn_node_ids(self.cmn):
            self.id_map[(id, 0)] = desc[:4]
        self.cmn_desc = cmn_desc(self.cmn)
        if self.cmn_desc is not None and self.cmn_desc.has_cpu_mappings():
            for cpu in self.cmn_desc.cpus():
                self.id_map[(cpu.id, cpu.lpid)] = "#%-3u" % cpu.cpu
        if o_verbose:
            print("ID map:")
            n_on_line = 0
            for k in sorted(self.id_map.keys()):
                (id, lpid) = k
                s = self.id_map[k]
                if n_on_line == 8:
                    print()
                    n_on_line = 0
                print("  %04x[%u]: %-6s" % (id, lpid, s), end="")
                n_on_line += 1
            print()

    def handle_flitgroup(self, xp, wp, fg):
        if xp != self.last_xp:
            print("%s:" % xp)
            self.last_xp = xp
        print("  %s WP%u: " % ("><"[(wp >> 1) & 1], wp), end="")
        print(fg)

    def decode_packet(self, xp, wp, w, data, cc):
        fg = CMNFlitGroupX(self.cfg, cmn_seq=self.cmn.seq, nodeid=xp.node_id(), DEV=w.dev, VC=w.chn, format=w.type, cc=w.cc, vis=self)
        fg.decode(data)
        self.handle_flitgroup(xp, wp, fg)


def is_cmn_polling_req(cmn, flit):
    """
    Detect ReadNoSnp reqs poll the XP FIFO registers
    """
    if flit.group.VC == cmn_flits.REQ and flit.opcode == 0x04 and flit.group.format == 4 and cmn.contains_addr(flit.addr):
        return True
    return False


class CMNHist(CMNVis):
    """
    Histogram to accmulate packet stats
    """
    def __init__(self):
        CMNVis.__init__(self)
        self.hist = {}
        self.witness = {}     # a witness flit for each key
        self.n_total = 0

    def handle_flitgroup(self, xp, wp, fg):
        # Override, to accumulate histogram
        for flit in fg:
            if (not o_include_polling) and is_cmn_polling_req(self.cmn, flit):
                continue
            key = self.flit_key(flit)
            if key not in self.hist:
                self.hist[key] = 0
                self.witness[key] = flit
            self.hist[key] += 1
            self.n_total += 1

    def flit_key(self, flit):
        # Construct a key to classify the flit into a sensible group.
        # We use at least the source and target type, and the opcode.
        if (flit.srcid, 0) not in self.id_map:
            if flit.srcid is not None:
                self.id_map[(flit.srcid, 0)] = "?%03x" % flit.srcid
            else:
                self.id_map[(None, 0)] = "-"    # e.g. format-0 tracing - transaction ids only
        stype = self.id_map[(flit.srcid, 0)]
        if stype.startswith("#"):
            stype = "RN-F"    # undo the CPU mapping!
        if flit.tgtid is not None:
            key = (flit.tgtid, 0)
            try:
                ttype = self.id_map[(flit.tgtid, 0)]
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
        key = (op, stype, ttype)
        return key

    def key_str(self, key):
        (op, stype, ttype) = key
        s = "%-5s %-5s  %-22s" % (stype, ttype, op)
        return s

    def print_histogram(self):
        # Sort by descending order of counts
        h = sorted(self.hist.items(), key=lambda x: -x[1])
        for (key, n) in h:
            pc = (n * 100.0) / self.n_total
            print("%8u %3.0f%%  %20s  %s" % (n, pc, self.key_str(key), self.witness[key].long_str()))


# The DTM behavior doesn't seem to correspond to the spec.
# Writing the fifo_entry register only works when trace_no_atb is set.
# Reading the FIFO only works when trace_no_atb is set.
# The FIFO fills when trace_no_atb is set even if dtm_enable is not set.


class TraceSession:
    """
    All the information we need to manage tracing flits.
    """
    def __init__(self, opts, handler=None, atb=False, init=True):
        self.opts = opts
        self.atb = atb
        self.C = None    # in case next line throws
        self.C = self.cmn_from_opts(opts)
        if (self.opts.data is not None) and not self.C.part_ge_650():
            print("%s: this product does not support data trace" % self.C, file=sys.stderr)
            sys.exit(1)
        self.TV = handler
        if handler is not None:
            handler.set_cmn(self.C)        # The trace visualizer
        self.construct_watchpoint()
        self.get_nodes()
        self.reset_next_port()
        if init:
            self.init_cmn()

    def __del__(self):
        """
        Always leave DTCs enabled, to avoid kernel PMU driver reading zeroes
        """
        if self.C is not None:
            self.C.dtc_enable()

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

    def init_cmn(self):
        """
        Iniitialize CMN for tracing
        """
        if self.opts.verbose:
            print("cmn_capture: initializing CMN %s" % self.C)
        # Enable all DTCs in the CMN
        if self.C.DTC0() is None:
            print("%s: could not discover DTC" % self.C, file=sys.stderr)
            sys.exit(1)
        self.C.dtc_enable(cc=self.opts.cc)   # need to enable CC in DTCs if we want timestamp in DTMs
        self.C.restore_dtc_status_on_deletion()
        # First disable all the non-involved XPs
        for dtm in self.C.DTMs():
            if self.opts.verbose >= 2:
                print("cmn_capture: disable DTM %s" % dtm)
            dtm.dtm_disable()

    def get_nodes(self):
        """
        Find out which XPs and ports we're monitoring
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
                xps = [self.C.XP(x) for x in self.opts.xp]
                for xp in xps:
                    sel = cmn_select.CMNSelectSingle(x=xp.x, y=xp.y)
                    nodes.append(sel)
        else:
            # Both were specified: apply the cross-product
            xps = [self.C.XP(x) for x in self.opts.xp]
            nsel = []
            for s in nodes.matchers:
                for xp in xps:
                    ns = s.copy()
                    ns.node_x = xp.x
                    ns.node_y = xp.y
                    nsel.append(ns)
            nodes.matchers = nsel
        # At this point, the 'nodes' selector should match all ports we're interested in profiling
        if self.opts.verbose:
            print("Node selector: %s" % nodes)
        # We now need to turn 'nodes' into a list of XPs, each tagged with port numbers.
        self.xps = [xp for xp in self.C.XPs() if nodes.can_match_devices_at_xp(xp)]
        if self.opts.verbose:
            print("XPs: %s" % (','.join([str(xp) for xp in self.xps])))
        for xp in self.xps:
            xp.dtm.capture_port_list = []
            for pn in range(0, xp.n_device_ports()):
                port = xp.port_object(pn)
                # Check port connected type rather than nodes, as some ports (RN-F, SN-F) have no nodes
                can_match =  nodes.can_match_devices_at_port(port)
                if self.opts.verbose >= 2:
                    print("%s: check %s => %s" % (nodes, port, can_match))
                if can_match:
                    xp.dtm.capture_port_list.append(pn)
        self.xps = [xp for xp in self.xps if xp.dtm.capture_port_list]
        if not self.xps:
            print("No ports matched: %s" % (nodes), file=sys.stderr)
            sys.exit(1)
        if self.opts.verbose:
            print("Monitoring ports:")
            for xp in self.xps:
                print("%20s: %s" % (xp, str(xp.dtm.capture_port_list)))
        self.dtms = [xp.dtm for xp in self.xps]

    def reset_next_port(self):
        # Some XPs may have more ports than watchpoints, e.g. three ports but
        # only two upload watchpoints and two download watchpoints.
        # Hence, we might not be able to trace all ports at the same time,
        #
        # So we progressively iterate through each selected port on each selected XP.
        # 'next_port' indicates the index (into the port list) of the next port to do for this XP.
        for dtm in self.dtms:
            dtm.next_port = 0

    def construct_watchpoint(self):
        """
        Use the command-line options to construct a watchpoint filter.
        Depending on the user's choice of CHI fields, this might require
        a single watchpoint or a pair of watchpoints.
        This routine doesn't program any watchpoints.
        """
        if self.opts.data is not None:
            self.opts.vc = 3
            self.opts.dataid = (self.opts.data & 2)
            self.data_format = 5 + (self.opts.data & 1)
        if self.opts.wp_val or self.opts.wp_mask:
            M = cmnwatch.MatchMask(self.opts.wp_val, self.opts.wp_mask)
        else:
            M = None
        try:
            if self.opts.watchpoint is not None:
                wps = cmnwatch.parse_short_watchpoint(self.opts.watchpoint, self.opts, cmn_version=self.C.product_config)
            else:
                wps = cmnwatch.match_obj(self.opts, chn=self.opts.vc, up=self.opts.up, cmn_version=self.C.product_config, mask=M)
        except cmnwatch.WatchpointError as e:
            print("Can't do this watchpoint: %s" % e, file=sys.stderr)
            sys.exit(1)
        wps.finalize()
        if self.opts.verbose:
            print("Watchpoint (groups %s)" % str(wps.grps()))
            print("  %s" % wps)
        self.wps = wps
        if self.opts.data is not None and self.wps.is_multigrp():
            print("Can't do DAT header+data with multi-group matching", file=sys.stderr)
            sys.exit(1)

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
        n_groups = len(self.wps.grps())
        if self.opts.data is not None:
            n_groups *= 2
        printed = False
        for xp in self.xps:
            n_ports = len(xp.dtm.capture_port_list)
            if n_groups > len(xp.dtm.capture_port_list):
                if warn and not printed:
                    print("%s monitoring %u ports, can't set up %u-group watchpoint without rotation" % (xp, n_ports, n_groups))
                    printed = True
                need_rotation = True
        return need_rotation

    def check_for_aliasing(self):
        """
        Check for aliasing between XPs
        """
        assert False, "This function for testing only"
        for xp1 in self.C.XPs():
            for xp2 in self.C.XPs():
                xp2.dtm.dtm_disable()
            xp1.dtm.dtm_enable()           # enable just xp1
            # check that only this one got enabled
            for xp2 in self.C.XPs():
                assert xp2.dtm.dtm_is_enabled() == (xp1 == xp2), "aliasing check failed"
            xp1.dtm.dtm_disable()

    def configure_xp(self, xp):
        self.configure_dtm(xp.dtm)

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
            print("%s: configure trace (ports=%s next_port=%d)" % (dtm, str(dtm.capture_port_list), dtm.next_port))
        if not dtm.capture_port_list:
            dtm.dtm_disable()
            for wp in range(0, 4):
                dtm.dtm_set_watchpoint(wp, gen=False)
            return
        # In read (non-ATB) mode, it appears that the FIFO starts filling as soon as
        # trace_no_atb is set, regardless of dtm_enable. So make sure the
        # watchpoints are configured and then clear the FIFO.
        dtm.dtm_disable()
        if not self.atb:
            dtm_control = cmn_devmem.CMN_DTM_CONTROL_TRACE_NO_ATB
        else:
            dtm_control = 0
        #if opts.fifo:
        #    xp.set64(cmn_devmem.CMN_DTM_CONTROL, 0x08)
        #else:
        #    xp.clear64(cmn_devmem.CMN_DTM_CONTROL, 0x08)    # send to ATB not FIFO
        # Set up WP0 to trace P0 and WP1 to trace P1
        for wp in [0, 1]:
            dev = dtm.capture_port_list[dtm.next_port]
            for (up, off) in [(True, 0), (False, 2)]:
                if self.wps.up != (not up):          # i.e. wps is free or matches WPs type
                    for (j, grp) in enumerate(self.wps.grps()):
                        M = self.wps.wps[grp]
                        combine = (self.wps.is_multigrp() and (j == 0))
                        w = cmn_devmem.DTMWatchpoint(dtm=dtm, pkt_gen=True,
                                                     value=M.val, mask=M.mask,
                                                     type=self.opts.format, cc=self.opts.cc,
                                                     ctrig=self.opts.cross_trigger,
                                                     dbgtrig=self.opts.debug_trigger,
                                                     dev=dev, chn=self.wps.chn, grp=M.grp,
                                                     exclusive=M.exclusive, combine=combine)
                        if o_verbose >= 2:
                            print("%s: set watchpoint WP%u: %s" % (dtm, wp+off+j, w))
                        dtm.dtm_wp_set(wp+off+j, w)
                    if self.opts.data is not None:
                        # Watchpoint is matching the same DAT flits, but capturing data
                        w.type = self.data_format
                        dtm.dtm_wp_set(wp+off+1, w)
                else:
                    dtm.dtm_set_watchpoint(wp+off, gen=False)
            dtm.next_port += 1
            if dtm.next_port == len(dtm.capture_port_list):
                dtm.next_port = 0
            if self.wps.is_multigrp() or (self.opts.data is not None):
                break        # we already used both watchpoints
            if len(dtm.capture_port_list) <= 1:
                break
            # else loop round and see if we can do another port
        #dtm.dtm_enable()
        if not self.atb:
            # Clearing the FIFO only works if trace_no_atb is already set
            dtm.dtm_set64(cmn_devmem.CMN_DTM_CONTROL_off, cmn_devmem.CMN_DTM_CONTROL_TRACE_NO_ATB)
            dtm.dtm_clear_fifo()
        dtm.dtm_write64(cmn_devmem.CMN_DTM_CONTROL_off, dtm_control)   # DTM is still disabled
        if self.opts.count:
            # Program the four local counters to count the four WPs (events 0..3).
            # The DTC has eight global counters which can catch rollovers from the
            # local counters. We have eight DTC counters so we might as well distribute
            # the XP rollovers between them.
            dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0)     # disable PMU while we're programming it
            dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_PMEVCNT_off, 0)    # clear the four local counters
            #dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0x0302010000000001)
            if wp == 0:
                dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0x03020100642000f1)
            else:
                dtm.dtm_write64(cmn_devmem.CMN_DTM_PMU_CONFIG_off, 0x03020100753100f1)
        # "The final step is to write 1'b1 to dtm_control.dtm_enable to enable the WP."
        if self.opts.verbose >= 2:
            print("enable DTM on %s" % dtm)
        dtm.dtm_enable()

    def trace_start(self):
        if self.opts.verbose:
            print("cmn_capture: start...")
        self.C.dtc_disable()
        if False:
            # Reset all the XP DTMs (even the ones we're not interested in) and stop
            # them generating ATB trace packets.
            for dtm in self.C.DTMs():
                dtm.dtm_disable()
                dtm.dtm_set64(cmn_devmem.CMN_DTM_CONTROL_off, cmn_devmem.CMN_DTM_CONTROL_TRACE_NO_ATB)
                dtm.dtm_clear_fifo()
        self.C.dtc_enable()
        for xp in self.xps:
            # Here we are scanning just the XPs that we want to monitor.
            # The others are left disabled.
            self.configure_xp(xp)

        if self.opts.count:
            # We've programmed the local PMUs in the DTMs, and even though we aren't
            # forwarding local counts to the DTC, the DTMs won't count until we set
            # the global PMU enable.
            for dtc in self.C.DTCs():
                dtc.pmu_clear()
                dtc.pmu_enable()

        # Start CMN generating ATB trace
        if self.opts.cg_disable:
            for dtc in self.C.DTCs():
                dtc.set64(cmn_devmem.CMN_DTC_CTL, cmn_devmem.CMN_DTC_CTL_CG_DISABLE)    # experimental
        self.C.dtc_enable()
        if False:
            # Generate some more alignment packets in the ATB stream
            for _ in range(0, 3):
                self.C.dtc_disable()
                self.C.dtc_enable()

    def trace_readout(self, fifocap=None, clear=True):
        """
        Check for trace and accumulate it into a map:
            xp -> wp# -> (w, data, cc)
        """
        if fifocap is None:
            fifocap = {}
        for xp in self.xps:
            if xp not in fifocap:
                fifocap[xp] = {}
        for xp in self.xps:
            fe = xp.dtm.dtm_fifo_ready()
            for e in range(0, 4):
                if fe & (1 << e):
                    w = xp.dtm.dtm_wp_config(e, value=False)
                    (data, cc) = xp.dtm.dtm_fifo_entry(e)
                    if self.opts.immediate:
                        self.TV.decode_packet(xp, e, w, data, cc)
                    ee = (e - 1) if (self.opts.data is not None and (e & 1)) else e
                    if ee not in fifocap[xp]:
                        fifocap[xp][ee] = []
                    fifocap[xp][ee].append((w, data, cc))
            if clear:
                xp.dtm.dtm_clear_fifo()
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
        for i in range(self.opts.samples):
            # Wait for a while
            time.sleep(self.opts.sleep)
            self.trace_readout(fifocap, clear=True)
        self.trace_stop()
        return fifocap

    def show_captured_trace(self, fifocap):
        """
        Decode and print some flits captured by trace().
        """
        for xp in self.xps:
            for e in sorted(fifocap[xp].keys()):
                for (w, data, cc) in fifocap[xp][e]:
                    self.TV.decode_packet(xp, e, w, data, cc)

    def trace_stop(self):
        # Stop generating trace, and collect it
        self.C.dtc_disable()
        for xp in self.xps:
            xp.dtm.dtm_disable()
        if self.opts.verbose >= 3:
            self.show_status()
        elif self.opts.verbose >= 2:
            self.show_dtm()

    def show_watchpoint_counts(self):
        """
        Show counts of watchpoint matches - assuming we programmed the PMU.
        """
        if self.opts.count:
            # Show watchpoint counts
            for xp in self.xps:
                # Read the local counters
                c = xp.dtm.dtm_read64(cmn_devmem.CMN_DTM_PMU_PMEVCNT_off)
                for wp in range(0,4):
                    print(" %6u" % bits(c, wp*16, 16), end="")
                print()

    def show_fifos(self):
        """
        Show DTM FIFO contents
        """
        # Show data from the FIFOs in the XPs
        for xp in self.xps:
            self.show_fifo(xp.dtm)

    def show_fifo(self, dtm):
        fe = dtm.dtm_fifo_ready()
        for e in range(0, 4):
            if fe & (1 << e):
                w = xp.dtm.dtm_wp_config(e, value=False)
                (data, cc) = dtm.dtm_fifo_entry(e)
                self.TV.decode_packet(dtm.xp, e, w, data, cc)

    def show_status(self):
        """
        Show all XPs and DTCs, even non-involved
        """
        for xp in self.C.XPs():
            xp.show()
        for dtc in self.C.DTCs():
            cmn_dtstat.print_dtc(dtc)

    def show_dtm(self):
        for xp in self.xps:
            cmn_dtstat.print_dtm_list(xp)
        for dtc in self.C.DTCs():
            cmn_dtstat.print_dtc(dtc)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN flit capture tool")
    add_trace_arguments(parser)
    parser.add_argument("--include-polling", action="store_true", help="include CMN polling reqs from script")
    parser.add_argument("--histogram", action="store_true", help="print histogram of packet types")
    parser.add_argument("--setup", action="store_true", help="set up but don't capture")
    parser.add_argument("--inspect", action="store_true", help="inspect captured data")
    parser.add_argument("--no-clear", action="store_true", help="don't clear captured data")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    if opts.setup and opts.inspect:
        print("Setup and inspect mode should be used separately", file=sys.stderr)
        sys.exit(1)
    if (opts.setup or opts.inspect) and opts.histogram:
        print("In setup/inspect mode, actions like --histogram are not available", file=sys.stderr)
        sys.exit(1)
    o_include_polling = opts.include_polling
    if opts.histogram:
        vis = CMNHist()
    else:
        vis = CMNVis()
    ts = TraceSession(opts, handler=vis, init=(not opts.inspect))
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
