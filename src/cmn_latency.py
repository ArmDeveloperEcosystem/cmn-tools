#!/usr/bin/python

"""
Measure latency of CMN transactions

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys
import os
import time

import cmn_devmem as cmn
import cmn_devmem_find
import cmn_base
import cmn_json
from cmn_enum import *
import cmnwatch
from cmn_flits import CMNTraceConfig, CMNFlitGroup
import cmn_dtstat


o_verbose = 0

g_system = None

def lookup_cpu(cpu_num):
    """
    Given a CPU number, find the CPU object, with CMN instance, crosspoint and port
    """
    global g_system
    if g_system is None:
        g_system = cmn_json.system_from_json_file()
    try:
        cpu = g_system.cpu(cpu_num)
    except cmn_base.CMNNoCPUMappings as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    if o_verbose:
        print("CPU#%u is %s" % (cpu_num, cpu))
    return cpu


def check_fifo_clear(dtm, msg=""):
    fe = dtm.dtm_fifo_ready()
    if fe != 0:
        print("%s: FIFO still has data (0x%x)%s" % (dtm, fe, msg), file=sys.stderr)
        if False:
            time.sleep(60)
            sys.exit()
    return fe == 0


def set_nomatch_watchpoints(dtm):
    """
    Change the watchpoints so they don't pick up anything. DTM must be disabled.
    """
    if o_verbose >= 2:
        print("%s: set watchpoints to not match anything" % (dtm))
    dtm.dtm_disable()
    for i in range(0, 4):
        dtm.dtm_set_watchpoint(i, val=0xcccccccccccccccc, mask=0, gen=False)


def really_clear_fifo(dtm):
    """
    Completely clear watchpoint state, including resetting all the watchpoint configuration.
    """
    if o_verbose >= 2:
        print("%s: really clear FIFO" % (dtm))
    dtm.dtm_disable()     # to be on the safe side
    dtm.dtm_set_control(atb=False)
    dtm.dtm_enable()
    dtm.dtm_clear_fifo()
    dtm.dtm_disable()
    check_fifo_clear(dtm, msg=" after clearing")
    #dtm.dtm_set_control(atb=True)
    #check_fifo_clear(dtm, msg=" after setting control")
    set_nomatch_watchpoints(dtm)
    check_fifo_clear(dtm, msg=" after setting watchpoints to null")
    dtm.dtm_set_control(atb=False)
    if check_fifo_clear(dtm, msg=" after setting ATB to false"):
        if o_verbose >= 2:
            print("%s: cleared" % dtm)
    else:
        print("%s: failed to clear" % dtm)


def sub16(a, b):
    """
    Subtract two numbers, modulo 2**16, as for wrapping counters.
    """
    if a < b - 300:
        a += 0x10000
    return a - b

assert sub16(5, 2) == 3
assert sub16(3, 4) == -1
assert sub16(1, 0xffff) == 2


class NotEnoughWatchpoints(Exception):
    """
    Each DTM has only two upload and two download watchpoints.
    Depending on the number of tag-matching watchpoints requested, we might run out of physical watchpoints,
    and raise this exception.
    """
    def __init__(self, dtm, up):
        self.dtm = dtm            # DTM which ran out of watchpoints
        self.up = up

    def __str__(self):
        return "%s: ran out of %s watchpoints" % (self.dtm, ["download", "upload"][self.up])


class Watchpoint:
    """
    A watchpoint as programmed into a specific DTM WP.
    Caches the watchpoint configuration.
    """
    def __init__(self, dtm, wp_num):
        self.dtm = dtm
        self.trace_config = CMNTraceConfig(dtm.C.product_config.product_id, has_MPAM=dtm.C.product_config.mpam_enabled, cmn_product_revision=dtm.C.product_config.revision_major)
        self.wp = wp_num
        w = dtm.dtm_wp_config(wp_num)
        (self.dev, self.vc, self.ty, self.cce) = (w.dev, w.chn, w.type, w.cc)
        if o_verbose >= 2:
            print("Trace config: %s %s %s %s %s" % (self.trace_config, self.dev, self.vc, self.ty, self.cce))

    def is_ready(self):
        return self.dtm.dtm_is_wp_ready(self.wp)

    def get_data_cc(self):
        if self.is_ready():
            return self.dtm.dtm_fifo_entry(self.wp)
        else:
            return None

    def get_fg(self):
        """
        If this watchpoint has data ready (i.e. a flit, for format=4) then retrieve and decode it.
        If nothing ready, return None.
        """
        x = self.get_data_cc()
        if x is not None:
            if o_verbose:
                assert x == self.get_data_cc(), "%s: watchpoint FIFO contents are unstable" % self
            (data, cc) = x
            fg = CMNFlitGroup(self.trace_config, cmn_seq=self.dtm.xp.C.seq, nodeid=self.dtm.xp.node_id(), WP=self.wp, DEV=self.dev, VC=self.vc, format=self.ty, cc=cc, payload=data)
            if o_verbose:
                print("%s: captured %s" % (self, fg))
            return fg
        else:
            return None

    def __str__(self):
        return "%s WP#%u" % (self.dtm, self.wp)


class CapturedData:
    """
    Flits or other data captured from a set of watchpoints.
    Contains the "request" flit and one or more "response" flits.
    N.b. although the "request" flit is usually present, we support scanning for
    existing tagged flits only (e.g. detect use of SPE), and in that case req will be None.
    """
    def __init__(self, req=None):
        self.req = req
        self.rsp = []       # tuples of (Watchpoint, CMNFlitGroup)

    def __str__(self):
        s = "Captured(%s,%s)" % (self.req, ','.join([str(rsp) for rsp in self.rsp]))
        return s

    def latency(self, rsp):
        """
        Get the latency of a response packet, relative to the baseline request.
        """
        return sub16(rsp.cc, self.req.cc) if (self.req is not None) else None

    def ordered_responses(self):
        """
        Yield the responses in increasing order of latency
        """
        if self.req is None:
            # no baseline for latency - just return them in order
            return sorted(self.rsp, key=(lambda rt:rt[1].cc if rt[1] is not None else 99999))
        return sorted(self.rsp, key=(lambda rt:(self.latency(rt[1]) if rt[1] is not None else 99999)))

    def print(self):
        print()
        print("      %s" % (self.req if (self.req is not None) else "<open>"))
        if not self.rsp:
            # None of the tag-catcher WPs saw anything
            print("        no response")
            return 1
        n_caught = 0
        # Show all the tagged flits we caught. Some of them might be
        # for unrelated (later) requests though. TBD we could inspect
        # fields such as TGTID and TXNID, but this would require careful
        # analysis of CHI scenarios to identify which comparisons are
        # in fact valid.
        for (rw, rsp) in self.ordered_responses():
            if not rsp:
                # get_capture() would only have put this in in verbose mode
                print("        %s - not seen" % (rw))
                continue
            is_same = (self.req is not None and self.req.payload == rsp.payload)   # doesn't work - RSP will have TAG set
            lat = self.latency(rsp)
            print("%s%5u  %s" % (" !"[is_same], (lat if lat is not None else rsp.cc), rsp))
            n_caught += 1
        return 1 + n_caught


_chi_channels = ["REQ", "RSP", "SNP", "DAT"]

class PortChannel:
    """
    A specific CHI channel on a specific XP port, possibly also with a LPID to match.
    """
    def __init__(self, xp=None, dev=None, chn=None, up=None, lpid=None):
        self.xp = xp     # XP object, including CMN instance
        self.dev = dev   # port number
        self.chn = chn
        self.up = up
        self.lpid = lpid

    def inverse(self, chn=None):
        return PortChannel(xp=self.xp, dev=self.dev, chn=(chn if chn is not None else self.chn), up=(not self.up))

    def dtm(self):
        # Get the DTM for the port, handling the multiple-DTM case
        return self.xp.port_dtm(self.dev)

    def __repr__(self):
        return str(self)

    def __str__(self):
        s = "%s:P%s:%s:%s" % (self.xp, self.dev, _chi_channels[self.chn], ["down", "up"][self.up])
        return s


class LatencyMonitor:
    """
    Manage configuration for monitoring latency using multiple watchpoints.
    We configure a single watchpoint (on a single DTM) to set TraceTag,
    and one or more watchpoints to catch flits with TraceTag set.

    Only upload watchpoints cause TraceTag to be set on flits.

    "WP0 and WP1 are assigned to flit uploads.
     WP2 and WP3 are assigned to flit downloads."
    """
    def __init__(self, Cs, verbose=0, poll_time=0.01):
        self.verbose = verbose
        self.poll_time = poll_time
        self.Cs = Cs          # All CMNs in the system
        self.n_captured = 0
        # To work around unwanted captures, we use a no-match WP config in between each capture.
        # Save the originaly requested configuration.
        self.pending_req = None
        self.pending_rsps = []
        self.init()
        self.need_reinit_and_program = True

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        self.close()

    def __str__(self):
        s = str(self.wp_req) if self.wp_req else "unset"
        if self.wp_rsps:
            s += ",watching:%u" % len(self.wp_rsps)
        s = "LatencyMonitor(%s)" % s
        return s

    def init(self):
        """
        Initialize DTMs to a known good state.
        All watchpoints are don't match anything, all FIFOs are empty, all DTMs are disabled.
        """
        self.dtms = {}        # All DTMs currently in use, mapped to bitset of WPs in use
        self.watching = {}    # DTM/channel/direction combination, so we watch only once
        self.wp_req = None    # The single tag-setting watchpoint (always an upload WP)
        self.wp_rsps = []     # All the tag-checking watchpoints
        self.dtc_enable()
        if self.verbose >= 2:
            print("Clearing previous watchpoints...")
        for dtm in self.all_DTMs():
            set_nomatch_watchpoints(dtm)
        for dtm in self.all_DTMs():
            really_clear_fifo(dtm)
            dtm.dtm_disable()
        self.check_all_FIFOs_empty(msg="initialization")

    def check_all_FIFOs_empty(self, msg=""):
        n_enabled = 0
        n_nonempty = 0
        for dtm in self.all_DTMs():
            if dtm.dtm_is_enabled():
                n_enabled += 1
            if dtm.dtm_fifo_ready() != 0:
                n_nonempty += 1
                print("%s: FIFO not empty (0x%x): %s (DTM enabled: %s)" % (dtm, dtm.dtm_fifo_ready(), msg, dtm.dtm_is_enabled()))
        if (not n_nonempty and self.verbose) or n_enabled > 0:
            print("%s: all FIFOs empty (%u DTMs enabled): %s" % (self, n_enabled, msg))
        return n_nonempty

    def all_DTMs(self):
        for C in self.Cs:
            for dtm in C.DTMs():
                yield dtm

    def active_DTMs(self):
        return self.dtms.keys()

    def is_using_wp(self, dtm, wpnum):
        return (self.dtms[dtm] & (1 << wpnum)) != 0

    def _set_wp(self, dtm, dev, wps, format=4):
        assert wps.up is not None
        if dtm not in self.dtms:
            self.dtms[dtm] = 0x0        # bitmask: no watchpoints in use in this DTM yet
        wpnum = 0 if wps.up else 2
        if self.is_using_wp(dtm, wpnum):
            if wps.is_multigrp() or self.is_using_wp(dtm, wpnum+1):
                raise NotEnoughWatchpoints(dtm, wps.up)
            wpnum += 1
        wps.finalize()
        assert wps.grps(), "empty watchpoint: %s" % wps
        for (i, grp) in enumerate(wps.grps()):
            self.dtms[dtm] |= (1 << (wpnum+i))
            M = wps.wps[grp]
            if self.verbose:
                print("%s: set watchpoint %s" % (dtm, M))
            dtm.dtm_set_watchpoint(wpnum+i, chn=wps.chn, format=format, cc=True, dev=dev, val=M.val, mask=M.mask, group=M.grp, combine=wps.is_multigrp())
        return Watchpoint(dtm, wpnum)

    def set_req(self, pc, wps, format=4):
        """
        Set the (single) tag-setting watchpoint.
        """
        assert self.pending_req is None, "only one tag-setting watchpoint allowed, %s and %s" % (self.pending_req, pc)
        assert wps.up, "tag-setting watchpoint must be upload: %s" % (wps)
        self.pending_req = (pc, wps, format)

    def _set_req(self, pc, wps, format=4):
        assert pc.chn == wps.chn and pc.up == wps.up
        assert self.wp_req is None, "only one tag-setting watchpoint allowed, %s and %s" % (self.wp_req, pc)
        dtm = pc.dtm()
        dtm.dtm_set_control(atb=False, tag=1)
        self.wp_req = self._set_wp(dtm, pc.dev, wps, format=format)

    def add_rsp(self, pc, format=4):
        self.pending_rsps.append((pc, format))

    def _add_rsp(self, pc, format=4):
        """
        Add a tag-matching watchpoint. The CMN TRM indicates that any flits with the
        tag set will be captured by any watchpoint on the channel - i.e. the match on
        TraceTag=1 is not necessary, and any other match fields would be ignored.
        """
        (xp, dev, chn, up) = (pc.xp, pc.dev, pc.chn, pc.up)
        dtm = pc.dtm()
        key = (dtm, dev, chn, up)
        if key in self.watching:
            if self.verbose:
                print("Duplicate tag-matching watchpoint" % (self.watching[key]))
            return
        rwps = cmnwatch.match_kwd(chn=chn, up=up, cmn_version=dtm.C.product_config, tracetag=1)
        wp = self._set_wp(dtm, dev, rwps, format=format)
        self.wp_rsps.append(wp)
        self.watching[key] = wp

    def program_pending(self):
        """
        Write the pending WP configurations into the DTMs.
        """
        for (pc, format) in self.pending_rsps:
            self._add_rsp(pc, format)
        if self.pending_req is not None:
            (pc, wps, format) = self.pending_req
            self._set_req(pc, wps, format)
        if self.verbose:
            print("Monitoring:")
            print("  Lead:   %s" % (self.wp_req))
            print("  Follow: %s" % (', '.join([str(w) for w in self.wp_rsps])))
        self.need_reinit_and_program = False

    def get_capture(self):
        """
        Check the FIFOs to see if we've got a request and response. Return as a CapturedData object.
        Return None if nothing ready in the tag-setting watchpoint.
        """
        if self.wp_req is not None:
            req = self.wp_req.get_fg()
            if req is None:
                # Haven't captured an initial (tag-setting) packet yet
                return None
            self.wp_req.dtm.dtm_disable()              # Stop any more captures
        else:
            req = None
        self.n_captured += 1
        cf = CapturedData(req)
        # Go through the tag-catcher WPs in their original registration order,
        # collecting any tagged flits
        for wp_rsp in self.wp_rsps:
            rsp = wp_rsp.get_fg()
            if rsp is not None or opts.verbose:
                cf.rsp.append((wp_rsp, rsp))
        return cf

    def dump_fifo(self):
        """
        Decode the current FIFO contents, whatever they are
        """
        for dtm in self.dtms.keys():
            self.dump_fifo_dtm(dtm)

    def dump_fifo_dtm(self, dtm):
        if Watchpoint is None:
             # We're in Python2 shutdown, module globals are disappearing
             return
        fe = dtm.dtm_fifo_ready()
        if fe == 0 and not self.verbose:
            print("%s: FIFO is empty" % dtm)
            return
        print("%s: current FIFO contents (ready=0x%x):" % (dtm, fe))
        for wp in range(0, 4):
            if (fe & (1<<wp)) or self.verbose:
                fg = Watchpoint(dtm, wp).get_fg()
                print("  #%u: %s" % (wp, fg))

    def clear(self):
        self.dtm_enable()
        for dtm in self.active_DTMs():
            dtm.dtm_clear_fifo()

    def dtc_disable(self):
        for C in self.Cs:
            C.dtc_disable()

    def dtc_enable(self):
        for C in self.Cs:
            C.dtc_enable(cc=True)

    def dtm_disable(self):
        for dtm in self.active_DTMs():
            dtm.dtm_disable()
        self.dtc_disable()

    def dtm_enable(self):
        self.dtc_enable()
        if self.verbose:
            print("Enable all active DTMs...")
        for dtm in self.active_DTMs():
            dtm.dtm_enable()

    def reset(self):
        """
        Reset to a good state, with the possibility of resuming.
        """
        if Watchpoint is None:
            # In Python2 shutdown, globals are disappearing
            return
        if self.verbose >= 2:
            print("Resetting state...")
            self.show_dtm()
            self.dump_fifo()
            print("Now setting no-match watchpoints...")
        for dtm in self.active_DTMs():
            set_nomatch_watchpoints(dtm)
        self.clear()
        if self.verbose >= 2:
            print("Dumping FIFO contents (should be empty)...")
            self.dump_fifo()
        if self.verbose >= 2:
            print("Reset done.")

    def close(self):
        self.reset()

    def __del__(self):
        self.close()

    def show_dtm(self):
        for dtm in self.active_DTMs():
            cmn_dtstat.print_dtm(dtm, show_pmu=False)

    def get_next(self, timeout=1.0):
        """
        Get a CapturedData object, or time out returning None.
        We poll more frequently, as set by self.poll_time.
        """
        if self.need_reinit_and_program:
            self.init()
            self.program_pending()
        t_end = time.time() + timeout
        while time.time() < t_end:
            time.sleep(opts.poll_time)
            cf = self.get_capture()
            if cf is not None:
                self.need_reinit_and_program = True
                return cf
        return None

    def get(self, timeout=1.0):
        """
        Yield a stream of CapturedData objects, until we time out.
        """
        while True:
            cf = self.get_next(timeout=timeout)
            if not cf:
                return
            yield cf

    def handle_capture(self, cf):
        """
        Handle a CapturedData object. Subclass can override.
        Default implementation: print the decode to stdout.
        """
        cf.print()

    def run(self, captures=1, wait_time=0.0):
        """
        Run a monitoring session. The watchpoints are already programmed.
        Code is currently complicated by trying to work around WPs capturing data even
        when dtm_enable=0 - it cycles through init/program_pending/reset_watchpoints.
        """
        if self.verbose >= 2:
            print("DTM status before enabling...")
            for dtm in self.active_DTMs():
                cmn_dtstat.print_dtm(dtm, show_pmu=False)
            self.dump_fifo()
            self.show_dtm()
        """
        At this point, all the FIFOs are empty and DTMs are disabled.
        """
        assert False, "no longer used"
        #self.program_pending()
        self.dtm_enable()
        need_init = True
        while self.n_captured < captures:
            if need_init:
                self.init()
                self.program_pending()
                need_init = False
            if self.verbose:
                print("Waiting...")
            time.sleep(wait_time)
            cf = self.get_capture()
            if cf is not None:
                self.handle_capture(cf)
                self.clear()
                need_init = True
            elif self.verbose:
                print("Nothing captured")
        self.reset()


def genlist(ls, x):
    if x is not None:
        yield x
    else:
        for x in ls:
            yield x


def port_class(Cs, spec):
    """
    Yield all ports of a given class
    """
    props = cmn_properties(spec)
    for C in Cs:
        for xp in C.XPs():
            for p in xp.ports(props):
                if o_verbose:
                    print("%s -> %s P%u" % (spec, xp, p))
                yield (xp, p)


def port_channels(Cs, spec, default_pc):
    """
    Given a port/channel/direction specifier, yield one or more PortChannel objects

    Specifiers are built out of several components, separated by ':':
      - an XP identifier ("0x40" etc.)
      - a port number ("P0" etc.)
      - a CHI channel name (REQ/RSP/SNP/DAT)
      - a watchpoint direction ("up", "down")
      - a LPID (to distinguish CPUs within a DSU)
    """
    if default_pc is not None:
        (xp, dev, chn, up) = (default_pc.xp, default_pc.dev, default_pc.chn, default_pc.up)
    else:
        (xp, dev, chn, up) = (None, None, None, None)
    if len(Cs) == 1:
        C = Cs[0]   # if only one CMN instance, use it
    else:
        C = None    # instance not specified yet
    lpid = None     # only relevant to the request watchpoint (upload)
    wilds = []
    xp_explicit = False
    if spec.upper() == "NONE":
        yield None   # only used on request, if we want an "open" scenario with no tag-setting
        return
    for comp in spec.upper().split(':'):
        if comp in _chi_channels:
            chn = _chi_channels.index(comp)
        elif comp == "UP":
            up = True
        elif comp == "DOWN":
            up = False
        elif comp.startswith("CMN") and len(comp) == 4:
            # Specify the CMN instance, for dual-socket etc.
            try:
                cmn_instance = int(comp[3:])
                assert cmn_instance < len(Cs)
                C = Cs[cmn_instance]
                if o_verbose:
                    print("Selected CMN: %s" % C)
            except Exception:
                print("%s: invalid CMN instance '%s'" % (spec, comp), file=sys.stderr)
                sys.exit(1)
            xp = None
            dev = None
        elif comp.startswith("P") and len(comp) == 2 and comp[1] in "0123":
            # Specify the port on the XP
            dev = int(comp[1])
        elif comp.startswith("0X"):
            # A srcid/tgtid - can imply both the XP and port.
            if C is None:
                print("%s: multiple CMN instances in system, must specify instance" % (spec), file=sys.stderr)
                sys.exit(1)
            devid = int(comp, 16)
            (xp, dev, _) = C.XP_port_device(devid)
            xp_explicit = True
        elif comp.startswith("CPU#"):
            # Specify a CPU (RN-F). CPU mapping must have been done.
            try:
                cpu_num = int(comp[4:])
                cpu = lookup_cpu(cpu_num)
            except ValueError:
                print("%s: invalid CPU number '%s'" % (spec, comp), file=sys.stderr)
                sys.exit(1)
            except KeyError:
                print("%s: non-existent CPU#%u" % (spec, cpu_num), file=sys.stderr)
                sys.exit(1)
            C = Cs[cpu.port.CMN().seq]
            xp = C.XP(cpu.port.xp.node_id())
            dev = cpu.port.port
            if cpu.lpid is not None:
                lpid = cpu.lpid
            xp_explicit = True
        elif comp.startswith("XP#"):
            # Specify an XP by logical id. Does not specify the port.
            if C is None:
                print("%s: multiple CMN instances in system, must specify instance" % (spec), file=sys.stderr)
                sys.exit(1)
            try:
                xpn = int(comp[3:])
            except ValueError:
                print("%s: invalid logical number '%s'" % (spec, comp), file=sys.stderr)
                sys.exit(1)
            xp = C.node_by_type_and_logical_id(CMN_NODE_XP, xpn)
            xp_explicit = True
        elif cmn_properties(comp, check=False) is not None:
            # Specify a port class, like HN-F etc.
            wilds.append(comp)
            if not xp_explicit:
                xp = None
                dev = None
        else:
            print("%s: unrecognized component '%s'" % (spec, comp), file=sys.stderr)
            sys.exit(1)
    if not wilds:
        if xp is None or dev is None:
            print("%s: must specify CMN port(s)" % (spec), file=sys.stderr)
            sys.exit(1)
        pc = PortChannel(xp=xp, dev=dev, chn=chn, up=up, lpid=lpid)
        if o_verbose:
            print("%s -> %s" % (spec, pc))
        yield pc
    else:
        # User has specified a class of nodes e.g. "RN-F"
        # They might also have specified XP and/or port number
        n_found = 0
        Cs = genlist(Cs, C)
        for w in wilds:
            for (wxp, wdev) in port_class(Cs, w):
                if xp is not None and wxp != xp:
                    continue
                if dev is not None and wdev != dev:
                    continue
                yield PortChannel(xp=wxp, dev=wdev, chn=chn, up=up, lpid=lpid)
                n_found += 1
        if n_found == 0:
            print("No ports matching '%s'" % str(wilds), file=sys.stderr)


def list_port_channels(Cs, specs, default_pc):
    for spec in specs:
        for pc in port_channels(Cs, spec, default_pc):
            yield pc


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Measure CMN transaction latency using TraceTag")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    cmnwatch.add_chi_arguments(parser)
    parser.add_argument("--wait", type=float, default=1.0, help="wait time")
    parser.add_argument("--poll-time", type=float, default=0.01, help="polling time for watchpoint FIFOs")
    parser.add_argument("-N", "--capture", type=int, default=1, help="number of transactions to capture")
    parser.add_argument("--format", type=int, default=4, help="CMN flit capture format")
    parser.add_argument("--diag", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("req", type=str, help="'request' watchpoint specification")
    parser.add_argument("wps", type=str, nargs="*", help="monitor locations")
    opts = parser.parse_args()
    o_verbose = opts.verbose

    Cs = cmn.cmn_from_opts(opts)
    if opts.verbose:
        print("CMNs: %s" % ', '.join([str(c) for c in Cs]))

    reqs = list(port_channels(Cs, opts.req, PortChannel(chn=0, up=True)))
    if len(reqs) != 1:
        print("Only one tag-setting watchpoint allowed, got %u:" % len(reqs), file=sys.stderr)
        for (i, req) in enumerate(reqs):
            if i >= 5:
                print("  ...", file=sys.stderr)
                break
            print("  %s" % req, file=sys.stderr)
        sys.exit(1)
    pc_req = reqs[0]
    if pc_req is not None and not pc_req.up:
        print("CMN requires tag-setting watchpoint to be upload: %s" % (opts.req), file=sys.stderr)
        sys.exit(1)
    if pc_req is not None and pc_req.lpid is not None:
        opts.lpid = pc_req.lpid
    # Now parse the tag-matching watchpoints - default channel is RSP
    pc_rsps = list(list_port_channels(Cs, opts.wps, pc_req.inverse(chn=1) if pc_req else PortChannel(up=False)))
    if not pc_rsps:
        # Default to catching tags on downloads from the tag-setting upload port
        if pc_req is None:
            print("Must specify either tag-setting or tag-matching locations", file=sys.stderr)
            sys.exit(1)
        pc_rsps = [pc_req.inverse(chn=1), pc_req.inverse(chn=3)]

    with LatencyMonitor(Cs, verbose=opts.verbose, poll_time=opts.poll_time) as mon:
        mon.check_all_FIFOs_empty("before programming")
        for pc_rsp in pc_rsps:
            mon.add_rsp(pc_rsp, format=opts.format)
        mon.check_all_FIFOs_empty("after programming tag-catchers")
        if pc_req is not None:
            try:
                m = cmnwatch.match_obj(opts, chn=pc_req.chn, up=pc_req.up, cmn_version=pc_req.xp.C.product_config)
            except cmnwatch.WatchpointBadValue as e:
                print("Bad watchpoint: %s" % e, file=sys.stderr)
                sys.exit(1)
            mon.set_req(pc_req, m, format=opts.format)
        else:
            if opts.verbose:
                print("Not setting primary watchpoint!")
        #mon.check_all_FIFOs_empty("after programming tag-setter")
        #mon.run(captures=opts.capture)
        try:
            # Try programming now, so we can catch if we run out of physical watchpoints
            mon.program_pending()
        except NotEnoughWatchpoints as e:
            print("%s" % e, file=sys.stderr)
            sys.exit(1)
        for cf in mon.get(timeout=opts.wait):
            cf.print()
            if mon.n_captured >= opts.capture:
                break
        if mon.n_captured < opts.capture:
            print("Timed out... %u packets captured." % mon.n_captured)

    if opts.verbose:
        print("Capture session complete.")
