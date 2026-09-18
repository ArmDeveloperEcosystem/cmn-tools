#!/usr/bin/python

"""
Report on status of CMN debug/trace nodes, including rapidly changing
information like PMU counters and FIFO contents.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import sys
import os


import cmn_base
import cmn_devmem
from cmn_devmem_regs import *


def BITS(x, p, n=1):
    return (x >> p) & ((1 << n) - 1)


def BIT(x, p):
    return (x >> p) & 1


def hexstr(x):
    s = ""
    # be portable for Python2/3
    for ix in range(len(x)):
        s += ("%02x" % ord(x[ix:ix+1]))
    return s


def cmn_label(C):
    return "CMN#%u" % C.cmn_seq


def print_dtc(dtc, pfx="", detail=0, sources=None):
    """
    Print summary information about a DTC.
    """
    print("%s%s %sDTC%u %28s:" % (pfx, cmn_label(dtc.C), " *"[dtc.is_DTC0()], dtc.dtc_domain(), dtc), end="")
    ctl = dtc.read64(CMN_DTC_CTL)
    pmcr = dtc.read64(dtc.PM_BASE + CMN_DTC_PMCR_off)
    # Print control bits. These are registered in all DTCs but are only functional in DTC0s.
    print(("    " if (ctl & CMN_DTC_CTL_DT_EN) else " dis"), end="")
    print(("   " if (ctl & CMN_DTC_CTL_CG_DISABLE) else " cg"), end="")
    print((" pmu" if (pmcr & CMN_DTC_PMCR_PMU_EN) else "    "), end="")
    if detail:
        print(" cc=%10x" % dtc.pmu_cc(), end="")       # 40-bit cycle counter
    ecs = dtc.pmu_counters()
    for i in range(0, 8):
        c = dtc.pmu_counter(i)
        print(" %s#%u: %08x" % (" *"[c != ecs[i]], i, c), end="")
    print()
    if detail:
        # Having printed the PMU counters, also print the snapshot
        pcoff = 0 if dtc.C.part_ge_650() else 0x1E00
        ssr = dtc.read64(dtc.PM_BASE + CMN_DTC_PMSSR_off)
        scc = dtc.read64(dtc.PM_BASE + CMN_DTC_PMCCNTRSR_off)
        ovf = dtc.read64(dtc.PM_BASE + CMN_DTC_PMOVSR_off)
        print("%s                     snapshot 0x%08x:" % (pfx, ssr), end="")
        print(" %10x" % scc, end="")
        for i in range(0, 8):
            c = dtc.pmu_counter(i, snapshot=True)
            print(" %s#%u: %08x" % (" *"[c != ecs[i]], i, c), end="")
        print()
        if ovf:
            print("%s      overflow: 0x%x" % (pfx, ovf))
    # wait_for_trigger is documented as DTC0 only
    if (ctl & CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER):
        tc = BITS(ctl, 4, 6)
        print("  Wait for %u cross-triggers" % tc)
    if (ctl & CMN_DTC_CTL_DBGTRIGGER_EN):
        print("  Generate debug trigger")
    if (ctl & CMN_DTC_CTL_ATBTRIGGER_EN):
        print("  Generate ATB trigger")
    ts = dtc.trigger_status()
    if ts is not None:
        (nodeid, wp) = ts
        print("  Trigger status: nodeid=0x%x, watchpoint=%u" % (nodeid, wp))
    if detail:
        print("%s      control: 0x%x" % (pfx, ctl), end="")
        print()
        tracectrl = dtc.read64(CMN_DTC_TRACECTRL)
        print("%s      trace:   0x%x" % (pfx, tracectrl), end="")
        if BITS(tracectrl, 5, 3):
            print(" (TS: %uK cycles)" % (1 << BITS(tracectrl, 5, 3)), end="")
        if tracectrl & CMN_DTC_TRACECTRL_CC_ENABLE:
            print(" (cc_enable)", end="")
        print(" (ATID: 0x%02x)" % dtc.atb_traceid(), end="")
        print()
        claim = dtc.read64(pcoff + CMN_DTC_PC_CLAIM)
        # we expect 0xffffffff indicating all bits can be set but none are set
        if claim != 0xffffffff:
            print("%s      claim:   0x%x" % (pfx, claim))
        print()     # a blank line after the multiple lines in detail mode
        # Run through the PrimeCell id registers, to keep register coverage happy
        for r in range(pcoff+0xFB8, pcoff+0x1000, 8):
             dtc.read64(r)
    if sources is not None:
        print_dtc_sources(sources, pfx=pfx+"    ", pmcr=pmcr)


def dtm_counter_input(pcfg, counter):
    """
    Return the event-selecting counter and its combined-counter annotation.

    See Arm CMN-700 TRM (102308), por_dtm_pmu_config and PMU system
    programming. Counter combination is separate from pairing with a DTC.
    """
    if pcfg & CMN_DTM_PMU_CONFIG_PMEVENTALL_COMBINED:
        first, last = 0, 3
    elif counter < 2 and pcfg & CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED:
        first, last = 0, 1
    elif counter >= 2 and pcfg & CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED:
        first, last = 2, 3
    else:
        return (counter, "")
    note = "combined #%u-#%u" % (first, last)
    if counter != first:
        note += "; carry from #%u" % (counter - 1)
    return (first, note)


def collect_dtc_sources(C, dtc=None, xps=None, if_tag=False):
    """
    Index configured DTM exports by DTC domain and global counter number.

    Reuse the same configuration reads and source decoder as --dtms. Read
    each selected DTM configuration once, and decode only exported inputs.
    Device lookup uses the existing discovery/isolation checks. A None domain
    is retained separately, never guessed to belong to the selected DTC.
    """
    sources = {}
    for dtm in C.DTMs():
        if xps is not None and dtm.xp.node_id() not in xps:
            continue
        domain = dtm.dtc_domain()
        if dtc is not None and domain is not None and domain != dtc:
            continue
        control = None
        if if_tag:
            control = dtm.dtm_read64(CMN_DTM_CONTROL_off)
            if not control & CMN_DTM_CONTROL_TRACE_TAG_ENABLE:
                continue
        pcfg = dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
        if not BITS(pcfg, 4, 4):
            continue
        if control is None:
            control = dtm.dtm_read64(CMN_DTM_CONTROL_off)
        status = []
        if not pcfg & CMN_DTM_PMU_CONFIG_PMU_EN:
            status.append("PMU disabled; inactive configuration")
        if not control & CMN_DTM_CONTROL_DTM_ENABLE:
            status.append("DTM disabled")
        counters = sources.setdefault(domain, [[] for _ in range(8)])
        descriptions = {}
        # Arm CMN-700 TRM, por_dtm_pmu_config: pmevcnt_paired[7:4]
        # enables exports; pmevcnt{0..3}_global_num selects counters A-H.
        for i in range(4):
            if not BIT(pcfg, 4+i):
                continue
            global_counter = BITS(pcfg, 16+i*4, 3)
            first, combined = dtm_counter_input(pcfg, i)
            eis = BITS(pcfg, 32+first*8, 8)
            if eis not in descriptions:
                descriptions[eis] = dtm.pmu_event_input_selector_str(eis)
            notes = status + ([combined] if combined else [])
            counters[global_counter].append((dtm, i, eis, descriptions[eis], notes))
    return sources


def print_dtc_sources(sources, pfx="    ", pmcr=0):
    """List all eight global counters, including those with no known sources."""
    print("%sDTM exports (configured routes):" % pfx)
    for i in range(8):
        entries = sources[i]
        paired = ""
        if BIT(pmcr, 1+(i//2)):
            paired = " [combined #%u-#%u]" % (i & ~1, (i & ~1)+1)
        if not entries:
            print("%s  #%u%s: no known DTM exports" % (pfx, i, paired))
            continue
        print("%s  #%u%s: %u DTM counter%s" % (pfx, i, paired, len(entries), "s" if len(entries) != 1 else ""))
        for dtm, counter, eis, description, notes in entries:
            annotation = " [%s]" % "; ".join(notes) if notes else ""
            print("%s    %s counter #%u%s: input 0x%02x: %s" %
                  (pfx, dtm, counter, annotation, eis, description))


def print_dtm(dtm, pfx="", detail=0, show_pmu=True, if_active=False):
    """
    Print summary information about a DTM, and also PMU config, FIFO contents etc.
    """
    dctl = dtm.dtm_read64(CMN_DTM_CONTROL_off)
    is_enabled = (dctl & CMN_DTM_CONTROL_DTM_ENABLE) != 0
    if if_active and not is_enabled:
        return
    fifo = dtm.dtm_fifo_ready()
    dom = dtm.dtc_domain()
    print("%s %s:" % (pfx, dtm), end="")
    if dom is not None:
        print(" (DTC%u)" % dom, end="")
    if detail > 0:
        print(" DTM control: 0x%08x" % (dctl), end="")
    print(" (%s)" % ("enabled" if is_enabled else "disabled"), end="")
    if dctl & CMN_DTM_CONTROL_TRACE_TAG_ENABLE:
        print(" (trace tag)", end="")
    if dctl & CMN_DTM_CONTROL_SAMPLE_PROFILE_ENABLE:
        print(" (sample profile)", end="")
    print(" (%s)" % ("FIFO" if (dctl & CMN_DTM_CONTROL_TRACE_NO_ATB) else "ATB"), end="")
    print("%s FIFO: 0x%x" % (pfx, fifo), end="")
    print()
    if show_pmu:
        print_dtm_pmu(dtm, pfx=(pfx+"    "))
    print_dtm_watchpoints(dtm, pfx=(pfx+"    "), if_active=if_active, fifo=fifo, print_all=detail)


def print_dtm_list(x, pfx="", detail=0):
    """
    Print all the DTMs in some container - e.g. an XP or a mesh
    """
    for dtm in x.DTMs():
        print_dtm(dtm, pfx=pfx, detail=detail)


def print_dtm_watchpoints(dtm, pfx="    ", if_active=False, fifo=None, print_all=False):
    """
    Show any DTM watchpoints that are "configured" i.e. have a non-trivial (non-reset) setting.
    """
    if fifo is None:
        fifo = dtm.dtm_fifo_ready()
    for wp in range(0, CMN_DTM_N_WP):
        w = dtm.dtm_wp_config(wp)      # Get a DTMWatchpoint object
        if if_active and w.is_inactive():
            continue
        if False:
            print("%sarm_cmn/%s/" % (pfx, w))
        ready = (fifo & (1 << wp)) != 0
        if w.cfg or w.value or w.mask or ready or print_all:
            print("%sWP #%u: ctrl=0x%016x comp=0x%016x mask=0x%016x" % (pfx, wp, w.cfg, w.value, w.mask), end="")
            dir = ["dn", "up"][w.up]
            print(" P%u %s %s type=%u" % (w.dev, dir, w.chn_str(), w.type), end="")
            print(" grp=%u" % w.grp, end="")
            if w.combine:
                print(" combine", end="")
            if w.exclusive:
                print(" exclusive", end="")
            if w.pkt_gen:
                print(" pkt_gen", end="")
            if w.cc:
                print(" cc", end="")
            if w.ctrig:
                print(" cross-trigger", end="")
            if w.dbgtrig:
                print(" debug-trigger", end="")
            if w.is_inactive():
                print(" (inactive)", end="")
            if ready:
                print(" ready", end="")
            print()
        if ready or print_all:
            (data, cc) = dtm.dtm_fifo_entry(wp)
            print("%s  FIFO: %s cc=0x%04x" % (pfx, hexstr(data), cc))


def print_dtm_pmu_config(dtm, pfx="    "):
    """
    Print dynamic configuration of the DTM as an event collector (not generator)
    """
    pcfg = dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
    if pcfg != 0:
        # Show the configuration of each of the DTM's four counters
        cnt = dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
        print("%sPMU config: 0x%016x, counts: 0x%016x" % (pfx, pcfg, cnt))
        for i in range(0, 4):      # DTM four counters
            eis = BITS(pcfg, 32+i*8, 8)    # on CMN-6xx it's only 6 bits
            egc = BITS(pcfg, 16+i*4, 3)
            paired = [0, (BIT(pcfg, 1) | BIT(pcfg, 3)), BIT(pcfg, 3), (BIT(pcfg, 2) | BIT(pcfg, 3))][i]
            print("%s    %s%u:" % (pfx, " *"[paired], i), end="")
            if BIT(pcfg, 4+i):
                print(" [DTC%s global %u]" % ((str(dtm.dtc_domain()) if dtm.dtc_domain() is not None else "?"), egc), end="")
            print(" event 0x%02x: %s" % (eis, dtm.pmu_event_input_selector_str(eis)))
    return pcfg


def print_dtm_pmu(dtm, pfx="    "):
    """
    Show DTM PMU configuration and counts,
    and the PMU export configuration of devices on this DTM's ports.
    """
    print_dtm_pmu_config(dtm, pfx=pfx)
    printed_header = False
    # DTM may be counting events from connected devices.
    for port in dtm.ports():
        for n in port.nodes():
            # A device may have zero, one or several PMUs that can export events to the DTM
            for soff in n.PMU_EVENT_SEL:
                pmu_sel = n.read64(soff)
                if not printed_header:
                    print("%s  Device PMU exports:" % pfx)
                    printed_header = True
                print("%s    %016x  %s" % (pfx, pmu_sel, n))
                pmu_filter = BITS(pmu_sel, 32, 8)
                for e in range(0, CMN_DTM_N_WP):
                    esel = BITS(pmu_sel, e*8, 8)
                    if esel != 0:
                        print("%s          E%u: 0x%x" % (pfx, e, esel), end="")
                        if dtm.C.pmu_events is not None:
                            pix = (soff - n.PMU_EVENT_SEL_BASE) >> 3
                            ev = dtm.C.pmu_events.get_event(n.type(), esel, pmu_index=pix, filter=pmu_filter)
                            if ev is not None:
                                print(" - %s" % ev.name(), end="")
                        print()


def main(argv):
    import argparse
    import cmn_devmem_find
    parser = argparse.ArgumentParser(description="CMN debug/trace tool")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--dtc-enable", action="store_true", help="enable DTC")
    parser.add_argument("--dtc-disable", action="store_true", help="disable DTC")
    parser.add_argument("--dtc-disable-cg", action="store_true", help="disable DTC clock-gating")
    parser.add_argument("--dtc-enable-cg", action="store_true", help="enable DTC clock-gating")
    parser.add_argument("--dtc-reset-cc", action="store_true", help="reset cycle counter to zero")
    parser.add_argument("--dtc-reset", action="store_true", help="reset DTC configuration")
    parser.add_argument("--dtc-atbtrigger", type=int, help="DTC trigger -> ATB trigger")
    parser.add_argument("--dtc-dbgtrigger", type=int, help="DTC trigger -> debug trigger")
    parser.add_argument("--dtc-trigger-wait", type=int, help="number of triggers to wait for")
    parser.add_argument("--dtc-clear-trigger", action="store_true", help="clear DTC trigger status")
    parser.add_argument("--dtc", type=int, help="select DTC (default all DTCs)")
    parser.add_argument("--dtc-sources", action="store_true", help="list DTM counter exports and event programming for each DTC counter")
    parser.add_argument("--dtms", action="store_true", help="show status of all DTMs")
    parser.add_argument("--pmu", action="store_true", help="show PMUs")
    parser.add_argument("--no-pmu", dest="pmu", action="store_false", help="don't show PMUs")
    parser.add_argument("--active", action="store_true", help="show active watchpoints and counters")
    parser.add_argument("--dtm-reset", action="store_true", help="reset DTM programming to match nothing")
    parser.add_argument("--dtm-clear-fifo", action="store_true", help="clear DTM FIFO")
    parser.add_argument("--dtm-enable", action="store_true", help="enable DTM")
    parser.add_argument("--if-tag", action="store_true", help="select DTMs that set TraceTag")
    parser.add_argument("--xp", type=(lambda x:int(x, 16)), action="append", help="select XP (default all XPs/DTMs)")
    parser.add_argument("-d", "--detail", action="count", default=0, help="increase detail")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    Cs = cmn_devmem.cmn_from_opts(opts)
    for C in Cs:
        if C.DTC0() is None:
            print("** %s: has no DTC - node was isolated?" % C, file=sys.stderr)
        sources = collect_dtc_sources(C, dtc=opts.dtc, xps=opts.xp, if_tag=opts.if_tag) if opts.dtc_sources else None
        for dtc in C.DTCs():
            if opts.dtc is None or opts.dtc == dtc.dtc_domain():
                if opts.dtc_disable:
                    dtc.dtc_disable()
                if opts.dtc_reset_cc:
                    dtc.pmu_clear_cc()
                if opts.dtc_reset:
                    dtc.dtc_reset()
                if opts.dtc_clear_trigger:
                    dtc.trigger_clear()
                if opts.dtc_enable:
                    dtc.dtc_enable()
                if opts.dtc_atbtrigger is not None or opts.dtc_dbgtrigger is not None or opts.dtc_trigger_wait is not None:
                    dtc.trigger_set(atbtrigger=opts.dtc_atbtrigger, dbgtrigger=opts.dtc_dbgtrigger, trigger_wait=opts.dtc_trigger_wait)
                if opts.dtc_enable_cg:
                    dtc.clock_disable_gating(disable_gating=False)
                if opts.dtc_disable_cg:
                    dtc.clock_disable_gating(disable_gating=True)
                entries = sources.get(dtc.dtc_domain(), [[] for _ in range(8)]) if sources is not None else None
                print_dtc(dtc, detail=opts.detail, sources=entries)
        if sources is not None and None in sources:
            print("%s DTC?: domain unknown; these exports cannot be assigned to a DTC" % cmn_label(C))
            print_dtc_sources(sources[None])
        if opts.dtms or opts.active or opts.xp or opts.dtm_reset or opts.dtm_enable or opts.dtm_clear_fifo:
            for dtm in C.DTMs():
                if (opts.xp is None or dtm.xp.node_id() in opts.xp) and (not opts.if_tag or dtm.dtm_sets_tracetag()):
                    print_dtm(dtm, detail=opts.detail, if_active=opts.active, show_pmu=opts.pmu)
                    if opts.dtm_reset:
                        dtm.dtm_reset_wps()
                        dtm.dtm_set_control()
                    if opts.dtm_clear_fifo:
                        dtm.dtm_clear_fifo()
                    if opts.dtm_enable:
                        dtm.dtm_enable()


if __name__ == "__main__":
    main(sys.argv[1:])
