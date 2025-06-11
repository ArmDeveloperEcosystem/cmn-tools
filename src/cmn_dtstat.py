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


def print_dtc(dtc, pfx="", detail=0):
    """
    Print summary information about a DTC.
    """
    print("%sDTC%u %24s:" % (pfx, dtc.dtc_domain(), dtc), end="")
    ctl = dtc.read64(CMN_DTC_CTL)
    pmcr = dtc.read64(CMN_DTC_PMCR)
    print(("    " if (ctl & CMN_DTC_CTL_DT_EN) else " dis"), end="")
    print(("  " if (ctl & CMN_DTC_CTL_CG_DISABLE) else " cg"), end="")
    print((" pmu" if (pmcr & CMN_DTC_PMCR_PMU_EN) else "    "), end="")
    if detail:
        print(" %10x" % dtc.pmu_cc(), end="")       # 40-bit cycle counter
    ecs = dtc.pmu_counters()
    for i in range(0, 8):
        c = dtc.pmu_counter(i)
        print(" %s#%u: %08x" % (" *"[c != ecs[i]], i, c), end="")
    print()
    if detail:
        pcoff = 0 if dtc.C.part_ge_650() else 0x1E00
        ssr = dtc.read64(CMN_DTC_PMSSR)
        scc = dtc.read64(CMN_DTC_PMCCNTRSR)
        ovf = dtc.read64(CMN_DTC_PMOVSR)
        print("%s                     snapshot 0x%08x:" % (pfx, ssr), end="")
        print(" %10x" % scc, end="")
        for i in range(0, 8):
            c = dtc.pmu_counter(i, snapshot=True)
            print(" %s#%u: %08x" % (" *"[c != ecs[i]], i, c), end="")
        print()
        if ovf:
            print("%s      overflow: 0x%x" % (pfx, ovf))
        print("%s      control: 0x%x" % (pfx, ctl), end="")
        if ctl & CMN_DTC_CTL_DBGTRIGGER_EN:
            print(" (dbgtrigger)", end="")
        if ctl & CMN_DTC_CTL_ATBTRIGGER_EN:
            print(" (ATB trigger)", end="")
        if ctl & CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER:
            print(" (wait for triggers: %u)" % BITS(ctl, 4, 6), end="")
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


def print_dtm(dtm, pfx="", detail=0, show_pmu=True):
    """
    Print summary information about a DTM, and also PMU config, FIFO contents etc.
    """
    dctl = dtm.dtm_read64(CMN_DTM_CONTROL_off)
    fifo = dtm.dtm_fifo_ready()
    dom = dtm.dtc_domain()
    print("%s %s:" % (pfx, dtm), end="")
    if dom is not None:
        print(" (DTC%u)" % dom, end="")
    if detail > 0:
        print(" DTM control: 0x%08x" % (dctl), end="")
    print(" (%s)" % ("enabled" if (dctl & CMN_DTM_CONTROL_DTM_ENABLE) else "disabled"), end="")
    if dctl & CMN_DTM_CONTROL_TRACE_TAG_ENABLE:
        print(" (trace tag)", end="")
    if dctl & CMN_DTM_CONTROL_SAMPLE_PROFILE_ENABLE:
        print(" (sample profile)", end="")
    print(" (%s)" % ("FIFO" if (dctl & CMN_DTM_CONTROL_TRACE_NO_ATB) else "ATB"), end="")
    print("%s FIFO: 0x%x" % (pfx, fifo), end="")
    print()
    if show_pmu:
        print_dtm_pmu(dtm, pfx=(pfx+"    "))
    print_dtm_watchpoints(dtm, pfx=(pfx+"    "))
    if fifo or detail:
        print_dtm_fifo(dtm, fifo=fifo, pfx=(pfx+"    "), print_all=detail)


def print_dtm_list(x, pfx="", detail=0):
    """
    Print all the DTMs in some container - e.g. an XP or a mesh
    """
    for dtm in x.DTMs():
        print_dtm(dtm, pfx=pfx, detail=detail)


N_WATCHPOINTS = 4

def print_dtm_watchpoints(dtm, pfx="    "):
    for wp in range(0, N_WATCHPOINTS):
        w = dtm.dtm_wp_config(wp)
        if w.cfg or w.value or w.mask:
            print("%sWP #%u: ctrl=0x%016x comp=0x%016x mask=0x%016x" % (pfx, wp, w.cfg, w.value, w.mask), end="")
            chn_name = ["REQ", "RSP", "SNP", "DAT"][w.chn]    # values 4..7 are reserved
            dir = ["up", "up", "dn", "dn"][w.wp]
            print(" P%u %s %s type=%u" % (w.dev, dir, chn_name, w.type), end="")
            print(" grp=%u" % w.grp, end="")
            if w.cfg & dtm.C.DTM_WP_COMBINE:
                print(" combine", end="")
            if w.cfg & dtm.C.DTM_WP_EXCLUSIVE:
                print(" exclusive", end="")
            if w.cfg & dtm.C.DTM_WP_PKT_GEN:
                print(" pkt_gen", end="")
            if w.cfg & dtm.C.DTM_WP_CC_EN:
                print(" cc", end="")
            print()


def print_dtm_fifo(dtm, pfx="", fifo=None, print_all=False):
    if fifo is None:
        fifo = dtm.dtm_fifo_ready()
    if fifo != 0 or print_all:
        for e in range(0, 4):
            if (fifo & (1 << e)) or print_all:
                (data, cc) = dtm.dtm_fifo_entry(e)
                print("%s    FIFO #%u: %s cc=0x%04x" % (pfx, e, hexstr(data), cc))


def print_dtm_pmu_config(dtm, pfx="    "):
    """
    Print dynamic configuration of the DTM as an event collector (not generator)
    """
    pcfg = dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
    if pcfg != 0:
        cnt = dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
        print("%sPMU config: 0x%016x, counts: 0x%016x" % (pfx, pcfg, cnt))
        for i in range(0, 4):
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
    Show DTM PMU configuration and counts
    """
    print_dtm_pmu_config(dtm, pfx=pfx)
    # DTM may be counting events from connected devices.
    for p in range(0, dtm.xp.n_device_ports()):
        for n in dtm.xp.port_nodes(p):
            for soff in n.PMU_EVENT_SEL:
                pmu_sel = n.read64(soff)
                print("%s      %016x  %s" % (pfx, pmu_sel, n))
                pmu_filter = BITS(pmu_sel, 32, 8)
                for e in range(0, 4):
                    esel = BITS(pmu_sel, e*8, 8)
                    if esel != 0:
                        print("%s          E%u: 0x%x" % (pfx, e, esel), end="")
                        if dtm.C.pmu_events is not None:
                            pix = (soff - CMN_any_PMU_EVENT_SEL) >> 3
                            ev = dtm.C.pmu_events.get_event(n.type(), esel, pmu_index=pix, filter=pmu_filter)
                            if ev is not None:
                                print(" - %s" % ev.name(), end="")
                        print()


if __name__ == "__main__":
    import argparse
    import cmn_devmem_find
    parser = argparse.ArgumentParser(description="CMN debug/trace tool")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--dtc-enable", action="store_true", help="enable DTC")
    parser.add_argument("--dtc-disable", action="store_true", help="disable DTC")
    parser.add_argument("--dtc-disable-cg", action="store_true", help="disable DTC clock-gating")
    parser.add_argument("--dtc-reset-cc", action="store_true")
    parser.add_argument("--dtc", type=int, help="select DTC (default all DTCs)")
    parser.add_argument("--dtms", action="store_true", help="show status of all DTMs")
    parser.add_argument("--xp", type=(lambda x:int(x, 16)), action="append", help="select XP (default all XPs/DTMs)")
    parser.add_argument("-d", "--detail", action="count", default=0, help="increase detail")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    Cs = cmn_devmem.cmn_from_opts(opts)
    for C in Cs:
        for dtc in C.DTCs():
            if opts.dtc is None or opts.dtc == dtc.dtc_domain():
                if opts.dtc_disable:
                    dtc.dtc_disable()
                if opts.dtc_reset_cc:
                    dtc.write64(CMN_DTC_PMCCNTR, 0)
                if opts.dtc_enable:
                    dtc.dtc_enable()
                if opts.dtc_disable_cg:
                    dtc.clock_disable_gating(disable_gating=True)
                print_dtc(dtc, detail=opts.detail)
        if opts.dtms or opts.xp:
            for dtm in C.DTMs():
                if opts.xp is None or dtm.xp.node_id() in opts.xp:
                    print_dtm(dtm, detail=opts.detail)
