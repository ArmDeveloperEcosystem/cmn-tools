#!/usr/bin/python

"""
Visualize live CMN PMU counters.

Copyright (C) Arm Ltd. 2024-2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Uses the live driver in cmn_devmem, not the Linux CMN PMU driver.
--watch and --pmu-enable reprogram the PMU and leave that configuration in
place on exit. Do not use them concurrently with perf or another PMU owner.
"""

from __future__ import print_function

import math
import sys
import time

import cmn_devmem
import cmn_devmem_find
from cmn_devmem import BITS
from cmn_devmem_regs import (
    CMN_DTM_PMU_CONFIG_off, CMN_DTM_PMU_PMEVCNT_off,
    CMN_DTM_PMU_CONFIG_PMEVENTALL_COMBINED,
    CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED,
    CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED, CMN_DTM_PMU_CONFIG_PMU_EN)
from cmn_diagram import CMNDiagram
from cmn_enum import CMN_NODE_DT, CMN_PROP_HNT


def pmu_counts(x, cfg):
    """
    Yield PMU event counts from an event counter register,
    taking counter combinations into account.
    """
    if cfg & CMN_DTM_PMU_CONFIG_PMEVENTALL_COMBINED:
        yield x
    else:
        if cfg & CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED:
            yield BITS(x, 0, 32)
        else:
            yield BITS(x, 0, 16)
            yield BITS(x, 16, 16)
        if cfg & CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED:
            yield BITS(x, 32, 32)
        else:
            yield BITS(x, 32, 16)
            yield BITS(x, 48, 16)


class CMNDiagramPerf(CMNDiagram):
    """
    CMN diagram with PMU counter annotations
    """
    def __init__(self, cmn, small=False, counter_scale=1, counter_threshold=1):
        self.pmu_config = {}
        self.counter_scale = counter_scale
        self.counter_threshold = counter_threshold
        cmn.discover_all_devices()
        CMNDiagram.__init__(self, cmn, small=small, update=False)
        for xp in cmn.XPs():
            self.pmu_config[xp] = xp.dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
        self.pmu = {}
        self.capture_pmu()
        self.update()

    def capture_pmu(self):
        for xp in self.C.XPs():
            self.pmu[xp] = xp.dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)

    def port_label_color(self, po):
        dev_label, dev_color = CMNDiagram.port_label_color(self, po)
        if self.C.is_live() and dev_color is not None and po.has_properties(CMN_PROP_HNT):
            # Live status annotations belong in this visualizer, not in the
            # shared topology renderer. Highlight an enabled DTC only once.
            for nd in po.nodes():
                if nd.type() == CMN_NODE_DT and not nd.is_disabled() and nd.dtc_is_enabled():
                    dev_color += "!"
                    break
        return (dev_label, dev_color)

    def update(self):
        CMNDiagram.update(self)
        for xp in self.C.XPs():
            if xp.dtm.pmu_is_enabled():
                (cx, cy) = self.XP_xy(xp)
                # Get the current PMU values, and calculate the deltas.
                cfg = self.pmu_config[xp]
                opd = self.pmu[xp]          # Previous snapshot
                npd = xp.dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
                tab = 0
                for (ov, nv) in zip(pmu_counts(opd, cfg), pmu_counts(npd, cfg)):
                    dv = nv - ov
                    if dv < 0:
                        # TBD: only expect to see this for non-concatenated counters,
                        # but if we did see it for concatenated, the adjustment is wrong
                        dv += 0x10000
                    dv >>= self.counter_scale
                    dcolor = None
                    if dv > self.counter_threshold:
                        dcolor = "red!"
                    self.at(cx+tab, cy-1, "%4x" % dv, color=dcolor)
                    tab += 5
                self.pmu[xp] = npd          # Update the snapshot


def cmn_enable_pmu(C, e0=None, e1=None):
    """
    Set up the PMUs to count interesting events. Each XP has a DTM with four counters.
    Each counter can be programmed to count either an XP event or an imported
    event from one of its connected nodes (HN-F, SN-F etc. or the XP itself);
    that node needs to be programmed to export a selected event.
    For example, to count HN-F cache misses:
      - program HN-F to export HN_CACHE_MISS event as node event #0
      - program XP DTM counter #0 to count HN-F's exported event #0
    """
    for dtm in C.DTMs():
        dtm.dtm_write64(CMN_DTM_PMU_CONFIG_off, 0)
    for hnf in C.home_nodes():
        hnf_evt0 = e0
        hnf_evt1 = e1
        hnf.write64(hnf.PMU_EVENT_SEL[0], (hnf_evt1 << 8) | (hnf_evt0))
        xp = hnf.XP()
        pc = xp.dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
        pc &= 0xffffffffffffff00   # mask out chaining bits etc.
        def xp_pmu_event(p,d,e):
            return ((p+1) << 4) | (d << 2) | e
        # Construct event selectors for HN-F events
        evt0 = xp_pmu_event(hnf.port_number, hnf.device_number, 0)
        evt1 = xp_pmu_event(hnf.port_number, hnf.device_number, 1)
        o_wide = True
        if not o_wide:
            # each XP can count up to four events - and we have two from each SLC
            if BITS(pc,32,16) == 0:
                # not yet used this XP's counters 0 and 1
                # make counters 2 and 3 count the SLC's event 2 (no-event) - avoid XP counting anything else
                evd = xp_pmu_event(hnf.port_number, hnf.device_number, 2)
                pc |= (evd << 56) | (evd << 48) | (evt1 << 40) | (evt0 << 32)
            else:
                pc = (evt1 << 56) | (evt0 << 48) | (pc & 0x0000ffffffffffff)
        else:
            pc = (evt1 << 56) | (evt1 << 48) | (evt0 << 40) | (evt0 << 32)
            pc |= CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED | CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED
        pc |= CMN_DTM_PMU_CONFIG_PMU_EN
        if C.verbose > 0:
            print("%s counting %s event %x" % (xp, hnf, pc))
        xp.dtm.dtm_write64(CMN_DTM_PMU_CONFIG_off, pc)
    C.pmu_enable()
    C.dtc_enable()


def cmn_sample_pmu(C):
    """
    Assuming that PMU events are being actively counted, show the rate of change.
    We read PMU counters from the individual XP DTMs, not the DTC overflow counters.
    """
    snap = {}
    for dtm in C.DTMs():
        snap[dtm] = dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
    time.sleep(0.01)
    delta = {}
    def dsub(a,b):
        r = a - b
        if r < 0:
            r += 65536
        return r
    # Read the PMU counters again and get the delta
    for dtm in C.DTMs():
        cr = dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
        delta[dtm] = [dsub(BITS(cr,i*16,16), BITS(snap[dtm],i*16,16)) for i in range(0,4)]
    for dtm in C.DTMs():
        print("%s: %s" % (dtm, delta[dtm]))


def main(argv):
    import argparse

    def inthex(s):
        return int(s, 16)

    description = "Visualize live CMN PMU counters"
    epilog = ("--watch and --pmu-enable reprogram the PMU and leave the "
              "configuration in place. Do not run concurrently with perf "
              "or another PMU owner.")
    try:
        parser = argparse.ArgumentParser(description=description, epilog=epilog, allow_abbrev=False)
    except TypeError:
        parser = argparse.ArgumentParser(description=description, epilog=epilog)
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--diagram", action="store_true", help="show PMU-annotated CMN diagram (default without an action)")
    parser.add_argument("--sketch", action="store_true", help="show small PMU-annotated CMN diagram")
    parser.add_argument("--watch", action="store_true", help="program SLC events and continuously update the diagram")
    parser.add_argument("--watch-interval", type=float, default=0.1, help="interval for watching, in seconds")
    parser.add_argument("--counter-scale", type=int, default=0, help="right-shift displayed counter deltas by this many bits")
    parser.add_argument("--counter-threshold", type=inthex, default=0x100, help="highlight deltas above this hexadecimal value")
    parser.add_argument("--no-color", action="store_true", help="don't use color output")
    parser.add_argument("--force-color", action="store_true", help="force color output even if not to tty")
    parser.add_argument("--dt-enable", action="store_true", help="enable DTCs and DTMs")
    parser.add_argument("--pmu-enable", action="store_true", help="program and enable PMU events for SLC")
    parser.add_argument("--e0", type=inthex, default=1, help="first SLC event number, in hexadecimal (default 1)")
    parser.add_argument("--e1", type=inthex, default=3, help="second SLC event number, in hexadecimal (default 3)")
    parser.add_argument("--pmu-sample", action="store_true", help="show DTM counter deltas over 10 ms")
    parser.add_argument("--pmu-snapshot", action="store_true", help="initiate a PMU snapshot, then disable the DTC PMU")
    parser.add_argument("--dtc", type=int, help="select snapshot DTC domain (default all)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    if opts.watch_interval < 0 or math.isnan(opts.watch_interval) or math.isinf(opts.watch_interval):
        parser.error("--watch-interval must be finite and non-negative")
    if opts.counter_scale < 0:
        parser.error("--counter-scale must be non-negative")
    if opts.counter_threshold < 0:
        parser.error("--counter-threshold must be non-negative")
    if not (0 <= opts.e0 <= 0xff and 0 <= opts.e1 <= 0xff):
        parser.error("--e0 and --e1 must be hexadecimal event numbers in 0..ff")
    if opts.dtc is not None and opts.dtc < 0:
        parser.error("--dtc must be non-negative")
    if opts.watch or not (opts.diagram or opts.sketch or opts.dt_enable or
                          opts.pmu_enable or opts.pmu_sample or opts.pmu_snapshot):
        opts.diagram = True
    for C in cmn_devmem.cmn_from_opts(opts):
        print(C)
        if opts.dt_enable:
            for dtc in C.DTCs():
                dtc.dtc_enable()
            for dtm in C.DTMs():
                dtm.dtm_enable()
        if opts.pmu_enable or opts.watch:
            # Configure before the diagram caches counter-combination settings.
            cmn_enable_pmu(C, e0=opts.e0, e1=opts.e1)
        if opts.pmu_sample:
            cmn_sample_pmu(C)
        if opts.pmu_snapshot:
            for dtc in C.DTCs():
                if opts.dtc is not None and opts.dtc != dtc.dtc_domain():
                    continue
                was_enabled = dtc.dtc_is_enabled()
                try:
                    dtc.dtc_enable()
                    dtc.pmu_enable()
                    status = dtc.pmu_snapshot()
                    print("PMU snapshot from %s: status=0x%x" % (dtc, status))
                    dtc.show()
                finally:
                    # Preserve the legacy cleanup policy, also on failure.
                    try:
                        dtc.pmu_disable()
                    finally:
                        if not was_enabled:
                            dtc.dtc_disable()
        if opts.diagram or opts.sketch:
            D = CMNDiagramPerf(C, small=opts.sketch, counter_scale=opts.counter_scale,
                               counter_threshold=opts.counter_threshold)
            if opts.watch:
                D.hide_cursor()
                try:
                    while True:
                        print(D.str_color(no_color=opts.no_color, force_color=opts.force_color,
                                          for_file=sys.stdout), end="")
                        time.sleep(opts.watch_interval)
                        print(D.cursor_up(), end="")
                        D.clear()
                        D.update()
                finally:
                    D.show_cursor()
            else:
                print(D.str_color(no_color=opts.no_color, force_color=opts.force_color,
                                  for_file=sys.stdout), end="")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        pass
