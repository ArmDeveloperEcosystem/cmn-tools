#!/usr/bin/python3

"""
Top-down performance analysis methodology for CMN interconnect

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys

import cmn_json
import cmn_perfstat
import cmnwatch
from cmn_enum import *
import cmn_perfcheck


o_verbose = 0

o_no_adjust = False


S = cmn_json.system_from_json_file()


def port_watchpoint_events(port, wp):
    wp_events = wp.perf_events(cmn_instance=port.CMN().seq, nodeid=port.XP().node_id(), dev=port.port)
    return wp_events


class Topdown:
    """
    Collect statistics for a level of top-down analysis.
    This is basically a set of categories with event rates per category.
    Categories are normally mutually exclusive.
    """
    def __init__(self, cats, name=None):
        self.name = name
        self.categories = cats
        self.rate = {}
        for c in cats:
            self.rate[c] = 0.0
        self.rate[None] = 0.0
        self.total_rate = 0.0

    def accumulate(self, cat, rate):
        self.total_rate += rate
        if cat not in self.rate:
            self.categories.append(cat)
            self.rate[cat] = 0.0
        self.rate[cat] += rate

    def proportion(self, cat):
        return self.rate[cat] / self.total_rate

    def adjust(self):
        """
        Reconcile the category rates so that they are consistent:
          (a) none of the individual category rates exceed the total rate
          (b) none of the rates are less than zero
          (c) the individual rates add up to the total rate, i.e. percentages add to 100%
        We justify this by the need to present results in a way that does not cause confusion.
        Hopefully we are only removing sampling artefacts.
        """
        self.total_rate = 0.0
        for cat in self.categories:
            if self.rate[cat] < 0.0:
                self.rate[cat] = 0.0
            self.total_rate += self.rate[cat]

    def dominator(self, level=0.95):
        assert level > 0.5     # if it's less, we might have >1 matching category
        for c in self.categories:
            if self.proportion(c) >= level:
                return c
        return None


def print_topdown(td):
    if not o_no_adjust:
        td.adjust()
    if td.name is not None:
        print("%s:" % td.name)
    dom = td.dominator()
    for c in td.categories + [None]:
        cname = c if c is not None else "uncategorized"
        if c is None and not td.rate[c]:
            continue
        print("  %-12s %12.2f %6.3f" % (cname, td.rate[c], td.proportion(c)), end="")
        if c == dom:
            print("  ** dominant **", end="")
        print()
    if dom is not None:
        print("Dominant category: %s" % dom)
    else:
        print("No dominant category")


# Level 1 aims to find the dominant requester type (RN-F, RN-I, RN-D, CCG)

def topdown_level1_ports():
    # For level 1, only interested in requests from RNs and CCG - not HN-F requests to SN-F
    for port in S.ports():
        if port.has_properties(CMN_PROP_RN) or port.has_properties(CMN_PROP_CCG):
            yield port


def topdown_level1_port_cat(port):
    cat = None
    if port.has_properties(CMN_PROP_CCG):
        cat = "CCG"
    elif port.has_properties(CMN_PROP_RNF):
        cat = "RN-F"
    elif port.has_properties(CMN_PROP_RNI):
        cat = "RN-I"
    elif port.has_properties(CMN_PROP_RND):
        cat = "RN-D"
    return cat


def topdown_level1():
    events = []
    for port in topdown_level1_ports():
        wp = cmnwatch.Watchpoint(chn=cmnwatch.REQ, up=True, cmn_version=S.cmn_version(), opcode="PrefetchTgt", exclusive=True)
        if o_verbose:
            print("watchpoint: %s" % wp)
        wp_events = port_watchpoint_events(port, wp)
        assert len(wp_events) == 1
        wp_event = wp_events[0]
        if o_verbose:
            print("  event: %s" % wp_event)
        events.append(wp_event)
    req_rates = cmn_perfstat.perf_rate(events)
    td = Topdown(["RN-F", "RN-I", "RN-D", "CCG"], name="Level 1 analysis")
    for (port, rate) in zip(topdown_level1_ports(), req_rates):
        if not rate:
            continue
        cat = topdown_level1_port_cat(port)
        if cat is None:
            print("unexpected rate from %s" % port)
        td.accumulate(cat, rate)
    print_topdown(td)


# Level 2 aims to distinguish local from remote traffic.
# Can't look at RN-F REQs as they always go to a home node in local mesh.
# Don't want to rely on DAT or RSP because we might have SPNIDEN=0.
# Count requests to HN-Fs, and subtract 2xCCG requests on the basis
# that each remote transaction via CCG encounters is counted in both
# local and remote HN-F.
# Exclude PrefetchTgt as it is in addition to normal requests but
# takes atypical routes direct from RN-F to CCG or CCG to SN-F.

def topdown_level2_ports():
    for port in S.ports():
        if port.has_properties(CMN_PROP_HNF) or port.has_properties(CMN_PROP_CCG):
            yield port


def topdown_level2():
    events = []
    for port in topdown_level2_ports():
        wp = cmnwatch.Watchpoint(chn=cmnwatch.REQ, up=False, cmn_version=S.cmn_version(), opcode="PrefetchTgt", exclusive=True)
        wp_events = port_watchpoint_events(port, wp)
        wp_event = wp_events[0]
        if o_verbose:
            print("  event: %s" % wp_event)
        events.append(wp_event)
    req_rates = cmn_perfstat.perf_rate(events)
    td = Topdown(["local", "remote"], name="Level 2 analysis")
    for (port, rate) in zip(topdown_level2_ports(), req_rates):
        if port.has_properties(CMN_PROP_CCG):
            td.accumulate("remote", rate)
            td.accumulate("local", -rate)
        else:
            td.accumulate("local", rate)
    print_topdown(td)


# Level 3 aims to find where RN-F requests are going - HN-F, I/O or CCG.
# The document talks loosely about counting requests from RN-F to SN-F;
# we interpret this as wanting to count requests to HN-F that miss in SLC
# and generate requests from HN-F to SN-F - but this is approximate, since
# a miss in SLC might instead be resolved by a snoop.

_hns_events = {
    "hnf_slc_sf_cache_access": "hns_slc_sf_cache_access_all",
    "hnf_cache_miss": "hns_cache_miss_all",
    "hnf_sf_hit": "hns_sf_hit_all",
}


def hnf_event(S, e):
    if S.has_HNS():
        e = _hns_events.get(e, e)
    return e


def topdown_level3_rnf():
    td = Topdown(["HN-F hit", "HN-F DRAM", "HN-I", "HN-D"], name="Level 3 request analysis")
    hnf_access_rate = cmn_perfstat.perf_rate(["arm_cmn/%s/" % hnf_event(S, "hnf_slc_sf_cache_access")])[0]
    hnf_sf_hit_rate = cmn_perfstat.perf_rate(["arm_cmn/%s/" % hnf_event(S, "hnf_sf_hit")])[0]
    hnf_miss_rate   = cmn_perfstat.perf_rate(["arm_cmn/%s/" % hnf_event(S, "hnf_cache_miss")])[0]
    hnf_dram_rate = hnf_access_rate - hnf_sf_hit_rate
    td.accumulate("HN-F hit", hnf_sf_hit_rate)
    #td.accumulate("HN-F miss", hnf_miss_rate)
    td.accumulate("HN-F DRAM", hnf_dram_rate)
    events = []
    def level3_hnd_ports():
        for port in S.ports():
            if port.has_properties(CMN_PROP_HNI) or port.has_properties(CMN_PROP_HND):
                yield port
    for port in level3_hnd_ports():
        wp = cmnwatch.Watchpoint(chn=cmnwatch.REQ, up=False, cmn_version=S.cmn_version())
        wp_events = port_watchpoint_events(port, wp)
        wp_event = wp_events[0]
        if o_verbose:
            print("  event: %s" % wp_event)
        events.append(wp_event)
    req_rates = cmn_perfstat.perf_rate(events)
    for (port, rate) in zip(level3_hnd_ports(), req_rates):
        cat = None
        if port.has_properties(CMN_PROP_HNI):
            cat = "HN-I"
        elif port.has_properties(CMN_PROP_HND):
            cat = "HN-D"
        td.accumulate(cat, rate)
    print_topdown(td)


def topdown_prefetch_ports():
    for port in S.ports(properties=CMN_PROP_RNF):
        yield port


def topdown_prefetch():
    td = Topdown(["normal", "prefetch"], name="PrefetchTgt request analysis")
    events = []
    catlist = []
    for port in topdown_prefetch_ports():
        wp = cmnwatch.Watchpoint(chn=cmnwatch.REQ, up=True, cmn_version=S.cmn_version(), opcode="PrefetchTgt", exclusive=True)
        wp_events = port_watchpoint_events(port, wp)
        wp_event = wp_events[0]
        events.append(wp_event)
        catlist.append("normal")
        wp = cmnwatch.Watchpoint(chn=cmnwatch.REQ, up=True, cmn_version=S.cmn_version(), opcode="PrefetchTgt", exclusive=False)
        wp_events = port_watchpoint_events(port, wp)
        wp_event = wp_events[0]
        events.append(wp_event)
        catlist.append("prefetch")
    req_rates = cmn_perfstat.perf_rate(events)
    for (cat, rate) in zip(catlist, req_rates):
        td.accumulate(cat, rate)
    print_topdown(td)


if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description="Top-down performance analysis for CMN interconnect")
    parser.add_argument("--level", type=str, action="append", default=[], help="run specified top-down level")
    parser.add_argument("--all", action="store_true", help="run all top-down levels")
    parser.add_argument("--time", type=float, default=0.5, help="measurement time for top-down")
    parser.add_argument("--no-adjust", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    o_no_adjust = opts.no_adjust
    cmn_perfstat.o_verbose = max(0, opts.verbose-1)
    cmn_perfstat.o_time = opts.time
    if not opts.level:
        opts.level = ["1"]
    if opts.all:
        opts.level = ["1", "2", "3"]
    if not cmn_perfcheck.check_cmn_pmu_events():
        print("CMN perf events not available - can't do top-down analysis",
              file=sys.stderr)
        sys.exit(1)
    print("CMN Top-down performance analysis")
    print("=================================")
    for level in opts.level:
        if level == "1":
            topdown_level1()
        elif level == "2":
            topdown_level2()
        elif level == "3":
            topdown_level3_rnf()
        elif level == "prefetch":
            topdown_prefetch()
        else:
            print("bad topdown level %s" % level, file=sys.stderr)
            sys.exit(1)
