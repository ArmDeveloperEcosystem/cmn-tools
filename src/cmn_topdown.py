#!/usr/bin/python3

"""
Top-down performance analysis methodology for CMN interconnect

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os
import sys
import subprocess
import json
import atexit


import cmn_json
import cmn_perfstat
import cmnwatch
from cmn_enum import *
import cmn_perfcheck
from memsize_str import memsize_str
import cmn_events


o_verbose = 0

o_no_adjust = False
o_dominance_level = 0.95
o_print_rate_bandwidth = False
o_print_percent = True
o_print_decimal = False
o_print_recipe = False
o_split = False

o_recipe_path = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "recipes")]


g_checked_cmn = False
g_checked_cpu = False


# CMN topology discovery needs to have already been done. This is needed so
# we can create watchpoint counters bound to specify port/node types.
S = cmn_json.system_from_json_file()


TOP_CAT = "#all"

class Topdown:
    """
    Collect statistics for a level of top-down analysis.
    This is basically a set of categories with event rates per category.
    Categories are normally mutually exclusive, but an "#all" category
    can be defined that represents total events.
    """
    def __init__(self, cats, name=None, desc=None, dominance_level=None):
        self.name = name
        self.desc = desc or name
        self.categories = cats      # e.g. "read", "write"
        self.dominance_level = dominance_level if dominance_level is not None else o_dominance_level
        self.init_measurements()

    def init_measurements(self):
        self.rate = {}
        for c in self.categories:
            self.rate[c] = 0.0
        self.rate[None] = 0.0
        self.total_rate = None
        self.is_measured = False

    def __str__(self):
        if o_verbose >= 2:
            s = "%s, name=\"%s\", dominance_level=%.2f" % (str(self.categories), self.name, self.dominance_level)
        else:
            s = "\"%s\"" % self.name
        s = "Topdown(%s)" % s
        return s

    def has_baseline(self):
        return TOP_CAT in self.categories

    @staticmethod
    def is_internal_category(cat):
        return cat.startswith("#")

    def measure(self):
        pass

    @staticmethod
    def get_actions(actions):
        """
        Given a list of actions (e.g. category updates) to be done in response to some metric,
        return the list of individual actions.
        Actions can be:
          <category>      - add measured value to category
          -<category>     - subtract measured value from category
          *<multiplier>   - multiply subsequent values (currently float literal)
        """
        return [action.strip() for action in actions.split(',')]

    def get_action_categories(self, actions):
        """
        Given a list of categories to be adjusted by some metric,
        return the individual category names.
        """
        for action in self.get_actions(actions):
            if action.startswith("*"):
                pass    # multiplier
            elif action.startswith("-"):
                yield action[1:]
            else:
                yield action

    def add_category(self, cat):
        if cat not in self.rate:
            self.categories.append(cat)
            self.rate[cat] = 0.0

    def accumulate(self, cat, rate):
        """
        Accumulate a metric measurement into the ongoing topdown analysis.
        Metrics can be negative, if they are intended to subtract from some other metric
        to give an overall category metric.
        """
        if cat is not None and cat.startswith("-"):
            cat = cat[1:]
            self.rate[cat] -= rate
        else:
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
        self.total_rate = self.rate[TOP_CAT] if self.has_baseline() else 0.0
        for cat in self.categories:
            if self.rate[cat] < 0.0:
                self.rate[cat] = 0.0
            if not self.has_baseline() and not self.is_internal_category(cat):
                self.total_rate += self.rate[cat]
        assert self.total_rate > 0.0, "unexpected zero total after adjustment"

    def dominator(self):
        assert self.dominance_level > 0.5     # if it's less, we might have >1 matching category
        for c in self.categories:
            if c is not None and self.is_internal_category(c):
                continue
            if self.proportion(c) >= self.dominance_level:
                return c
        return None


def port_watchpoint_events(port, wp):
    """
    Given a cmnwatch.Watchpoint, return a list of perf event strings.
    There will be more than one string if the watchpoint requires multiple matching groups in CMN.
    """
    wp_events = wp.perf_events(cmn_instance=port.CMN().seq, nodeid=port.XP().node_id(), dev=port.port)
    return wp_events


def port_watchpoint_event(port, wp):
    """
    Currently, we only handle single-group watchpoints. Catch any watchpoints that
    require multiple groups, and crash out.
    """
    wp_events = port_watchpoint_events(port, wp)
    assert len(wp_events) == 1, "bad events: %s" % wp_events
    wp_event = wp_events[0]
    if o_verbose >= 2:
        print("  event: %s" % wp_event)
    return wp_event


class TopdownPerf(Topdown):
    """
    Topdown analysis from PMU events
    """
    def __init__(self, S, cats, **kw):
        Topdown.__init__(self, cats, **kw)
        self.S = S
        self.has_HNS = self.S.has_HNS()
        self.events = []     # these two lists are in 1:1 correspondence
        self.actlist = []

    def add_event(self, actions, event):
        if o_verbose:
            print("%s: add \"%s\" = %s" % (self, actions, event))
        for cat in self.get_action_categories(actions):
            self.add_category(cat)
        self.actlist.append(actions)
        self.events.append(event)

    def add_cmn_event(self, actions, e):
        if self.has_HNS:
            e = cmn_events.hns_events.get(e, e)
        e = "arm_cmn/%s/" % e
        self.add_event(actions, e)

    def add_port_watchpoint(self, actions, port, **kw):
        try:
            wp = cmnwatch.Watchpoint(cmn_version=self.S.cmn_version(), **kw)
        except cmnwatch.WatchpointValueOutOfRange as e:
            # Most likely due to a range of CHI opcodes, of which some are
            # not valid for this older CHI.
            if o_verbose >= 2:
                print("%s: ignoring unavailable watchpoint: %s" % (self, e), file=sys.stderr)
            return
        except cmnwatch.WatchpointError as e:
            # This shouldn't occur, but given that the recipes are data-driven,
            # and may be user-modified or user-written, we should avoid crashing
            # out with a Python backtrace.
            print("%s: unexpected bad watchpoint: %s" % (self, e), file=sys.stderr)
            sys.exit(1)
        event = port_watchpoint_event(port, wp)
        self.add_event(actions, event)

    def measure(self):
        """
        Set up some perf measurements on CMN, and then process the resulting data.
        """
        # If this throws cmn_perfstat.PerfNotAvailable, there may be a permissions issue.
        # But that should have been guarded by a call to cmn_perfcheck earlier.
        rates = cmn_perfstat.perf_rate(self.events)
        mult = 1.0
        for (actions, rate) in zip(self.actlist, rates):
            if o_verbose >= 2:
                if rate is not None:
                    print("  %14.2f  %s" % (rate, actions))
                else:
                    print("  <rate not available>")
            if rate is None:
                print("Hardware event count not collected: try running with a longer --time", file=sys.stderr)
                sys.exit(1)
            for act in self.get_actions(actions):
                if act is not None and act.startswith("-"):
                    self.accumulate(act[1:], -rate*mult)
                elif act is not None and act.startswith("*"):
                    mult = float(act[1:])
                else:
                    self.accumulate(act, rate*mult)
        self.is_measured = True
        return self


def decode_properties(x):
    """
    Properties can be supplied either as a string ("RN-F"), or a mask (CMN_PROP_RNF).
    """
    if not isinstance(x, int):
        x = cmn_properties(x, check=False)
        if x is None:
            print("invalid port specifier \"%s\", expect e.g. \"RN-F\"" % x, file=sys.stderr)
            sys.exit(1)
    return x


def create_Topdown(d, measure=True):
    """
    Given a topdown recipe, create a Topdown object, and optionally take a measurement.
    """
    td = TopdownPerf(S, d.get("categories", []), name=d["name"], desc=d.get("description", None))
    for m in d["measure"]:
        cat = m["measure"]
        if "event" in m or "ports" in m:
            # CMN named event
            global g_checked_cmn
            if not g_checked_cmn:
                if not cmn_perfcheck.check_cmn_pmu_events(check_rsp_dat=False):
                    print("CMN perf events not available - can't do top-down analysis",
                          file=sys.stderr)
                    sys.exit(1)
                g_checked_cmn = True
                if o_verbose:
                    print("CMN PMU events are available", file=sys.stderr)
        if "event" in m:
            td.add_cmn_event(cat, m["event"])
        elif "ports" in m:
            # CMN watchpoint, on a given class of crosspoint ports
            props = decode_properties(m["ports"])
            for port in S.ports(properties=props):
                if o_split or m.get("split", False):
                    ecat = cat + ":0x%x" % port.base_id()
                else:
                    ecat = cat
                if "watchpoint_up" in m:
                    td.add_port_watchpoint(ecat, port, up=True, **m["watchpoint_up"])
                elif "watchpoint_down" in m:
                    td.add_port_watchpoint(ecat, port, up=False, **m["watchpoint_down"])
                else:
                    td.add_port_watchpoint(ecat, port, **m["watchpoint"])
        elif "cpu-event" in m:
            # CPU hardware events can be added as their bare event name
            global g_checked_cpu
            if not g_checked_cpu:
                if not cmn_perfcheck.check_cpu_pmu_events():
                    print("CPU perf events not available - can't do top-down analysis",
                          file=sys.stderr)
                    sys.exit(1)
                g_checked_cpu = True
                if o_verbose:
                    print("CPU PMU events are available", file=sys.stderr)
            td.add_event(cat, m["cpu-event"])
        elif "sys-event" in m:
            # Other uncore event - perhaps a DDR controller
            td.add_event(cat, m["sys-event"])
        else:
            assert False, "invalid analysis recipe: %s" % m
    if measure:
        td.measure()
    return td


def measure_and_print_topdown(recipe):
    """
    Complete a top-down analysis and print the results.
    """
    if o_print_recipe:
        print(json.dumps(recipe, indent=4))
        return
    td = create_Topdown(recipe)
    if not td.is_measured:
        td.measure()
    rate_bandwidth = recipe.get("rate_bandwidth", None)
    print_rate_bandwidth = (rate_bandwidth is not None) or o_print_rate_bandwidth
    if o_verbose:
        print("%s: completing top-down analysis" % td)
    if not o_no_adjust:
        td.adjust()
    if td.desc is not None:
        print("%s:" % td.desc)
    dom = td.dominator()
    catlist = td.categories + [None]
    if TOP_CAT in catlist:
        catlist.remove(TOP_CAT)
        catlist += [TOP_CAT]
    for c in td.categories + [None]:
        cname = "(total)" if c == TOP_CAT else c if c is not None else "uncategorized"
        if c is None and not td.rate[c]:
            continue
        if c is not None and c != TOP_CAT and td.is_internal_category(c):
            # internal category - don't print
            continue
        print("  %-13s" % (cname), end="")
        # These numbers can get pretty big. Potentially things happening
        # at 1GHz in 1000 places, so rates may be around 1e12.
        # It might be better to print the rates per microsecond,
        # or use scientific notation.
        if print_rate_bandwidth:
            print(" %12s/s" % memsize_str(rate_bandwidth*td.rate[c], decimal=o_print_decimal), end="")
        else:
            print(" %14.2f" % (td.rate[c]), end="")
        # For TOP_CAT this will always be 100%
        if o_print_percent:
            print(" %6.1f%%" % (td.proportion(c) * 100.0), end="")
        else:
            print(" %6.3f" % (td.proportion(c)), end="")
        if c == dom:
            print(" **", end="")
        print()
    if dom is not None:
        print("Dominant category: %s" % dom)
    else:
        if o_verbose:
            print("No dominant category at %.0f%% level" % (td.dominance_level*100.0))
    if o_verbose:
        print()


def print_topdown(recipe):
    assert "measure" in recipe or "subrecipes" in recipe
    if "measure" in recipe:
        measure_and_print_topdown(recipe)
    if "subrecipes" in recipe:
        for r in recipe["subrecipes"]:
            print_topdown(r)


def recipe_load(name):
    """
    Load a recipe, either from an explicitly specified JSON file,
    or from the recipe path.
    """
    if name.endswith(".json"):
        with open(name) as f:
            return json.load(f)
    for p in o_recipe_path:
        fn = os.path.join(p, name + ".json")
        if os.path.isfile(fn):
            return recipe_load(fn)
    raise IOError


#
# From here onwards are individual topdown recipes.
#

# Level 1 aims to find the dominant requester type (RN-F, RN-I, RN-D, CCG)

recipe_level1 = {
    "name": "Level 1 analysis",
    "categories": ["RN-F", "RN-I", "RN-D", "CCG"],
    "measure": [
        { "measure": "CCG", "ports": CMN_PROP_CCG, "watchpoint_up": { "opcode": "PrefetchTgt", "exclusive": True } },
        { "measure": "RN-F", "ports": CMN_PROP_RNF, "watchpoint_up": { "opcode": "PrefetchTgt", "exclusive": True } },
        { "measure": "RN-I", "ports": CMN_PROP_RNI, "watchpoint_up": { "opcode": "PrefetchTgt", "exclusive": True } },
        { "measure": "RN-D", "ports": CMN_PROP_RND, "watchpoint_up": { "opcode": "PrefetchTgt", "exclusive": True } },
    ]
}


# Level 2 aims to distinguish local from remote traffic.
# Can't look at RN-F REQs as they always go to a home node in local mesh.
# Don't want to rely on DAT or RSP because we might have SPNIDEN=0.
# Count requests to HN-Fs, and subtract 2xCCG requests on the basis
# that each remote transaction via CCG encounters is counted in both
# local and remote HN-F.
# Exclude PrefetchTgt as it is in addition to normal requests but
# takes atypical routes direct from RN-F to CCG or CCG to SN-F.


recipe_level2 = {
    "name": "Level 2 analysis",
    "categories": ["local", "remote"],
    "run_if": ["multisocket"],
    "measure": [
        { "measure": "local",         "ports": CMN_PROP_HNF, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": True } },
        # { "measure": "local",            "ports": CMN_PROP_HNF, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "ReadNotSharedDirty" } },
        { "measure": "remote,-local,-local", "ports": CMN_PROP_CCG, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": True } },
    ]
}


# Level 3 aims to find where RN-F requests are going - HN-F, I/O or CCG.
# The document talks loosely about counting requests from RN-F to SN-F;
# we interpret this as wanting to count requests to HN-F that miss in SLC
# and generate requests from HN-F to SN-F - but this is approximate, since
# a miss in SLC might instead be resolved by a snoop.
# Note that hnf_slc_sf_cache_access does not count evicts (even with data),
# but hnf_mc_reqs does count writes. So we need to be clear whether we
# are calculating a breakdown of just reads (including CPUs bringing lines
# in to modify) or all traffic from CPU to home nodes.


recipe_level3_rnf = {
    "name": "Level 3 request analysis",
    "categories": ["HN-F hit", "HN-F snoop", "HN-F DRAM", "HN-I", "HN-D"],
    "measure": [
        { "measure": "#all,HN-F hit",    "event": "hnf_slc_sf_cache_access" },
        { "measure": "#miss,HN-F snoop,-HN-F hit",  "event": "hnf_cache_miss" },
        { "measure": "HN-F DRAM,-HN-F snoop", "ports": CMN_PROP_SNF, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "ReadNoSnp" } },
        { "measure": "HN-F DRAM,-HN-F snoop", "ports": CMN_PROP_SNF, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "ReadNoSnpSep" } },
        { "measure": "HN-I",      "ports": CMN_PROP_HNI, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "ReadNoSnp" } },
        { "measure": "HN-D",      "ports": CMN_PROP_HND, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "ReadNoSnp" } },
    ]
}


recipe_prefetch = {
    "name": "PrefetchTgt request analysis",
    "categories": ["normal", "prefetch"],
    "measure": [
        { "measure": "normal",   "ports": CMN_PROP_RNF, "watchpoint_up": { "chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": True } },
        { "measure": "prefetch", "ports": CMN_PROP_RNF, "watchpoint_up": { "chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": False } },
    ]
}


recipe_bandwidth_cpu = {
    "name": "CPU bandwidth",
    "categories": ["read", "write"],
    "rate_bandwidth": 32,      # TBD: will need updating for 512-bit CHI interface
    "measure": [
        { "measure": "read", "cpu-event": "bus_access_rd" },
        { "measure": "write", "cpu-event": "bus_access_wr" },
    ]
}


recipe_bandwidth_rnf = {
    "name": "CPU/SLC bandwidth",
    "categories": ["read", "write clean", "write dirty"],
    "rate_bandwidth": 64,
    "measure": [
        { "measure": "read", "ports": CMN_PROP_RNF, "watchpoint_up": { "opcode": "ReadNotSharedDirty" } },
        { "measure": "read", "ports": CMN_PROP_RNF, "watchpoint_up": { "opcode": "ReadUnique" } },
        { "measure": "write clean", "ports": CMN_PROP_RNF, "watchpoint_up": { "opcode": "WriteEvictFull" } },
        { "measure": "write clean", "ports": CMN_PROP_RNF, "watchpoint_up": { "opcode": "WriteEvictOrEvict" } },  # later CHI only
        { "measure": "write dirty", "ports": CMN_PROP_RNF, "watchpoint_up": { "opcode": "WriteBackFull" } },
        { "measure": "write dirty", "ports": CMN_PROP_RNF, "watchpoint_up": { "opcode": "WriteCleanFull" } },
    ]
}


recipe_bandwidth_dram = {
    "name": "DRAM bandwidth",
    "categories": ["read", "write"],
    "rate_bandwidth": 64,
    "measure": [
        { "measure": "read", "ports": CMN_PROP_SNF, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "ReadNoSnp" } },
        { "measure": "read", "ports": CMN_PROP_SNF, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "ReadNoSnpSep" } },
        { "measure": "write", "ports": CMN_PROP_SNF, "watchpoint_down": { "chn": cmnwatch.REQ, "opcode": "WriteNoSnpFull" } },
    ],
}


recipe_bandwidth = {
    "name": "Bandwidth",
    "subrecipes": [recipe_bandwidth_cpu, recipe_bandwidth_rnf, recipe_bandwidth_dram],
}


recipe_retries_hnf = {
    "name": "Retried requests from CPU to SLC",
    "categories": ["retry", "non-retry"],
    "measure": [
        { "measure": "non-retry",  "event": "hnf_pocq_reqs_recvd" },
        { "measure": "retry,-non-retry", "event": "hnf_pocq_retry" },
    ]
}


recipe_retries_snf = {
    "name": "Retried requests from SLC to DRAM",
    "categories": ["retry", "non-retry"],
    "measure": [
        { "measure": "non-retry",  "event": "hnf_mc_reqs" },
        { "measure": "retry,-non-retry", "event": "hnf_mc_retries" },
    ]
}


recipe_retries = {
    "name": "Retried requests",
    "subrecipes": [recipe_retries_hnf, recipe_retries_snf],
}


if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description="Top-down performance analysis for CMN interconnect")
    parser.add_argument("--level", type=str, action="append", default=[], help="run specified top-down level")
    parser.add_argument("--all", action="store_true", help="run all top-down levels")
    parser.add_argument("--time", type=float, default=None, help="measurement time for top-down")
    parser.add_argument("--dominance-level", type=float, default=0.95, help="threshold for traffic to be considered dominant")
    parser.add_argument("--percentage", action="store_true", help="print as percentages")
    parser.add_argument("--bandwidth", action="store_true", help="print request counts as bandwidth")
    parser.add_argument("--decimal", action="store_true", help="print bandwidth as decimal (MB not MiB)")
    parser.add_argument("--recipe", type=str, action="append", help="use JSON top-down recipe")
    parser.add_argument("--recipe-path", type=str, action="append", help="additional recipe paths")
    parser.add_argument("--print-recipe", action="store_true", help="print recipe as JSON")
    parser.add_argument("--no-adjust", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--split", action="store_true", help="split measurements by port")
    parser.add_argument("--perf-bin", type=str, default="perf", help="perf command")
    parser.add_argument("--cmd", type=str, help="microbenchmark to run (will be killed on exit)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    o_no_adjust = opts.no_adjust
    o_dominance_level = opts.dominance_level
    if opts.percentage:
        o_print_percent = True
    if opts.bandwidth:
        o_print_rate_bandwidth = True
    if opts.decimal:
        o_print_decimal = True
    if opts.recipe_path:
        o_recipe_path = opts.recipe_path + o_recipe_path
    o_print_recipe = opts.print_recipe
    o_split = opts.split
    cmn_perfstat.o_verbose = max(0, opts.verbose-1)
    if opts.time is None and S.CMNs:
        # Default measurement time should be longer for larger mesh
        cmn0 = S.CMNs[0]
        mesh_size = cmn0.dimX * cmn0.dimY
        opts.time = 0.01 * mesh_size
        if o_verbose:
            print("Mesh size %ux%u: measurement time set to %.2fs" % (cmn0.dimX, cmn0.dimY, opts.time))
    cmn_perfstat.o_time = opts.time
    cmn_perfstat.o_perf_bin = opts.perf_bin
    if not opts.level:
        opts.level = ["1"] if (not opts.recipe) else []
    if opts.all or opts.level == ["all"]:
        opts.level = ["1", "2", "3", "bandwidth", "retries"]
    if opts.cmd:
        # Run a subprocess while doing top-down. Unlike "perf stat" etc. we don't
        # time the top-down analysis to the subprocess - we simply start it, hope it
        # keeps running, and then kill it. Typically it would be a microbenchmark
        # like "lmbench" or "stream".
        p = subprocess.Popen(opts.cmd.split())
        # Subprocess will be killed on exit. This is harmless if it's already terminated.
        atexit.register(lambda p: p.kill(), p)
    print("CMN Top-down performance analysis")
    print("=================================")
    for level in opts.level:
        if level == "1":
            print_topdown(recipe_level1)
        elif level == "2" or level == "c2c":
            if len(S.CMNs) == 1 and opts.all:
                print("Skipping Level 2 because system has only one interconnect")
            else:
                print_topdown(recipe_level2)
        elif level == "3":
            print_topdown(recipe_level3_rnf)
        elif level == "prefetch":
            print_topdown(recipe_prefetch)
        elif level == "bandwidth":
            print_topdown(recipe_bandwidth)
        elif level == "retries":
            print_topdown(recipe_retries)
        else:
            print("bad topdown level %s" % level, file=sys.stderr)
            sys.exit(1)
    if opts.recipe:
        for recipe_fn in opts.recipe:
            try:
                recipe = recipe_load(recipe_fn)
                print_topdown(recipe)
            except IOError as e:
                print("%s" % e, file=sys.stderr)
                sys.exit(1)
