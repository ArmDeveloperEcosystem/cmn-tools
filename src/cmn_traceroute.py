#!/usr/bin/python

"""
CMN interconnect routing and latency modelling utility

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import sys


import cmn_routing
import cmn_select
import cmn_json


def endpoints(S, spec):
    return list(cmn_select.iter_system_devices(S, spec)) or list(cmn_select.iter_system_nodes(S, spec))


def print_routes(S, fspec, tspec, opts):
    print("%s -> %s:" % (fspec, tspec))
    stats = cmn_routing.RouteStatistics()
    from_devs = endpoints(S, fspec)
    to_devs = endpoints(S, tspec)
    if not from_devs:
        print("%s: no source endpoints found" % fspec)
        return
    if not to_devs:
        print("%s: no destination endpoints found" % tspec)
        return
    if opts.verbose:
        print("From devices: %u" % len(from_devs))
        if opts.verbose >= 2:
            for d in from_devs:
                print("  %s" % d)
        print("To devices: %u" % len(to_devs))
        if opts.verbose >= 2:
            for d in to_devs:
                print("  %s" % d)
    for from_dev in from_devs:
        if opts.format == "list":
            print("  %s:" % from_dev)
        elif opts.format == "table":
            print("  %20s:" % from_dev, end="")
        for to_dev in to_devs:
            try:
                r = cmn_routing.Route(from_dev, to_dev)
                stats.add_route(r)
            except cmn_routing.RouteCrossMesh:
                r = None
            if opts.format == "list":
                if r is not None:
                    print("    %s" % r)
            elif opts.format == "table":
                if r is not None:
                    print(" %2u" % r.cost(), end="")
                else:
                    print("   ", end="")
        if opts.format == "table":
            print()
    if True:
        print("  Route statistics (%u routes):" % stats.n)
        print("    %s" % stats)
        if stats.n == 1:
            print("    Route: %s" % (stats.item_min))
        elif stats.n >= 2 and stats.item_min != stats.item_max:
            print("    Best:  %s" % (stats.item_min))
            print("    Worst: %s" % (stats.item_max))


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="Find and measure routes between devices")
    parser.add_argument("dev", type=cmn_select.CMNSelect, nargs="*", help="endpoint device(s)")
    parser.add_argument("--format", type=str, choices=["list", "table", "stats"], default="table", help="output format")
    parser.add_argument("--cmn-instance", type=int, default=0, help="CMN instance")
    parser.add_argument("--json", type=str, default=None, help="input JSON")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    if len(opts.dev) < 2:
        print("need at least two endpoint selector expressions")
        sys.exit(1)
    S = cmn_json.system_from_json_file(opts.json)
    C = S.CMNs[opts.cmn_instance]
    while len(opts.dev) >= 2:
        print_routes(S, opts.dev[0], opts.dev[1], opts)
        opts.dev = opts.dev[1:]


if __name__ == "__main__":
    main(sys.argv[1:])
