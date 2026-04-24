#!/usr/bin/python

"""
CMN interconnect routing and latency modelling

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import sys
from cmn_enum import *


def normalize(d):
    try:
        d = d.device_object
    except AttributeError:
        pass
    return d


class RouteCrossMesh(Exception):
    """Raised when we try to get a route across mesh boundaries."""
    pass


class Statistics:
    """
    Summary statistics for a generic measureable value.
    """
    def __init__(self):
        self.n = 0
        self.total = 0
        self.v_min = None
        self.v_max = None
        self.item_min = None
        self.item_max = None

    def mean(self):
        if self.n == 0:
            return None
        return float(self.total) / self.n

    def add(self, v, item=None):
        self.n += 1
        self.total += v
        if self.v_min is None or v < self.v_min:
            self.v_min = v
            self.item_min = item
        if self.v_max is None or v > self.v_max:
            self.v_max = v
            self.item_max = item

    def __str__(self):
        if self.n == 0:
            return "no data"
        s = "mean %.2f min %.2f max %.2f" % (self.mean(), self.v_min, self.v_max)
        return s


class RouteStatistics(Statistics):
    """
    Summary statistics for a set of route costs or related derived values.
    The min/max items are Route objects for best/worst-case reporting.
    """
    def add_route(self, route):
        self.add(route.cost(), item=route)

    def __str__(self):
        if self.n == 0:
            return "no routes"
        return Statistics.__str__(self)


class RouteHop:
    """
    One routing segment, either between a device and its XP or between adjacent XPs.
    """
    def __init__(self, obj_from, obj_to, base_cost=0, mcs=0, device_slices=0, cal_slices=0):
        self.obj_from = obj_from
        self.obj_to = obj_to
        self.base_cost = base_cost
        self.mcs = (0 if mcs is None else mcs)
        self.device_slices = device_slices
        self.cal_slices = cal_slices

    def cost(self):
        return self.base_cost + self.mcs + self.device_slices + self.cal_slices

    def detail_str(self):
        ds = []
        if self.mcs:
            ds.append("mcs=%u" % self.mcs)
        if self.device_slices:
            ds.append("dcs=%u" % self.device_slices)
        if self.cal_slices:
            ds.append("cal=%u" % self.cal_slices)
        if not ds:
            return ""
        return "[%s]" % ",".join(ds)


class Route:
    """
    Represent a path from one node to another, with hops along the way.
    Nodes can be XPs or device nodes.
    Mesh/CAL/device credited slices are also accumulated.
    Currently, both nodes must be in the same mesh.
    """
    def __init__(self, node_from, node_to):
        node_from = normalize(node_from)
        node_to = normalize(node_to)
        #assert node_from.type() != CMN_NODE_CFG and node_to.type() != CMN_NODE_CFG
        self.node_from = node_from
        self.node_to = node_to
        self.hops = None              # list of RouteHop objects
        self.mesh_hops = None         # list of mesh RouteHop objects between XPs
        self.find_route()

    def xp_str(self, xp):
        """
        Because paths contain long strings of XPs with a similar context, we only need
        minimal information to differentiate XPs.
        """
        s = "(%u,%u)" % (xp.x, xp.y)
        return s

    def __str__(self):
        if self.hops is None:
            s = "%s -> %s" % (self.node_from, self.node_to)
        else:
            s = self.path_str()
            s += " (%u cycles: %u hops" % (self.cost(), self.n_hops)
            if self.n_local_slices > 0:
                s += ", %u local slices" % (self.n_local_slices)
            if self.n_mcs > 0:
                s += ", %u mcs" % (self.n_mcs)
            s += ")"
        return s

    def point_str(self, obj):
        if getattr(obj, "is_XP", lambda: False)():
            return self.xp_str(obj)
        return str(obj)

    def path_str(self):
        if not self.hops:
            return self.point_str(self.node_from)
        s = self.point_str(self.hops[0].obj_from)
        for hop in self.hops:
            s += " -%u%s-> %s" % (hop.cost(), hop.detail_str(), self.point_str(hop.obj_to))
        return s

    @property
    def xps(self):
        if self.mesh_hops is None:
            return None
        xps = [self.node_from.XP()]
        for hop in self.mesh_hops:
            xps.append(hop.obj_to)
        return xps

    def next_xp_and_mcs(self, xp, xp_to):
        """
        Given a current XP, and a destination XP, return the next XP and any MCS.
        Manhattan XY routing - horizontal (X) first, then vertical (Y).
        """
        if xp.x < xp_to.x:
            xp_next = xp.CMN().XP_at(xp.x+1, xp.y)
            mcs = xp.mesh_credited_slices(0)
        elif xp.x > xp_to.x:
            xp_next = xp.CMN().XP_at(xp.x-1, xp.y)
            mcs = xp_next.mesh_credited_slices(0)
        elif xp.y < xp_to.y:
            xp_next = xp.CMN().XP_at(xp.x, xp.y+1)
            mcs = xp.mesh_credited_slices(1)
        elif xp.y > xp_to.y:
            xp_next = xp.CMN().XP_at(xp.x, xp.y-1)
            mcs = xp_next.mesh_credited_slices(1)
        else:
            xp_next = xp
            mcs = 0
        return (xp_next, mcs)

    def node_local_costs(self, node):
        if getattr(node, "is_XP", lambda: False)():
            return (0, 0)
        po = node.port
        dcs = po.device_credited_slices(node.device_number)
        if dcs is None:
            dcs = 0
        cal = po.cal_credited_slices
        if cal is None:
            cal = 0
        return (dcs, cal)

    @property
    def n_local_slices(self):
        return self.n_from_slices + self.n_to_slices

    @property
    def n_total_slices(self):
        return self.n_mcs + self.n_local_slices

    def find_route(self):
        if self.node_from.CMN() != self.node_to.CMN():
            raise RouteCrossMesh("Only same-mesh routes supported (%s -> %s)" % (self.node_from, self.node_to))
        # Initialize the route information
        self.hops = []
        self.mesh_hops = []
        (from_dcs, from_cal) = self.node_local_costs(self.node_from)
        self.n_from_slices = from_dcs + from_cal
        xp_from = self.node_from.XP()
        xp_to = self.node_to.XP()
        if not getattr(self.node_from, "is_XP", lambda: False)():
            self.hops.append(RouteHop(self.node_from, xp_from, device_slices=from_dcs, cal_slices=from_cal))
        xp = xp_from
        while xp != xp_to:
            xp_prev = xp
            (xp, mcs) = self.next_xp_and_mcs(xp, xp_to)
            hop = RouteHop(xp_prev, xp, base_cost=1, mcs=mcs)
            self.mesh_hops.append(hop)
            self.hops.append(hop)
        self.n_hops = len(self.mesh_hops)
        self.n_mcs = sum([hop.mcs for hop in self.mesh_hops])
        # Finally after reaching the destination node's XP, get to the node itself.
        (to_dcs, to_cal) = self.node_local_costs(self.node_to)
        self.n_to_slices = to_dcs + to_cal
        if not getattr(self.node_to, "is_XP", lambda: False)():
            self.hops.append(RouteHop(xp_to, self.node_to, device_slices=to_dcs, cal_slices=to_cal))
        return self

    def cost(self):
        """
        Return the total cost in cycles, for this route.
        The base cost comprises 1 cycle for passing through each XP.
        Credited slices (mesh, CAL and device) are added on top of that.
        TBD: check whether a CAL adds an additional cycle.
        TBD: check cost where from/to are on the same XP.
        """
        return self.n_hops + self.n_total_slices


def route_statistics(node_froms, node_tos):
    """
    Build summary cost statistics for all source/destination pairs.
    item_min and item_max are Route objects.
    """
    s = RouteStatistics()
    for node_from in node_froms:
        for node_to in node_tos:
            r = Route(node_from, node_to)
            #s.add(r.cost(), item=(node_from, node_to, r))
            s.add_route(r)
    return s


def main(argv):
    import cmn_json
    import argparse
    parser = argparse.ArgumentParser(description="CMN routing calculations")
    parser.add_argument("inputs", type=str, nargs="+", help="input JSON files")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    for fn in opts.inputs:
        S = cmn_json.system_from_json_file(fn)
        C = S.CMNs[0]
        print("Routing for %s (%u nodes)" % (C, len(list(C.nodes()))))
        for from_node in C.nodes(CMN_PROP_CONN):
            for to_node in C.nodes(CMN_PROP_CONN):
                r = Route(from_node, to_node)
                print(r)


if __name__ == "__main__":
    main(sys.argv[1:])
