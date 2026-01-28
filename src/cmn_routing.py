#!/usr/bin/python

"""
CMN interconnect routing and latency modelling

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


from cmn_enum import *


class Route:
    """
    Represent a path from one node to another, with hops along the way.
    Nodes can be XPs or device nodes.
    Mesh/CAL/device credited slices are also accumulated.
    Currently, both nodes must be in the same mesh.
    """
    def __init__(self, node_from, node_to):
        assert node_from.type() != CMN_NODE_CFG and node_to.type() != CMN_NODE_CFG
        self.node_from = node_from
        self.node_to = node_to
        self.xps = None               # list of XPs
        self.find_route()

    def __str__(self):
        if self.xps is None:
            s = "%s -> %s" % (self.node_from, self.node_to)
        else:
            s = " -> ".join([str(xp) for xp in self.xps])
            if not self.node_from.is_XP():
                s = "%s -> %s" % (self.node_from, s)
            if not self.node_to.is_XP():
                s = "%s -> %s" % (s, self.node_to)
            s += " (%u cycles: %u hops" % (self.cost(), self.n_hops)
            if self.n_local_slices > 0:
                s += ", %u local slices" % (self.n_local_slices)
            if self.n_mcs > 0:
                s += ", %u mcs" % (self.n_mcs)
            s += ")"
        return s

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

    def node_local_slices(self, node):
        if node.is_XP():
            return 0
        n = 0
        po = node.port
        dcs = po.device_credited_slices(node.device_number())
        if dcs is not None:
            n += dcs
        if po.cal_credited_slices is not None:
            n += po.cal_credited_slices
        return n

    @property
    def n_local_slices(self):
        return self.n_from_slices + self.n_to_slices

    @property
    def n_total_slices(self):
        return self.n_mcs + self.n_local_slices

    def find_route(self):
        assert self.node_from.CMN() == self.node_to.CMN(), "Only same-mesh routes supported (%s -> %s)" % (self.node_from, self.node_to)
        # Initialize the route information
        self.n_hops = 0
        self.n_mcs = 0
        self.xps = []
        self.n_from_slices = self.node_local_slices(self.node_from)
        xp_from = self.node_from.XP()
        xp_to = self.node_to.XP()
        xp = xp_from
        self.xps.append(xp)
        while xp != xp_to:
            (xp, mcs) = self.next_xp_and_mcs(xp, xp_to)
            self.xps.append(xp)
            self.n_hops += 1
            if mcs is not None:
                self.n_mcs += mcs
        self.n_to_slices = self.node_local_slices(self.node_to)
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


if __name__ == "__main__":
    import cmn_json
    import argparse
    parser = argparse.ArgumentParser(description="CMN routing calculations")
    parser.add_argument("inputs", type=str, nargs="+", help="input JSON files")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    for fn in opts.inputs:
        S = cmn_json.system_from_json_file(fn)
        C = S.CMNs[0]
        print("Routing for %s (%u nodes)" % (C, len(list(C.nodes()))))
        for from_node in C.nodes(CMN_PROP_CONN):
            for to_node in C.nodes(CMN_PROP_CONN):
                r = Route(from_node, to_node)
                print(r)
