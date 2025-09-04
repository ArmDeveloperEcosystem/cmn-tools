#!/usr/bin/python

"""
CMN interconnect routing and latency modelling

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


class Route:
    """
    Represent a path from one node to another, with hops along the way.
    Mesh credited slices are also accumulated.
    """
    def __init__(self, node_from, node_to):
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
                s = "%s:%s" % (self.node_from, s)
            if not self.node_to.is_XP():
                s = "%s:%s" % (s, self.node_to)
            s += " (%u hops" % self.n_hops
            if self.n_mcs > 0:
                s += ", %u mcs" % (self.n_mcs)
            s += ")"
        return s

    def next_xp_and_mcs(self, xp, xp_to):
        if xp.x < xp_to.x:
            xp_next = xp.C.XP_at(xp.x+1, xp.y)
            mcs = xp.mesh_credited_slices(0)
        elif xp.x > xp_to.x:
            xp_next = xp.C.XP_at(xp.x-1, xp.y)
            mcs = xp_next.mesh_credited_slices(0)
        elif xp.y < xp_to.y:
            xp_next = xp.C.XP_at(xp.x, xp.y+1)
            mcs = xp.mesh_credited_slices(1)
        elif xp.y > xp_to.y:
            xp_next = xp.C.XP_at(xp.x, xp.y-1)
            mcs = xp_next.mesh_credited_slices(1)
        else:
            xp_next = xp
            mcs = 0
        return (xp_next, mcs)

    def find_route(self):
        assert self.node_from.C == self.node_to.C
        self.n_hops = 0
        self.n_mcs = 0
        self.xps = []
        xp_from = self.node_from.XP()
        xp_to = self.node_to.XP()
        # Manhattan routing - horizontal first
        xp = xp_from
        self.xps.append(xp)
        while xp != xp_to:
            (xp, mcs) = self.next_xp_and_mcs(xp, xp_to)
            self.xps.append(xp)
            self.n_hops += 1
            self.n_mcs += mcs
        return self

    def cost(self):
        return self.n_hops + self.n_mcs
