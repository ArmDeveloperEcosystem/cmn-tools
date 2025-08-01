#!/usr/bin/python

"""
Report on error status of CMN debug/trace nodes.

This is generally unlikely to be useful unless you have access
to CMN's normally-Secure registers. More functions (e.g. clearing
and injecting errors) may be added in future.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import sys
import os

import cmn_devmem
from cmn_enum import *


def BITS(x, p, n=1):
    return (x >> p) & ((1 << n) - 1)


def node_has_errstatus(n):
    return n.is_home_node() or n.type() in [CMN_NODE_SBSX, CMN_NODE_HNI, CMN_NODE_HNP, CMN_NODE_CCLA]


def nodes_with_errstatus(C):
    """
    Yield all nodes which can report error status.
    Functionality might not be identical in all nodes.
    """
    for xp in C.XPs():
        yield xp
    nm = {}
    for n in C.nodes():
        if not n.is_XP() and node_has_errstatus(n):
            nm[n] = True
    for n in sorted(nm.keys(), key=(lambda x: x.type())):
        yield n


_feats = [
    ("CEC", 12, 3),
    ("CFI", 10, 2),
    ("FI", 6, 2),
    ("UI", 4, 2),
    ("DE", 2, 2),
    ("ED", 0, 2),
]

def errfeat_str(e):
    s = "0x%x " % e
    s += ' '.join(["%s=%u" % (name, BITS(e, p, n)) for (name, p, n) in _feats])
    return s


def print_errstatus(C):
    """
    Print error status and configuration.
    Status registers are present in XP and some nodes including HN-F.
    """
    print("%s error status:" % C)
    last_feat = None
    last_ctrl = None
    last_feat_ns = None
    last_ctrl_ns = None
    for node in nodes_with_errstatus(C):
        print("  %s" % node)
        if C.secure_accessible:
            feat = node.read64(0x3000)
            ctrl = node.read64(0x3008)
            if feat != last_feat:
                print("    Features:     %s" % errfeat_str(feat))
                last_feat = feat
            if ctrl != last_ctrl:
                print("    Control:      %s" % errfeat_str(ctrl))
                last_ctrl = ctrl
        feat_ns = node.read64(0x3100)
        ctrl_ns = node.read64(0x3108)
        if feat_ns != last_feat_ns:
            print("    Features(NS): %s" % errfeat_str(feat_ns))
            last_feat_ns = feat_ns
        if ctrl_ns != last_ctrl_ns:
            print("    Control(NS):  %s" % errfeat_str(ctrl_ns))
            last_ctrl_ns = ctrl_ns
        misc_ns = node.read64(0x3120)
        if misc_ns != 0:
            print("    Info: 0x%x: CEC=%u" % (misc_ns, BITS(misc_ns, 32, 16)), end="")
            if BITS(misc_ns, 63):
                print(" overflow", end="")
            print(" source=0x%x, type=%u" % (BITS(misc_ns, 4, 11), BITS(misc_ns, 0, 4)), end="")
            print()
        addr_ns = node.read64(0x3118)
        if addr_ns != 0:
            print("    Address: 0x%x" % addr)
    # Run through the PrimeCell-style id registers in the root node,
    # to keep register coverage happy
    for r in range(0x3FB8, 0x4000, 8):
        C.rootnode.read64(r)


if __name__ == "__main__":
    import argparse
    import cmn_devmem_find
    parser = argparse.ArgumentParser(description="CMN error status")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="incerase verbosity")
    opts = parser.parse_args()
    Cs = cmn_devmem.cmn_from_opts(opts)
    for C in Cs:
        print_errstatus(C)
