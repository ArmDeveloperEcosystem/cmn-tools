#!/usr/bin/python

"""
CMN node groups

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import sys


from cmn_enum import *


o_verbose = 0


class CMNSelectBad(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return self.reason


class CMNSelectSingle:
    """
    Selector for a group of CMN nodes, by node type, position, logical id etc.
    """
    def __init__(self, s=None):
        self.node_props = None       # CMN_PROP_...
        self.node_type = None
        self.node_x = None
        self.node_y = None
        self.logical_id = None
        self.match_str = s
        if s:
            self.update(s)

    def update(self, s):
        s = s.upper()
        if '#' in s:
            # logical id e.g. "XP#3"
            hix = s.index('#')
            self.logical_id = int(s[hix+1:])
            nts = s[:hix]
            self.update_node_type(s[:hix])
        elif '(' in s and s.endswith(")") and ',' in s:
            # mesh coordinates
            bix = s.index('(')
            (x, y) = s[bix+1:-1].split(',')
            self.node_x = int(x) if x != "" else None
            self.node_y = int(y) if y != "" else None
            if bix > 0:
                self.update_node_type(s[:bix])
        else:
            self.update_node_type(s)
        if o_verbose:
            print("after update: %s" % self)

    def update_node_type(self, nts):
        self.node_type = None
        self.node_props = None
        self.node_props = cmn_properties(nts, check=False)
        if self.node_props is None:
            for (nv, ns) in cmn_node_type_strings.items():
                if ns == nts:
                    self.node_type = nv
                    break
        if self.node_props is None and self.node_type is None:
            raise CMNSelectBad("bad node selector: %s" % nts)

    def __str__(self):
        s = self.match_str if self.match_str else ""
        ms = []
        if self.node_type is not None:
            ms.append("type=%s" % cmn_node_type_str(self.node_type))
        if self.logical_id is not None:
            ms.append("#%u" % self.logical_id)
        if self.node_props is not None:
            ms.append("props=%s" % cmn_properties_str(self.node_props, join="|"))
        if self.node_x is not None:
            ms.append("x=%u" % self.node_x)
        if self.node_y is not None:
            ms.append("y=%u" % self.node_y)
        s += "{%s}" % ','.join(ms)
        return s

    def match_node(self, node):
        if self.node_x is not None and (node.is_rootnode() or self.node_x != node.XY()[0]):
            return False
        if self.node_y is not None and (node.is_rootnode() or self.node_y != node.XY()[1]):
            return False
        if self.node_type is not None and self.node_type != node.type():
            return False
        if self.logical_id is not None and self.logical_id != node.logical_id():
            return False
        if self.node_props is not None and not node.has_properties(self.node_props):
            return False
        return True

    def can_match_devices_at_xp(self, node):
        """
        In some tree walks, to avoid having to recursively discover device nodes
        before applying matches, we want to check that no device node could
        possibly match.
        """
        assert node.is_XP(), "expected XP: %s" % node
        if self.node_x is not None and self.node_x != node.XY()[0]:
            return False
        if self.node_y is not None and self.node_y != node.XY()[1]:
            return False
        if self.node_type is not None and self.node_type in [CMN_NODE_CFG, CMN_NODE_XP]:
            return False
        if self.node_props is not None and not cmn_has_property(self.node_props, CMN_PROP_DEV):
            return False
        return True


def rec_split(s, delim, exclude_empty=False):
    """
    Split a string, taking account of brackets, e.g.
      split("a,(b,c),d")
    returns
      ["a", "(b,c)", "d"]
    """
    ix = 0
    start = 0
    brackets = ["()", "[]", "<>", "{}"]
    in_bra = {}
    out_bra = {}
    tot_bra = 0
    for b in brackets:
        in_bra[b[0]] = 0
        out_bra[b[1]] = b[0]
    while ix < len(s):
        if not tot_bra and s[ix:].startswith(delim):
            if ix != start or not exclude_empty:
                yield s[start:ix]
            ix += len(delim)
            start = ix
        elif s[ix] in in_bra:
            in_bra[s[ix]] += 1
            tot_bra += 1
            ix += 1
        elif s[ix] in out_bra:
            in_bra[out_bra[s[ix]]] -= 1
            tot_bra -= 1
            ix += 1
        else:
            ix += 1
    if s[start:] or not exclude_empty:
        yield s[start:]


assert list(rec_split("a,(b,c),d", ",")) == ["a", "(b,c)", "d"]


class CMNSelect:
    """
    Match against one or more match expressions.
    This class name is suitable for using as a type name in argparse.
    """
    def __init__(self, exprs=None):
        self.matchers = []
        if exprs:
            self.matchers = [CMNSelectSingle(s) for s in rec_split(exprs, ',', exclude_empty=True)]

    def match_node(self, node):
        return any([m.match_node(node) for m in self.matchers])

    def can_match_devices_at_xp(self, node):
        return any([m.can_match_devices_at_xp(node) for m in self.matchers])

    def __str__(self):
        return ", ".join([str(m) for m in self.matchers])


def cmn_select_merge(mlist):
    """
    Marge several CMNSelect objects into one.
    """
    if mlist is None:
        return None
    else:
        m = CMNSelect()
        for me in mlist:
            m.matchers += me.matchers
        return m


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN node match test")
    parser.add_argument("--select", type=CMNSelect, action="append")
    parser.add_argument("exprs", type=str, nargs="*")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    ms = [CMNSelect(s) for s in opts.exprs]
    print(cmn_select_merge(ms))
    print(cmn_select_merge(opts.select))
