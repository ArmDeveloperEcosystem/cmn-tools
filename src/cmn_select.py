#!/usr/bin/python

"""
CMN node groups

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This module provides 'node selectors' which can be used to designate nodes
within the CMN mesh(es), for various purposes e.g. setting up watchpoints.
A typical use case might be:

  parser.add_argument("--node", type=cmn_select.CMNSelect, action="append")
  ...
  nodes = cmn_select.cmn_select_merge(opts.node)
"""

from __future__ import print_function


import sys
import copy


from cmn_enum import *


o_verbose = 0


_help_text_exprs = """
selection expressions:

  [<type>][<coordinates>]
  <type>@0x<node-id>
  <type>[#<logical-id>]
  cpu#<number>

  Types:
    Node types e.g. XP, SN-F
    Node generic properties e.g. HN
  Coordinates:
    (x, y)
    (x, y, port)
    (x, y, port, device)

  Examples:
    xp#1        - select XP with logical id #1
    rn-f@0xa1   - select RN-F with node id 0xA1
    0xa1        - select any node with node id 0xA1
    sn-f(0,_)   - select all SN-Fs at left edge of mesh
    m1:hn-f     - select all HN-Fs in mesh #1
    cpu#7       - select the device slot and device nodes for CPU #7
"""


_tests = ["xp#1", "rn-f@0xa1", "0xa1", "sn-f(0,_)", "cpu#0"]


# Make this a ValueError so argument parsing handles it nicely
class CMNSelectBad(ValueError):
    def __init__(self, expr, reason):
        self.expr = expr
        self.reason = reason

    def __str__(self):
        return "%s: %s" % (self.expr, self.reason)


class CMNSelectSingle:
    """
    Selector for a group of CMN nodes, by node type, position, logical id etc.
    """
    def __init__(self, s=None, props=None, type=None, x=None, y=None, port=None, dev=None, nodeid=None, cmn_seq=None, cpu_number=None, logical_id=None):
        self.cmn_seq = cmn_seq
        self.node_props = props    # CMN_PROP_...
        self.node_type = type
        self.cpu_number = cpu_number
        self.node_x = x
        self.node_y = y
        self.node_port = port
        self.node_device = dev
        self.node_id = nodeid      # Note that a node id that is 0 mod 8, will match an XP as well as P0.D0 devices
        self.logical_id = logical_id
        self.match_str = s         # Save the original string, for diagnostics etc.
        if s:
            self.update(s)

    def copy(self):
        return copy.copy(self)

    def update(self, s):
        """
        Given a selector string, update the selection object.
        """
        expr = s
        s = s.upper()
        if len(s) > 1 and s.startswith("M") and s[1] in "0123456789":
            ix = s.find(':')
            meshs = s[1:ix] if ix >= 0 else s
            try:
                self.cmn_seq = int(meshs)
            except ValueError:
                raise CMNSelectBad(expr, "bad mesh selector")
            s = s[ix+1:] if ix >= 0 else ""
        if s.startswith("CPU#"):
            try:
                self.cpu_number = int(s[4:])
            except ValueError:
                raise CMNSelectBad(expr, "bad CPU number")
        elif '#' in s:
            # logical id e.g. "XP#3"
            hix = s.index('#')
            try:
                self.logical_id = int(s[hix+1:])
            except ValueError:
                raise CMNSelectBad(expr, "bad logical id")
            nts = s[:hix]
            self.update_node_type(s[:hix])
        elif '(' in s and s.endswith(")") and ',' in s:
            # mesh coordinates
            def coord(s):
                try:
                    return int(s) if s not in ["", "_"] else None
                except ValueError:
                    raise CMNSelectBad(expr, "bad coordinate")
            bix = s.index('(')
            cos = s[bix+1:-1].split(',')
            if len(cos) not in [2, 3, 4]:
                raise CMNSelectBad(expr, "expected coordinates (x, y, [port], [device])")
            self.node_x = coord(cos[0])
            self.node_y = coord(cos[1])
            self.node_port = coord(cos[2]) if len(cos) >= 3 else None
            self.node_device = coord(cos[3]) if len(cos) >= 4 else None
            if bix > 0:
                self.update_node_type(s[:bix])
        elif '@' in s:
            aix = s.index('@')
            try:
                self.node_id = int(s[aix+1:], 16)
            except ValueError:
                raise CMNSelectBad(expr, "bad node id")
            if aix > 0:
                self.update_node_type(s[:aix])
        elif s.startswith("0X"):
            try:
                self.node_id = int(s, 16)
            except ValueError:
                raise CMNSelectBad(expr, "bad node id")
        else:
            self.update_node_type(s)
        if o_verbose:
            print("after update: %s" % self)

    def update_node_type(self, nts):
        """
        Given either a node properties string, or a node type string, configure the selector
        to match only the matching nodes.
        """
        self.node_type = None
        self.node_props = None
        self.node_props = cmn_properties(nts, check=False)
        if self.node_props is None:
            for (nv, ns) in cmn_node_type_strings.items():
                if ns == nts:
                    self.node_type = nv       # must match this exact node type
                    self.node_props = cmn_node_type_properties(nv)
                    break
        if self.node_props is None and self.node_type is None:
            raise CMNSelectBad(nts, "bad node selector")

    def __str__(self):
        s = self.match_str if self.match_str else ""
        ms = []
        if self.cmn_seq is not None:
            ms.append("seq=%u" % self.cmn_seq)
        if self.cpu_number is not None:
            ms.append("cpu=%u" % self.cpu_number)
        if self.node_type is not None:
            ms.append("type=%s" % cmn_node_type_str(self.node_type))
        if self.logical_id is not None:
            ms.append("#%u" % self.logical_id)
        if self.node_id is not None:
            ms.append("nodeid=0x%x" % self.node_id)
        if self.node_props is not None:
            ms.append("props=%s" % cmn_properties_str(self.node_props, join="|"))
        if self.node_x is not None:
            ms.append("x=%u" % self.node_x)
        if self.node_y is not None:
            ms.append("y=%u" % self.node_y)
        if self.node_port is not None:
            ms.append("port=%u" % self.node_port)
        if self.node_device is not None:
            ms.append("device=%u" % self.node_device)
        s += "{%s}" % ','.join(ms)
        return s

    def _cmn_cpu(self, cmn):
        if self.cpu_number is None:
            return None
        if not cmn.has_cpu_mappings():
            return None
        try:
            return cmn.owner.cpu(self.cpu_number)
        except Exception:
            return None

    def _device_matches_cpu(self, dev):
        if self.cpu_number is None:
            return True
        if not dev.port.has_properties(CMN_PROP_RNF):
            return False
        return any([cpu.cpu == self.cpu_number for cpu in getattr(dev, "cpus", [])])

    def match_node(self, node):
        """
        Return true if the selector matches a node (device, XP or CFG)
        """
        if self.cmn_seq is not None and self.cmn_seq != node.CMN().cmn_seq:
            return False
        if self.cpu_number is not None:
            if node.is_rootnode() or node.is_XP():
                return False
            dev = node.device_object
            if not self._device_matches_cpu(dev):
                return False
        if self.node_x is not None and (node.is_rootnode() or self.node_x != node.XY()[0]):
            return False
        if self.node_y is not None and (node.is_rootnode() or self.node_y != node.XY()[1]):
            return False
        if self.node_port is not None and (node.is_rootnode() or node.is_XP() or self.node_port != node.coords()[2]):
            return False
        if self.node_device is not None and (node.is_rootnode() or node.is_XP() or self.node_device != node.coords()[3]):
            return False
        if self.node_type is not None and self.node_type != node.type():
            return False
        if self.node_id is not None and self.node_id != node.node_id():
            return False
        if self.logical_id is not None and self.logical_id != node.logical_id():
            return False
        if self.node_props is not None and not node.has_properties(self.node_props):
            return False
        return True

    def match_device(self, dev):
        """
        Return true if the selector matches a device slot.
        This is primarily driven by any device nodes within the slot, but for
        external attachments such as RN-F/SN-F, which have no device nodes,
        we fall back to the port's connected-device properties.
        """
        xy = dev.XP().XY()
        if self.cmn_seq is not None and self.cmn_seq != dev.CMN().cmn_seq:
            return False
        if not self._device_matches_cpu(dev):
            return False
        if self.node_x is not None and self.node_x != xy[0]:
            return False
        if self.node_y is not None and self.node_y != xy[1]:
            return False
        if self.node_port is not None and self.node_port != dev.port.port_number:
            return False
        if self.node_device is not None and self.node_device != dev.device_number:
            return False
        if self.node_id is not None and self.node_id != dev.node_id():
            return False
        dnodes = list(dev.device_nodes)
        if self.node_type is not None:
            if self.node_type in [CMN_NODE_CFG, CMN_NODE_XP]:
                return False
            if not any([n.type() == self.node_type for n in dnodes]):
                return False
        if self.logical_id is not None:
            if not any([n.logical_id() == self.logical_id for n in dnodes]):
                return False
        if self.node_props is not None:
            if any([n.has_properties(self.node_props) for n in dnodes]):
                return True
            if dev.port.has_properties(self.node_props):
                return True
            return False
        return True

    def can_match_devices_at_cmn(self, cmn):
        """
        Return true if the selector might match some devices in the given CMN.
        """
        if self.cmn_seq is not None and self.cmn_seq != cmn.cmn_seq:
            return False
        if self.cpu_number is not None:
            cpu = self._cmn_cpu(cmn)
            return cpu is not None and cpu.CMN() == cmn
        return True

    def can_match_devices_at_xp(self, node):
        """
        In some tree walks, to avoid having to recursively discover device nodes
        before applying matches, we want to check that no device node could
        possibly match. Return true if the selector could match any devices under the XP.
        """
        assert node.is_XP(), "expected XP: %s" % node
        if not self.can_match_devices_at_cmn(node.CMN()):
            return False
        if self.cpu_number is not None and not node.has_any_ports(CMN_PROP_RNF):
            return False
        if self.node_x is not None and self.node_x != node.XY()[0]:
            return False
        if self.node_y is not None and self.node_y != node.XY()[1]:
            return False
        if self.node_id is not None and not node.is_valid_id(self.node_id):
            return False
        if self.node_type is not None and self.node_type in [CMN_NODE_CFG, CMN_NODE_XP]:
            return False
        if self.node_props is not None and not cmn_has_property(self.node_props, CMN_PROP_DEV):
            # Maybe the selector is matching XPs/CFG only.
            return False
        return True

    def can_match_devices_at_port(self, port):
        """
        Check if the selector can match some devices under a CMNPort object.
        This may check the port properties (although watch out for CALs!).
        """
        if not self.can_match_devices_at_xp(port.XP()):
            return False
        if self.cpu_number is not None and not port.has_properties(CMN_PROP_RNF):
            return False
        if self.node_port is not None and self.node_port != port.port_number:
            return False
        if self.node_props is not None and not port.has_properties(self.node_props):
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
    The empty selector (no expressions) matches everything.
    """
    def __init__(self, exprs=None):
        if o_verbose:
            print("Constructing selection:")
            print("  Expressions: %s" % str(exprs))
            #print("  Selectors:   %s" % str(selectors))
        self.matchers = []
        if exprs:
            self.matchers += [CMNSelectSingle(s) for s in rec_split(exprs, ',', exclude_empty=True)]

    def append(self, expr):
        self.matchers.append(expr)

    def match_node(self, node):
        """
        Return true if any match-expression matches a node.
        """
        return (not self.matchers) or any([m.match_node(node) for m in self.matchers])

    def match_device(self, dev):
        """
        Return true if any match-expression matches a device slot.
        """
        return (not self.matchers) or any([m.match_device(dev) for m in self.matchers])

    def can_match_devices_at_cmn(self, cmn):
        return (not self.matchers) or any([m.can_match_devices_at_cmn(cmn) for m in self.matchers])

    def can_match_devices_at_xp(self, node):
        return (not self.matchers) or any([m.can_match_devices_at_xp(node) for m in self.matchers])

    def can_match_devices_at_port(self, port):
        return (not self.matchers) or any([m.can_match_devices_at_port(port) for m in self.matchers])

    def __str__(self):
        return ", ".join([str(m) for m in self.matchers]) if self.matchers else "{}"


def iter_xp_nodes(xp, selector=None, include_xp=True, include_devices=True):
    """
    Yield the selected topology nodes for an XP, in lexicographic coordinate
    order: XP first, then port/device order underneath it.
    """
    if o_verbose >= 2:
        print("%s:     XP %s" % (selector, xp))
    if selector is None:
        if include_xp:
            yield xp
        if include_devices:
            for port in xp.ports():
                for node in port.nodes():
                    yield node
        return
    if include_xp and selector.match_node(xp):
        yield xp
    if not include_devices or not selector.can_match_devices_at_xp(xp):
        return
    for port in xp.ports():
        if not selector.can_match_devices_at_port(port):
            if o_verbose >= 2:
                print("      skipping %s, can't match" % port)
            continue
        for node in port.nodes():
            if selector.match_node(node):
                yield node


def iter_port_devices(port, selector=None):
    """
    Yield the selected device slots for a port, in device-number order.
    """
    if selector is not None and not selector.can_match_devices_at_port(port):
        return
    for id in port.ids():
        dev = port.device_at_id(id, create=True)
        if selector is None or selector.match_device(dev):
            yield dev


def iter_xp_devices(xp, selector=None):
    """
    Yield the selected device slots for an XP, in port/device order.
    """
    if selector is not None and not selector.can_match_devices_at_xp(xp):
        return
    for port in xp.ports():
        for dev in iter_port_devices(port, selector=selector):
            yield dev


def iter_cmn_nodes(cmn, selector=None, include_root=False, include_xps=True, include_devices=True):
    """
    Yield the selected topology nodes for a CMN, ordered by XP coordinates.
    """
    if o_verbose >= 2:
        print("%s: %s" % (selector, cmn))
    rootnode = getattr(cmn, "rootnode", None)
    if include_root and rootnode is not None and (selector is None or selector.match_node(rootnode)):
        yield rootnode
    if selector is not None and not selector.can_match_devices_at_cmn(cmn):
        return
    if not include_xps and not include_devices:
        return
    for xp in cmn.XPs():
        for node in iter_xp_nodes(xp, selector=selector, include_xp=include_xps, include_devices=include_devices):
            yield node


def iter_cmn_devices(cmn, selector=None):
    """
    Yield the selected device slots for a CMN, ordered by XP coordinates.
    """
    if selector is not None and not selector.can_match_devices_at_cmn(cmn):
        return
    for xp in cmn.XPs():
        for dev in iter_xp_devices(xp, selector=selector):
            yield dev


def iter_system_nodes(system, selector=None, include_root=False, include_xps=True, include_devices=True):
    """
    Yield the selected topology nodes for a system.
    """
    for cmn in sorted(system.CMNs, key=lambda cmn: cmn.cmn_seq):
        for node in iter_cmn_nodes(cmn, selector=selector, include_root=include_root, include_xps=include_xps, include_devices=include_devices):
            yield node


def iter_system_devices(system, selector=None):
    """
    Yield the selected device slots for a system.
    """
    for cmn in sorted(system.CMNs, key=lambda cmn: cmn.cmn_seq):
        for dev in iter_cmn_devices(cmn, selector=selector):
            yield dev


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


def main(argv):
    global o_verbose
    import argparse
    parser = argparse.ArgumentParser(description="CMN node match test",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=_help_text_exprs)
    parser.add_argument("--select", type=CMNSelect, action="append", help="selection expressions")
    parser.add_argument("--test", action="store_true", help="run self-tests")
    parser.add_argument("exprs", type=str, nargs="*", help="selection expressions")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    if opts.test:
        print("Tests:")
        for e in _tests:
            print("  %s: %s" % (e, CMNSelect(e)))
    ms = [CMNSelect(s) for s in opts.exprs]
    print("Selection: %s" % (cmn_select_merge(ms)))
    if opts.select:
        print(cmn_select_merge(opts.select))


if __name__ == "__main__":
    main(sys.argv[1:])
