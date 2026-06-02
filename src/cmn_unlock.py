#!/usr/bin/python

"""
Write to Secure-writeable-only security override registers,
to allow NonSecure reading of SLC/SF, RN-SAM etc.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This tool supports writing:

 - the global Secure override register, in the Configuration node

 - override registers (Secure, and Root) in individual nodes

The exact effects are described in product documentation.
This tool will generally need to be run from an environment that
can generate accesses with Secure and/or Root privilege, such as
JTAG access via ArmDS.

Alternatively, run with --dump to output a list of device addresses
and values to pass to another tool to do the access.
"""

from __future__ import print_function

import sys
import os


import devmem_base
import cmn_devmem_find
import cmn_devmem
import cmn_select
import cmn_base
from cmn_enum import *


def select_nodes(c, sel):
    """
    Yield all selected nodes in a CMN instance
    """
    for node in cmn_select.iter_cmn_nodes(c, selector=sel, include_root=True):
        yield node


def iter_nodes(opts):
    """
    Yield all matching nodes
    """
    clocs = list(cmn_devmem_find.cmn_locators(opts))
    CS = [cmn_devmem.CMN(cl, verbose=opts.verbose) for cl in clocs]
    for c in CS:
        if opts.node is None:
            yield c.rootnode
        else:
            for node in select_nodes(c, opts.node):
                yield node


def reg_name(r):
    return {
        cmn_devmem.CMN_any_SECURE_ACCESS: "Secure",
        cmn_devmem.CMN_any_ROOT_ACCESS:   "Root",
        0x990:                            "Secure",   # in cfgm, for its own regs
    }[r]



_nom_600 = {
    CMN_NODE_DN:       0x1,
    CMN_NODE_HNF:     0x3f,
    CMN_NODE_HNI:      0x3,
    CMN_NODE_RNI:      0x7,
    CMN_NODE_RND:      0x7,
    CMN_NODE_RNSAM:    0x1,
    CMN_NODE_CXRA:     0xf,
    CMN_NODE_CXHA:     0x3,
    CMN_NODE_CXLA:     0x4,
}


_nom_650 = {
    CMN_NODE_DN:       0x3,
    CMN_NODE_HNF:     0x7f,
    CMN_NODE_HNI:      0x3,
    CMN_NODE_XP:      0x3f,
    CMN_NODE_SBSX:     0x1,
    CMN_NODE_RNI:      0xf,
    CMN_NODE_RND:      0xf,
    CMN_NODE_RNSAM:    0x1,
    CMN_NODE_CXRA:     0xf,
    CMN_NODE_CXHA:     0xf,
    CMN_NODE_CXLA:     0xd,
}


_nom_700 = {
    CMN_NODE_DN:       0x3,
    CMN_NODE_CFG:     0x80,
    CMN_NODE_HNF:    0x1ff,
    CMN_NODE_HNI:     0x83,
    CMN_NODE_XP:      0xff,
    CMN_NODE_SBSX:    0x81,
    CMN_NODE_RNI:      0xf,
    CMN_NODE_RND:      0xf,
    CMN_NODE_RNSAM:    0x1,
    CMN_NODE_MTSX:    0x83,   # aka MTU
    CMN_NODE_HNP:     0x83,   # HN-I
    CMN_NODE_CXRA:     0xf,
    CMN_NODE_CXHA:    0x8f,
    CMN_NODE_CXLA:   0x980,
    CMN_NODE_CCG_RA:   0xf,
    CMN_NODE_CCG_HA:  0x8f,
    CMN_NODE_CCLA:     0x9,
    CMN_NODE_HNS:    0x3ff,
    CMN_NODE_APB:      0x1,
}


_nom_S3 = {
    CMN_NODE_DN:       0x3,
    CMN_NODE_CFG:      0x7,
    CMN_NODE_HNF:    0x3ff,
    CMN_NODE_HNI:     0x83,
    CMN_NODE_XP:     0x1ff,
    CMN_NODE_SBSX:    0x81,
    CMN_NODE_RNI:      0xf,
    CMN_NODE_RND:      0xf,
    CMN_NODE_RNSAM:    0x1,
    CMN_NODE_MTSX:    0x83,   # aka MTU
    CMN_NODE_HNP:     0x83,   # HN-I
    CMN_NODE_CXRA:     0xf,
    CMN_NODE_CXHA:    0x8f,
    CMN_NODE_CXLA:   0x980,
    CMN_NODE_CCG_RA:   0xf,
    CMN_NODE_CCG_HA:   0xf,
    CMN_NODE_CCLA:   0x1f9,
    CMN_NODE_HNS:    0x3ff,
    CMN_NODE_APB:      0x1,
}


def node_override_mask(node):
    if node.C.product_config.product_id == cmn_base.PART_CMN600:
        return _nom_600.get(node.type(), 0)
    elif node.C.product_config.product_id == cmn_base.PART_CMN650:
        return _nom_650.get(node.type(), 0)
    elif node.C.product_config.product_id == cmn_base.PART_CMN700:
        return _nom_700.get(node.type(), 0)
    elif node.C.part_ge_S3():
        return _nom_S3.get(node.type(), 0)
    else:
        return 0x01


class CMNLocker:
    def __init__(self, opts):
        self.verbose = opts.verbose
        self.value = opts.value      # or None to use node-appropriate value
        self.lock = opts.lock
        self.unlock = opts.unlock
        self.opts = opts
        self.last_c = None
        self.n_changed = 0

    def is_action(self):
        return self.lock or self.unlock

    def node_value(self, node):
        return self.value if self.value else node_override_mask(node)

    def node_local_overrides(self, node):
        if not self.opts.root_only:
            yield 0x990 if node.is_rootnode() else cmn_devmem.CMN_any_SECURE_ACCESS
        if node.C.part_ge_S3() and not self.opts.secure_only:
            yield cmn_devmem.CMN_any_ROOT_ACCESS

    def do_nodes(self):
        """
        Visit all selected nodes.
        If a node selector is provided, visit those nodes.
        Else, if CMN supports a global override, just visit the root node to do that.
        Else, visit all nodes and do their local overrides.
        """
        if self.verbose:
            print("visiting nodes...", file=sys.stderr)
        for node in iter_nodes(self.opts):
            # iter_nodes() at least gives us the root node on all meshes
            if node.is_rootnode() and not self.opts.node:
                # User wants default action
                if (not self.opts.local) and (not node.C.part_ge_S3()):
                    # Global override
                    self.do_node_reg(node, cmn_devmem.CMN_any_SECURE_ACCESS, 0x01)
                else:
                    # S3: have to do local overrides on all nodes
                    if not self.opts.local:
                        print("%s: no global override, setting local overrides only" % (node.CMN()), file=sys.stderr)
                    for node in cmn_select.iter_cmn_nodes(node.CMN(), include_root=True):
                        self.do_node_local(node)
            else:
                self.do_node_local(node)

    def do_node_local(self, node):
        """
        Do local overrides on a node, i.e. controls for (some of) its own registers.
        """
        v = self.node_value(node)
        if self.verbose >= 2:
            print("local %s: 0x%x" % (node, v), file=sys.stderr)
        if v == 0:
            # This node type has no local overrides
            if self.verbose >= 2:
                print("  no local overrides, ignoring", file=sys.stderr)
            return
        for r in self.node_local_overrides(node):
            self.do_node_reg(node, r, v)

    def do_node_reg(self, node, r, v):
        self.n_changed += 1
        if self.opts.dump:
            if self.is_action():
                verb = "set" if self.opts.unlock else "clear"
                print("%s %x %x" % (verb, node.node_base_addr + r, v))
            else:
                print("print %x" % (node.node_base_addr + r))
        else:
            c = node.CMN()
            if c != self.last_c:
                if self.verbose or not self.is_action():
                    print("%s:" % c)
                    print("  global security: 0x%08x" % c.rootnode.read64(cmn_devmem.CMN_any_SECURE_ACCESS))
                self.last_c = c
            if self.is_action():
                if self.verbose and not node.is_rootnode():
                    print("  %s:" % node)
                if not c.secure_accessible:
                    olds = node.set_secure_access(c.root_security)
                oldv = node.read64(r)
                if self.verbose and not node.is_rootnode():
                    print("    local %s security: 0x%08x" % (reg_name(r), oldv))
                olds = None
                if self.unlock:
                    newv = oldv | v
                else:
                    newv = oldv & ~v
                if newv != oldv:
                    node.write64(r, newv, check=(self.unlock))
                    changed = True
                chkv = node.read64(r)
                if olds is not None:
                    node.set_secure_access(olds)
                if self.verbose:
                    print("              now: 0x%08x" % chkv)
            else:
                print("%s: %s: 0x%x" % (node, reg_name(r), node.read64(r)))


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="CMN lock/unlock")
    gex = parser.add_mutually_exclusive_group()
    gex.add_argument("--unlock", action="store_true", help="unlock CMN secure registers")
    gex.add_argument("--lock", action="store_true", help="lock CMN secure registers")
    parser.add_argument("--value", type=(lambda x:int(x, 16)), help="lock bits")
    parser.add_argument("-n", "--node", type=cmn_select.CMNSelect, help="nodes (default root node)")
    parser.add_argument("--dump", action="store_true", help="dump list of writes")
    parser.add_argument("--local", action="store_true", help="all local overrides")
    rex = parser.add_mutually_exclusive_group()
    rex.add_argument("--secure-only", action="store_true", help="write only Secure override register")
    rex.add_argument("--root-only", action="store_true", help="write only Root override register")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    if opts.value == 0:
        print("flags value must be non-zero", file=sys.stderr)
        sys.exit(1)
    L = CMNLocker(opts)
    try:
        L.do_nodes()
    except devmem_base.DevMemNoSecure as e:
        print("%s" % e, file=sys.stderr)
        sys.exit(1)
    # Any failures will have been reported already
    if L.is_action():
        print("Target %s %sed" % (("now" if L.n_changed else "already"), ("lock" if opts.lock else "unlock")))


if __name__ == "__main__":
    main(sys.argv[1:])
