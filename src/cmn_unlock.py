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


import cmn_devmem_find
import cmn_devmem
import cmn_select


def select_nodes(c, sel):
    """
    Yield all selected nodes in a CMN instance
    """
    if sel.can_match_devices_at_cmn(c):
        for xp in c.XPs():
            if sel.match_node(xp):
                yield xp
            if sel.can_match_devices_at_xp(xp):
                for p in range(0, 4):
                    for node in xp.port_nodes(p):
                        if sel.match_node(node):
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
    }[r]


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="CMN lock/unlock")
    gex = parser.add_mutually_exclusive_group()
    gex.add_argument("--unlock", action="store_true", help="unlock CMN secure registers")
    gex.add_argument("--lock", action="store_true", help="lock CMN secure registers")
    parser.add_argument("--value", type=(lambda x:int(x, 16)), default=0x01, help="lock bits")
    parser.add_argument("-n", "--node", type=cmn_select.CMNSelect, help="nodes (default root node)")
    parser.add_argument("--dump", action="store_true", help="dump list of writes")
    rex = parser.add_mutually_exclusive_group()
    rex.add_argument("--root", action="store_true", help="write root security register")
    rex.add_argument("--root-only", action="store_true", help="write only root security register")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    if opts.value == 0:
        print("flags value must be non-zero", file=sys.stderr)
        sys.exit(1)
    last_c = None
    regs = []
    if not opts.root_only:
        regs.append(cmn_devmem.CMN_any_SECURE_ACCESS)
    if opts.root or opts.root_only:
        regs.append(cmn_devmem.CMN_any_ROOT_ACCESS)
    assert regs
    for node in iter_nodes(opts):
        if opts.dump:
            for r in regs:
                if opts.lock or opts.unlock:
                    verb = "set" if opts.unlock else "clear"
                    print("%s %x %x" % (verb, node.node_base_addr + r, opts.value))
                else:
                    print("print %x" % (node.node_base_addr))
            continue
        c = node.CMN()
        if c != last_c:
            if opts.verbose or not (opts.lock or opts.unlock):
                print("%s:" % c)
                print("  global security: 0x%08x" % c.rootnode.read64(cmn_devmem.CMN_any_SECURE_ACCESS))
            last_c = c
        if opts.lock or opts.unlock:
            if opts.verbose and not node.is_rootnode():
                print("  %s:" % node)
            for r in regs:
                oldv = node.read64(r)
                if opts.verbose and not node.is_rootnode():
                    print("    local %s security: 0x%08x" % (reg_name(r), oldv))
                if not c.secure_accessible:
                    node.set_secure_access(c.root_security)
                if opts.unlock:
                    newv = oldv | opts.value
                else:
                    newv = oldv & ~opts.value
                node.write64(r, newv, check=True)
                if opts.verbose:
                    print("              now: 0x%08x" % node.read64(r))
        else:
            if not node.is_rootnode():
                print("%s:" % node, end="")
                for r in regs:
                    print(" %s: 0x%x" % (reg_name(r), node.read64(r)), end="")
                print()


if __name__ == "__main__":
    main(sys.argv[1:])
