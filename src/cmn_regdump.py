#!/usr/bin/python

"""
Dump all registers from CMN

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os
import sys
import re


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cmn_devmem import cmn_from_opts
from cmn_enum import *
import cmn_base
import cmn_devmem_find
import cmn_select
import regview


o_verbose = 0


def BITS(x, p, n):
    return (x >> p) & ((1 << n) - 1)


_cmn_part_map = {
    cmn_base.PART_CMN600: "cmn600",
    cmn_base.PART_CMN650: "cmn650",
    cmn_base.PART_CMN700: "cmn700",
    cmn_base.PART_CMN_S3: "cmns3",
}


def get_pident(cfg):
    pident = _cmn_part_map.get(cfg.product_id, None)
    if cfg.product_id == cmn_base.PART_CMN700:
        if cfg.revision < 1:
            pident += "-r0"
        elif cfg.revision < 2:
            pident += "-r1"
        else:
            pident += "-r3"
    if cfg.product_id == cmn_base.PART_CMN_S3:
        if cfg.revision < 2:
            pident += "-r0"
        elif cfg.revision < 3:
            pident += "-r1"
        else:
            pident += "-r2"
    return pident


_cmn_node_map = {
    CMN_NODE_DN: "por_dn",
    CMN_NODE_CFG: "por_cfgm",
    CMN_NODE_DT: "por_dt",
    CMN_NODE_HNI: "por_hni",
    CMN_NODE_HNF: "por_hnf",
    CMN_NODE_XP: "por_mxp",
    CMN_NODE_SBSX: "por_sbsx",
    CMN_NODE_MPAM_S: "por_hnf_mpam_s",
    CMN_NODE_MPAM_NS: "por_hnf_mpam_ns",
    CMN_NODE_RNI: "por_rni",
    CMN_NODE_RND: "por_rnd",
    CMN_NODE_RNSAM: "por_rnsam",
    CMN_NODE_HNP: "por_hni",   # sic
    CMN_NODE_CXRA: "por_cxg_ra",
    CMN_NODE_CXHA: "por_cxg_ha",
    CMN_NODE_CXLA: "por_cxla",
    CMN_NODE_CCG_RA: "por_ccg_ra",
    CMN_NODE_CCG_HA: "por_ccg_ha",
    CMN_NODE_CCLA: "por_ccla",
    CMN_NODE_CCLA_RNI: "por_rni",
    CMN_NODE_HNS: "cmn_hns",
    CMN_NODE_HNS_MPAM_S: "cmn_hns_mpam_s",
    CMN_NODE_HNS_MPAM_NS: "cmn_hns_mpam_ns",
    CMN_NODE_APB: "por_apb",
}


def node_ident(n):
    """
    Given a CMN node type, construct the register group name.
    """
    nident = _cmn_node_map.get(n.type(), None)
    if nident.startswith("por_hnf"):
        # HN-F or one of its MPAM nodes
        if (n.C.part_ge_700() and n.C.product_config.revision >= 3) or n.C.part_ge_S3():
            nident = "cmn_hns" + nident[7:]    # not "por_hnf"...
    return nident + "_registers" if nident is not None else None


class CMNRegMapper:
    """
    Dump CMN configuration registers
    """
    def __init__(self, regdefs_dir=None, regmaps=None, descriptions=True, description_limit=100, fields=True, include_read_only=False, skip_zeroes=True, match_reg_names=None, match_nodes=None, flat=False):
        self.regdefs_dir = regdefs_dir
        self.regmaps = regmaps
        self.regmaps_product = None
        self.o_descriptions = descriptions
        self.description_limit = 100
        self.o_fields = fields
        self.o_include_read_only = include_read_only
        self.o_match_reg_names = match_reg_names
        self.o_match_nodes = match_nodes
        self.o_skip_zeroes = skip_zeroes
        self.o_flat = flat
        self.n_regs_reserved_bits_set = 0
        if regdefs_dir is None:
            rdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "regdefs")
            self.set_regdefs_dir(rdir)

    def had_errors(self):
        """
        See if any errors were encountered - this could be reserved bits set,
        or (in future) invalid values for enumerators.
        """
        return self.n_regs_reserved_bits_set > 0

    def set_regdefs_dir(self, regdefs_dir):
        self.regdefs_dir = regdefs_dir
        if regdefs_dir is not None and not os.path.isdir(regdefs_dir):
            print("%s: can't find register definitions directory" % regdefs_dir, file=sys.stderr)
            sys.exit(1)

    def set_regmaps_from_cmn_product(self, cfg):
        if o_verbose:
            print("Getting register definitions for %s" % cfg, file=sys.stderr)
        if cfg == self.regmaps_product:
            if o_verbose:
                print("(using previous definitions)", file=sys.stderr)
            return
        pident = get_pident(cfg)
        regdefs_dir = self.regdefs_dir or "."
        if self.o_descriptions:
            regfn = os.path.join(regdefs_dir, pident + "-desc.regdefs")
        else:
            regfn = None
        if regfn is None or not os.path.isfile(regfn):
            regfn = os.path.join(regdefs_dir, pident + ".regdefs")
        if not os.path.isfile(regfn):
            print("No register definitions yet: %s (expect %s)" % (cfg, regfn), file=sys.stderr)
            sys.exit(1)
        self.set_regmaps_from_file(regfn)
        self.regmaps_product = cfg

    def set_regmaps_from_file(self, regfn):
        if o_verbose:
            print("%s: loading register map" % regfn, file=sys.stderr)
        regmaps = regview.regdefs_from_file(regfn, verbose=o_verbose)
        self.set_regmaps(regmaps)

    def set_regmaps(self, regmaps):
        self.regmaps = regmaps
        self.regmaps_product = None

    @staticmethod
    def valstr(x, width=None):
        # Print a value in hex or decimal, taking account of the value itself and its field width.
        # Printing 11-bit values as hex ensures that CHI node ids are always hex.
        if x >= 1000 or width >= 11:
            return "0x%x" % x
        else:
            return "%u" % x

    def descstr(self, s):
        if len(s) > self.description_limit:
            return s[:self.description_limit] + "..."
        return s

    def cmn_dump_regs(self, C):
        self.set_regmaps_from_cmn_product(C.product_config)
        self.node_dump_regs(C.rootnode)
        for xp in C.XPs():
            self.node_dump_regs(xp)
            for i in range(0, 4):
                for node in xp.port_nodes(i):
                    self.node_dump_regs(node)

    @staticmethod
    def locator_str(n):
        if n.type() == CMN_NODE_CFG:
            s = "cfg"
        else:
            (x, y, p, d) = n.coords()
            s = "mxp(%u,%u)" % (x, y)
            if not n.is_XP():
                ntype = cmn_node_type_str(n.type()).replace('-', '_').lower()
                s += ".p%u.d%u.%s" % (p, d, ntype)
        return s

    def node_dump_regs(self, n):
        if self.o_match_nodes and not self.o_match_nodes.match_node(n):
            return
        nident = node_ident(n)
        if nident is None:
            print("%s: node type not known" % (n), file=sys.stderr)
            return
        if nident not in self.regmaps:
            if o_verbose:
                print("%s: no register map (%s), type=0x%x" % (n, nident, n.type()), file=sys.stderr)
            #sys.exit(1)
            return
        self.node_loc_str = self.locator_str(n)
        rm = self.regmaps[nident]
        printed_node = False
        for reg in rm.regs():
            if self.o_match_reg_names and not any([re.search(e, reg.name, flags=re.I) for e in self.o_match_reg_names]):
                continue
            if reg.access == "RO" and not self.o_include_read_only:
                if o_verbose >= 2:
                    print("%s: excluded as read-only" % reg)
                continue
            if reg.security == "S" and not n.C.secure_accessible:
                if o_verbose >= 2:
                    print("%s: excluded as Secure" % reg)
                # this would read as zero if we tried
                continue
            if reg.n_bits == 64:
                x = n.read64(reg.addr)
            else:
                if o_verbose >= 2:
                    print("%s: excluded because can't handle %u-bit register" % (reg, reg.n_bits))
                continue
            if x == 0 and self.o_skip_zeroes:
                if o_verbose >= 2:
                    print("%s: excluded because zero" % reg)
                continue
            if not printed_node:
                print()
                print("Node: %s at 0x%x" % (n, n.node_base_addr))
                printed_node = True
            self.reg_dump(reg, x)
            # Check to see if any reserved bits (not mapped by named fields) are set.
            # This may indicate that we've mis-identified the product version, or the node type.
            if reg.has_fields:
                extra_bits = x & reg.reserved_mask
                if extra_bits != 0:
                    print("    %s %s reserved bits are set: 0x%x" % (n, reg, extra_bits))
                    self.n_regs_reserved_bits_set += 1

    def reg_dump(self, reg, x):
        if self.o_fields:
            # When listing fields, separate each register with a blank line.
            print()
        if self.o_flat:
            print("%s.%s = 0x%x" % (self.node_loc_str, reg.name, x))
        else:
            print("  %04x  %016x  %s" % (reg.addr, x, reg.name), end="")
            if reg.access:
                print(" (%s)" % reg.access, end="")
            if reg.reset is not None and x == reg.reset[0]:
                print(" (reset value)", end="")
            if self.o_descriptions and reg.desc:
                print("  %s" % self.descstr(reg.desc), end="")
            print()
        if self.o_fields:
            self.reg_dump_fields(reg, x)

    def reg_dump_fields(self, reg, x):
        for fld in reg.fields:
            val = fld.extract(x)
            if val == 0 and self.o_skip_zeroes:
                continue
            if self.o_flat:
                print("%s.%s.%s = %s" % (self.node_loc_str, reg.name, fld.name, self.valstr(val, width=fld.width)))
                continue
            print("    %-7s %28s = %-10s" % (fld.range_str(), fld.name, self.valstr(val, width=fld.width)), end="")
            if self.o_descriptions and fld.desc:
                print("  %s" % self.descstr(fld.desc), end="")
            print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN register dump")
    parser.add_argument("--include-read-only", action="store_true", default=True, help="include read-only registers")
    parser.add_argument("-w", "--exclude-read-only", dest="include_read_only", action="store_false", help="exclude read-only registers")
    parser.add_argument("-z", "--include-zero", action="store_true", help="include registers with value 0")
    parser.add_argument("-f", "--fields", action="store_true", help="show register fields")
    parser.add_argument("--no-fields", dest="fields", action="store_false", help="don't show register fields")
    parser.add_argument("-d", "--descriptions", action="store_true", help="show register and field descriptions")
    parser.add_argument("--no-descriptions", dest="descriptions", action="store_false", help="don't show descriptions")
    parser.add_argument("-n", "--node", type=cmn_select.CMNSelect, action="append", help="match nodes or node types")
    parser.add_argument("-r", "--reg", type=str, action="append", help="match register name")
    parser.add_argument("--flat", action="store_true", help="unformatted display")
    parser.add_argument("--max-desc", type=int, default=72, help="maximum length to print for descriptions")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    D = CMNRegMapper(descriptions=opts.descriptions, description_limit=opts.max_desc, fields=opts.fields,
                     include_read_only=opts.include_read_only, skip_zeroes=(not opts.include_zero),
                     match_reg_names=opts.reg,
                     match_nodes=cmn_select.cmn_select_merge(opts.node),
                     flat=opts.flat)
    CS = cmn_from_opts(opts)
    printed_sec_warning = False
    for C in CS:
        if not C.secure_accessible and not printed_sec_warning:
            print("** Showing Non-Secure registers only", file=sys.stderr)
            printed_sec_warning = True
        D.cmn_dump_regs(C)
    if D.had_errors():
        print("** Warnings/errors encountered - check full output for details", file=sys.stderr)
