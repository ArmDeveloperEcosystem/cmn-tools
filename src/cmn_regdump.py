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
    """
    Given a CMN configuration (product and revision), get the identifier for the
    register mapping file. This is ad hoc and reflects the major breaking changes
    between published CMN versions.
    """
    pident = _cmn_part_map.get(cfg.product_id, None)
    if cfg.product_id in [cmn_base.PART_CMN700, cmn_base.PART_CMN_S3]:
        pident += ("-r%u" % cfg.revision_major)
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
    if nident is None:
        return None
    if nident.startswith("por_hnf"):
        # HN-F or one of its MPAM nodes
        if (n.C.part_ge_700() and n.C.product_config.revision_code >= 3) or n.C.part_ge_S3():
            nident = "cmn_hns" + nident[7:]    # not "por_hnf"...
    return nident + "_registers"


def get_regdefs_dir(d=None):
    """
    Check the regdefs directory, defaulting it if not supplied.
    """
    if d is None:
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "regdefs")
    if not os.path.isdir(d):
        print("%s: can't find register definitions directory" % d, file=sys.stderr)
        sys.exit(1)
    return d


class CMNRegMapper:
    """
    Map CMN configuration registers by name
    """
    def __init__(self, regdefs_dir=None, regmaps=None):
        self.regmaps = regmaps
        self.regmaps_product = None
        self.set_regdefs_dir(regdefs_dir)

    def set_regdefs_dir(self, regdefs_dir):
        self.regdefs_dir = get_regdefs_dir(regdefs_dir)

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

    def node_regmap(self, n):
        nident = node_ident(n)
        if nident is None:
            print("%s: node type not known" % (n), file=sys.stderr)
            return None
        if nident not in self.regmaps:
            if o_verbose:
                print("%s: no register map (%s), type=0x%x" % (n, nident, n.type()), file=sys.stderr)
            #sys.exit(1)
            return None
        rm = self.regmaps[nident]
        return rm


class CMNRegDumper(CMNRegMapper):
    """
    Dump CMN configuration registers
    """
    def __init__(self, regdefs_dir=None, regmaps=None, descriptions=True, description_limit=100, fields=True, include_read_only=False, skip_zeroes=True, match_reg_names=None, match_nodes=None, flat=False):
        CMNRegMapper.__init__(self, regdefs_dir=regdefs_dir, regmaps=regmaps)
        self.o_descriptions = descriptions
        self.description_limit = 100
        self.o_fields = fields
        self.o_include_read_only = include_read_only
        self.o_match_reg_names = match_reg_names
        self.o_match_nodes = match_nodes
        self.o_skip_zeroes = skip_zeroes
        self.o_flat = flat
        self.n_selected = 0    # Selected as matching name, regex etc.
        self.n_selected_2 = 0  # Selected after other filtering criteria (RO, zero etc.)
        self.n_regs_reserved_bits_set = 0

    def had_errors(self):
        """
        See if any errors were encountered - this could be reserved bits set,
        or (in future) invalid values for enumerators.
        """
        return self.n_regs_reserved_bits_set > 0

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

    def cmn_nodes_iter(self, C):
        self.set_regmaps_from_cmn_product(C.product_config)
        yield C.rootnode
        for xp in C.XPs():
            yield xp
            for i in range(0, 4):
                for node in xp.port_nodes(i):
                    yield node

    def cmn_nodes(self, C):
        for node in self.cmn_nodes_iter(C):
            if self.o_match_nodes and not self.o_match_nodes.match_node(node):
                continue
            yield node

    def cmn_dump_regs(self, C):
        for node in self.cmn_nodes(C):
            self.node_dump_regs(node)

    def cmn_access_reg(self, C, reg_name, fld_name, val=None, fields=False):
        """
        Read, and optionally write (if val is not None), a register
        """
        n_found = 0
        for n in self.cmn_nodes(C):
            rm = self.node_regmap(n)
            if rm is None:
                continue
            reg = rm.regs_by_name.get(reg_name, None)
            if reg is None:
                continue
            n_found += 1
            rname = self.locator_str(n) + "." + reg_name
            if reg.is_secure and not n.C.secure_accessible:
                print("** %s is secure and not accessible" % (rname))
                continue
            if fld_name is not None:
                fld = reg.field_by_name(fld_name)
                if fld is None:
                    print("%s has no field '%s'" % (reg_name, fld_name), file=sys.stderr)
                    sys.exit(1)
            else:
                fld = None
            old_val = n.read64(reg.addr)
            if fld_name is not None:
                rname += "." + fld_name
            if fld is None:
                if val is None:
                    print("%s = 0x%x" % (rname, old_val))
                    if fields:
                        self.reg_dump_fields(reg, old_val)
                else:
                    n.write64(reg.addr, val)
                    rb_val = n.read64(reg.addr)
                    print("%s = 0x%x -> 0x%x" % (rname, old_val, rb_val), end="")
                    if rb_val != val:
                        print(" (wrote 0x%x)" % val, end="")
                    print()
            else:
                if val is None:
                    print("%s = 0x%x" % (rname, fld.extract(old_val)))
                else:
                    new_val = fld.insert(old_val, val)
                    n.write64(reg.addr, new_val)
                    rb_val = n.read64(reg.addr)
                    rb_field = fld.extract(rb_val)
                    print("%s = 0x%x -> 0x%x" % (rname, fld.extract(old_val), rb_field), end="")
                    if rb_field != val:
                        print(" (wrote 0x%x, read 0x%x)" % (new_val, rb_val), end="")
                    print()
        if n_found == 0:
            print("** Register not found: '%s'" % reg_name, file=sys.stderr)

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

    def reg_selected(self, name):
        if not self.o_match_reg_names:
            return True
        return any([e.search(name) for e in self.o_match_reg_names])

    def node_dump_regs(self, n):
        rm = self.node_regmap(n)
        if rm is None:
            return
        self.node_loc_str = self.locator_str(n)
        printed_node = False
        for reg in rm.regs():
            if not self.reg_selected(reg.name):
                continue
            self.n_selected += 1
            if reg.access == "RO" and not self.o_include_read_only:
                if o_verbose >= 2:
                    print("%s: excluded as read-only" % reg)
                continue
            if reg.is_secure and not n.C.secure_accessible:
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
            self.n_selected_2 += 1
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


def search_all_in_regdefs(reg_ex, rd, file_name=None, description=False, fields=False, flat=False):
    """
    Search and describe registers in a regdefs
    """
    n_found = 0
    printed_file = False
    last_regmap = None
    for r in rd.regs():
        if reg_ex.search(r.name):
            if file_name is not None and not printed_file:
                print("%s:" % file_name)
                printed_file = True
            if flat:
                print("%s.%s" % (r.regmap.name, r.name))
                if fields:
                    for f in r.fields:
                        print("%s.%s%s %s" % (r.regmap.name, r.name, f.range_str(), f.name))
                continue
            if r.regmap != last_regmap:
                print("  %s" % r.regmap)
                last_regmap = r.regmap
            print("    %s" % r, end="")
            if description and r.desc:
                print(" -- %s " % r.desc, end="")
            print()
            if fields:
                for f in r.fields:
                    print("      %s" % f)
            n_found += 1
    return n_found


def search_all(reg_ex, description=False, fields=False, flat=False):
    """
    Given a register regex, search for it in all known register definitions, i.e. across all products.
    """
    rdir = get_regdefs_dir()
    n_found = 0
    for d in sorted(os.listdir(rdir)):
        if not d.endswith(".regdefs"):
            continue
        if description:
            if not d.endswith("-desc.regdefs") and os.path.isfile(os.path.join(rdir, d[:-8] + "-desc.regdefs")):
                continue
        else:
            if d.endswith("-desc.regdefs") and os.path.isfile(os.path.join(rdir, d[:-13] + ".regdefs")):
                continue
        rf = os.path.join(rdir, d)
        rd = regview.regdefs_from_file(rf)
        n_found += search_all_in_regdefs(reg_ex, rd, file_name=rf, description=description, fields=fields, flat=flat)
    if not n_found:
        # str(reg_ex) will be something like "re.compile('xxx', re.IGNORECASE)".
        # Ideally we want to turn it back to a grep-like syntax.
        print("No matches found for '%s'" % reg_ex.pattern)


if __name__ == "__main__":
    import argparse
    def regex(s):
        try:
            return re.compile(s, flags=re.I)
        except Exception as e:
            raise ValueError(s)
    parser = argparse.ArgumentParser(description="CMN register dump")
    parser.add_argument("--include-read-only", action="store_true", default=True, help="include read-only registers")
    parser.add_argument("-w", "--exclude-read-only", dest="include_read_only", action="store_false", help="exclude read-only registers")
    parser.add_argument("-z", "--include-zero", action="store_true", help="include registers with value 0")
    parser.add_argument("-f", "--fields", action="store_true", help="show register fields")
    parser.add_argument("--no-fields", dest="fields", action="store_false", help="don't show register fields")
    parser.add_argument("-d", "--descriptions", action="store_true", help="show register and field descriptions")
    parser.add_argument("--no-descriptions", dest="descriptions", action="store_false", help="don't show descriptions")
    parser.add_argument("-n", "--node", type=cmn_select.CMNSelect, action="append", help="match nodes or node types")
    parser.add_argument("-r", "--reg", type=regex, action="append", help="match register name")
    parser.add_argument("--flat", action="store_true", help="unformatted display")
    parser.add_argument("--max-desc", type=int, default=72, help="maximum length to print for descriptions")
    parser.add_argument("--search", action="store_true", help="search and describe registers")
    parser.add_argument("--search-all", action="store_true", help="find register descriptions across all products")
    parser.add_argument("regs", type=str, nargs="*", help="register names or field names")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    if opts.search:
        opts.descriptions = True
    if opts.search_all:
        if not opts.reg and not opts.regs:
            print("must specify register(s) to search for", file=sys.stderr)
            sys.exit(1)
        opts.regs = [regex(r) for r in opts.regs]
        if opts.reg:
            opts.regs.insert(0, opts.reg)
        for r in opts.regs:
            n = search_all(r, description=opts.descriptions, fields=opts.fields, flat=opts.flat)
            if n == 0:
                print("No registers found for '%s'" % r.pattern, file=sys.stderr)
        sys.exit()
    D = CMNRegDumper(descriptions=opts.descriptions, description_limit=opts.max_desc, fields=opts.fields,
                     include_read_only=opts.include_read_only, skip_zeroes=(not opts.include_zero),
                     match_reg_names=opts.reg,
                     match_nodes=cmn_select.cmn_select_merge(opts.node),
                     flat=opts.flat)
    CS = cmn_from_opts(opts)
    if opts.search:
        D.set_regmaps_from_cmn_product(CS[0].product_config)
        opts.regs = [regex(r) for r in opts.regs]
        for reg_ex in opts.regs:
            n = search_all_in_regdefs(reg_ex, D.regmaps, description=True, fields=True, flat=opts.flat)
            if n == 0:
                print("No registers found for '%s'" % reg_ex.pattern, file=sys.stderr)
        sys.exit()
    if opts.regs:
        for rs in opts.regs:
            if '=' in rs:
                (rs, val) = rs.split('=')
                val = int(val, 16)
            else:
                val = None
            if '.' in rs:
                (rs, fld) = rs.split('.')
            else:
                fld = None
            for C in CS:
                D.cmn_access_reg(C, rs, fld, val, fields=opts.fields)
        sys.exit()
    printed_sec_warning = False
    for C in CS:
        if not C.secure_accessible and not printed_sec_warning:
            print("** Showing Non-Secure registers only", file=sys.stderr)
            printed_sec_warning = True
        D.cmn_dump_regs(C)
    if D.n_selected == 0:
        print("** No registers matched expressions", file=sys.stderr)
    elif D.n_selected_2 == 0:
        print("** Registers matched, but skipped", file=sys.stderr)
    if D.had_errors():
        print("** Warnings/errors encountered - check full output for details", file=sys.stderr)
