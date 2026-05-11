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
import devmem_base
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
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data/regdefs")
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
        if not (os.path.isfile(regfn) or os.path.isfile(regfn + ".gz")):
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


class Style:
    """
    Style controls for printing register information
    """
    def __init__(self, descriptions=True, description_limit=100, fields=True, address=False, flat=False, reset=True):
        self.o_descriptions = descriptions
        self.description_limit = 100
        self.o_fields = fields
        self.o_flat = flat
        self.o_reset = reset
        self.o_address = address

    def __str__(self):
        s = "Style(desc=%s(%u),fields=%s,flat=%s,reset=%s,address=%s)" % (self.o_descriptions, self.description_limit, self.o_fields, self.o_flat, self.o_reset, self.o_address)
        return s


class CMNRegDumper(CMNRegMapper, Style):
    """
    Dump CMN configuration registers
    """
    def __init__(self, regdefs_dir=None, regmaps=None, descriptions=True, description_limit=100, fields=True, include_read_only=False, exclude_volatile=False, skip_zeroes=True, match_reg_names=None, match_nodes=None, flat=False, address=False, node_order="topology", no_common=False):
        CMNRegMapper.__init__(self, regdefs_dir=regdefs_dir, regmaps=regmaps)
        Style.__init__(self, descriptions=descriptions, description_limit=description_limit, fields=fields, flat=flat, address=address)
        self.o_include_read_only = include_read_only
        self.o_exclude_volatile = exclude_volatile
        self.o_match_reg_names = match_reg_names
        self.o_match_nodes = match_nodes
        self.o_skip_zeroes = skip_zeroes
        self.o_no_common = no_common
        if node_order not in ["topology", "type"]:
            raise ValueError("bad node order: %s" % node_order)
        self.o_node_order = node_order
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
        if self.o_node_order == "type":
            nodes = cmn_select.iter_cmn_nodes_by_type(C, selector=self.o_match_nodes, include_root=True)
        else:
            nodes = cmn_select.iter_cmn_nodes(C, selector=self.o_match_nodes, include_root=True)
        for node in nodes:
            yield node

    def cmn_nodes(self, C):
        for node in self.cmn_nodes_iter(C):
            if self.o_match_nodes and not self.o_match_nodes.match_node(node):
                continue
            yield node

    def cmns_nodes_iter(self, CS):
        if self.o_node_order == "type":
            nodes = cmn_select.iter_cmns_nodes_by_type(CS, selector=self.o_match_nodes, include_root=True)
        else:
            nodes = cmn_select.iter_cmns_nodes(CS, selector=self.o_match_nodes, include_root=True)
        for node in nodes:
            self.set_regmaps_from_cmn_product(node.C.product_config)
            yield node

    def cmns_nodes(self, CS):
        for node in self.cmns_nodes_iter(CS):
            if self.o_match_nodes and not self.o_match_nodes.match_node(node):
                continue
            yield node

    def cmn_dump_regs(self, C):
        for node in self.cmn_nodes(C):
            self.node_dump_regs(node)

    def cmns_dump_regs(self, CS):
        for node in self.cmns_nodes(CS):
            self.node_dump_regs(node)

    def cmns_dump_regs_aggregate(self, CS):
        for (node_type, nodes) in cmn_select.iter_cmns_node_type_groups(CS, selector=self.o_match_nodes, include_root=True):
            self.node_type_dump_regs_aggregate(node_type, nodes)

    def cmn_iter_reg(self, C, reg_name):
        """
        Iterate over instances of a named register
        """
        for n in self.cmn_nodes(C):
            rm = self.node_regmap(n)
            if rm is None:
                continue
            reg = rm.regs_by_name.get(reg_name, None)
            if reg is None:
                continue
            yield (n, reg)

    def cmn_access_reg(self, C, reg_name, fld_name, val=None, fields=False):
        """
        Read, and optionally write (if val is not None), a register
        """
        n_found = 0
        for (n, reg) in self.cmn_iter_reg(C, reg_name):
            n_found += 1
            rname = self.locator_str(n) + "." + reg_name
            if self.o_address:
                rname = ("0x%x:" % (n.node_base_addr + reg.addr)) + rname
            if reg.is_secure and not n.C.secure_accessible:
                print("** %s is secure (%s) and not accessible" % (rname, reg.security))
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

    def locator_str(self, n):
        if n.type() == CMN_NODE_CFG:
            s = "cfg"
            cmn = n.CMN()
        else:
            (x, y, p, d) = n.coords()
            s = "mxp(%u,%u)" % (x, y)
            if not n.is_XP():
                ntype = cmn_node_type_str(n.type()).replace('-', '_').lower()
                s += ".p%u.d%u.%s" % (p, d, ntype)
            cmn = n.XP().CMN()
        s = ("cmn(%u)." % cmn.cmn_seq) + s
        return s

    def reg_selected(self, name):
        if not self.o_match_reg_names:
            return True
        return any([e.search(name) for e in self.o_match_reg_names])

    def reg_is_readable(self, n, reg):
        if reg.access == "RO" and not self.o_include_read_only:
            if o_verbose >= 2:
                print("%s: excluded as read-only" % reg)
            return False
        if reg.is_volatile and self.o_exclude_volatile:
            if o_verbose >= 2:
                print("%s: excluded as volatile" % reg)
            return False
        if reg.is_secure and not n.C.secure_accessible:
            if o_verbose >= 2:
                print("%s: excluded as Secure" % reg)
            return False
        if reg.n_bits != 64:
            if o_verbose >= 2:
                print("%s: excluded because can't handle %u-bit register" % (reg, reg.n_bits))
            return False
        return True

    def node_dump_regs(self, n):
        self.set_regmaps_from_cmn_product(n.C.product_config)
        rm = self.node_regmap(n)
        if rm is None:
            return
        self.node_loc_str = self.locator_str(n)
        printed_node = False
        for reg in rm.regs():
            if not self.reg_selected(reg.name):
                continue
            self.n_selected += 1
            if not self.reg_is_readable(n, reg):
                continue
            x = n.read64(reg.addr)
            if reg.is_secure:
                try:
                    old_sec = n.set_secure_access("S")
                    xs = n.read64(reg.addr)
                    n.set_secure_access(old_sec)
                    if xs != x:
                        if x != 0:
                            print("%s: NS read 0x%x, S read 0x%x" % (reg, x, xs))
                        else:
                            #print("%s: security protected" % (reg))
                            pass
                    x = xs
                except devmem_base.DevMemNoSecure:
                    pass
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

    def node_type_dump_regs_aggregate(self, node_type, nodes):
        if not nodes:
            return
        if len(nodes) == 1:
            if not self.o_no_common:
                self.node_dump_regs(nodes[0])
            return
        printed_node_type = False
        rm_regs = []
        for n in nodes:
            self.set_regmaps_from_cmn_product(n.C.product_config)
            rm = self.node_regmap(n)
            if rm is not None:
                rm_regs = list(rm.regs())
                break
        if not rm_regs:
            return
        for reg in rm_regs:
            if not self.reg_selected(reg.name):
                continue
            vals = []
            for n in nodes:
                self.set_regmaps_from_cmn_product(n.C.product_config)
                rm = self.node_regmap(n)
                if rm is None:
                    continue
                nreg = rm.regs_by_name.get(reg.name, None)
                if nreg is None:
                    continue
                self.n_selected += 1
                if not self.reg_is_readable(n, nreg):
                    continue
                vals.append((n, nreg, n.read64(nreg.addr)))
            if not vals:
                continue
            different = any([x != vals[0][2] for (n, nreg, x) in vals[1:]])
            if not different:
                x = vals[0][2]
                if x == 0 and self.o_skip_zeroes:
                    if o_verbose >= 2:
                        print("%s: excluded because zero" % reg)
                    continue
                self.n_selected_2 += len(vals)
                if self.o_no_common:
                    continue
            else:
                self.n_selected_2 += len(vals)
            if not printed_node_type:
                print()
                print("Node type: %s (%u nodes)" % (cmn_node_type_str(node_type), len(nodes)))
                printed_node_type = True
            if different:
                self.reg_dump_aggregate_different(vals)
            else:
                self.reg_dump_aggregate_common(vals[0][1], vals[0][2], len(nodes))
            for (n, nreg, x) in vals:
                if nreg.has_fields:
                    extra_bits = x & nreg.reserved_mask
                    if extra_bits != 0:
                        print("    %s %s reserved bits are set: 0x%x" % (n, nreg, extra_bits))
                        self.n_regs_reserved_bits_set += 1

    def reg_dump_common_suffix(self, reg, x, show_reset=True):
        if reg.access:
            print(" (%s)" % reg.access, end="")
        if reg.is_secure:
            print(" (%s)" % reg.security, end="")
        if show_reset and reg.reset is not None and x == reg.reset[0]:
            print(" (reset value)", end="")
        if self.o_descriptions and reg.desc:
            print("  %s" % self.descstr(reg.desc), end="")

    def reg_dump_aggregate_common(self, reg, x, n_nodes):
        if self.o_fields and not self.o_flat:
            print()
        if self.o_flat:
            print("%s.%s = 0x%x" % (reg.regmap.name, reg.name, x))
        else:
            print("  %04x  %016x  %s (common across %u nodes)" % (reg.addr, x, reg.name, n_nodes), end="")
            self.reg_dump_common_suffix(reg, x)
            print()
        if self.o_fields and not self.o_flat:
            self.reg_dump_fields(reg, x)

    def reg_dump_aggregate_different(self, vals):
        reg = vals[0][1]
        if self.o_flat:
            for (n, nreg, x) in vals:
                print("%s.%s = 0x%x" % (self.locator_str(n), nreg.name, x))
            if self.o_fields:
                self.reg_dump_aggregate_fields(vals)
            return
        print("  %04x  %s (differs)" % (reg.addr, reg.name), end="")
        self.reg_dump_common_suffix(reg, vals[0][2], show_reset=False)
        print()
        for (n, nreg, x) in vals:
            print("    %-42s  %016x" % (self.locator_str(n), x))
        if self.o_fields:
            self.reg_dump_aggregate_fields(vals)

    def reg_dump_aggregate_fields(self, vals):
        reg = vals[0][1]
        for fld in reg.fields:
            fvals = [(n, nreg, fld.extract(x)) for (n, nreg, x) in vals]
            different = any([v != fvals[0][2] for (n, nreg, v) in fvals[1:]])
            if not different:
                v = fvals[0][2]
                if self.o_no_common:
                    continue
                if v == 0 and self.o_skip_zeroes:
                    continue
                if self.o_flat:
                    print("%s.%s.%s = %s" % (reg.regmap.name, reg.name, fld.name, self.valstr(v, width=fld.width)))
                    continue
                print("    %-7s %28s = %-10s (common)" % (fld.range_str(), fld.name, self.valstr(v, width=fld.width)), end="")
                if self.o_descriptions and fld.desc:
                    print("  %s" % self.descstr(fld.desc), end="")
                print()
                continue
            if self.o_flat:
                for (n, nreg, v) in fvals:
                    print("%s.%s.%s = %s" % (self.locator_str(n), nreg.name, fld.name, self.valstr(v, width=fld.width)))
                continue
            print("    %-7s %28s (differs)" % (fld.range_str(), fld.name), end="")
            if self.o_descriptions and fld.desc:
                print("  %s" % self.descstr(fld.desc), end="")
            print()
            for (n, nreg, v) in fvals:
                print("      %-40s  %s" % (self.locator_str(n), self.valstr(v, width=fld.width)))

    def reg_dump(self, reg, x):
        """
        Dump a register value (x) with reference to register definitions.
        """
        if self.o_fields:
            # When listing fields, separate each register with a blank line.
            print()
        if self.o_flat:
            print("%s.%s = 0x%x" % (self.node_loc_str, reg.name, x))
        else:
            print("  %04x  %016x  %s" % (reg.addr, x, reg.name), end="")
            self.reg_dump_common_suffix(reg, x)
            print()
        if self.o_fields:
            self.reg_dump_fields(reg, x)

    def reg_dump_fields(self, reg, x):
        """
        Dump fields of a register (value x) with reference to register definitions.
        """
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


def search_all_in_regdefs(reg_ex, rd, style, file_name=None):
    """
    Search and describe registers in a regdefs
    """
    n_found = 0
    printed_file = False
    last_regmap = None
    for r in rd.regs():
        if reg_ex.search(r.name):
            n_found += 1
            if file_name is not None and not printed_file:
                print("%s:" % file_name)
                printed_file = True
            if style.o_flat:
                reg_name = "%s.%s" % (r.regmap.name, r.name)
                print("%s" % (reg_name), end="")
                if style.o_reset and r.reset is not None:
                    # The reset value typically has a mask of valid bits, but we just print the value here
                    print(" (reset 0x%x)" % (r.reset[0]), end="")
            else:
                if r.regmap != last_regmap:
                    print("  %s" % r.regmap)
                    last_regmap = r.regmap
                print("    %s" % r, end="")
                if style.o_descriptions and r.desc:
                    print(" -- %s " % r.desc, end="")
            print()
            if style.o_fields:
                for f in r.fields:
                    if style.o_flat:
                        print("%s%s %s" % (reg_name, f.range_str(), f.name), end="")
                    else:
                        print("      %s" % f, end="")
                    if style.o_reset and f.reset is not None:
                        # E.g. RTL parameter name
                        print(" (reset %s)" % (f.reset), end="")
                    if style.o_descriptions and f.desc:
                        print(" -- %s" % f.desc, end="")
                    print()
    return n_found


def search_all(reg_ex, style):
    """
    Given a register regex, search for it in all known register definitions, i.e. across all products.
    """
    rdir = get_regdefs_dir()
    n_found = 0
    for d in sorted(os.listdir(rdir)):
        if not d.endswith(".regdefs"):
            continue
        if style.o_descriptions:
            if not d.endswith("-desc.regdefs") and os.path.isfile(os.path.join(rdir, d[:-8] + "-desc.regdefs")):
                continue
        else:
            if d.endswith("-desc.regdefs") and os.path.isfile(os.path.join(rdir, d[:-13] + ".regdefs")):
                continue
        rf = os.path.join(rdir, d)
        rd = regview.regdefs_from_file(rf)
        n_found += search_all_in_regdefs(reg_ex, rd, style=style, file_name=rf)
    if not n_found:
        # str(reg_ex) will be something like "re.compile('xxx', re.IGNORECASE)".
        # Ideally we want to turn it back to a grep-like syntax.
        print("No matches found for '%s'" % reg_ex.pattern)


def main(argv):
    global o_verbose
    import argparse
    def regex(s):
        try:
            return re.compile(s, flags=re.I)
        except Exception as e:
            raise ValueError(s)
    parser = argparse.ArgumentParser(description="CMN register dump")
    parser.add_argument("--include-read-only", action="store_true", default=True, help="include read-only registers")
    parser.add_argument("-w", "--exclude-read-only", dest="include_read_only", action="store_false", help="exclude read-only registers")
    parser.add_argument("--exclude-volatile", action="store_true", help="exclude volatile registers")
    parser.add_argument("-z", "--include-zero", action="store_true", help="include registers with value 0")
    parser.add_argument("-f", "--fields", action="store_true", help="show register fields")
    parser.add_argument("--no-fields", dest="fields", action="store_false", help="don't show register fields")
    parser.add_argument("-d", "--descriptions", action="store_true", default=None, help="show register and field descriptions")
    parser.add_argument("--no-descriptions", dest="descriptions", action="store_false", help="don't show descriptions")
    parser.add_argument("--address", action="store_true", help="show address of each register")
    parser.add_argument("--node-order", choices=["topology", "type"], default="topology", help="node traversal order for register dumps")
    parser.add_argument("--aggregate", action="store_true", help="aggregate register values by node type")
    parser.add_argument("--no-common", action="store_true", help="in aggregate mode, suppress registers common to all nodes of a type")
    parser.add_argument("--reset", action="store_true", default=True, help="show reset values")
    parser.add_argument("--no-reset", dest="reset", action="store_false", help="don't show reset values")
    parser.add_argument("-n", "--node", type=cmn_select.CMNSelect, action="append", help="match nodes or node types")
    parser.add_argument("-r", "--reg", type=regex, action="append", help="match register name")
    parser.add_argument("--flat", action="store_true", help="unformatted display")
    parser.add_argument("--max-desc", type=int, default=72, help="maximum length to print for descriptions")
    parser.add_argument("--search", action="store_true", help="search and describe registers")
    parser.add_argument("--search-all", action="store_true", help="find register descriptions across all products")
    parser.add_argument("regs", type=str, nargs="*", help="register names or field names")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    if opts.descriptions is None and opts.search:
        opts.descriptions = True
    if opts.search_all:
        # Search across all products (CMN-600, CMN-700 etc.) regardless of current system
        if not opts.reg and not opts.regs:
            print("must specify register(s) to search for", file=sys.stderr)
            sys.exit(1)
        opts.regs = [regex(r) for r in opts.regs]
        if opts.reg:
            opts.regs.insert(0, opts.reg)
        style = Style(descriptions=opts.descriptions, fields=opts.fields, flat=opts.flat, reset=opts.reset)
        for r in opts.regs:
            n = search_all(r, style)
            if n == 0:
                print("No registers found for '%s'" % r.pattern, file=sys.stderr)
        sys.exit()
    D = CMNRegDumper(descriptions=opts.descriptions, description_limit=opts.max_desc, fields=opts.fields,
                     include_read_only=opts.include_read_only, skip_zeroes=(not opts.include_zero),
                     exclude_volatile=opts.exclude_volatile,
                     match_reg_names=opts.reg,
                     match_nodes=cmn_select.cmn_select_merge(opts.node),
                     address=opts.address,
                     node_order=opts.node_order,
                     no_common=opts.no_common,
                     flat=opts.flat)
    CS = cmn_from_opts(opts)
    if opts.search:
        D.set_regmaps_from_cmn_product(CS[0].product_config)
        opts.regs = [regex(r) for r in opts.regs]
        style = Style(descriptions=opts.descriptions, fields=opts.fields, flat=opts.flat, reset=opts.reset, address=opts.address)
        for reg_ex in opts.regs:
            n = search_all_in_regdefs(reg_ex, D.regmaps, style)
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
    if opts.aggregate:
        D.cmns_dump_regs_aggregate(CS)
    else:
        D.cmns_dump_regs(CS)
    if D.n_selected == 0:
        print("** No registers matched expressions", file=sys.stderr)
    elif D.n_selected_2 == 0:
        print("** Registers matched, but skipped", file=sys.stderr)
    if D.had_errors():
        print("** Warnings/errors encountered - check full output for details", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
