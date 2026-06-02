#!/usr/bin/python

"""
Registers and register fields.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This module manages definitions of programming registers and their fields.
It can read and write registers in its own simple format ('regdefs'),
and also read them from IP-XACT XML.
"""

from __future__ import print_function


import os
import sys
import gzip


o_verbose = 0


def BITS(x, p, n):
    return (x >> p) & ((1 << n) - 1)


WARNING_LIMIT = 10


class RegDefs:
    """
    A set of RegMap objects, mapping different types of module within an IP component.
    """
    def __init__(self, name=None):
        self.name = name
        self._maps_by_name = {}
        self._maps_by_addr = {}

    def __str__(self):
        s = self.name or "<regdefs>"
        s += " (%u maps)" % len(self._maps_by_name)
        return s

    def keys(self):
        return self._maps_by_name.keys()

    def maps(self):
        for name in sorted(self.keys()):
            yield self._maps_by_name[name]

    def maps_by_addr(self):
        for addr in sorted(self._maps_by_addr.keys()):
            yield self._maps_by_addr[addr]

    def regs(self):
        for rm in self.maps():
            for r in rm.regs():
                yield r

    def __getitem__(self, name):
        return self._maps_by_name[name]

    def __contains__(self, name):
        return name in self._maps_by_name

    def add_regmap(self, rm):
        if rm.name in self._maps_by_name:
            print("%s: duplicate maps: %s" % (self, rm), file=sys.stderr)
        self._maps_by_name[rm.name] = rm
        if rm.addr is not None:
            self._maps_by_addr[rm.addr] = rm
        return self

    def add_regmaps(self, rms):
        for rm in rms:
            self.add_regmap(rm)
        return self

    def new_regmap(self, *args, **kwds):
        rm = RegMap(*args, **kwds)
        self.add_regmap(rm)
        return rm

    def dump(self, f, fields=True, descriptions=True):
        """
        Serialize using our simple 'regdefs' format.
        Dump all the maps, each preceded by "GROUP".
        """
        for rm in self.maps():
            rm.dump(f, fields=fields, descriptions=descriptions)

    def load(self, f, filename="<file>", verbose=0):
        """
        Deserialize using our simple 'regdefs' format.
        From a file-like object, load a set of RegMap objects into this RegDefs.
        """
        for rm in regmaps_load(f, filename=filename):
            self.add_regmap(rm)
            if verbose:
                print("loaded register map: %s" % (rm), file=sys.stderr)
        return self


class RegMap:
    """
    A set of registers within a block of memory. This might correspond to a
    single programmable component within a larger IP component.
    Each address has at most one register. Currently we don't support
    parameter-dependent alternative registers, or overlapping RO/WO registers.

    The base address (which may itself be relevant to a larger subsystem's
    base address) can be supplied, or left as None if the component is
    not at a fixed base address.
    """
    def __init__(self, name="", file_name=None, addr=None, range=None):
        self.name = name          # Name for block. Could be RTL module name.
        self.addr = addr          # Base address of component (in a larger subsystem)
        self.range = range        # Size, in bytes, as specified
        self.file_name = file_name
        self.regs_by_addr = {}
        self.regs_by_name = {}
        self.overrides = {}       # Field references for security overrides - see fixup_overrides()
        self.addr_hwm = 0         # Highest address (after register) seen so far
        self.n_warn_dup = 0

    def is_empty(self):
        return not self.regs_by_addr

    def add_register(self, r):
        """
        Add a Register object.
        """
        if r.addr in self.regs_by_addr:
            self.n_warn_dup += 1
            if self.n_warn_dup < WARNING_LIMIT:
                print("%s: duplicate address %s vs. %s" % (self.name, self.reg_at(r.addr), r), file=sys.stderr)
        self.regs_by_addr[r.addr] = r
        if r.name in self.regs_by_name:
            print("%s: duplicate name %s vs. %s" % (self.name, self.regs_by_name[r.name], r), file=sys.stderr)
        self.regs_by_name[r.name] = r
        r.regmap = self          # back pointer from Register to RegMap
        end_addr = r.addr + (r.n_bits // 8)
        if end_addr > self.addr_hwm:
            self.addr_hwm = end_addr
            if self.range is not None and self.addr_hwm > self.range:
                print("%s: register offset 0x%x out of range 0x%x" % (self.name, r.addr, self.range), file=sys.stderr)

    def new_register(self, addr, *args, **kwds):
        r = Register(addr, *args, **kwds)
        self.add_register(r)
        return r

    def addrs_sorted(self):
        return sorted(self.regs_by_addr.keys())

    def regs(self):
        """
        Yield registers in address order
        """
        for raddr in self.addrs_sorted():
            reg = self.regs_by_addr[raddr]
            yield reg

    def reg_at(self, addr, default=None):
        return self.regs_by_addr[addr] if addr in self.regs_by_addr else default

    def reg_field(self, name, fname):
        return self.regs_by_name[name].field_by_name(fname)

    def field(self, rf):
        (reg, fld) = rf.split('.')
        return self.reg_field(reg, fld)

    def __str__(self):
        return "%s: %u registers" % (self.name, len(self.regs_by_addr))

    def reg_str(self, r):
        return "0x%x %u %s %s %s" % (r.addr, r.n_bits, (r.access or "-"), (r.security or "-"), r.name)

    def fixup_overrides(self):
        """
        After reading the register definitions, security overrides have been recorded as strings.
        Resolve them to field references.
        """
        override_regs = []
        for ovr in self.overrides.keys():
            f = self.field(ovr)
            self.overrides[ovr] = f
            f.is_security_override = True
            f.reg.is_security_override = True
            if f.reg not in override_regs:
                override_regs.append(f.reg)
        for r in override_regs:
            if r.is_overrideable:
                print("%s is a security override register but is overrideable" % (r), file=sys.stderr)
            for f in r.fields:
                if not f.is_security_override:
                    if o_verbose:
                        print("%s has non-override field %s" % (r, f), file=sys.stderr)
        for r in self.regs():
            if r.root_group_override is not None:
                r.root_group_override = self.overrides[r.root_group_override]
            if r.secure_group_override is not None:
                r.secure_group_override = self.overrides[r.secure_group_override]

    def dump(self, f, fields=True, descriptions=True, base=None):
        """
        Dump this regmap to a file-like object, starting with a GROUP statement.
        Further regmaps can be written to the same object.
        """
        print("GROUP %s" % self.name, file=f)
        if self.addr is not None:
            print("BASE 0x%x" % self.addr, file=f)
        if self.range is not None:
            print("RANGE 0x%x" % self.range, file=f)
        if base is not None:
            # Print any registers that were completely deleted
            for rb in base.regs():
                if self.reg_at(rb.addr) is None:
                    print("-R %s" % self.reg_str(rb), file=f)
        for r in self.regs():
            rb = base.reg_at(r.addr) if base is not None else None
            if r == rb:
                continue
            if rb is not None and not r.same_spec(rb):
                print("# register changed specification", file=f)
                print("-R %s" % self.reg_str(rb), file=f)
                rb = None
            print("R %s" % self.reg_str(r), file=f)
            if r.reset is not None and not (rb is not None and r.reset == rb.reset):
                print("RESET 0x%x 0x%x" % (r.reset[0], r.reset[1]), file=f)
            if descriptions and (r.desc and not (rb is not None and r.desc == rb.desc)):
                try:
                    print("DESC %s" % r.desc, file=f)
                except UnicodeEncodeError:
                    print("DESC (Unicode error)", file=f)
            if r.root_group_override is not None:
                print("RGO %s" % r.root_group_override.qual_name(), file=f)
            if r.secure_group_override is not None:
                print("SGO %s" % r.secure_group_override.qual_name(), file=f)
            if fields and not (rb is not None and r.same_fields(rb)):
                for fld in r.fields:
                    print("F %u %u %s" % (fld.pos, fld.width, fld.name), file=f)
                    if descriptions and fld.desc:
                        try:
                            print("DESC %s" % fld.desc, file=f)
                        except UnicodeEncodeError:
                            print("DESC (Unicode error)", file=f)
                    if fld.reset is not None:
                        print("PAR %s" % fld.reset, file=f)
        print("ENDGROUP", file=f)

    def dump_file(self, fn, fields=True, descriptions=True, mode="w"):
        """
        Dump this regmap to a named file.
        """
        with open(fn, mode=mode) as f:
            self.dump(f, fields=fields, descriptions=descriptions)

    def load(self, f):
        """
        Load this regmap from the current position in file-like object.
        It is assumed a GROUP line has been read. Return when a regmap has been read,
        leaving the file-like object open for more reading.

        The input file is assumed to be machine-generated (likely by this module);
        formatting errors will generally trigger asserts.
        """
        r = None
        fld = None
        in_desc = False
        for ln in f:
            ln = ln.strip()
            if ln.startswith("#"):
                pass
            elif not ln:
                pass
            elif ln.startswith("R "):
                # Register definition
                (_, addr, n_bits, access, sec, name) = ln.split()
                n_bits = int(n_bits, 0)
                r = Register(int(addr, 16), name, n_bits=n_bits, access=("" if access == "-" else access), security=("" if sec == "-" else sec))
                self.add_register(r)
                fld = None
                in_desc = False
            elif ln.startswith("F "):
                assert r is not None
                (_, pos, width, name) = ln.split()
                fld = RegField(name, int(pos), int(width))
                r.add_field(fld)
                in_desc = False
            elif ln.startswith("RESET "):
                assert r is not None and fld is None
                (_, value, mask) = ln.split()
                r.reset = (int(value, 16), int(mask, 16))
            elif ln.startswith("PAR "):
                assert r is not None and fld is not None
                (_, value) = ln.split(None, 1)
                fld.set_reset(value)
            elif ln.startswith("DESC "):
                assert r is not None
                (_, desc) = ln.split(None, 1)
                if fld is not None:
                    fld.desc = desc
                else:
                    r.desc = desc
                in_desc = True
            elif ln.startswith("RGO "):
                assert r is not None
                (_, ovr) = ln.split()
                r.set_root_group_override(ovr)
            elif ln.startswith("SGO "):
                assert r is not None
                (_, ovr) = ln.split()
                r.set_secure_group_override(ovr)
            elif ln.startswith("BASE "):
                assert r is None
                (_, addr) = ln.split()
                self.addr = int(addr, 16)
            elif ln.startswith("RANGE "):
                assert r is None
                (_, srange) = ln.split()
                self.range = int(srange, 16)
            elif ln.startswith("ENDGROUP"):
                break
            elif in_desc:
                # continuation line
                assert r is not None       # should be true by construction
                if fld is not None:
                    fld.desc += " " + ln
                else:
                    r.desc += " " + ln
            else:
                print("bad line in regdefs: %s" % ln, file=sys.stderr)
                sys.exit(1)
        self.fixup_overrides()


def regmaps_load(f, filename="<file>"):
    """
    Given a file-like object, yield some RegMap objects.
    """
    for ln in f:
        if ln.startswith("GROUP"):
            (_, gname) = ln.strip().split()
            rm = RegMap(gname)
            rm.load(f)
            yield rm
        elif ln.startswith("#"):
            pass
        else:
            print("%s: unexpected line: %s" % (filename, ln), file=sys.stderr)


def regmaps_from_file(fn):
    """
    Yield all RegMap objects from a regdefs file.
    """
    if os.path.isfile(fn + ".gz"):
        fn += ".gz"
    if fn.endswith(".gz"):
        with gzip.open(fn, "rt") as f:
            for rm in regmaps_load(f, filename=fn):
                yield rm
    else:
        with open(fn, "r") as f:
            for rm in regmaps_load(f, filename=fn):
                yield rm


def regdefs_from_file(fn, verbose=0):
    """
    Return a RegDefs structure from a regdefs file.
    """
    if fn.endswith(".gz"):
        with gzip.open(fn, "rt") as f:
            return RegDefs(fn).load(f, filename=fn, verbose=verbose)
    else:
        with open(fn, "r") as f:
            return RegDefs(fn).load(f, filename=fn, verbose=verbose)


class Register:
    """
    A single register, possibly with fields.
    """
    def __init__(self, addr, name=None, desc=None, n_bits=64, access=None, security=None, external=False, reset=None):
        assert n_bits > 0
        self.regmap = None       # Will be back pointer when added to RegMap
        self.addr = addr         # Generally, offset from base address of a component
        assert n_bits in [8, 16, 32, 64], "%s: unexpected register size: %s" % (name, n_bits)
        self.n_bits = n_bits
        self.name = name
        self.desc = desc
        self.access = access
        self.security = security
        self.external = external
        self.reset = reset
        self.fields = []
        self.fields_mask = 0              # OR of all field masks (fields don't overlap)
        self.n_parameterized = 0          # count of parameterized fields
        self.root_group_override = None
        self.secure_group_override = None
        self.is_security_override = False  # might be updated in fixup_overrides()

    @property
    def is_volatile(self):
        return self.access.endswith("V")

    @property
    def is_secure(self):
        """
        Return true if register is anything other than NonSecure accessible
        """
        return self.security

    @property
    def is_overrideable(self):
        """
        Return true if the security can be overridden by a local (group) override
        """
        return (self.security == "S" and self.secure_group_override) or (self.security == "ROOT" and self.root_group_override and self.secure_group_override)

    @property
    def is_parameterized(self):
        return self.n_parameterized > 0

    def same_spec(self, r):
        """
        Check if this register has the same basic specification as another register,
        ignoring field definitions, reset, and description
        """
        return (r is not None and
                self.addr == r.addr and self.n_bits == r.n_bits and self.name == r.name and
                self.access == r.access and self.security == r.security and self.external == r.external)

    def same_fields(self, r):
        if self.fields_mask != r.fields_mask:
            return False
        for f in self.fields:
            rf = r.field_at(f.pos)
            if f != rf:
                return False
        return True

    @property
    def n_fields(self):
        return len(self.fields)

    def __eq__(self, r):
        return self.same_spec(r) and self.desc == r.desc and self.reset == r.reset and self.same_fields(r)

    def __ne__(self, r):
        return not (self == r)

    def set_root_group_override(self, ovr):
        # Set the override field as a string, pending fixup to a RegField
        self.root_group_override = ovr
        if ovr is not None:
            assert self.is_secure
            self.regmap.overrides[ovr] = True

    def set_secure_group_override(self, ovr):
        self.secure_group_override = ovr
        if ovr is not None:
            assert self.is_secure
            self.regmap.overrides[ovr] = True

    def add_field(self, f):
        """
        Add a field to this register. We're justified in raising assertions for impossible fields,
        but should be cautious about reporting overlaps etc.
        """
        assert (f.pos + f.width) <= self.n_bits, "%s: bad field %s" % (self, f)
        if (f.mask_in_reg & self.fields_mask) != 0:
            # This field overlaps with a previous field.
            print("%s: overlapping field %s:" % (self, f), end="", file=sys.stderr)
            for of in self.fields:
                if (f.mask_in_reg & of.mask_in_reg) != 0:
                    print(" %s" % (of), end="", file=sys.stderr)
            print("", file=sys.stderr)
        self.fields.append(f)
        self.fields_mask |= f.mask_in_reg
        f.reg = self
        if f.is_parameterized:
            self.n_parameterized += 1

    def new_field(self, *args, **kwds):
        f = RegField(*args, **kwds)
        self.add_field(f)
        return f

    def field_by_name(self, name):
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def field_at(self, pos):
        for f in self.fields:
            if f.pos == pos:
                return f
        return None

    @property
    def has_fields(self):
        return bool(self.fields)

    @property
    def mask(self):
        return (1 << self.n_bits) - 1

    @property
    def reserved_mask(self):
        return self.mask & ~self.fields_mask

    def __str__(self):
        s = "%s at 0x%x" % (self.name, self.addr)
        if self.n_bits != 64:
            s += " (%u bits)" % self.n_bits
        if self.access:
            s += " (%s)" % self.access
        if self.security:
            s += " (%s)" % self.security
        return s


class RegField:
    """
    A register field.

    'access' may refine the register access, e.g. a RO field of a RW register.

    'reset' is typically a named RTL parameter rather than a literal value.
    """
    def __init__(self, name=None, pos=None, width=1, desc=None, access=None, reset=None, is_reserved=False):
        assert pos is not None
        assert width > 0
        self.reg = None
        self.name = name
        self.desc = desc
        self.pos = pos
        self.width = width
        self.access = access
        self.reset = reset
        self.is_reserved = is_reserved
        self.is_security_override = False    # may be set in fixup_overrides()

    def range_str(self):
        if self.width == 1:
            s = "[%u]" % self.pos
        else:
            s = "[%u:%u]" % (self.pos+self.width-1, self.pos)
        return s

    def __eq__(self, f):
        return (f is not None and self.pos == f.pos and self.width == f.width and
                self.name == f.name and self.desc == f.desc and self.reset == f.reset)

    def __ne__(self, f):
        return not (self == f)

    @property
    def mask_in_reg(self):
        return ((1 << self.width) - 1) << self.pos

    @property
    def is_whole_reg(self):
        return self.pos == 0 and self.width == self.reg.n_bits

    def extract(self, x):
        return BITS(x, self.pos, self.width)

    def insert(self, x, v):
        if v >= (1 << self.width):
            raise ValueError("value 0x%x too wide for %u-bit field" % (v, self.width))
        m = self.mask_in_reg
        return (x & ~m) | (v << self.pos)

    def set_reset(self, value):
        self.reset = value
        if self.is_parameterized and self.reg is not None:
            self.reg.n_parameterized += 1

    @property
    def is_parameterized(self):
        # A "parameterized" field is one whose value is set by some external parameter,
        # typically a synthesis-time RTL parameter or possibly a tied-off external signal.
        # In register definitions this is indicated by an expression in the reset value.
        # Fields whose reset value is simply an integer, are not indicated this way.
        return self.reset is not None

    def qual_name(self):
        return self.reg.name + "." + self.name

    def __str__(self):
        """
        Return a string identifying just the field, with its bit position, e.g. "[3:2] XYZ"
        """
        s = self.range_str() + " " + self.name
        return s


def merge_keys(ka, kb):
    return sorted(set(ka) | set(kb))


def diff_regdefs(rda, rdb, file=None):
    """
    Show diff between two regdefs
    """
    if file is None:
        file = sys.stdout
    for n in merge_keys(rda.keys(), rdb.keys()):
        if n not in rdb._maps:
            print("-GROUP %s" % n, file=file)
        elif n not in rda._maps:
            rdb[n].dump(file)
        else:
            rdb[n].dump(file, base=rda[n])


def filename_is_regdefs(fn):
    return fn.endswith(".regdefs") or fn.endswith(".regdefs.gz")


def regmaps_from_paths(fns):
    for fn in fns:
        if filename_is_regdefs(fn):
            for rm in regmaps_from_file(fn):
                yield rm
            continue
        else:
            print("%s: must be file or directory" % fn, file=sys.stderr)
            sys.exit(1)


class RegStats:
    """
    Statistics about register maps
    """
    def __init__(self, name=""):
        self.name = name
        self.n_maps = 0
        self.n_regs = 0
        self.n_fields = 0
        self.sec_count = {None: 0, "": 0, "S": 0, "ROOT": 0, "REALM": 0}
        self.ovr_count = {"S": 0, "ROOT": 0}
        self.n_no_override = 0

    @staticmethod
    def print_header():
        print("File                         maps   regs  fields     NS     S  ROOT REALM  n/ov")

    def print(self):
        name_str = self.name
        if len(name_str) > 28:
            print("%s" % name_str)
            name_str = ""
        print("%-28s  %3u  %5u   %5u " % (name_str, self.n_maps, self.n_regs, self.n_fields), end="")
        for sec in ["", "S", "ROOT", "REALM"]:
            print(" %5u" % (self.sec_count[sec]), end="")
        print(" %5u" % (self.n_no_override))


def stats_update_reg(st, r):
    st.n_regs += 1
    st.n_fields += r.n_fields
    st.sec_count[r.security] += 1
    if r.secure_group_override:
        st.ovr_count["S"] += 1
    if r.root_group_override:
        st.ovr_count["ROOT"] += 1
    if not r.is_overrideable:
        st.n_no_override += 1


def stats_update_regmap(st, rm):
    st.n_maps += 1
    for r in rm.regs():
        stats_update_reg(st, r)


def stats_update_regdefs(st, rd):
    for rm in rd.maps():
        stats_update_regmap(st, rm)


def regdefs_print_stats(defs, print_header=True, detail=True):
    if print_header:
        RegStats.print_header()
    st = RegStats(defs.name)
    stats_update_regdefs(st, defs)
    st.print()
    if detail:
        for rm in defs.maps():
            st = RegStats("  " + rm.name)
            stats_update_regmap(st, rm)
            st.print()


def main(argv):
    global o_verbose
    import argparse
    parser = argparse.ArgumentParser(description="Register descriptions")
    parser.add_argument("-o", "--output", type=str, help="output file")
    parser.add_argument("--no-description", action="store_true", help="don't output descriptions")
    parser.add_argument("--select", type=str, help="select only matching blocks")
    parser.add_argument("--diff", action="store_true", help="show differences")
    parser.add_argument("--detail", action="store_true", help="show individual maps")
    parser.add_argument("--list-overrides", action="store_true", help="list override registers")
    parser.add_argument("files", type=str, nargs="+", help="register definition files")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    if opts.diff:
        if len(opts.files) < 2:
            print("--diff needs at least two files", file=sys.stderr)
            sys.exit(1)
        rda = regdefs_from_file(opts.files[0])
        for fn in opts.files[1:]:
            rdb = regdefs_from_file(fn)
            diff_regdefs(rda, rdb)
    elif opts.output:
        with open(opts.output, "w") as f:
            for regmap in regmaps_from_paths(opts.files):
                if opts.select and not opts.select in regmap.name:
                    continue
                regmap.dump(f, descriptions=(not opts.no_description))
    else:
        RegStats.print_header()
        for fn in opts.files:
            defs = regdefs_from_file(fn)
            regdefs_print_stats(defs, print_header=False, detail=opts.detail)
            if opts.list_overrides:
                for rm in defs.maps():
                    for r in rm.regs():
                        if r.is_security_override:
                            off = [f for f in r.fields if f.is_security_override]
                            mask = 0
                            for f in off:
                                mask |= f.mask_in_reg
                            print("  %s mask 0x%x" % (r, mask), end="")
                            for f in off:
                                print(" %s" % (f), end="")
                            print()


if __name__ == "__main__":
    main(sys.argv[1:])
