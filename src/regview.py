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


o_verbose = 0


def BITS(x, p, n):
    return (x >> p) & ((1 << n) - 1)


class RegDefs:
    """
    A set of RegMap objects, mapping different types of module within an IP component.
    """
    def __init__(self, name=None):
        self.name = name
        self._maps = {}

    def __str__(self):
        s = self.name or "<regdefs>"
        s += " (%u maps)" % len(self._maps)
        return s

    def keys(self):
        return self._maps.keys()

    def maps(self):
        for n in sorted(self.keys()):
            yield self._maps[n]

    def __getitem__(self, n):
        return self._maps[n]

    def __contains__(self, n):
        return n in self._maps

    def add_regmap(self, rm):
        if rm.name in self._maps:
            print("%s: duplicate maps: %s" % (self, rm), file=sys.stderr)
        self._maps[rm.name] = rm

    def dump(self, f, fields=True, descriptions=True):
        """
        Dump all the maps, each preceded by "GROUP".
        """
        for rm in self.maps():
            rm.dump(f, fields=fields, descriptions=descriptions)

    def load(self, f, filename="<file>", verbose=0):
        """
        Load a set of RegMap objects into this RegDefs.
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
    """
    def __init__(self, name):
        self.name = name          # Name for block. Could be RTL module name.
        self.regs_by_addr = {}
        self.regs_by_name = {}

    def add_register(self, r):
        if r.addr in self.regs_by_addr:
            print("%s: duplicate address %s vs. %s" % (self.name, self.reg_at(r.addr), r), file=sys.stderr)
        self.regs_by_addr[r.addr] = r
        if r.name in self.regs_by_name:
            print("%s: duplicate name %s vs. %s" % (self.name, self.regs_by_name[r.name], r), file=sys.stderr)
        self.regs_by_name[r.name] = r

    def addrs_sorted(self):
        return sorted(self.regs_by_addr.keys())

    def regs(self):
        for raddr in self.addrs_sorted():
            reg = self.regs_by_addr[raddr]
            yield reg

    def reg_at(self, addr, default=None):
        return self.regs_by_addr[addr] if addr in self.regs_by_addr else default

    def __str__(self):
        return "%s: %u registers" % (self.name, len(self.regs_by_addr))

    def reg_str(self, r):
        return "0x%x %u %s %s %s" % (r.addr, r.n_bits, (r.access or "-"), (r.security or "-"), r.name)

    def dump(self, f, fields=True, descriptions=True, base=None):
        """
        Dump this regmap to a file-like object, starting with a GROUP statement.
        Further regmaps can be written to the same object.
        """
        print("GROUP %s" % self.name, file=f)
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
        """
        r = None
        fld = None
        in_desc = False
        for ln in f:
            ln = ln.strip()
            if ln.startswith("#"):
                pass
            elif ln.startswith("R "):
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
                (_, desc) = ln.split(None, 1)
                if fld is not None:
                    fld.desc = desc
                else:
                    r.desc = desc
                in_desc = True
            elif ln.startswith("ENDGROUP"):
                break
            elif in_desc:
                if fld is not None:
                    fld.desc += " " + ln
                else:
                    r.desc += " " + ln
            else:
                print("bad line in regdefs: %s" % ln, file=sys.stderr)
                sys.exit(1)


def regmaps_load(f, filename="<file>"):
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
    with open(fn, "r") as f:
        for rm in regmaps_load(f, filename=fn):
            yield rm


def regdefs_from_file(fn, verbose=0):
    """
    Return a RegDefs structure from a file.
    """
    with open(fn, "r") as f:
        return RegDefs().load(f, filename=fn, verbose=verbose)


class Register:
    """
    A single register, possibly with fields.
    """
    def __init__(self, addr, name, desc=None, n_bits=64, access=None, security=None, external=False):
        assert n_bits > 0
        self.addr = addr
        self.n_bits = n_bits
        self.name = name
        self.desc = desc
        self.access = access
        self.security = security
        self.external = external
        self.reset = None
        self.fields = []
        self.fields_mask = 0              # OR of all field masks (fields don't overlap)
        self.n_parameterized = 0          # count of parameterized fields

    @property
    def is_volatile(self):
        return self.access.endswith("V")

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

    def __eq__(self, r):
        return self.same_spec(r) and self.desc == r.desc and self.reset == r.reset and self.same_fields(r)

    def __ne__(self, r):
        return not (self == r)

    def add_field(self, f):
        assert (f.pos + f.width) <= self.n_bits, "%s: bad field %s" % (self, f)
        assert (f.mask_in_reg & self.fields_mask) == 0, "%s: overlapping field %s" % (self, f)
        self.fields.append(f)
        self.fields_mask |= f.mask_in_reg
        f.reg = self
        if f.is_parameterized:
            self.n_parameterized += 1

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

    'reset' is typically a named RTL parameter rather than a literal value.
    """
    def __init__(self, name, pos, width=1, desc=None, reset=None):
        assert width > 0
        self.reg = None
        self.name = name
        self.desc = desc
        self.pos = pos
        self.width = width
        self.reset = reset

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

    def extract(self, x):
        return BITS(x, self.pos, self.width)

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

    def __str__(self):
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


def regmaps_from_paths(fns):
    for fn in fns:
        if fn.endswith(".regdefs"):
            for rm in regmaps_from_file(fn):
                yield rm
            continue
        else:
            print("%s: must be file or directory" % fn, file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Register descriptions")
    parser.add_argument("-o", "--output", type=str, help="output file")
    parser.add_argument("--no-description", action="store_true", help="don't output descriptions")
    parser.add_argument("--select", type=str, help="select only matching blocks")
    parser.add_argument("--diff", action="store_true", help="show differences")
    parser.add_argument("files", type=str, nargs="+", help="register definition files")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
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
        for regmap in regmaps_from_paths(opts.files):
            print(regmap)
