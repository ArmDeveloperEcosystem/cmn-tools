#!/usr/bin/python3

"""
Read DMI file from /sys/firmware/dmi/tables/DMI

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

The format is defined in the DMTF publication:
  "System Management BIOS (SMBIOS) Reference Specification"
"""

from __future__ import print_function

import os, sys, struct


o_verbose = 0

DEFAULT_DMI = "/sys/firmware/dmi/tables/DMI"


class DMIStructure:
    def __init__(self, raw, strs):
        assert strs[0] is None, "must have None for string[0]"
        self.raw = raw
        (self.type, _, self.handle) = struct.unpack("BBH", raw[:4])
        self.strings = strs

    def string(self, n):
        return self.strings[n].decode()

    def __str__(self):
        s = "handle=0x%04x type=0x%04x %s" % (self.handle, self.type, DMI_type_str(self.type))
        for x in self.strings[1:]:
            s += " \"%s\"" % x.decode()
        return s


class DMI:
    """
    Provide a basic read interface to DMI (BIOS) definitions.
    Currently this doesn't attempt to decode every structure or
    efficiently cache what it reads.
    """
    def __init__(self, fn=DEFAULT_DMI):
        self.fn = fn
        self.index = {}     # map handle to structure
        for d in self.raw_structures():
            assert d.handle not in self.index
            self.index[d.handle] = d

    def structures(self, type=None):
        for d in self.index.values():
            if type is None or d.type == type:
                yield d

    def raw_structures(self):
        """
        Open the file and yield all the DMI structures, in file order.
        This is generally done once when populating the index.
        """
        if o_verbose:
            print("DMI: opening %s..." % self.fn, file=sys.stderr)
        with open(self.fn, "rb") as f:
            while True:
                hdr = f.read(2)
                if len(hdr) == 0:
                    break    # end of file
                (ty, ln) = struct.unpack("BB", hdr)
                raw = f.read(ln-2)
                strs = [None]     # index 0 refers to no string
                # read strings
                while True:
                    s = f.read(1)
                    if s == b'\0':
                        break    # nul byte to terminate list
                    while True:
                        b = f.read(1)
                        if b == b'\0':   # nul byte to terminate string
                            break
                        s += b
                    strs.append(s)
                if len(strs) == 1:
                    # no strings, but the record ends with a double-nul
                    f.read(1)
                s = DMIStructure(hdr+raw, strs)
                if o_verbose >= 2:
                    print("DMI: %s" % s, file=sys.stderr)
                yield s

    def processor(self):
        """
        Example of extracting a specific structure field
        """
        for d in self.structures(type=4):
            (_, skt, ptype, pfamily, pmfr, id, vsn) = struct.unpack("IBBBBQB", d.raw[:17])
            return d.string(vsn)
        return None

    def memory(self):
        """
        Yield all memory objects.
        """
        for d in self.structures(type=0x11):
            (_, harray, herr, d.t_width, d.d_width, sz, d.form_factor, _) = struct.unpack("<IHHHHHBB", d.raw[:16])
            (_, _, d.mem_type, d.md, d.p_speed, mfr, _, _, part, d.rank, xsize, d.c_speed) = struct.unpack("<BBBHHBBBBBIH", d.raw[16:34])
            if sz == 0xffff:
                size = None   # unknown
            elif sz == 0:
                size = 0      # uninstalled
            elif sz == 0x7fff:
                size = xsize << 20
            else:
                size = ((sz & 0x7fff) << 10) if (sz & 0x8000) else (sz << 20)
            d.size = size
            d.mfr = d.string(mfr)
            d.part = d.string(part)
            yield d


DMI_types = {
    0x00: "BIOS information",
    0x01: "System Information",
    0x02: "Base Board Information",
    0x03: "Chassis Information",
    0x04: "Processor Information",
    0x07: "Cache Information",
    0x08: "Port Connector Information",
    0x09: "System Slots",
    0x0a: "On Board Devices Information",    # obsolete
    0x0b: "OEM Strings",
    0x0d: "BIOS Language Information",
    0x0e: "Group Associations",
    0x10: "Physical Memory Array",
    0x11: "Memory Device",
    0x12: "32-Bit Memory Error Information",
    0x13: "Memory Array Mapped Address",
    0x18: "Hardware Security",
    0x20: "System Boot Information",
    0x26: "IPMI Device Information",
    0x27: "System Power Supply",
    0x29: "Onboard Devices Extended Information",
    0x2a: "Management Controller Host Interface",
    0x7f: "End Of Table",
}


def DMI_type_str(ty):
    if ty in DMI_types:
        return DMI_types[ty]
    elif ty >= 128:
        return "OEM-specific Type (%u)" % ty
    else:
        return "UNKNOWN-TYPE(%u)" % ty


def print_DMI_summary(D, type=None):
    for d in D.structures(type=type):
        print("%04x %3u %3u" % (d.handle, d.type, len(d.raw)), end="")
        print("  %s" % DMI_type_str(d.type), end="")
        if len(d.strings) > 1:
            print(" %s" % str(d.strings), end="")
        print()


def print_DMI_detail(D, type=None):
    for d in D.structures(type=type):
        print()
        print("Handle 0x%04x, DMI type %u, %u bytes" % (d.handle, d.type, len(d.raw)))
        print("%s" % DMI_type_str(d.type))
        if d.type >= 128 or True:
            print("        Header and Data:")
            for i in range(len(d.raw)):
                if i % 16 == 0:
                    if i > 0:
                        print()
                    print("                ", end="")
                print("%02X" % struct.unpack("B", d.raw[i:i+1])[0], end="")
                if i % 16 < 15:
                    print(" ", end="")
            print()
            if len(d.strings) > 1:
                print("        Strings:")
                for s in d.strings[1:]:
                    print("                %s" % s.decode())


def print_DMI_memory(D):
    print("Memory:")
    _types = {
        0x18: "DDR3",
        0x1a: "DDR4",
        0x1b: "LPDDR",
        0x1c: "LPDDR2",
        0x1d: "LPDDR3",
        0x1e: "LPDDR4",
        0x20: "HBM",
        0x21: "HBM2",
        0x22: "DDR5",
        0x23: "LPDDR5",
    }
    for d in D.memory():
        print("  %s %u-bit %u-bit size=0x%x" % (_types.get(d.mem_type, "?"), d.t_width, d.d_width, d.size), end="")
        print(" speed=%u/%u" % (d.p_speed, d.c_speed), end="")
        print("  %s %s" % (d.mfr, d.part), end="")
        print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="read SMBIOS DMI file")
    parser.add_argument("-i", "--input", type=str, default=DEFAULT_DMI, help="input DMI file")
    parser.add_argument("--decode", action="store_true", help="print in detail (like dmidecode)")
    parser.add_argument("--summary", action="store_true", help="print one line per structure")
    parser.add_argument("--memory", action="store_true", help="print memory records")
    parser.add_argument("-t", "--type", type=int, help="DMI record type")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    D = DMI(opts.input)
    if opts.decode:
        print_DMI_detail(D, type=opts.type)
    if opts.summary:
        print_DMI_summary(D, type=opts.type)
    if opts.memory:
        print_DMI_memory(D)
    print("Processor: %s" % D.processor())
