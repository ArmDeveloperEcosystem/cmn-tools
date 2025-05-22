#!/usr/bin/python3

"""
Read DMI file from /sys/firmware/dmi/tables/DMI

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

The format is defined in the DMTF publication DSP0134:
  "System Management BIOS (SMBIOS) Reference Specification"

Functionality is similar to the "dmidecode" tool.

This script will generally need root privilege.

Note that some individual properties are exposed by Linux under
/sys/class/dmi/id, and (other than ones that expose individual
device identity) these are generally world-readable, and might be
more convenient for scripts to use.
"""

from __future__ import print_function

import sys
import os
import struct
import uuid


o_verbose = 0

DEFAULT_DMI = "/sys/firmware/dmi/tables/DMI"

DEFAULT_DMI_STRINGS = "/sys/class/dmi/id"

DDR_MTS = 1000000    # DDR megatransfers = 1 million (not 2**20)


DMI_BIOS                   = 0x00
DMI_SYSTEM                 = 0x01
DMI_BASE_BOARD             = 0x02
DMI_CHASSIS                = 0x03
DMI_PROCESSOR              = 0x04
DMI_CACHE                  = 0x07
DMI_PORT_CONNECTOR         = 0x08
DMI_SYSTEM_SLOTS           = 0x09
DMI_MEMORY_ARRAY           = 0x10
DMI_MEMORY_DEVICE          = 0x11
DMI_ARRAY_MAPPED_ADDRESS   = 0x13
DMI_DEVICE_MAPPED_ADDRESS  = 0x14
DMI_INACTIVE               = 0x7e
DMI_END_OF_TABLE           = 0x7f


DMI_CPU_ENABLED         = 1


def BITS(x, p, n):
    return (x >> p) & ((1 << n) - 1)


def BIT(x, p):
    return (x >> p) & 1


class DMIStructure:
    """
    A single entry in a DMI file, with a unique handle.
    'type' indicates the type of entry e.g. DMI_SYSTEM.
    Any entry may have an array of strings, indexed from 1.
    """

    def __init__(self, dmi, raw, strs):
        assert strs[0] is None, "must have None for string[0]"
        self.dmi = dmi      # DMI table in which handles etc. are looked up
        self.raw = raw
        (self.type, _, self.handle) = struct.unpack("BBH", raw[:4])
        self.strings = strs
        self._decoded = False

    @property
    def n_strings(self):
        """
        Return the number of strings, i.e. if we have strings #1 and #2, return 2.
        A suitable range to iterate over the strings is range(1, n_strings+1).
        """
        return len(self.strings)

    def string(self, n):
        """
        Return the n'th string (indexed from 1) pertaining to this entry.
        "If a string field references no string, a null (0) is placed in that string field."
        """
        if n == 0:
            return None
        sb = self.strings[n]
        try:
            s = sb.decode()
        except UnicodeDecodeError:
            s = "<Unicode decode error>"
        return s

    def string_at(self, p):
        if p >= len(self.raw):
            return None
        n = struct.unpack("B", self.raw[p:p+1])[0]
        return self.string(n)

    def __str__(self):
        s = "handle=0x%04x type=0x%04x %s" % (self.handle, self.type, DMI_type_str(self.type))
        for i in range(1, self.n_strings+1):
            s += " \"%s\"" % self.string(i)
        return s

    def decode(self):
        """
        Unpack the raw data and populate fields of this structure.
        General principles of decoding:
          - null or missing values are turned into None
          - handles to other structures are left as integers: see resolve()
          - string handles are turned into the string
        """
        if self._decoded:
            return self
        self._decoded = True
        if self.type == DMI_SYSTEM:
            _decode_system(self)
        elif self.type == DMI_PROCESSOR:
            _decode_processor(self)
        elif self.type == DMI_CACHE:
            _decode_cache(self)
        elif self.type == DMI_MEMORY_ARRAY:
            _decode_memory_array(self)
        elif self.type == DMI_MEMORY_DEVICE:
            _decode_memory_device(self)
        elif self.type == DMI_ARRAY_MAPPED_ADDRESS:
            _decode_array_mapped_address(self)
        elif self.type == DMI_DEVICE_MAPPED_ADDRESS:
            _decode_device_mapped_address(self)
        return self


def _decode_system(d):
    """
    DMI_SYSTEM decode. We create a uuid.UUID() object.
    """
    (_, mfr, prod, vsn, ser) = struct.unpack("<IBBBB", d.raw[:8])
    d.mfr = d.string(mfr)
    d.product = d.string(prod)
    d.version = d.string(vsn)
    d.serial = d.string(ser)
    d.uuid = uuid.UUID(bytes_le=d.raw[8:0x18])


def _decode_processor(d):
    """
    DMI_PROCESSOR decode
    """
    (_, skt, d.processor_type, d.processor_family, pmfr, d.id, vsn) = struct.unpack("<IBBBBQB", d.raw[:17])
    d.socket = d.string(skt)
    d.mfr = d.string(pmfr)
    d.version = d.string(vsn)
    d.h_cache = {}
    (d.max_speed, d.cur_speed, flags, _, h_L1, h_L2, h_L3) = struct.unpack("<HHBBHHH", d.raw[0x14:0x20])
    d.is_populated = BIT(flags, 6)
    d.cpu_status = BITS(flags, 0, 3)    # e.g. DMI_CPU_ENABLED
    d.h_cache[1] = h_L1 if h_L1 != 0xffff else None
    d.h_cache[2] = h_L2 if h_L2 != 0xffff else None
    d.h_cache[3] = h_L3 if h_L3 != 0xffff else None
    (d.n_cores, d.n_cen, d.n_threads) = struct.unpack("<BBB", d.raw[0x23:0x26])
    if d.n_cores == 0xff:
        d.n_cores = struct.unpack("<H", d.raw[0x2a:0x2c])[0]
    if d.n_cen == 0xff:
        d.n_cen = struct.unpack("<H", d.raw[0x2c:0x2e])[0]
    if d.n_threads == 0xff:
        d.n_threads = struct.unpack("<H", d.raw[0x2e:0x30])[0]


DMI_CACHE_assoc = [None, None, None, 1, 2, 4, -1, 8, 16, 12, 24, 32, 48, 64, 20]


def _decode_cache(d):
    """
    DMI_CACHE decode.
    """
    (_, s_socket, d.config, max_size, inst_size, _, _, d.speed, d.ecc, d.cache_type, assoc) = struct.unpack("<IBHHHHHBBBB", d.raw[:0x13])
    d.socket = d.string(s_socket)
    d.level = d.config & 7
    d.assoc = DMI_CACHE_assoc[assoc] if assoc < len(DMI_CACHE_assoc) else None
    if max_size == 0xffff:
        (max_size, inst_size) = struct.unpack("<II", d.raw[0x13:0x1b])
        (d.max_size, d.inst_size) = ((max_size & 0x7fffffff) << 16, (inst_size & 0x7fffffff) << 16)
    else:
        d.max_size = max_size << (16 if (max_size & 0x8000) else 10)
        d.inst_size = inst_size << (16 if (max_size & 0x8000) else 10)
    d.p_processor = None      # link not resolved yet


def _decode_memory_array(d):
    """
    DMI_MEMORY_ARRAY decode
    """
    (_, d.location, d.use, d.ecc, capacity_k, d.h_errinfo, d.n_devices) = struct.unpack("<IBBBIHH", d.raw[:0xf])
    if capacity_k == 0x80000000:
        d.capacity = struct.unpack("<Q", d.raw[0xf:0x17])[0]
    else:
        d.capacity = capacity_k << 10
    d.p_devices = []            # memory device structures
    d.p_address_map = None      # address map


def _decode_memory_device(d):
    """
    DMI_MEMORY_DEVICE decode
    """
    (_, d.h_array, herr, d.t_width, d.d_width, sz, d.form_factor, _) = struct.unpack("<IHHHHHBB", d.raw[:16])
    (dloc, bloc, d.mem_type, d.md, d.p_speed_mts, mfr, _, _, part, d.rank, xsize, d.c_speed_mts) = struct.unpack("<BBBHHBBBBBIH", d.raw[16:34])
    d.device_locator = d.string(dloc)
    d.bank_locator = d.string(bloc)
    d.is_installed = True
    if sz == 0xffff:
        size = None   # unknown
    elif sz == 0:
        size = 0      # uninstalled
        d.is_installed = False
    elif sz == 0x7fff:
        size = xsize << 20
    else:
        size = ((sz & 0x7fff) << 10) if (sz & 0x8000) else (sz << 20)
    d.size = size
    if d.is_installed:
        d.mfr = d.string(mfr)
        d.part = d.string(part)
        d.mem_type_str = DMI_memory_types.get(d.mem_type, "?")
    d.h_array = d.h_array if d.h_array else None
    # Device might have an owning array, but some systems don't have arrays
    d.p_array = None            # not linked yet
    # Device might have a device address map, but sometimes doesn't
    d.p_address_map = None      # not linked yet


def _decode_array_mapped_address(d):
    """
    DMI_ARRAY_MAPPED_ADDRESS decode
    """
    (_, start_k, end_k, d.h_array, d.width) = struct.unpack("<IIIHB", d.raw[:0x0f])
    if start_k == 0xffffffff:
        (d.start, d.end) = struct.unpack("<QQ", d.raw[0x0f:0x1f])
    else:
        (d.start, d.end) = (start_k << 10, (end_k << 10) + 0xfff)
    d.p_device_address_maps = []


def _decode_device_mapped_address(d):
    """
    DMI_DEVICE_MAPPED_ADDRESS decode
    """
    (_, start_k, end_k, d.h_device, d.h_array_map, d.row, d.interleave, d.depth) = struct.unpack("<IIIHHBBB", d.raw[:0x13])
    if start_k == 0xffffffff:
        (d.start, d.end) = struct.unpack("<QQ", d.raw[0x13:0x23])
    else:
        (d.start, d.end) = (start_k << 10, (end_k << 10) + 0xfff)


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
            assert d.handle not in self.index, "DMI: duplicate handle 0x%x" % d.handle
            self.index[d.handle] = d

    def structures(self, type=None, decode=True):
        for d in self.index.values():
            if type is None or d.type == type:
                yield d.decode() if decode else d

    def resolve_links(self):
        """
        After reading the structures, resolve all links, creating forward pointers
        from memory arrays to memory devices and their respective address maps.
        This generally requires decoding all the structures.
        """
        for d in self.structures():
            d.decode()
        for d in self.structures():
            if d.type == DMI_PROCESSOR:
                for lv in [1, 2, 3]:
                    if d.h_cache[lv] is not None:
                        self.index[d.h_cache[lv]].p_processor = d
            elif d.type == DMI_MEMORY_DEVICE:
                if d.h_array is not None:
                    self.index[d.h_array].p_devices.append(d)
            elif d.type == DMI_ARRAY_MAPPED_ADDRESS:
                self.index[d.h_array].p_address_map = d
            elif d.type == DMI_DEVICE_MAPPED_ADDRESS:
                self.index[d.h_device].p_address_map = d
                self.index[d.h_array_map].p_device_address_maps.append(d)

    def raw_structures(self):
        """
        Open the file and yield all the DMI structures, in file order.
        This is generally done once, when populating the index.
        """
        if o_verbose:
            print("DMI: opening %s..." % self.fn, file=sys.stderr)
        if self.fn == "-":
            # Read stdin as binary, e.g. piped from "xxd -r".
            bin = sys.stdin.buffer if sys.version_info[0] >= 3 else sys.stdin
            for s in self.raw_structures_stream(bin):
                yield s
        else:
            with open(self.fn, "rb") as f:
                for s in self.raw_structures_stream(f):
                    yield s

    def raw_structures_stream(self, f):
        """
        Yield all DMI structures from a stream. The only reason for
        factoring this out is so we can handle "-" meaning sys.stdin.
        """
        if True:
            while True:
                hdr = f.read(2)
                if len(hdr) < 2:
                    print("DMI: reached end of file without seeing end-of-table entry",
                          file=sys.stderr)
                    break    # end of file
                (ty, ln) = struct.unpack("BB", hdr)
                if o_verbose >= 2:
                    print("DMI: read type 0x%02x length 0x%02x" % (ty, ln), file=sys.stderr)
                raw = f.read(ln-2)
                assert len(raw) == (ln-2), "file is truncated: not a DMI binary file?"
                strs = [None]     # index 0 refers to no string
                # read strings - we need to do this byte by byte,
                # as the overall entry length is not indicated
                while True:
                    s = f.read(1)
                    assert len(s) == 1, "file is truncated"
                    if s == b'\0':
                        break    # nul byte to terminate list
                    while True:
                        b = f.read(1)
                        assert len(b) == 1, "file is truncated"
                        if b == b'\0':   # nul byte to terminate string
                            break
                        s += b
                    strs.append(s)
                if len(strs) == 1:
                    # no strings, but the record ends with a double-nul
                    f.read(1)
                s = DMIStructure(self, hdr+raw, strs)
                if o_verbose >= 2:
                    print("DMI: %s" % s, file=sys.stderr)
                yield s
                if ty == DMI_END_OF_TABLE:
                    break

    def structure(self, type=None):
        """
        Get the unique structure of a given type, or None.
        It is an error if there are multiple structures of the type.
        """
        ds = list(self.structures(type=type))
        assert len(ds) <= 1, "unexpected: %u structures of type %s" % (len(ds), DMI_type_str(type))
        return ds[0].decode() if len(ds) == 1 else None

    def processor(self):
        """
        Return the processor type from the (first) processor entry
        """
        for d in self.structures(type=DMI_PROCESSOR):
            return d.version
        return None

    def system(self):
        """
        Yield the (unique?) system entry.
        """
        return self.structure(type=DMI_SYSTEM)

    def processors(self, include_unpopulated=False):
        """
        Yield the processor entries.
        """
        for d in self.structures(type=DMI_PROCESSOR):
            if d.is_populated or include_unpopulated:
                yield d

    def memory(self, include_uninstalled=False):
        """
        Yield all memory device objects.
        """
        for d in self.structures(type=DMI_MEMORY_DEVICE):
            if d.is_installed or include_uninstalled:
                yield d


DMI_types = {
    0x00: "BIOS information",
    0x01: "System Information",
    0x02: "Base Board Information",
    0x03: "Chassis Information",
    0x04: "Processor Information",
    0x05: "Memory Controller",       # obsolete
    0x06: "Memory Module",           # obsolete
    0x07: "Cache Information",
    0x08: "Port Connector Information",
    0x09: "System Slots",
    0x0a: "On Board Devices Information",    # obsolete
    0x0b: "OEM Strings",
    0x0c: "System Configuration Options",
    0x0d: "BIOS Language Information",
    0x0e: "Group Associations",
    0x0f: "System Event Log",
    0x10: "Physical Memory Array",
    0x11: "Memory Device",
    0x12: "32-Bit Memory Error Information",
    0x13: "Memory Array Mapped Address",
    0x14: "Memory Device Mapped Address",
    0x18: "Hardware Security",
    0x1a: "Voltage Probe",
    0x1b: "Cooling Device",
    0x1c: "Temperature Probe",
    0x1d: "External Current Probe",
    0x20: "System Boot Information",
    0x26: "IPMI Device Information",
    0x27: "System Power Supply",
    0x29: "Onboard Devices Extended Information",
    0x2a: "Management Controller Host Interface",
    0x2b: "TPM Device",
    0x7e: "Inactive",         # inactive entry in DMI table
    0x7f: "End Of Table",     # end of DMI table
}


DMI_memory_array_locations = {
    0x03: "System board",
}


DMI_memory_array_ecc = {
    0x01: "other",
    0x02: "unknown",
    0x03: "None",
    0x04: "Parity",
    0x05: "SECC",
    0x06: "MECC",
    0x07: "CRC",
}


DMI_memory_types = {
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


def memsize_str(n):
    for u in range(4, 0, -1):
        if n >= (1 << (u*10)):
            return "%.3g%sB" % ((float(n) / (1 << (u*10))), "BKMGT"[u])
    return str(n)


assert memsize_str(1024*1024) == "1MB"


def DMI_type_str(ty):
    """
    Return a string indicating the DMI structure type
    """
    if ty in DMI_types:
        return DMI_types[ty]
    elif ty >= 128:
        return "OEM-specific Type (%u)" % ty
    else:
        return "UNKNOWN-TYPE(%u)" % ty


def print_DMI_summary(D, type=None):
    """
    Print a summary of the whole DMI table, one line per structure
    """
    for d in D.structures(type=type):
        print("%04x %3u %3u" % (d.handle, d.type, len(d.raw)), end="")
        print("  %s" % DMI_type_str(d.type), end="")
        if len(d.strings) > 1:
            for i in range(1, len(d.strings)):
                print(" \"%s\"" % d.string(i), end="")
        print()


def print_DMI_detail(D, type=None, include_std=True):
    """
    Dump out the DMI table as a hex dump
    """
    for d in D.structures(type=type):
        print()
        print("Handle 0x%04x, DMI type %u, %u bytes" % (d.handle, d.type, len(d.raw)))
        print("%s" % DMI_type_str(d.type))
        if d.type >= 128 or include_std:
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
            if d.n_strings > 0:
                print("        Strings:")
                for i in range(1, d.n_strings+1):
                    print("                \"%s\"" % d.string(i))


def print_DMI_memory(D):
    """
    Summarize the system's memory configuration.

    Some systems have "memory array" structures which contain the memory devices.
    Other systems (e.g. Graviton) only have the memory devices.
    """
    D.resolve_links()
    def print_memory_device(d):
        if not d.is_installed:
            print("    (no device installed at %s %s)" % (d.device_locator, d.bank_locator))
            return
        print("    %s %u-bit %u-bit size=%s" % (d.mem_type_str, d.t_width, d.d_width, memsize_str(d.size)), end="")
        dm = d.p_address_map
        if dm is not None:
            print("  0x%012x - 0x%012x  %6s" % (dm.start, dm.end, memsize_str(dm.end - dm.start)), end="")
            print("  row %u  i/l %u  depth %u" % (dm.row, dm.interleave, dm.depth), end="")
        print()
        bw = d.c_speed_mts * DDR_MTS * d.d_width       # bits per second
        print("      speed=%u/%u MT/s" % (d.p_speed_mts, d.c_speed_mts), end="")
        print(" - b/w=%u Mbits/s, %u MB/s" % (bw//0x100000, bw//0x100000//8), end="")
        print("  %s %s %s %s" % (d.mfr, d.part, d.device_locator, d.bank_locator))

    print("Memory:")
    for da in D.structures(type=DMI_MEMORY_ARRAY):
        print("  Memory array:   %6s  %-6s" % (memsize_str(da.capacity), DMI_memory_array_ecc.get(da.ecc, "?")), end="")
        dam = da.p_address_map
        print("  0x%012x - 0x%012x  %6s" % (dam.start, dam.end, memsize_str(dam.end - dam.start)), end="")
        print()
        # Show devices in this array
        for d in da.p_devices:
            print_memory_device(d)
    # Print any memory devices not found under arrays, and also collect overall statistics
    total_size = 0
    total_bw = 0
    n_memory = 0
    for d in D.structures(type=DMI_MEMORY_DEVICE):
        if d.h_array is None:
            print_memory_device(d)    # not seen this one already
        bw = d.c_speed_mts * DDR_MTS * d.d_width       # bits per second
        total_size += d.size
        total_bw += bw
        n_memory += 1
    total_bw_Mb = total_bw // 0x100000
    n_sockets = len(list(D.processors()))
    print("  Total memory: %s, %u mcs" % (memsize_str(total_size), n_memory))
    print("  Bandwidth:    %u Mbits/s = %s/s" % (total_bw_Mb, memsize_str(total_bw//8)))
    if n_sockets > 1:
        bwps = total_bw // n_sockets
        bwps_Mb = total_bw_Mb // n_sockets
        print("    per socket: %u Mbits/s = %s/s" % (bwps_Mb, memsize_str(bwps//8)))
    print("Processor caches:")
    for dp in D.processors():
        print("  %s:" % dp.socket)
        for level in [1, 2, 3]:
            if dp.h_cache[level] is not None:
                dc = D.index[dp.h_cache[level]]
                print("    L%u %3u-way  %s" % (dc.level, dc.assoc, memsize_str(dc.inst_size)))
    for d in D.structures(type=DMI_CACHE):
        if d.p_processor is None:
            print("  System cache:")
            print("    L%u %3u-way  %s" % (d.level, d.assoc, memsize_str(d.inst_size)))


def print_DMI_system(D, file_is_local=True):
    """
    Print some basic information about the system from its DMI info.
    """
    dsys = D.system()
    print("System:    %s %s %s" % (dsys.mfr, dsys.product, dsys.version))
    # Compare with whatever the kernel has got - although this only makes
    # sense if the DMI file we read was from the current system.
    if file_is_local and os.path.isdir(DEFAULT_DMI_STRINGS):
        sys_from_os = (os_dmi_string("sys_vendor") + " " +
                       os_dmi_string("product_name") + " " +
                       os_dmi_string("product_version"))
        print("(from OS): %s" % sys_from_os)
    print("UUID:      %s" % D.system().uuid)
    print("Processors:")
    for d in D.processors(include_unpopulated=True):
        print("  %s: %s - %uMHz (max %uMHz), %u cores, %u threads" %
              (d.socket, d.version, d.cur_speed, d.max_speed, d.n_cores, d.n_threads), end="")
        if not d.is_populated:
            print(" **unpopulated**", end="")
        elif d.cpu_status != DMI_CPU_ENABLED:
            print(" status=%u" % d.cpu_status, end="")
        print()


def os_dmi_string(s):
    """
    As an alternative to scanning the current system's DMI table directly,
    we can get some strings from the kernel, in /sys/class/dmi/id.
    """
    fn = os.path.join(DEFAULT_DMI_STRINGS, s)
    if os.path.isfile(fn):
        return open(fn).read().strip()
    else:
        return None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="read SMBIOS DMI file")
    parser.add_argument("-i", "--input", type=str, default=DEFAULT_DMI, help="input DMI file")
    parser.add_argument("--decode", action="store_true", help="print in detail (like dmidecode)")
    parser.add_argument("--summary", action="store_true", help="print one line per structure")
    parser.add_argument("--system", action="store_true", help="print system information")
    parser.add_argument("--uuid", action="store_true", help="print system UUID")
    parser.add_argument("--memory", action="store_true", help="print memory records")
    parser.add_argument("-t", "--type", type=int, help="DMI record type")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    D = DMI(opts.input)
    if not (opts.decode or opts.summary or opts.memory or opts.uuid):
        opts.system = True
    if opts.decode:
        print_DMI_detail(D, type=opts.type)
    if opts.summary:
        print_DMI_summary(D, type=opts.type)
    if opts.memory:
        print_DMI_memory(D)
    if opts.system:
        print_DMI_system(D, file_is_local=(opts.input == DEFAULT_DMI))
    if opts.uuid:
        # Bare UUID - should be same as /sys/class/dmi/id/product_uuid
        print("%s" % D.system().uuid)
