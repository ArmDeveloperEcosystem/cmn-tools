#!/usr/bin/python3

"""
Read ACPI tables

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Generally requires root privilege, if directly accessing tables in /sys/firmware.

https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/21_ACPI_Data_Tables_and_Table_Def_Language/ACPI_Data_Tables.html

For human-readable dumping of ACPI tables, install the acpica-tools package,
and use 'acpidump', 'acpixtract' and 'iasl'. Note that this will only decode
tables standardized in the ACPI specification, not vendor-defined tables
including Arm MPAM.
"""

from __future__ import print_function

import os
import sys
import struct


o_verbose = 0

sys_tables = "/sys/firmware/acpi/tables"


def hexstr(bs):
    s = ""
    for c in bs:
        s += "%02x" % c
    return s


def stripz(bs):
    return str(bs).replace("\\x00",".")


class System:
    def __init__(self):
        pass


class ACPITable:
    """
    Base class for all ACPI table types. Often the caller will have already
    opened the file and know its type, and be constructing a subclass instance.
    """
    def __init__(self, fn, handle=None, sig=None, system=None):
        self.system = system
        self.f = handle      # set early so that destructor sees it
        self.f_we_opened = False
        if fn is None:
            assert sig is not None
            fn = os.path.join(sys_tables, sig.decode())
        self.fn = fn
        self.sig = sig
        if self.f is None:
            self.f = open(fn, "rb")
            self.f_we_opened = True
            self.sig = self.f.read(4)
            assert sig is None or sig == self.sig, "sig mismatch %s vs. %s" % (sig, self.sig)
        self.header = self.f.read(32)
        (self.size, self.rev, self.chk, self.oemid, self.oemtabid, self.oemrev, self.aslid, self.aslrev) = struct.unpack("<IBB6s8sI4sI", self.header)
        # We have now read 36 bytes. Table-specific information might follow immediately.

    def __del__(self):
        if self.f is not None and self.f_we_opened:
            self.f.close()

    def show(self):
        """
        Show generic information from an ACPI table.
        """
        print("%-32s %s %6u v%02u  %-12s %-12s 0x%08x %-8s 0x%08x" %
              (self.fn, self.sig, self.size, self.rev, self.oemid, stripz(self.oemtabid), self.oemrev, self.aslid, self.aslrev))
        self.show_subclass()

    def show_subclass(self):
        pass


class APIC_GICC:
    """
    Arm GIC controller
    """
    def __init__(self, n):
        self.n = n

    def __str__(self):
        s = "GICC #%u:" % self.n
        if self.gicr_addr is not None:
            s += " GICR:0x%x" % self.gicr_addr
        s += " irqs: pmu:%3u vgic:%3u" % (self.pmu_irq, self.vgic_irq)
        if self.spe_irq is not None:
            s += " spe:%3u" % self.spe_irq
        if self.trbe_irq is not None:
            s += " trbe:%3u" % self.trbe_irq
        return s


class APIC(ACPITable):
    """
    APIC: Interrupt controller definition

    In the ACPI spec, this table is called MADT, the "Multiple APIC Description Table".
    But the signature and Linux filename is "APIC".
    """
    type_names = {
        0x00: "proc local",
        0x01: "I/O APIC",
        0x02: "interrupt source",
        0x03: "NMI source",
        0x04: "local APIC NMI",
        0x09: "proc x2APIC",
        0x0a: "local x2APIC NMI",
        0x0b: "GICC",
        0x0c: "GICD",
        0x0e: "GICR",
        0x0f: "GITS"
    }

    def __init__(self, fn=None, handle=None, sig=b"APIC", system=None):
        ACPITable.__init__(self, fn, handle=handle, sig=sig, system=system)
        self.gicc = {}
        self.gicd_address = None
        self.gicr = {}
        self.gicr_ranges = []
        self.gits = {}
        (addr, flags) = struct.unpack("<II", self.f.read(8))
        while True:
            ih = self.f.read(2)
            if not ih:
                break
            (itype, ilen) = struct.unpack("<BB", ih)
            id = ih + self.f.read(ilen-2)
            assert len(id) == ilen
            if o_verbose:
                print("  APIC type:%02x (%s)  len:%2u  data:%s" % (itype, self.type_names.get(itype, "?"), ilen, hexstr(id)))
            # Dispatch on IRQ node type. Some of these are Arm-specific, but it is not obvious
            # how to work out from the APIC header that we're dealing with an Arm system.
            # At least the Arm-specific codes are allocated in the main ACPI specs, and don't
            # seem to mean entirely different things on different architectures.
            if itype == 0x9:
                (self.x2apic_id, self.flags, self.acpi_processor_uid) = struct.unpack("<III", id[4:16])
            elif itype == 0xB:
                (_, cpuif, cpuid, flags, _, pmu_irq, pp_addr, base_addr, gicv_addr, gich_addr, vgic_irq, gicr_addr, mpidr, pclass, _, spe_irq) = struct.unpack("<IIIIIIQQQQIQQBBH", id[:80])
                if spe_irq == 0:
                    spe_irq = None
                if len(id) >= 82:
                    trbe_irq = struct.unpack("<H", id[80:82])[0]
                else:
                    trbe_irq = None
                gicc = APIC_GICC(cpuid)
                gicc.gicr_addr = gicr_addr if gicr_addr else None
                gicc.pmu_irq = pmu_irq
                gicc.vgic_irq = vgic_irq
                gicc.spe_irq = spe_irq
                gicc.trbe_irq = trbe_irq
                if o_verbose:
                    print("    cpu:%3u 0x%x 0x%x 0x%x 0x%x 0x%x" % (cpuid, pp_addr, base_addr, gicv_addr, gich_addr, gicr_addr))
                    print("    %s" % (gicc))
                assert cpuid not in self.gicc
                self.gicc[cpuid] = gicc
                if gicr_addr != 0:
                    assert cpuid not in self.gicr, "duplicate CPU number %u" % cpuid
                    self.gicr[cpuid] = gicr_addr
            elif itype == 0xC:
                assert self.gicd_address is None
                (self.gicd_address, _, self.gic_version, _) = struct.unpack("<QIB3s", id[8:])
            elif itype == 0xE:
                (range_base, range_size) = struct.unpack("<QI", id[4:])
                self.gicr_ranges.append((range_base, range_size))
            elif itype == 0xF:
                (gits_id, gits_addr) = struct.unpack("<IQ", id[4:16])
                assert gits_id not in self.gits
                self.gits[gits_id] = gits_addr
            else:
                # possibly a non-Arm system? Don't be too verbose
                if o_verbose:
                    print("APIC unknown type 0x%x" % itype, file=sys.stderr)

    def show_subclass(self):
        if self.gicd_address is not None:
            print("  GICD: 0x%x" % self.gicd_address)
        else:
            print("  no GICD - non-Arm system?")
        for c in sorted(self.gicc.keys()):
            print("  %s" % (self.gicc[c]))
        for c in sorted(self.gicr.keys()):
            print("  GICR #%u: 0x%x" % (c, self.gicr[c]))
        print("  GICR address ranges:")
        for (b, s) in self.gicr_ranges:
            print("    0x%x size 0x%x" % (b, s))
        for k in sorted(self.gits.keys()):
            print("  GITS #%u: 0x%x" % (k, self.gits[k]))


class PPTTStruct:
    def __init__(self, PPTT, offset, raw):
        self.PPTT = PPTT
        self.offset = offset
        (itype, ilen) = struct.unpack("<BB", raw[:2])
        self.type = itype
        self.raw = raw
        #print("  PPTT @ %7u: type=%3d len=%3d %3d" % (offset, itype, ilen, len(raw)))
        if itype == 0:
            # Processor
            (_, self.flags, self.parent_ref, acpi_id, self.n_resources) = struct.unpack("<IIIII", raw[:20])
            self.acpi_id = acpi_id if (self.flags & 0x02) else None
            self.resources_ref = struct.unpack("<" + str(self.n_resources) + "I", raw[20:20+(self.n_resources*4)])
        elif itype == 1:
            # Cache
            (_, self.flags, self.next_ref, self.n_bytes, self.n_sets, self.n_ways, self.attr, self.line_bytes) = struct.unpack("<IIIIIBBH", raw[:24])
            if self.flags & 0x80:
                self.cache_id = struct.unpack("<I", raw[24:28])[0]
            else:
                self.cache_id = None

    def __str__(self):
        if self.type == 0:
            s = "proc flags=0x%x n_resources=%d" % (self.flags, self.n_resources)
            if self.flags & 0x01:
                s += " package"
            if self.flags & 0x02:
                s += " acpi_id=%d" % self.acpi_id
            if self.flags & 0x04:
                s += " thread"
            if self.flags & 0x08:
                s += " leaf"
            if (self.flags & 0x18) == 0x00:
                s += " heterogeneous"     # neither a leaf node nor homogeneous
            if self.n_resources:
                s += " " + ", ".join([str(r) for r in self.resources_ref])
            if self.parent is not None:
                s += " parent @%u" % self.parent.offset
        elif self.type == 1:
            s = "cache flags=0x%x bytes=0x%x sets=%u ways=%u attr=0x%02x" % (self.flags, self.n_bytes, self.n_sets, self.n_ways, self.attr)
            if not (self.attr & 0x08):
                s += " " + ["data", "inst"][(self.attr >> 2) & 1]
            s += " " + ["ra", "wa", "rwa", "rwa3"][self.attr & 3]
            if self.cache_id is not None:
                s += " id 0x%x" % self.cache_id
            if self.next is not None:
                s += " next @%u" % self.next.offset
        else:
            s = "type=%u?" % (self.type)
        s = (" %5u " % (self.offset)) + s
        return s


class PPTT(ACPITable):
    """
    PPTT: Processor Properties Topology Table

    Topological structure of processors, and their shared resources, such as caches.
    """
    def __init__(self, fn=None, handle=None, sig=b"PPTT", system=None):
        ACPITable.__init__(self, fn, handle=handle, sig=sig, system=system)
        self.structs = {}         # Indexed by offset
        off = 36
        while True:
            ih = self.f.read(2)
            if not ih:
                break
            (itype, ilen) = struct.unpack("<BB", ih)
            raw = ih + self.f.read(ilen-2)
            self.structs[off] = PPTTStruct(self, off, raw)
            off += ilen
        for t in self.structs.values():
            if t.type == 0:
                t.parent = self.struct_at(t.parent_ref)
                t.resources = [self.struct_at(r) for r in t.resources_ref]
            elif t.type == 1:
                t.next = self.struct_at(t.next_ref)

    def struct_at(self, offset):
        return self.structs[offset] if offset > 0 else None

    def show_subclass(self):
        for t in self.structs.values():
            print("  %s" % t)


class SLIT(ACPITable):
    """
    SLIT: System Locality Distance Information Table

    This is a matrix representing latency between localities
    """
    def __init__(self, fn=None, handle=None, sig=b"SLIT"):
        ACPITable.__init__(self, fn, handle=handle, sig=sig)
        self.n_localities = struct.unpack("<Q", self.f.read(8))[0]
        self.entry = []
        for i in range(self.n_localities):
            self.entry.append(list(struct.unpack(str(self.n_localities) + "B", self.f.read(self.n_localities))))

    def show_subclass(self):
        if not self.n_localities:
            print("  no locality matrix")
            return
        print("  locality matrix")
        for i in range(self.n_localities):
            print("  ", end="")
            for j in range(self.n_localities):
                dist = self.entry[i][j]
                print(" %3u" % (dist), end="")
            print()


class SRATStruct:
    def __init__(self, itype):
        self.type = itype

    def __str__(self):
        if self.type == 0:
            s = "cpu pd=%u apic_id=%u" % (self.pd, self.apic_id)
        elif self.type == 1:
            s = "mem pd=%u base=%x size=%x" % (self.pd, self.base, self.size)
        elif self.type == 2:
            s = "x2apic id=%d" % (self.x2apic_id)
        elif self.type == 3:
            s = "gicc pd=%u acpi_uid=%d" % (self.pd, self.acpi_uid)
        elif self.type == 4:
            s = "its pd=%u its_id=%d" % (self.pd, self.its_id)
        else:
            s = "type=%d?" % (self.type)
        return s


class SRAT(ACPITable):
    """
    SRAT: System resources affinity
    """
    type_names = {
        0x00: "cpu",
        0x01: "mem",
        0x02: "x2apic",
        0x03: "gicc",
        0x04: "its",
    }

    def __init__(self, fn=None, handle=None, sig=b"SRAT", system=None):
        ACPITable.__init__(self, fn, handle=handle, sig=sig, system=system)
        self.structs = []
        self.f.read(12)
        while True:
            ih = self.f.read(2)
            if not ih:
                break
            (itype, ilen) = struct.unpack("<BB", ih)
            id = ih + self.f.read(ilen-2)
            assert len(id) == ilen
            if o_verbose:
                print("  SRAT type:%02x (%s)  len:%2u  data:%s" % (itype, self.type_names.get(itype, "?"), ilen, hexstr(id)))
            s = SRATStruct(itype)
            if itype == 0:
                (_, pd0, s.apic_id, s.flags, spd, s.cd) = struct.unpack("<HBBIII", id[:16])
                s.pd = (spd & 0xffffff00) | pd0
                s.sapic_eid = spd & 0xff
            elif itype == 1:
                (_, pdlo, pdhi, _, s.base, s.size) = struct.unpack("<HHHHQQ", id[:24])
                s.pd = (pdhi << 16) | pdlo
            elif itype == 2:
                (_, s.pd, s.x2apic_id, s.flags, s.cd) = struct.unpack("<IIIII", id[:20])
            elif itype == 3:
                (s.pd, s.acpi_uid, s.flags, s.cd) = struct.unpack("IIII", id[2:18])
            elif itype == 4:
                (_, pdlo, pdhi, _, s.its_id) = struct.unpack("<HHHHI", id[:12])
                s.pd = (pdhi << 16) | pdlo
            else:
                print("SRAT unexpected entry type: %d" % itype)
            self.structs.append(s)

    def show_subclass(self):
        for s in self.structs:
            print("    %s" % s)


class MSC:
    """
    MPAM Memory System Controller

    "From a software viewpoint, an MSC is a container of resources."
    """
    MSC_MMIO = 0
    MSC_PCC  = 0x0A

    def __init__(self, itype, uid, mbase, msize, oirq, eirq, ldev, owner=None):
        self.owner = owner
        self.itype = itype
        self.uid = uid
        self.mbase = mbase
        self.msize = msize
        self.ovf_irq = oirq
        self.err_irq = eirq
        self.linked_device = ldev
        self.resources = []

    def add_resource(self, **kw):
        """
        Add a resource controlled by this MSC.
        """
        r = MSCResource(self, **kw)
        self.resources.append(r)
        return r

    def __str__(self):
        s = "MSC 0x%x" % self.uid
        if self.itype == self.MSC_MMIO:
            s += " at 0x%x size 0x%x" % (self.mbase, self.msize)
        elif self.itype == self.MSC_PCC:
            s += " PCC subspace 0x%x" % self.mbase
        else:
            s += " type %u?" % self.itype
        if self.ovf_irq:
            s += " overflow IRQ %u" % self.ovf_irq
        if self.err_irq:
            s += " error IRQ %u" % self.err_irq
        if self.linked_device:
            s += " linked to HID 0x%x" % self.linked_device
        if self.resources:
            s += " resources: " + ' '.join([str(r) for r in self.resources])
        return s


class MSCResource:
    """
    MPAM Resource, contained in an MSC (see above)
    """
    _ltypes = {
        0x00: "processor cache",
        0x01: "memory",
        0x02: "SMMU",
        0x03: "memory-side cache",
        0x04: "ACPI device",
        0x05: "interconnect",
    }

    def __init__(self, msc, rid, ltype, loc1, loc2):
        self.msc = msc
        self.rid = rid
        self.location_type = ltype
        self.deps = []
        self.loc1 = loc1
        self.loc2 = loc2

    def __str__(self):
        s = "id 0x%x " % self.rid
        if self.location_type in self._ltypes:
            s += self._ltypes[self.location_type]
        else:
            s += "type 0x%x?" % self.location_type
        s += " (0x%x,0x%x)" % (self.loc1, self.loc2)
        if self.deps:
            s += " depends: " + str(self.deps)
        return s


class MPAM(ACPITable):
    """
    MPAM: Memory Partitioning and Monitoring
    This table is defined by Arm Platform Design Document DEN0065B.
    """
    def __init__(self, fn=None, handle=None, sig=b"MPAM", system=None):
        ACPITable.__init__(self, fn, handle=handle, sig=sig, system=system)
        self.msc = {}        # MSCs indexed by unique MSC id
        self.resource = {}   # Resources indexed by unique resource id
        msg_dup_resource_id = False
        # Read an array of MSC descriptors
        while True:
            ih = self.f.read(2)
            if not ih:
                break
            nlen = struct.unpack("<H", ih)[0]
            id = ih + self.f.read(nlen-2)
            if o_verbose >= 2:
                print("%s  " % hexstr(id), end="")
            (_, itype, _, uid, mbase, msize, oirq, oirqf, _, oirqa, eirq, eirqf, _, eirqa, _, ldev, ldevi, nres) = struct.unpack("<HBBIQIIIIIIIIIIQII", id[:72])
            msc = MSC(itype, uid, mbase, msize, oirq, eirq, ldev, owner=self)
            if uid in self.msc:
                print("MPAM: unexpected duplicate MSC ID: %s vs. %s" % (self.msc[uid], msc), file=sys.stderr)
            self.msc[uid] = msc
            rd = id[72:]           # 24-byte resource nodes, followed by supplementary data
            if o_verbose >= 2:
                print("  %s with %u resource nodes, %u bytes" % (msc, nres, len(rd)))
            for i in range(nres):
                # Read the MSC's resources. "An MSC has resource partitioning controls that operate on resources."
                (rid, rix, _, _, ltype, loc1, loc2, ndep) = struct.unpack("<IBBBBQII", rd[:24])
                rd = rd[24:]
                # "Each resource in the system must be assigned an identifier that is
                #  globally unique among all resources in the system."
                r = msc.add_resource(rid=rid, ltype=ltype, loc1=loc1, loc2=loc2)
                if rid in self.resource:
                    if not msg_dup_resource_id:
                        print("MPAM: unexpected duplicate resource ID: %s vs. %s" % (self.resource[rid], r), file=sys.stderr)
                        msg_dup_resource_id = True
                self.resource[rid] = r
                # now read the functional dependency descriptors
                for j in range(ndep):
                    (prod, _) = struct.unpack("<II", rd[:8])
                    rd = rd[8:]
                    r.deps.append(prod)
            if len(rd) != 0:
                print("%s: unexpected %u bytes data" % (self, len(rd)), file=sys.stderr)
                sys.exit(1)
            if o_verbose:
                print("  %s" % msc)

    def show_subclass(self):
        for msc_id in sorted(self.msc.keys()):
            print("  %s" % self.msc[msc_id])


def ACPI(fn, system=None):
    """
    Open an ACPI file, returning an ACPITable or subclass thereof.
    """
    if '/' not in fn:
        fn = os.path.join(sys_tables, fn)
    with open(fn, "rb") as f:
        sig = f.read(4)
        if sig == b"APIC":
            return APIC(fn, handle=f, sig=sig, system=system)
        elif sig == b"PPTT":
            return PPTT(fn, handle=f, sig=sig, system=system)
        elif sig == b"SLIT":
            return SLIT(fn, handle=f, sig=sig, system=system)
        elif sig == b"SRAT":
            return SRAT(fn, handle=f, sig=sig, system=system)
        elif sig == b"MPAM":
            return MPAM(fn, handle=f, sig=sig, system=system)
        else:
            # Other tables not handled specially
            return ACPITable(fn, handle=f, sig=sig, system=system)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="read ACPI tables")
    parser.add_argument("-i", "--input", type=str, default="/sys/firmware/acpi/tables", help="input file")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    if not os.path.isdir(opts.input):
        # Build a single ACPI table object from a single file
        A = ACPI(opts.input)
        A.show()
    else:
        # Build a collection of ACPI table objects from a directory
        S = System()
        acpi_dir = opts.input
        for fn in sorted(os.listdir(acpi_dir)):
            fn = os.path.join(acpi_dir, fn)
            if os.path.isfile(fn):
                A = ACPI(fn, system=S)
                A.show()
