#!/usr/bin/python3

"""
CMN (Coherent Mesh Network) driver

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This is a userspace device driver. It is not expected to disrupt CMN
interconnect operation, but the PMU configuration features might come
into conflict with the Linux driver (drivers/perf/arm-cmn.c).
"""

from __future__ import print_function


import os
import sys
import struct
import time
import traceback
import atexit
import datetime


import devmem
import cmn_devmem_find
from cmn_devmem_regs import *
import cmn_base
import cmn_config
from cmn_enum import *
import cmn_events

#
# In response to an environment variable (CMN_DEVMEM_DIAG) we can log register accesses to a file.
#
g_trace_fd = None


def BITS(x,p,n):
    return (x >> p) & ((1 << n)-1)


def BIT(x,p):
    return (x >> p) & 1


def hexstr(x):
    s = ""
    # be portable for Python2/3
    for ix in range(len(x)):
        s += ("%02x" % ord(x[ix:ix+1]))
    return s

assert hexstr(b"\x12\x34") == "1234"


# Diagnostic options for debugging CMN programming issues (c.f. --cmn-diag command-line option)
DIAG_DEFAULT  = 0x00
DIAG_READS    = 0x01     # Trace all device reads
DIAG_WRITES   = 0x02     # Trace all device writes


class CMNDiscoveryError(Exception):
    def __init__(self, cmn, msg):
        self.cmn = cmn
        self.msg = msg

    def __str__(self):
        return "CMN discovery error in %s: %s" % (self.cmn, self.msg)


def node_has_logical_id(nt):
    """
    Check if this node type has a "logical id" field.
    Logical ids are numbered sequentially from 0 for a given node type.
    For DTCs, the logical id is the DTC domain number.
    CFG (root) node can have a logical id.
    """
    return nt not in [CMN_NODE_RNSAM]


class NotTestable:
    def __init__(self, msg):
        self.msg = msg

    def __bool__(self):
        assert False, self.msg


def any_cpus_offline():
    """
    Check whether any Linux CPUs are offline.
    Offline CPUs may create a risk of lockups when discovering RN-SAM devices.
    """
    return open("/sys/devices/system/cpu/offline").read().strip() != ""


def node_type_has_pmu_events(nt):
    """
    Return True if this node type has a PMU that can export events to a DTM.
    """
    return nt not in [CMN_NODE_CFG, CMN_NODE_DT, CMN_NODE_RNSAM] and not cmn_node_type_has_properties(nt, CMN_PROP_MPAM)


def pmu_event_sel_offset(base, nt):
    """
    Return the offset(s) from the node base, of the pmu_event_sel register(s),
    given the "PMU base" (see PMU_EVENT_SEL_BASE).
    """
    if nt == CMN_NODE_CCLA:
        return [base+8]
    elif nt == CMN_NODE_CCLA_RNI or nt == CMN_NODE_HNP:
        return [base+0, base+8]
    elif not node_type_has_pmu_events(nt):
        return []
    else:
        assert base is not None, "node type %s needs pmu_event base" % cmn_node_type_str(nt)
        return [base]


class CMNSecureAccess:
    def __init__(self, node):
        self.node = node
        self.old = None if node.C.secure_accessible else node.set_secure_access(node.C.root_security)

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        if self.old is not None:
            self.node.set_secure_access(self.old)


class CMNNodeBase:
    """
    A single CMN node, at some offset in the overall peripheral space.
    Spans a 16K range of configuration registers.

    Subclassed for XP and DT.
    """
    def __init__(self, cmn, node_offset, map=None, write=False, parent=None, is_external=False, node_info=None, disabled=False):
        if not isinstance(disabled, bool):
            raise TypeError("node disabled must be a boolean")
        self.disabled = disabled
        self.C = cmn
        self.diag_trace = DIAG_DEFAULT       # defer to owning CMN object
        self.parent = parent                 # parent in the CMN hierarchy, e.g. CFG or XP
        self.is_external = is_external       # device is external, e.g. RN-SAM
        if node_offset in self.C.offset_node:
            raise CMNDiscoveryError(self.C, "node already discovered: %s" % self.C.offset_node[node_offset])
        self.C.offset_node[node_offset] = self
        self.node_base_addr = cmn.periphbase + node_offset
        himem = self.node_base_addr + self.C.node_size()
        if himem > self.C.himem:
            self.C.himem = himem
        if self.C.verbose >= 3:
            self.C.log("created node at 0x%x" % (self.node_base_addr), level=3)
        if map is not None:
            self.m = map
        else:
            self.m = self.C.D.map(self.node_base_addr, self.C.node_size(), write=write)
        if node_info is not None:
            self.node_info = node_info
        else:
            self.node_info = 0x0000     # in case we throw in the next line
            self.node_info = self.read64(CMN_any_NODE_INFO)
        if parent is not None and parent.is_XP():
            # We're creating a device node
            if self.node_id() not in parent._device_objects:
                xp_devices = parent._device_objects.keys()
                print("%s: node 0x%03x not in devices: %s" % (parent, self.node_id(), ','.join(["0x%03x" % d for d in xp_devices])), file=sys.stderr)
            self.device = parent._device_objects[self.node_id()]
        if self.C.verbose >= 3:
            self.C.log("  node: %s" % (self), level=3)
        if not self.has_pmu_events():
            self.PMU_EVENT_SEL_BASE = None
        elif self.is_XP() or not self.C.part_ge_S3():
            self.PMU_EVENT_SEL_BASE = self.C.DTM_BASE   # 0x2000 or 0xA000
        else:
            self.PMU_EVENT_SEL_BASE = 0xD900
        self.PMU_EVENT_SEL = pmu_event_sel_offset(self.PMU_EVENT_SEL_BASE, self.type())
        if self.is_child():
            if (self.node_id() >> 3) != (parent.node_id() >> 3):
                self.C.log("Parent XP %s child %s has odd coordinates" % (parent, self), level=1)
        # We haven't yet discovered this node's children.
        # For an XP in S3, with node isolation, we might never do so.
        self.discovered_children = False
        #self.children = []
        #print("%s%s" % ((self.level()*"  "), self))

    def CMN(self):
        return self.C

    def is_disabled(self):
        """Return the recorded disabled state; this never reads device registers."""
        return self.disabled

    def do_trace_reads(self):
        return (self.diag_trace | self.C.diag_trace) & DIAG_READS

    def do_trace_writes(self):
        return (self.diag_trace | self.C.diag_trace) & DIAG_WRITES

    def ensure_writeable(self):
        if not self.m.writing:
            self.m = self.m.ensure_writeable()

    def set_secure_access(self, secure):
        """
        For this node, ensure that future accesses are performed with the given security level.
        Return the previous security level.
        It is expected that this sequence is performant enough to do on every access:
          old = n.set_secure_access(n.C.root_security)
          n.read64()
          n.set_secure_access(old)
        """
        return self.m.set_secure_access(secure)

    def read64(self, off):
        if self.do_trace_reads():
            print()
            print("at %s:" % self.C.source_line())
            self.C.log("%s: read 0x%x (0x%x)" % (str(self), off, self.node_base_addr+off), end="", level=0)
        data = self.m.read64(off)
        if self.do_trace_reads():
            self.C.log(" => 0x%x" % data, prefix=None, level=0)
        if g_trace_fd is not None:
            print("R 0x%x 0x%x" % (self.node_base_addr+off, data), file=g_trace_fd)
        return data

    def read64_secure(self, off):
        """
        Read a normally Secure-only CMN register. This doesn't necessarily perform
        a Secure read - it will take advantage of the global security override flag.
        """
        if self.C.secure_accessible:
            return self.read64(off)
        try:
            old = self.set_secure_access(self.C.root_security)
        except Exception:
            return None
        x = self.read64(off)
        self.set_secure_access(old)
        return x

    def test64(self, off, x):
        return (self.read64(off) & x) == x

    def check_reg_is_writeable(self, off):
        """
        Check that the node is in a suitable programming state to allow writing.
        Expect a subclass to override this.
        """
        pass

    def write64(self, off, data, check=None):
        """
        Write to a device register. N.b. we automatically upgrade the
        mapping to writeable, i.e. remove write-protection, on the
        assumption that the caller knows what they are doing.
        """
        self.ensure_writeable()
        self.check_reg_is_writeable(off)
        if self.do_trace_writes():
            print()
            print("at %s:" % self.C.source_line())
            self.C.log("%s: write 0x%x := 0x%x" % (str(self), off, data), level=0)
        self.m.write64(off, data, check=check)

    def set64(self, off, mask, check=None):
        old = self.read64(off)
        self.write64(off, old | mask, check=check)
        return (old & mask)

    def clear64(self, off, mask, check=None):
        old = self.read64(off)
        self.write64(off, old & ~mask, check=check)
        return (old & mask)

    def setclear64(self, off, mask, flag, check=None):
        """
        Set or clear a mask (likely a single bit) under control of a flag.
        """
        if flag:
            old = self.set64(off, mask, check=check)
        else:
            old = self.clear64(off, mask, check=check)
        return old

    def level(self):
        """
        Node level: 0 for config, 1 for XPs, 2 for child nodes.
        """
        lv = 0
        node = self
        while node.parent is not None:
            node = node.parent
            lv += 1
            assert lv <= 2
        return lv

    def discover_children(self):
        """
        From the configuration node, iterate the XPs;
        from an XP, iterate the child (device) nodes.
        There is a risk of system lockup when scanning child devices, for two reasons:
         - RN-SAMs for offline CPUs
         - isolated HNs using the CMN S3 device isolation feature
        We guard against these, at the cost of maybe missing some unrelated devices
        that happen to be on the same XP. Options for dealing with RN-SAMs:
         - never skip
         - skip if external and XP has any RN-F ports and any CPUs are offline
         - skip if external and XP has any RN-F ports
         - skip if external

        We also honor node_skiplist if present. Note that there is a distinction:
         - node_skiplist None: nothing is known about isolated nodes
         - node_skiplist empty: there are no isolated nodes

        por_xx_child_info has the register offset to the child pointer array (typically 0x100),
        and the number of entries in the array. We expect the registers following the array
        are zero, but we have seen cases where they are non-zero - possibly as a way to
        hide inactive devices by changing only the n_children field.
        """
        if self.discovered_children:
            return
        self.C.log("%s: discover children" % self, level=2)
        self.children = []
        # Only do the discovery once, even if we terminate because of node isolation
        self.discovered_children = True
        if self.is_XP():
            self.C.n_XPs_discovered_devices += 1
        cobits = 30 if self.C.part_ge_650() else 28
        if self.is_XP() and self.C.isolation_enabled and self.C.node_skiplist is None:
            # In S3, scanning isolated child HN-F/HN-Ss will fault and lock up the system.
            # From S3 r2p0 on, child isolation status is flagged in bit 30 of the child offsets.
            # Before then, we could check if there are any HN-F/HN-S connected ports for this XP,
            # and abandon the scan if so. Or we could try and make a secure
            # access to por_mxp_device_port_disable and check if any ports are disabled.
            # We could even try to infer the port numbers from the offsets and skip
            # just disabled ports (from por_mxp_device_port_disable) or all HN ports.
            # Otherwise, all we can do is abandon the scan and miss not just all
            # home nodes (whether isolated or not) but any nodes on the same XP.
            # If a skiplist was provided (including an empty skiplist), we assume
            # that the user has full knowledge of isolated devices and we don't need
            # to be conservative.
            if (not self.C.part_ge_S3r2()) and self.has_any_ports(CMN_PROP_HNF):
                pd = self.read64_secure(0x0A70)
                if pd is None:
                    # Couldn't do Secure read - have to bail out
                    if self.C.verbose >= 1:
                        self.C.log("%s has HN-F/HN-S ports and couldn't determine node isolation status - skip" % self, level=1)
                    if not self.C.isolation_warned:
                        print("%s: node isolation is enabled, but no skiplist was provided - node discovery will be incomplete" % self.C, file=sys.stderr)
                        self.C.isolation_warned = True
                    self.skipped_nodes = SKIP_ALL
                elif pd != 0:
                    if self.C.verbose >= 1:
                        self.C.log("%s has HN-F/HN-S ports and node isolation map is 0x%x - skip" % (self, pd), level=1)
                    self.skipped_nodes = SKIP_ALL
        # Skip external devices (e.g. RN-Fs) if they might be powered off
        skip_external = self.is_XP() and self.has_any_ports(CMN_PROP_RNF) and self.C.skip_external_if_RNF
        # Even if we're skipping all devices, it's safe to read and display the child pointers
        for child in self.child_pointers():
            child_offset = BITS(child, 0, cobits)
            if self.is_XP() and self.skipped_nodes == SKIP_ALL:
                self.C.log("%s: skipping device at 0x%x because cannot determine isolation status" % (self, child_offset), level=1)
                continue
            is_external = BIT(child, 31)
            if is_external and skip_external:
                self.C.log("%s: skipping external device at 0x%x" % (self, child_offset), level=1)
                continue
            is_isolated = BIT(child, 30) and self.C.part_ge_S3r2()
            if self.C.node_skiplist is not None:
                # The skiplist can be used to skip isolated nodes (e.g. in CMN S3 r0 where bit 30
                # is not implemented, or to override isolation bits.
                is_skipped = (child_offset in self.C.node_skiplist or (self.C.periphbase+child_offset) in self.C.node_skiplist)
            else:
                is_skipped = None
            # There are now six cases:
            #   !is_isolated  is_skipped=None    - go ahead (normal case for pre-S3 and S3 r2)
            #   !is_isolated  is_skipped=False   - go ahead (S3 r0, not isolated)
            #   !is_isolated  is_skipped=True    - skip (S3 r0, isolated)
            #   is_isolated   is_skipped=None    - skip (normal case for S3 r2 where isolation bit is set)
            #   is_isolated   is_skipped=False   - go ahead (override for S3 r2 incorrect isolation bit)
            #   is_isolated   is_skipped=True    - skip (S3 r2, isolation bit correctly set but skip list needed for other nodes)
            if is_isolated:
                if is_skipped is None or is_skipped:
                    self.C.log("%s: skipping isolated device at 0x%x (bit 30 set)" % (self, child_offset), level=1)
                    self.skipped_nodes = SKIP_SPECIFIC
                    continue
                # is_skipped is False - skiplist was provided, but does not contain this node
                self.C.log("%s: device at 0x%x is marked as isolated (bit 30 set), but is not in skiplist" % (self, child_offset), level=0)
            else:
                if is_skipped:
                    self.C.log("%s: skipping skiplist marked node at 0x%x" % (self, child_offset), level=0)
                    # We only expect a skiplist match when discovering an XP's devices,
                    # and not when discovering child XPs of the root configuration node.
                    # In fact, skiplist validation will check all skiplist entries are under XPs.
                    if not self.is_XP():
                        self.C.log("Unexpected skiplist match when discovering XPs!", level=0)
                    self.skipped_nodes = SKIP_SPECIFIC
                    continue
            child_node = self.C.create_node(child_offset, parent=self, is_external=is_external)
            if child_node is None:
                # Probably a child of a RN-F port
                continue
            self.children.append(child_node)
            if self.is_XP():
                # The XP will have CMNPort objects for all its ports. The device nodes should point back to the port.
                assert child_node.port == self.port(child_node.port_number)

    def child_pointers(self):
        self.child_info = self.read64(CMN_any_CHILD_INFO)
        self.n_children = BITS(self.child_info, 0, 16)
        # For top-level configuration, max children at least 144 for 12x12. For an XP it's 32.
        if self.n_children > (32 if self.is_XP() else 256):
            self.C.log("CMN discovery found too many (%u) node children: %s" % (self.n_children, self), level=1)
        child_off = BITS(self.child_info, 16, 16)
        if child_off != 0x100:
            self.C.log("%s has child offset 0x%x" % (self, child_off), level=1)
        for i in range(0, self.n_children):
            child = self.read64(child_off + (i*8))
            yield child
        # Check that the other child pointers are zero, by scanning the remaining entries.
        # TBD: this shouldn't really be controlled by 'verbose'.
        if self.C.verbose >= 4:
            for i in range(self.n_children, 32):
                child = self.read64(child_off + (i*8))
                if child != 0x0:
                    self.C.log("%s: %u children but child pointer #%u is 0x%x" % (self, self.n_children, i, child), level=1)

    def type(self):
        """
        The node type e.g. CMN_NODE_XP, CMN_NODE_HNF from node_info.
        Not to be confused with XP connected device type.
        """
        return BITS(self.node_info, 0, 16)

    def type_str(self):
        return cmn_node_type_str(self.type())

    def node_id(self):
        """
        The node id, incorporating X/Y coordinates, port and device.
        """
        return BITS(self.node_info, 16, 16) if not self.is_rootnode() else None

    def logical_id(self):
        """
        The logical ID is programmed by the mesh configurator.
        It should be unique for nodes of a particular type.
        For a DTC, this is actually a 2-bit field, dtc_domain.
        """
        if not node_has_logical_id(self.type()):
            return None
        return BITS(self.node_info, 32, 16)

    def is_rootnode(self):
        return self.type() == CMN_NODE_CFG

    def is_XP(self):
        return self.type() == CMN_NODE_XP

    def XP(self):
        """
        For any node, return its crosspoint. For XPs, this is the node itself.
        """
        return self if self.is_XP() else self.parent

    def is_child(self):
        return self.parent is not None and self.parent.is_XP()

    def has_properties(self, props):
        return cmn_node_type_has_properties(self.type(), props)

    def properties(self):
        return cmn_node_properties.get(self.type(), CMN_PROP_none)

    def is_home_node(self):
        return self.has_properties(CMN_PROP_HNF)    # HN-F and HN-S

    def cache_geometry(self):
        # move to subclass, if/when we have a HN-F subclass
        assert self.has_properties(CMN_PROP_HNF), "%s: only HN-F has cache geometry" % self
        return hn_cache_geometry(self)

    def has_pmu_events(self):
        """
        Can this node generate PMU events? I.e. does it have por_xxx_pmu_event_sel?
        """
        return node_type_has_pmu_events(self.type())

    def XY(self):
        """
        Get the (X, Y) coordinates for the node. This can only be done when
        the mesh size is known.
        """
        id = self.node_id()
        cb = self.C.coord_bits
        assert cb is not None, "can't get coordinates until mesh size is known"
        Y = BITS(id, 3, cb)
        X = BITS(id, 3+cb, cb)
        return (X, Y)

    @property
    def x(self):
        return self.XY()[0]

    @property
    def y(self):
        return self.XY()[1]

    def coords(self):
        """
        Return device coordinates as a tuple (X, Y, P, D).
        For an XP, P and D will be zero.
        Otherwise, P is the port number, and D is the device number.
        D is generally zero, but for CAL-attached devices it may be 0 or 1.
        (X, Y) can only be discovered after the mesh size is known.
        """
        (X, Y) = self.XY()
        (P, D) = self.PD() if not self.is_XP() else (0, 0)
        return (X, Y, P, D)

    @property
    def port_number(self):
        assert not self.is_XP()
        (P, D) = self.PD()
        return P

    @property
    def device_number(self):
        assert not self.is_XP()
        (P, D) = self.PD()
        return D

    @property
    def device_object(self):
        """
        Return the CMNDevice corresponding to this node.
        For non-device nodes, return None so the API is safe to use across
        both the base-model and live-discovery object models.
        """
        if self.is_rootnode() or self.is_XP():
            return None
        return self.device

    def show(self):
        # Node-specific subclass can override
        pass

    def extra_str(self):
        # Node-specific subclass can override
        return ""

    def __lt__(self, node):
        return self.node_base_addr < node.node_base_addr

    def __str__(self):
        cmn_s = "CMN#%u" % self.C.cmn_seq
        lid = self.logical_id()
        s = "%s" % cmn_node_type_str(self.type())
        if lid is not None:
            s += "#%u" % lid
        if self.is_external:
            s += "(ext)"
        s = "%s:%s" % (cmn_s, s)
        if self.C.verbose > 0:
            s = "@0x%x:%s" % (self.node_base_addr, s)
        if not self.is_rootnode():
            s += ":0x%x" % self.node_id()
            if self.C.coord_bits is not None:
                (X, Y, P, D) = self.coords()
                if self.is_XP():
                    s += ":(%u,%u)" % (X, Y)
                else:
                    s += ":(%u,%u,%u,%u)" % (X, Y, P, D)
        if self.C.verbose >= 2:
            s += ":info=0x%x" % self.node_info
        if self.is_disabled():
            s += " (disabled)"
        return s


class CMNDevice:
    """
    Lightweight view of a CHI-addressable device slot on a port.
    This mirrors the topology concept used in cmn_base without changing
    cmn_devmem's live-discovery model.
    """
    def __init__(self, port, node_id, device_number):
        self.port = port
        self._node_id = node_id
        self.device_number = device_number
        self._c2c_endpoints = []

    def c2c_endpoints(self):
        """Iterate recorded link endpoints without discovering child nodes."""
        return iter(self._c2c_endpoints)

    def cached_node_by_type(self, node_type):
        """Resolve a previously discovered node without reading registers."""
        xp = self.XP()
        if not xp.discovered_children:
            return None
        # device_nodes would invoke child discovery; inspect cached children.
        for node in xp.children:
            if node.node_id() == self.node_id() and node.type() == node_type:
                return node
        return None

    def node_id(self):
        return self._node_id

    def CMN(self):
        return self.port.CMN()

    def XP(self):
        return self.port.XP()

    def PD(self):
        return (self.port.port_number, self.device_number)

    def has_properties(self, props):
        return cmn_base.device_has_properties(self, props)

    @property
    def device_nodes(self):
        return list(self.XP().port_device_nodes(self.port.port_number, self.device_number))

    @property
    def device_credited_slices(self):
        return self.port.device_credited_slices(self.device_number)

    def __str__(self):
        return "%s.D%u" % (self.port, self.device_number)


class CMNPort:
    """
    Information about an XP port
    The XP's CMNPort objects are created along with the XP, based on the
    "connected device info" in the XP. Initially they are not populated
    with device nodes.

    The port number is an index into the XP's port information registers.
    Port numbers aren't necessarily contiguous from zero.
    """
    def __init__(self, xp, port_number=None, connect_info=None, dtm=None, base_id=None):
        self.xp = xp
        self.port_number = port_number
        self._base_id = base_id
        self.dtm = dtm          # CMNDTM object for this port
        self.connect_info = connect_info
        self.connected_type = self.xp.connect_info_type(self.connect_info)
        self._port_info = {}    # Cache for the port_info register(s)
        self._devices = {}      # CMNDevice objects, indexed by device number

    @property
    def connected_type_s(self):
        return cmn_port_device_type_str(self.connected_type)

    def device_type(self):
        """
        Compatibility alias for connected_type.
        """
        return self.connected_type

    def XP(self):
        return self.xp

    def CMN(self):
        return self.xp.C

    def has_properties(self, props):
        return cmn_base.port_has_properties(self, props)

    def port_info(self, n=0):
        """
        Get the port_info[n] word for the port. Return None if
        the word is not present for this implementation.
        Lazy: reads on demand, caches the result.
        """
        if n not in self._port_info:
            if not self.xp.C.part_ge_700():
                if n > 0:
                    return None   # Only one info register
                off = CMN_any_UNIT_INFO + (self.port_number * 8)
            else:
                if n > 1:
                    return None   # Only two info registers
                if self.port_number < 6:
                    off = CMN_any_UNIT_INFO + (self.port_number * 16) + (n * 8)
                else:
                    off = 0xEE0 + ((self.port_number - 6) * 16) + (n * 8)
            self._port_info[n] = self.xp.read64(off)
        return self._port_info[n]

    def n_devices_from_port_info(self):
        """
        Return the number of devices on the port, as indicated by the port information in the XP.
        Note that CCGs with PCIe tunnelling RN-Is indicate 1 when they really have 2.
        """
        return BITS(self.port_info(), 0, 3)

    def n_devices(self):
        """
        Return the actual number of devices on the port, adjusting for PCIe-capable CCGs.
        """
        n = self.n_devices_from_port_info()
        if n == 1 and self.has_properties(CMN_PROP_CCG):
            # TBD: We should check ccg_type in the CCLA.
            # Only some CCG types have the RN-I device:
            # CCGPCI (6), CCGDPCI (13), CCGPCIT1HT3H (3), CCGDPCIT1HT3H (10).
            # Most of them don't. Of the ones that don't, CCGSMP/CCGDSMP have a
            # distinct port connected type, so we can rule them out.
            if self.connected_type != CMN_PORT_DEVTYPE_CCGSMP:
                n = 2
        return n

    def has_cal(self):
        """
        If the port has a CAL, return a number between 2 and 4 indicating the CAL multiplicity.
        Otherwise, return 0.
        """
        has_cal = BIT(self.connect_info, CMN_XP_DEVICE_PORT_CAL_CONNECTED_BIT)
        return BITS(self.port_info(), 0, 3) if has_cal else 0

    def devices(self, properties=CMN_PROP_none):
        """
        Yield the CMNDevice objects for the port.
        """
        for dev in cmn_base.port_devices(self, properties=properties):
            yield dev

    @property
    def cal(self):
        return self.has_cal()

    @property
    def cal_credited_slices(self):
        return BITS(self.connect_info, 8, 4)

    def device_credited_slices(self, d):
        """
        Return device credited slices for device D<d> on this port.
        Having this as a port function means this works for RN-Fs and SN-Fs,
        which are external to CMN and don't have node objects.
        """
        return BITS(self.connect_info, 16+(d*4), 4)

    def nodes(self, discover=True):
        """
        Yield port nodes in device-number (and hence node-id) order.
        With discover=False, only inspect previously discovered children.
        """
        if not discover and not self.xp.discovered_children:
            return
        for n in self.xp.port_nodes(self.port_number):
            yield n

    def ids(self):
        """
        Yield device node ids in order
        """
        for id in cmn_base.port_ids(self):
            yield id

    def device(self, device_number, create=False):
        dev = self._devices.get(device_number, None)
        if dev is None and create:
            raise IndexError("%s: no device slot D%u" % (self, device_number))
        return dev

    def device_at_id(self, id, create=False):
        return cmn_base.port_device_at_id(self, id, create=create)

    def device_numbers(self):
        """
        Return sorted slot numbers from the cache populated during XP creation.
        Slots exist independently of child nodes, which might not yet have
        been discovered.
        """
        return sorted(self._devices.keys())

    def device_has_explicit_description(self, d):
        return bool(self.XP().port_device_nodes(self.port_number, d)) or (self.device_credited_slices(d) != 0)

    def is_valid_id(self, id):
        return cmn_base.port_device_number(self, id) in self.device_numbers()

    def base_id(self):
        return self._base_id

    def __str__(self):
        return "%s P%u" % (self.xp, self.port_number)


# Remember if we skipped some device nodes
SKIP_NONE     = 0     # nothing skipped - all children found
SKIP_SPECIFIC = 1     # specific nodes were skipped because flagged as isolated
SKIP_ALL      = 2     # all devices skipped because of insufficient information

# Indexes for mesh_credited_slices()
MCS_EAST   = 0
MCS_NORTH  = 1


class CMNNodeXP(CMNNodeBase):
    """
    Crosspoint node. This has special behavior as follows:
      - manages child nodes on its ports P0, P1..., possibly several on each
      - contains a Debug/Trace Monitor (DTM), or possibly multiple DTMs
    """
    def __init__(self, *args, **kwargs):
        CMNNodeBase.__init__(self, *args, **kwargs)
        self._port_objects = {}     # Indexed by port number
        self._device_objects = {}   # Indexed by node id
        self.skipped_nodes = None
        # At this point, child device nodes are not yet discovered.
        # In CMN S3, device discovery may be hindered by node isolation.
        # But we can discover which ports exist, and create port objects
        # In S3 with FlatID, n_device_ports is not to be trusted
        npc = 8 if self.C.part_ge_S3r2() else self.n_device_ports()
        cis = [self.read64(CMN_XP_DEVICE_PORT_CONNECT_INFO_P(pn)) for pn in range(npc)]
        cit = [self.connect_info_type(ci) for ci in cis]
        mc = -1
        for (pn, t) in enumerate(cit):
            if t != CMN_PORT_DEVTYPE_NOT_CONNECTED:
                mc = pn
        self.flatid = (mc >= 6)    # If ports 7 or 8 are in use, assume FlatID scheme
        if "CMN_FLATID" in os.environ:
            self.flatid = True
        if not self.flatid:
            # Number of device bits depends on highest port number
            ndb = 1 if self.n_device_ports() > 2 else 2
        else:
            ndb = None
        self.set_dtms(max_port_number=mc)
        bio = 0
        for pn in range(npc):
            connect_info = cis[pn]
            type = cit[pn]
            if type != CMN_PORT_DEVTYPE_NOT_CONNECTED:
                if not self.flatid:
                    bio = (pn << ndb)
                po = CMNPort(self, pn, connect_info, dtm=self.port_dtm(pn), base_id=(self.node_id() + bio))
                self.C._record_home_node_type(
                    {CMN_PORT_DEVTYPE_HNF: CMN_NODE_HNF, CMN_PORT_DEVTYPE_HNS: CMN_NODE_HNS}.get(type))
                self._port_objects[pn] = po
                nd = po.n_devices()
                for dn in range(nd):
                    dev = CMNDevice(po, cmn_base.port_device_id(po, dn), dn)
                    po._devices[dn] = dev
                    self._device_objects[dev.node_id()] = dev
                if self.flatid:
                    bio += nd
        # At this point, CMNPort objects have been created for all ports in use,
        # but we haven't discovered device nodes.

    def set_dtms(self, max_port_number=1):
        """
        Given a maximum port number in use, set up the DTM objects.
        """
        if self.C.multiple_dtms:
            n_dtms = max(1, ((max_port_number + 2) // 2))
        else:
            n_dtms = 1
        self.dtms = [CMNDTM(self, index=ix) for ix in range(n_dtms)]
        self.dtm = self.dtms[0]     # Legacy

    @property
    def n_ports(self):
        """
        Number of ports in use (numbering might not be consecutive)
        """
        return len(self._port_objects)

    def DTMs(self):
        for dtm in self.dtms:
            yield dtm

    def dtc_domains(self):
        """
        Return a list of DTC domains, one per DTM in index order.
        A domain is None if unknown. Unit-info reads are cached by each DTM.
        """
        return [dtm.dtc_domain() for dtm in self.DTMs()]

    def connect_info_type(self, connect_info):
        """
        Get the "connected device info" from a port-connected-device word.
        This will indicate whether the port is in use, and its type if so.
        """
        dtbits = 6 if self.C.part_ge_S3() else 5
        return BITS(connect_info, 0, dtbits)

    def mesh_credited_slices(self, i):
        assert i in [MCS_EAST, MCS_NORTH]
        pbase = 6 if self.C.part_ge_700() else 2
        link = self.read64(CMN_XP_DEVICE_PORT_CONNECT_INFO_P(pbase+i))
        mcs = BITS(link, 0, 4)
        return mcs

    def port(self, port_number):
        """
        Return the CMNPort object for a given port.
        Return None if port does not exist or is not connected.
        """
        return self._port_objects.get(port_number, None)

    def port_dtm(self, p):
        if self.C.multiple_dtms:
            # In the multiple-DTM case, DTM#1 handles P2/P3, DTM#2 handles P4/P5 etc.
            ix = p // 2
        else:
            ix = 0
        assert ix < len(self.dtms), "Port P%u out of range, only %u DTMs" % (ix, len(self.dtms))
        return self.dtms[ix]

    def port_nodes(self, rP):
        """
        Yield all a port's device nodes, ordered by device number.
        (There may be multiple device nodes for a given device number.)
        """
        if not self.discovered_children:
            self.discover_children()
        po = self.port(rP)
        for rD in range(0, po.n_devices()):
            for n in self.port_device_nodes(rP, rD):
                yield n

    def port_device_nodes(self, rP, rD):
        """
        Yield all a port's device nodes, for a given device number.
        Note that a RN-F port will only have a RN-SAM device node,
        and a SN-F port will not have any device nodes at all.
        """
        if not self.discovered_children:
            self.discover_children()
        for n in self.children:
            (X, Y, P, D) = n.coords()
            if P == rP and D == rD:
                yield n

    def n_device_ports(self):
        """
        The number of (device) ports on this XP. In general it is not guaranteed that
        devices exist on every port. For CMN-6xx, each XP is assumed to have 2 ports.
        For CMN-700, the number of device ports is discoverable from the XP's info register
        (some XPs might have 3 or 4), but even so, some might be unused.
        It is possible for there to be a device on P1 but not on P0.
        """
        if self.C.part_ge_700():
            return BITS(self.node_info, 48, 4)
        else:
            return 2

    def port_device_type(self, rP):
        """
        Return a "connected device type" value indicating the type of device(s)
        attached to this port. This is not the same as the node type.
        """
        p = self.port(rP)
        return p.connected_type if p is not None else None

    def port_device_type_str(self, rP):
        """
        The string for the port's "connected device type".
        """
        dt = self.port_device_type(rP)
        if dt is not None:
            return cmn_port_device_type_str(dt)
        else:
            return "?"

    def ports(self, properties=CMN_PROP_none):
        """
        Yield port objects of any ports with the given properties,
        based on the connected type and CAL information cached when the XP
        was created. This includes the HN-I role of HCAL3 ports.
        This should be usable before scanning child nodes, because we
        rely on it in CMN S3 to avoid lockups due to device isolation.
        """
        for p in range(0, self.n_device_ports()):
            port = self.port(p)
            if port is not None and port.has_properties(properties):
                yield port

    def has_any_ports(self, props):
        """
        Return True if this XP has any ports with the given properties.
        """
        return bool(list(self.ports(properties=props)))

    def port_base_id(self, rP):
        return self.port(rP).base_id()

    def id_port_device(self, id):
        """
        Given a device identifier (i.e. CHI srcid/tgtid) belonging
        to this XP, return a tuple of (port, device)
        """
        return self._device_objects[id].PD()

    def device_at_id(self, id, create=False):
        """
        Look up a slot created during XP initialization, without child discovery.
        create is accepted for compatibility; live slots are already populated.
        """
        return self._device_objects.get(id, None)

    def is_valid_id(self, id):
        return (id & ~7) == self.node_id()

    def pmu_event_sel(self, eix):
        """
        Get the event selector for the XP itself. This will only be relevant
        if a DTM in the XP has selected an XP event.

        From CMN-700 onwards, XP event export selectors are 16-bit fields.
        (Device event export selectors remain as 8-bit fields.)
        """
        fw = 16 if self.C.part_ge_700() else 8
        return BITS(self.read64(self.PMU_EVENT_SEL[0]), (eix*fw), fw)


class DTMWatchpoint:
    """
    Current configuration of a single DTM physical watchpoint.

    Some of the terminology here reflects DTM register field naming:
      'dev' is a port number (not a device number).
      'chn' is a CHI channel selector (wp_chn_sel), 0/1/2/3 for REQ/RSP/SNP/DAT.
      'chn_num' is a channel instance selector (0,1,...) for parallel channels.

    This structure describes a single watchpoint configuration. Any watchpoint grouping,
    e.g. for multiple ports, or multiple fragments of a DAT packet, or multiple
    channel instances, must be handled at a higher level.
    """
    def __init__(self, dtm=None, up=None, wp=None, cfg=None, value=None, mask=None, chn=None, chn_num=0, dev=None, grp=None, type=None, pkt_gen=None, cc=None, exclusive=None, combine=None, ctrig=None, dbgtrig=None):
        self.dtm = dtm
        self.C = self.dtm.C
        self.wp = wp           # Watchpoint number
        self.up = up if up is not None else (wp <= 1) if wp is not None else None
        self.value = value
        self.mask = mask
        self.chn = chn
        self.chn_num = chn_num
        self.dev = dev
        self.grp = grp
        self.type = type          # i.e. format (4 for full flit)
        self.pkt_gen = pkt_gen
        self.cc = cc
        self.exclusive = exclusive
        self.combine = combine    # Valid for even-numbered watchpoints only
        self.ctrig = ctrig
        self.dbgtrig = dbgtrig
        self.rsvdc_bsel = None
        self.cfg = cfg
        if cfg is not None:
            self.decode()

    def is_inactive(self):
        """
        Return true if the watchpoint can't match anything
        """
        return self.value == 0 and self.mask == 0xffffffffffffffff and self.exclusive

    def decode(self):
        """
        Unpack watchpoint configuration, from the configuration register value
        """
        self.chn = BITS(self.cfg, 1, 2)
        if self.C.DTM_WP_CHN_NUM_SHIFT is not None:
            self.chn_num = BITS(self.cfg, self.C.DTM_WP_CHN_NUM_SHIFT, 2)
        else:
            self.chn_num = 0
        self.dev = BIT(self.cfg, 0)
        if self.dtm.xp.n_device_ports() > 2:
            self.dev |= (BIT(self.cfg, 17) << 1)
        self.grp = BITS(self.cfg, 4, (1 if self.C.product_config.product_id == cmn_base.PART_CMN600 else 2))
        self.type = BITS(self.cfg, self.C.DTM_WP_PKT_TYPE_SHIFT, 3)
        self.pkt_gen = (self.cfg & self.C.DTM_WP_PKT_GEN) != 0
        self.cc = BIT(self.cfg, self.C.DTM_WP_PKT_TYPE_SHIFT+3)
        self.exclusive = (self.cfg & self.C.DTM_WP_EXCLUSIVE) != 0
        self.combine = (self.cfg & self.C.DTM_WP_COMBINE) != 0
        self.ctrig = (self.cfg & self.C.DTM_WP_CTRIG) != 0
        self.dbgtrig = (self.cfg & self.C.DTM_WP_DBGTRIG) != 0
        if self.C.DTM_WP_RSVDC_BSEL_SHIFT is not None:
            self.rsvdc_bsel = BITS(self.cfg, self.C.DTM_WP_RSVDC_BSEL_SHIFT, 2)
        else:
            self.rsvdc_bsel = None
        return self

    def encode(self, cfg=0):
        """
        Pack (generate) watchpoint configuration register value, from individual properties.
        This will be programmed into e.g. por_dtm_wp0_config.
        """
        config = cfg
        if self.pkt_gen:
            config |= self.C.DTM_WP_PKT_GEN
        if self.combine:
            config |= self.C.DTM_WP_COMBINE
        if self.type is not None:
            config |= (self.type << self.C.DTM_WP_PKT_TYPE_SHIFT)
        if self.chn is not None:
            # wp_chn_sel selects the CHI channel: REQ, RSP, SNP, DAT.
            # wp_chn_num selects the replicated channel.
            assert self.chn in [0, 1, 2, 3], "bad watchpoint channel: %u" % self.chn
            config |= (self.chn << 1)
        if self.chn_num:
            assert self.chn_num < self.C.vc_num[self.chn], "bad channel number for %s (%u VCs): %u" % (["REQ", "RSP", "SNP", "DAT"][self.chn], self.C.vc_num[self.chn], self.chn_num)
            config |= (self.chn_num << self.C.DTM_WP_CHN_NUM_SHIFT)
        if self.dev is not None:
            dev0 = self.dev & 1
            config |= (dev0 << 0)
            if self.dev >= 2:
                # dev_sel is actually the port number, not the device number
                assert self.dev < self.dtm.xp.n_device_ports(), "%s: invalid dev_sel=%u" % (self, self.dev)
                dev1 = self.dev >> 1
                config |= (dev1 << 17)
        if self.grp is not None:
            config |= (self.grp << 4)     # for CMN-650 onwards this is a 2-bit field[5:4]
        if self.cc:
            # note: must also be enabled in the DTM
            config |= self.C.DTM_WP_CC_EN
        if self.exclusive:
            config |= self.C.DTM_WP_EXCLUSIVE
        if self.ctrig:
            config |= self.C.DTM_WP_CTRIG
        if self.dbgtrig:
            config |= self.C.DTM_WP_DBGTRIG
        if self.rsvdc_bsel is not None and self.C.DTM_WP_RSVDC_BSEL_SHIFT is not None:
            config |= (self.rsvdc_bsel << self.C.DTM_WP_RSVDC_BSEL_SHIFT)
        self.cfg = config
        return self.cfg

    def chn_str(self):
        s = ["REQ", "RSP", "SNP", "DAT"][self.chn]
        if self.chn_num > 0:
            s += str(self.chn_num + 1)     # our number is zero-based, but conventionally RSP, RSP2 etc.
        return s

    def __str__(self):
        """
        Generate a watchpoint descriptor, in the same format as the Linux PMU driver
        """
        s = "watchpoint"
        if self.up is not None:
            s += "_" + ["down", "up"][self.up]
        if self.chn is not None:
            s += ",wp_chn_sel=%u" % self.chn
        if self.dev is not None:
            s += ",wp_dev_sel=%u" % self.dev
        if self.grp is not None:
            s += ",wp_grp=%u" % self.grp
        if self.value is not None:
            s += ",wp_val=0x%x" % self.value
        if self.mask is not None:
            s += ",wp_mask=0x%x" % self.mask
        if self.exclusive:
            s += ",wp_exclusive=1"
        if self.combine:
            s += ",wp_combine=1"
        # Remainder are extensions, not recognized by Linux PMU driver
        if self.rsvdc_bsel:
            s == ",wp_rsvdc_bsel=%u" % self.rsvdc_bsel
        s += ",wp_pkt_gen=%u" % int(self.pkt_gen)
        if self.ctrig:
            s += ",wp_ctrig=1"
        if self.dbgtrig:
            s += ",wp_dbgtrig=1"
        return s

#
# DT-specific
#

DTM_N_WATCHPOINTS = 4
DTM_N_FIFO_ENTRIES = 4

class DTMState(object):
    """Saved DTM control, watchpoints and local PMU state, owned by one DTM.

    Obtain this through dtm_save(). FIFO contents, snapshot registers and
    device event selections are outside its scope. Saving does not stop the
    DTM, so counter values are observations at the time of the reads.
    """
    def __init__(self, dtm):
        self.dtm = dtm
        self.control = dtm.dtm_read64(CMN_DTM_CONTROL_off)
        self.pmu_config = dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
        self.counters = dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
        self.watchpoints = [dtm.dtm_wp_config(wp) for wp in range(DTM_N_WATCHPOINTS)]

    def _validate(self, dtm):
        if self.dtm is not dtm:
            raise ValueError("saved state belongs to a different DTM")
        if len(self.watchpoints) != DTM_N_WATCHPOINTS:
            raise ValueError("saved state must contain all DTM watchpoints")
        values = [self.control, self.pmu_config, self.counters]
        for wp in self.watchpoints:
            values.extend([wp.cfg, wp.value, wp.mask])
        for value in values:
            cmn_config.check_integer(value, "saved DTM register", maximum=(1 << 64) - 1)


class CMNDTM(object):
    """
    Debug/trace functionality within an XP.
    Split out from XP partly motivated by register offsets having changed in S3.
    """
    def __init__(self, xp, index=0):
        self.xp = xp
        self.C = xp.C
        self.index = index
        self.base = xp.C.DTM_BASE + (index * 0x200)
        self.N_FIFO_WORDS = 4 if self.C.part_ge_S3r1() else 3
        self._unit_info = None
        # We maintain a cached copy of the original DTM enable bit so we can fault writes
        # to DTM configuration registers when enabled.
        self._dtm_is_enabled = None

    def __str__(self):
        s = "%s DTM" % (self.xp)
        if self.index > 0:
            s += ".%u" % self.index
        return s

    def ports(self):
        """
        Yield this DTM's existing ports, with XP-wide port numbers.
        Does not discover child nodes or read registers.
        """
        for port in self.xp.ports():
            if port.dtm is self:
                yield port

    def dtm_read64(self, off):
        return self.xp.read64(self.base+off)

    def dtm_write64(self, off, value, check=None):
        self.dtm_check_reg_is_writeable(off)
        return self.xp.write64(self.base+off, value, check=check)

    def dtm_set64(self, off, value, check=None):
        self.dtm_check_reg_is_writeable(off)
        return self.xp.set64(self.base+off, value, check=check)

    def dtm_clear64(self, off, value, check=None):
        self.dtm_check_reg_is_writeable(off)
        return self.xp.clear64(self.base+off, value, check=check)

    def dtm_test64(self, off, value):
        return self.xp.test64(self.base+off, value)

    @property
    def unit_info(self):
        """
        Read and cache this DTM's unit-info register on first access.
        Return None on CMN-600, which has no DTM unit-info register.
        """
        config = self.C.product_config
        if config.is_before_gen(cmn_config.CMN_GEN_650):
            return None
        if self._unit_info is None:
            # Unit-info registers are in the XP's identification area, with
            # an 8-byte stride, not the DTM control block's 0x200-byte stride.
            # See the TRM's por_dtm_unit_info and por_dtm_unit_info_dt<n>.
            # CI-700 uses the CMN-650 layout (Arm 101569, section 5.3.6.12-13).
            if config.is_before_gen(cmn_config.CMN_GEN_700) or config.product_id == cmn_base.PART_CI700:
                off = CMN650_DTM_UNIT_INFO
            else:
                off = CMN700_DTM_UNIT_INFO
            self._unit_info = self.xp.read64(off + (self.index * 8))
        return self._unit_info

    def dtc_domain(self):
        """
        Return this DTM's DTC domain, or None if it cannot be determined.
        """
        info = self.unit_info
        if info is not None:
            return BITS(info, 0, 2)
        # CMN-600 has no domain indicator. Preserve the single-DTC fallback;
        # with multiple DTCs the assignment cannot be discovered this way.
        return 0 if len(self.C.debug_nodes) == 1 else None

    def dtm_check_reg_is_writeable(self, off):
        """
        Some DTM configuration registers are only writeable when the DTM is disabled.
        The documentation of dtm_enable says:
          "Enables debug watchpoint and PMU function; prior to writing this bit, all other DT
           configuration registers must be programmed; once this bit is set, other DT
           configuration registers must not be modified"
        """
        if off not in [CMN_DTM_CONTROL_off, CMN_DTM_FIFO_ENTRY_READY_off] and self._dtm_is_enabled:
            assert False, "%s: try to write DTM programming register at 0x%x when DTM is enabled" % (self, off)

    def dtm_enable(self):
        """
        Enable debug watchpoint and PMU function; prior to writing this bit,
        all other DT configuration registers must be programmed; once this bit
        is set, other DT configuration registers must not be modified.
        """
        self.dtm_set64(CMN_DTM_CONTROL_off, 0x1)
        self._dtm_is_enabled = True

    def dtm_disable(self):
        self.dtm_clear64(CMN_DTM_CONTROL_off, 0x1)
        self._dtm_is_enabled = False
        assert not self.dtm_is_enabled()

    def dtm_is_enabled(self):
        """
        Check whether por_dtm_control.dtm_enable is set, indicating that DTM is enabled.
        "Once this bit is set, other DT configuration registers must not be modified."
        """
        e = self.dtm_test64(CMN_DTM_CONTROL_off, CMN_DTM_CONTROL_DTM_ENABLE)
        if self._dtm_is_enabled is not None:
            assert e == self._dtm_is_enabled, "%s: cached DTM emable state out of sync" % self
        else:
            self._dtm_is_enabled = e
        return e

    def dtm_sets_tracetag(self):
        return self.dtm_test64(CMN_DTM_CONTROL_off, CMN_DTM_CONTROL_TRACE_TAG_ENABLE)

    def dtm_save(self):
        """Read the state needed to undo watchpoint and local PMU programming.

        Reads only control, PMU configuration/live counters and the four
        watchpoint configurations/values/masks. No writes or FIFO accesses.
        The caller must own this DTM until restoration is complete.
        """
        return DTMState(self)

    def dtm_restore(self, state, restore_control=True):
        """Restore saved watchpoints/counters/configuration while disabled.

        The caller must first disable the DTM. With restore_control=False,
        leave it disabled so multiple DTMs can be restored before any resume.
        Use dtm_restore_control() afterwards to restore the original enables.
        Configuration words are restored exactly, including fields unknown to
        DTMWatchpoint.decode()/encode(). If a register restore fails, control
        is not restored.
        """
        if not isinstance(state, DTMState):
            raise TypeError("expected a DTMState")
        state._validate(self)
        if self._dtm_is_enabled is None or self._dtm_is_enabled:
            raise ValueError("disable the DTM before restoring its state")
        for slot, wp in enumerate(state.watchpoints):
            self.dtm_write64(CMN_DTM_WP0_VAL_off + 24 * slot, wp.value)
            self.dtm_write64(CMN_DTM_WP0_MASK_off + 24 * slot, wp.mask)
            self.dtm_write64(CMN_DTM_WP0_CONFIG_off + 24 * slot, wp.cfg)
        self.dtm_write64(CMN_DTM_PMU_PMEVCNT_off, state.counters)
        self.dtm_write64(CMN_DTM_PMU_CONFIG_off, state.pmu_config)
        if restore_control:
            self.dtm_restore_control(state)

    def dtm_restore_control(self, state):
        """Resume saved DTM control after all related configurations are restored."""
        if not isinstance(state, DTMState):
            raise TypeError("expected a DTMState")
        state._validate(self)
        self.dtm_set_control(control=state.control, atb=True,
                             enable=bool(state.control & CMN_DTM_CONTROL_DTM_ENABLE))

    def dtm_update_control(self, enable=None, tag=None, sample=None, atb=None, control=None):
        """Change specified controls, preserving all other bits; return the word.

        Unlike dtm_set_control(), False explicitly clears a feature and None
        leaves it unchanged. Supply an already saved control word to avoid a
        read; otherwise read the current control register once. Does not clear
        watchpoints, counters or FIFO entries.
        """
        fields = [(enable, CMN_DTM_CONTROL_DTM_ENABLE),
                  (tag, CMN_DTM_CONTROL_TRACE_TAG_ENABLE),
                  (sample, CMN_DTM_CONTROL_SAMPLE_PROFILE_ENABLE),
                  (None if atb is None else not atb, CMN_DTM_CONTROL_TRACE_NO_ATB)]
        for value in [enable, tag, sample, atb]:
            if value is not None and not isinstance(value, bool):
                raise TypeError("DTM control flags must be bool or None")
        if control is None:
            control = self.dtm_read64(CMN_DTM_CONTROL_off)
        cmn_config.check_integer(control, "DTM control", maximum=(1 << 64) - 1)
        for value, mask in fields:
            if value is not None:
                control = (control | mask) if value else (control & ~mask)
        self.dtm_set_control(control=control, atb=True,
                             enable=bool(control & CMN_DTM_CONTROL_DTM_ENABLE))
        return control

    def dtm_clear_fifo(self):
        """
        Ensure the FIFO is empty, after reading its contents.
        Appears to be possible to do this even when the DTM is enabled.
        But it appears that data will still go into the FIFO if trace_no_atb is set.
        """
        #print("%s: DTM control = 0x%x" % (self, self.dtm_read64(CMN_DTM_CONTROL_off)))
        self.dtm_write64(CMN_DTM_FIFO_ENTRY_READY_off, 0xf, check=False)
        #self.dtm_write64(CMN_DTM_FIFO_ENTRY_READY_off, 0x0, check=True)
        fe = self.dtm_read64(CMN_DTM_FIFO_ENTRY_READY_off)
        if fe != 0:
            ctl = self.dtm_read64(CMN_DTM_CONTROL_off)
            self.C.log("%s: FIFO not empty after clearing: 0x%x (control=0x%x)" % (self, fe, ctl))

    def dtm_fifo_ready(self):
        return self.dtm_read64(CMN_DTM_FIFO_ENTRY_READY_off)

    def dtm_is_wp_ready(self, wp):
        return (self.dtm_fifo_ready() & (1 << wp)) != 0

    def dtm_fifo_entry(self, e):
        """
        Get a FIFO entry, returning it as (byte string, cycle count)
        """
        assert 0 <= e and e <= DTM_N_FIFO_ENTRIES
        #print("FIFO: 0x%016x 0x%016x 0x%016x" % (ws[0], ws[1], ws[2]))
        # The cycle count is at a fixed bit offset in register #2, but the
        # offset varies by part number, reflecting the FIFO data size
        cc_off = 48
        if self.C.product_config.is_before_gen(cmn_config.CMN_GEN_650):
            dwidth = 144
            cc_off = 16       # 31:16 in word 2
        elif self.C.product_config.is_before_gen(cmn_config.CMN_GEN_700):
            dwidth = 160
        elif self.C.product_config.is_before_gen(cmn_config.CMN_GEN_S3r2):
            dwidth = 176
        else:
            dwidth = 196
        ws = []
        for w in range(0, self.N_FIFO_WORDS):
            ws.append(self.dtm_read64(CMN_DTM_FIFO_ENTRY_off(e, w, self.N_FIFO_WORDS)))
        cc = BITS(ws[-1], cc_off, 16)
        if self.N_FIFO_WORDS == 3:
            b = struct.pack("<QQQ", ws[0], ws[1], ws[2])[:(dwidth//8)]
        elif self.N_FIFO_WORDS == 4:
            b = struct.pack("<QQQQ", ws[0], ws[1], ws[2], ws[3])[:(dwidth//8)]
        return (b, cc)

    def dtm_wp_details(self, wp):
        """
        Return a tuple indicating the current configuration of a watchpoint,
        so that it can be decoded.
          (nodeid, dev:0..3, wp#, channel:0..3, format:0..7, cc)
        Counterpart of dtm_set_watchpoint()
        Deprecated: prefer dtm_wp_config instead.
        """
        assert 0 <= wp and wp <= DTM_N_WATCHPOINTS
        cfg = self.dtm_read64(CMN_DTM_WP0_CONFIG_off+(wp*24))
        VC = BITS(cfg, 1, 2)
        dev = BIT(cfg, 0)
        if self.xp.n_device_ports() > 2:
            dev |= (BIT(cfg, 17) << 1)
        type = BITS(cfg, self.C.DTM_WP_PKT_TYPE_SHIFT, 3)
        cc = BIT(cfg, self.C.DTM_WP_PKT_TYPE_SHIFT+3)
        return (self.xp.node_id(), dev, wp, VC, type, cc)

    def dtm_wp_config(self, wp, value=True):
        """
        Return a DTMWatchpoint object with the current configuration of a watchpoint.
        """
        assert 0 <= wp and wp <= DTM_N_WATCHPOINTS
        w = DTMWatchpoint(self, wp=wp, cfg=self.dtm_read64(CMN_DTM_WP0_CONFIG_off+(wp*24)))
        if value:
            w.value = self.dtm_read64(CMN_DTM_WP0_VAL_off+(wp*24))
            w.mask = self.dtm_read64(CMN_DTM_WP0_MASK_off+(wp*24))
        return w

    def dtm_set_watchpoint(self, wp, val=0, mask=0xffffffffffffffff, gen=True, group=None, format=None, chn=None, chn_num=0, dev=None, cc=False, exclusive=False, combine=False):
        """
        Configure a watchpoint on the XP. The DTM should be disabled.
        The mask is the bits we don't care about. I.e. 0 is exact match, 0xffffffffffffffff is don't care.
        Deprecated: prefer dtm_wp_set instead.
        """
        w = DTMWatchpoint(dtm=self, value=val, mask=mask, pkt_gen=gen, combine=combine, type=format, chn=chn, chn_num=chn_num, dev=dev, cc=cc, grp=group, exclusive=exclusive)
        self.dtm_wp_set(wp, w)

    def dtm_wp_set(self, wp, w):
        """
        Given a DTMWatchpoint object, program a watchpoint.
        """
        assert 0 <= wp and wp <= DTM_N_WATCHPOINTS, "invalid watchpoint number #%u" % wp
        assert ((wp & 1) == 0) or (not w.combine), "wp_combine invalid in odd-numbered watchpoint #%u" % wp
        if w.value is not None:
            self.dtm_write64(CMN_DTM_WP0_VAL_off+(wp*24), w.value)
            self.dtm_write64(CMN_DTM_WP0_MASK_off+(wp*24), w.mask)
        self.dtm_write64(CMN_DTM_WP0_CONFIG_off+(wp*24), w.encode())

    def dtm_wp_reset(self, wp, preserve_config=True):
        """
        Reset a watchpoint to match nothing and do nothing.
        By default preserve format and channel info needed to decode existing
        FIFO entries. With preserve_config=False also clear all configuration
        (including trace/trigger/combine settings), without reading it first.
        Neither mode reads or clears FIFO contents. The DTM must be disabled.
        """
        cmn_config.check_integer(wp, "watchpoint number", maximum=DTM_N_WATCHPOINTS - 1)
        if not preserve_config:
            self.dtm_write64(CMN_DTM_WP0_VAL_off + wp * 24, 0xffffffffffffffff)
            self.dtm_write64(CMN_DTM_WP0_MASK_off + wp * 24, 0)
            self.dtm_write64(CMN_DTM_WP0_CONFIG_off + wp * 24, 0)
            return
        cfg = self.dtm_read64(CMN_DTM_WP0_CONFIG_off+(wp*24))
        cfg &= ~self.C.DTM_WP_PKT_GEN
        self.dtm_write64(CMN_DTM_WP0_CONFIG_off+(wp*24), cfg)    # disable packet gen immediately
        if False:
            self.dtm_write64(CMN_DTM_WP0_MASK_off+(wp*24), 0x0000000000000000)
            self.dtm_write64(CMN_DTM_WP0_VAL_off+(wp*24), 0xcccccccccccccccc)
            cfg &= ~self.C.DTM_WP_EXCLUSIVE
        else:
            # Match everything, but then invert it, matching nothing
            self.dtm_write64(CMN_DTM_WP0_MASK_off+(wp*24), 0xffffffffffffffff)
            self.dtm_write64(CMN_DTM_WP0_VAL_off+(wp*24), 0x0000000000000000)
            cfg |= self.C.DTM_WP_EXCLUSIVE
        self.dtm_write64(CMN_DTM_WP0_CONFIG_off+(wp*24), cfg)

    def dtm_reset_wps(self, preserve_config=True):
        """
        Reset all watchpoints; see dtm_wp_reset() for configuration retention.
        """
        for i in range(0, CMN_DTM_N_WP):
            if preserve_config:
                self.dtm_wp_reset(i)
            else:
                self.dtm_wp_reset(i, preserve_config=False)

    def dtm_atb_packet_header(self, wp, lossy=0):
        """
        Construct a trace packet header, as if for a packet output on ATB.
        """
        w = self.dtm_wp_config(wp)
        nid = self.xp.node_id()
        if self.C.product_config.gen == cmn_config.CMN_GEN_600:
            h = (w.chn << 30) | (w.dev << 29) | (w.wp << 27) | (w.type << 24) | (nid << 8) | 0x40 | (w.cc << 4) | lossy
        else:
            h = (w.chn_num << 30) | (w.chn << 28) | (w.wp << 24) | ((nid >> 3) << 11) | (w.dev << 8) | 0x40 | (w.cc << 4) | (w.type << 1) | lossy
        return h

    def pmu_enable(self):
        self.dtm_set64(CMN_DTM_PMU_CONFIG_off, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_disable(self, config=None):
        """Disable local counting, optionally using a saved configuration to avoid a read."""
        if config is None:
            self.dtm_clear64(CMN_DTM_PMU_CONFIG_off, CMN_DTM_PMU_CONFIG_PMU_EN)
        else:
            cmn_config.check_integer(config, "DTM PMU configuration", maximum=(1 << 64) - 1)
            self.dtm_write64(CMN_DTM_PMU_CONFIG_off, config & ~CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_configure_local(self, inputs, width=16):
        """Configure and enable local counting without exporting to DTC counters.

        Supply one input selector per counter: four at width=16, two at 32,
        or one at 64. Selectors 0..3 count WP0..WP3 matches; other selectors
        count XP/device events. Device event selections are programmed separately.
        The DTM must be disabled. Does not reset counter values or enable DTCs.

        Arm CMN S3 TRM 107858_0203_05, por_dtm_pmu_config:
        https://documentation-service.arm.com/static/67ac4cf66dbc975ccea92cd0
        Pair/all-combined fields concatenate local counters. Paired-global bits
        remain clear, so local counter rollovers are not exported to a DTC.
        """
        self._pmu_check_width(width)
        inputs = list(inputs)
        if len(inputs) != 64 // width:
            raise ValueError("need %u input selectors for %u-bit local counters" % (64 // width, width))
        for value in inputs:
            cmn_config.check_integer(value, "DTM PMU input selector", maximum=255)
        config = CMN_DTM_PMU_CONFIG_PMU_EN
        if width == 32:
            config |= CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED | CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED
        elif width == 64:
            config |= CMN_DTM_PMU_CONFIG_PMEVENTALL_COMBINED
        for i, value in enumerate(inputs):
            config |= value << (32 + i * (width // 16) * 8)
        if self._dtm_is_enabled is None or self._dtm_is_enabled:
            raise ValueError("disable the DTM before configuring local counters")
        self.dtm_write64(CMN_DTM_PMU_CONFIG_off, config)

    @staticmethod
    def _pmu_check_width(width):
        cmn_config.check_integer(width, "DTM PMU counter width")
        if width not in [16, 32, 64]:
            raise ValueError("DTM PMU counter width must be 16, 32 or 64")

    def pmu_counters(self, width=16):
        """Read all live local counters in one access, with the programmed width.

        The caller supplies the width so sampling needs no configuration read.
        Ordering is from the lowest to highest local counter.
        """
        self._pmu_check_width(width)
        value = self.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
        mask = (1 << width) - 1
        return [(value >> shift) & mask for shift in range(0, 64, width)]

    def pmu_set_counters(self, values, width=16):
        """Set all live local counters in one write while the DTM is disabled."""
        self._pmu_check_width(width)
        values = list(values)
        if len(values) != 64 // width:
            raise ValueError("need %u values for %u-bit local counters" % (64 // width, width))
        packed = 0
        for i, value in enumerate(values):
            cmn_config.check_integer(value, "DTM PMU counter value", maximum=(1 << width) - 1)
            packed |= value << (i * width)
        if self._dtm_is_enabled is None or self._dtm_is_enabled:
            raise ValueError("disable the DTM before setting local counters")
        self.dtm_write64(CMN_DTM_PMU_PMEVCNT_off, packed)

    def pmu_is_enabled(self):
        return self.dtm_test64(CMN_DTM_PMU_CONFIG_off, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_event_input_selector_str(self, eis):
        """
        Given a DTM event selector (por_dtm_pmu_config), return a descriptive string.
        Many values of the DTM event selector will select one of 4 events from a
        device, or the containing XP, as selected by their pmu_event_sel.
        """
        if eis <= 0x03:
            # DTM is counting matches by one of its own watchpoints.
            s = "DTM WP#%u" % eis
            s += ": %s" % self.dtm_wp_config(eis)
        elif eis <= 0x07:
            # DTM is counting events within its XP, as selected by the XP's pmu_event_sel.
            xpen = eis - 4
            xpe = self.xp.pmu_event_sel(xpen)
            # Now decode the XP event. XP events are encoded orthogonally:
            #   bits 7:5 (or 8:5 in later CMN) indicate the channel
            #   bits 4:2 indicate the port or link (TBD: we assume NUM_XP > 1)
            #   bits 1:0 indicate the nature of the event e.g. flit valid
            chn = ["req", "rsp", "snp", "dat", "pub", "rsp2", "dat2", "req2",
                   "snp2", "?9", "?10", "?11", "axiwse", "axiwde", "paore", "?15"][BITS(xpe, 5, 4)]
            ifc = ["e", "w", "n", "s", "p0", "p1", "p2", "p3"][BITS(xpe, 2, 3)]
            evt = ["none", "txflit_valid", "txflit_stall", "partial_dat_flit"][BITS(xpe, 0, 2)]
            xpes = "mxp_%s_%s_%s" % (ifc, chn, evt)
            s = "XP PMU Event #%u: event=0x%02x: %s" % (xpen, xpe, xpes)
        elif eis >= 0x10:
            # DTM is counting events from one of the XP's connected devices,
            # selected by port number, device number, and event index (i.e. out of 4 exported events).
            # The actual event exported by the device will be selected by the device's pmu_event_sel.
            # (Note that for a given (port, device) pair, there must be at
            # most one device capable of exporting PMU events.)
            # Multi-DTM selectors use DTM-local ports 0/1. Device discovery
            # uses XP-wide ports. CMN-700 TRM 102308, por_dtm_pmu_config_dt1-3.
            port = (eis >> 4) - 1 + 2*self.index
            device = BITS(eis, 2, 2)
            eix = (eis & 3)       # index into device's pmu_event_sel
            s = "P%u device %u PMU Event #%u" % (port, device, eix)
            (device_node, pix, event_number, filter) = self.device_pmu_event_sel(port, device, eix)
            if device_node is not None:
                s += " - %s[%u] event 0x%x" % (device_node, pix, event_number)
                if self.C.pmu_events is not None:
                    ev = self.C.pmu_events.get_event(device_node.type(), event_number, pmu_index=pix, filter=filter)
                    if ev is not None:
                        s += ": %s" % ev.name()
        else:
            s = "?(eis=0x%x)" % eis
        return s

    def dtm_set_control(self, control=0, atb=False, tag=False, enable=False):
        """
        Configure the DTM, which controls all watchpoints and PMU.
        Note that this function isn't read/modify/write.
        """
        if not atb:
            control |= CMN_DTM_CONTROL_TRACE_NO_ATB
        if tag:
            control |= CMN_DTM_CONTROL_TRACE_TAG_ENABLE
        if enable:
            control |= CMN_DTM_CONTROL_DTM_ENABLE
        self.dtm_write64(CMN_DTM_CONTROL_off, control)
        self._dtm_is_enabled = enable

    def device_pmu_event_sel(self, port, device, eix):
        """
        Assuming that we're counting a device event, find the actual device node
        that is exporting the event, and the event number (and filter).
        The DTM pmu_event_sel will indicate port and device.
        But this isn't always enough to identify the actual device involved.
        Sometimes there are multiple nodes with the same (port, device)
        combination, each capable of exporting events.
        In general, we must iterate through the connected devices and
        find one that is exporting an event.

        Note that XP's (although not devices) move to 16-bit event fields
        from CMN-700 onwards. We might see devices start to do that.
        """
        for n in self.xp.port_device_nodes(port, device):
            for soff in n.PMU_EVENT_SEL:
                pmu_sel = n.read64(soff)
                pmu_filter = BITS(pmu_sel, 32, 8)
                en = BITS(pmu_sel, eix*8, 8)
                if en > 0:
                    pix = (soff - n.PMU_EVENT_SEL_BASE) >> 3
                    return (n, pix, en, pmu_filter)
        return (None, None, None, None)


class CMNNodeDev(CMNNodeBase):
    """
    Any device node (not XP or CFG).
    Currently subclassed for DTC.
    """
    def __init__(self, *args, **kwargs):
        CMNNodeBase.__init__(self, *args, **kwargs)

    @property
    def port(self):
        return self.XP().port(self.port_number)

    def PD(self):
        """
        Get the (port, device) for the node.
        """
        return self.device.PD()


class DTCState(object):
    """Saved DTC debug/PMU controls; excludes event counters and trace state."""
    def __init__(self, dtc):
        self.dtc = dtc
        self.control = dtc.read64(CMN_DTC_CTL)
        self.pmu_control = dtc.read64(dtc.PM_BASE + CMN_DTC_PMCR_off)

    def _validate(self, dtc):
        if self.dtc is not dtc:
            raise ValueError("saved state belongs to a different DTC")
        for value in [self.control, self.pmu_control]:
            cmn_config.check_integer(value, "saved DTC register", maximum=(1 << 64) - 1)


class CMNNodeDT(CMNNodeDev):
    """
    DTC (debug/trace controller) node. There is one per DTC domain.
    The one located in the HN-D is designated as DTC0, and has additional functions.
    """
    def __init__(self, *args, **kwargs):
        CMNNodeDev.__init__(self, *args, **kwargs)
        if not self.C.part_ge_S3():
            self.PM_BASE = CMN_DTC_PM_BASE_OLD
        else:
            self.PM_BASE = CMN_DTC_PM_BASE_S3

    def extra_str(self):
        return "DTC%u" % self.dtc_domain()

    def atb_traceid(self):
        return BITS(self.read64(CMN_DTC_TRACEID), 0, 7)

    def set_atb_traceid(self, x):
        if self.C.verbose > 0:
            self.C.log("ATB ID 0x%02x: %s" % (x, self))
        self.write64(CMN_DTC_TRACEID, x)

    def dtc_domain(self):
        """
        The domain number for this DTC, in the same field as the logical_id
        would be for other nodes.
        Expected to be the same as the domain number for the DTC's XP's DTM.
        (For CMN-600, XP DTMs don't have a dtc_domain indicator.)
        """
        return BITS(self.node_info, 32, 2)

    def is_DTC0(self):
        """
        Return true if this DTC is a DTC0. As of S3, a mesh may contain multiple DTC0s.
        The node type is always CMN_NODE_DT.
        """
        return self.port.has_properties(CMN_PROP_HND)

    def dtc_reset(self):
        self.write64(CMN_DTC_CTL, 0)

    def dtc_save(self):
        """Read DTC debug and PMU controls, without changing hardware."""
        return DTCState(self)

    def dtc_restore(self, state):
        """Restore saved debug/PMU controls after related DTMs have been stopped."""
        if not isinstance(state, DTCState):
            raise TypeError("expected a DTCState")
        state._validate(self)
        self.write64(self.PM_BASE + CMN_DTC_PMCR_off, state.pmu_control)
        self.write64(CMN_DTC_CTL, state.control)

    def dtc_enable(self, cc=None, pmu=None, clock_disable_gating=None, state=None, wait=None):
        """
        Enable the DTC. Optionally also enable other DTC features,
        e.g.
          - cycle-counting for trace
          - PMU
          - always-on clock (i.e. disable clock-gating)
        wait=False clears wait-for-trigger so counting starts immediately;
        None preserves it. A state from dtc_save() supplies the control and
        PMU configuration without read/modify/write accesses. Other optional
        features retain their existing access behavior.
        """
        if state is not None:
            if not isinstance(state, DTCState):
                raise TypeError("expected a DTCState")
            state._validate(self)
        if wait is not None and not isinstance(wait, bool):
            raise TypeError("DTC wait flag must be bool or None")
        self.C.log("DTC enable: %s" % self)
        if state is None and wait is None:
            self.set64(CMN_DTC_CTL, CMN_DTC_CTL_DT_EN)
        else:
            control = self.read64(CMN_DTC_CTL) if state is None else state.control
            if wait is not None:
                control = (control | CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER) if wait else (control & ~CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER)
            self.write64(CMN_DTC_CTL, control | CMN_DTC_CTL_DT_EN)
        if cc:
            # Enable cycle counting at the DTMs. This is sticky - regardless of the future contents
            # of this bit, the DTMs continue to count once started.
            self.set64(CMN_DTC_TRACECTRL, CMN_DTC_TRACECTRL_CC_ENABLE)
        if pmu:
            if state is None:
                self.pmu_enable()
            else:
                self.pmu_enable(config=state.pmu_control)
        if clock_disable_gating is not None:
            self.clock_disable_gating(clock_disable_gating)

    def dtc_disable(self):
        self.C.log("DTC disable: %s" % self)
        self.clear64(CMN_DTC_CTL, CMN_DTC_CTL_DT_EN)

    def dtc_is_enabled(self):
        return self.test64(CMN_DTC_CTL, CMN_DTC_CTL_DT_EN)

    def pmu_enable(self, config=None):
        """
        Enable counting, optionally using saved PMU control to avoid a read.
        """
        if config is None:
            self.set64(self.PM_BASE + CMN_DTC_PMCR_off, CMN_DTC_PMCR_PMU_EN)
        else:
            cmn_config.check_integer(config, "DTC PMU control", maximum=(1 << 64) - 1)
            self.write64(self.PM_BASE + CMN_DTC_PMCR_off, config | CMN_DTC_PMCR_PMU_EN)

    def pmu_disable(self):
        self.clear64(self.PM_BASE + CMN_DTC_PMCR_off, CMN_DTC_PMCR_PMU_EN)

    def pmu_is_enabled(self):
        return self.test64(self.PM_BASE + CMN_DTC_PMCR_off, CMN_DTC_PMCR_PMU_EN)

    def pmu_clear(self):
        for i in range(0,8,2):
            self.write64(self.PM_BASE + CMN_DTC_PMEVCNT_off + 8*i, 0)
            self.write64(self.PM_BASE + CMN_DTC_PMEVCNTSR_off + 8*i, 0)

    def pmu_counter(self, n, snapshot=False):
        """
        Get the current value of a DTC PMU counter.
        """
        base = self.PM_BASE + (CMN_DTC_PMEVCNT_off if not snapshot else CMN_DTC_PMEVCNTSR_off)
        v = self.read64(base + (n//2)*16)
        return (v >> 32) if (n & 1) else (v & 0xffffffff)

    def pmu_counters(self, snapshot=False):
        return [self.pmu_counter(i, snapshot=snapshot) for i in range(0, 8)]

    def pmu_cc(self):
        """
        Read the DTC's fixed-function cycle counter. Currently this is 40 bits,
        so at a typical frequency of 2Ghz we might expect a rollover every
        ten minutes.
        """
        return self.read64(self.PM_BASE + CMN_DTC_PMCCNTR_off)

    def pmu_clear_cc(self, value=0):
        """
        Reset the DTC's fixed-function cycle counter to zero
        """
        self.write64(self.PM_BASE + CMN_DTC_PMCCNTR_off, value)

    def pmu_cc_subtract(self, t1, t0):
        """
        Return a delta (t1-t0) between two cycle counts, assuming they were read
        close together. TBD: we assume 40-bit counters.
        """
        if t1 < t0:
            t1 += 0x10000000000
        return t1 - t0

    def pmu_snapshot(self):
        """
        Cause the DTC to send a PMU snapshot instruction to the DTMs.
        Return the status flags, or None if the snapshot did not complete.
        """
        status = None
        if self.C.verbose > 0:
            self.C.log("PMU snapshot from %s" % (self))
        c0 = self.pmu_cc()
        s0 = self.read64(self.PM_BASE + CMN_DTC_PMSSR_off)
        self.write64(self.PM_BASE + CMN_DTC_PMSRR_off, CMN_DTC_PMSRR_SS_REQ, check=False)
        s1 = self.read64(self.PM_BASE + CMN_DTC_PMSSR_off)
        # "The DTC updates por_dt_pmssr.ss_status after receiving PMU snapshot
        #  packets. Software can poll this register field to check if the snapshot
        #  process is complete." We also check that the snapshot is not active.
        for i in range(0, 10):
            ssr = self.read64(self.PM_BASE + CMN_DTC_PMSSR_off)
            if not (ssr & CMN_DTC_PMSSR_SS_CFG_ACTIVE):
                status = BITS(ssr, 0, 9)           # Return the status (0..7: counters, 8: cycle counter)
                break
        assert status is not None, "%s: snapshot did not complete after %u reads" % (self, i)
        c1 = self.pmu_cc()
        if self.C.verbose > 0:
            self.C.log("PMU snapshot complete: 0x%x (cyc=0x%x) => 0x%x (cyc=0x%x) => 0x%x, %u reads" % (s0, c0, s1, c1, ssr, i))
        return status

    def clock_disable_gating(self, disable_gating=True):
        """
        We need to set the "disable clock-gating" bit... this allows
        the clock to run all the time.
        Return the previous setting.
        Only functional in DTC0.
        """
        return self.setclear64(CMN_DTC_CTL, CMN_DTC_CTL_CG_DISABLE, disable_gating)

    def trigger_status(self):
        s = self.read64(CMN_DTC_TRIGGER_STATUS)
        if BIT(s, 0):
            nodeid = BITS(s, 8, 11)
            wp = BITS(s, 20, 4)
            return (nodeid, wp)
        else:
            return None

    def trigger_clear(self):
        self.write64(CMN_DTC_TRIGGER_STATUS_CLR, 1, check=False)

    def trigger_set(self, atbtrigger=None, dbgtrigger=None, trigger_wait=None):
        x0 = self.read64(CMN_DTC_CTL)
        x = x0
        def setclear(x, mask, flag):
            if flag is None:
                pass
            elif flag:
                x |= mask
            else:
                x &= ~mask
            return x
        x = setclear(x, CMN_DTC_CTL_ATBTRIGGER_EN, atbtrigger)
        x = setclear(x, CMN_DTC_CTL_DBGTRIGGER_EN, dbgtrigger)
        if trigger_wait is not None:
            x &= ~(0x3f << 4)
            x |= (trigger_wait << 4)
            x |= CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER
        if x != x0:
            self.write64(CMN_DTC_CTL, x)


class CMN:
    """
    A complete CMN mesh interconnect.
    There is usually one per die.

    The interconnect has a base address of the entire 256MB (0x10000000) region,
    and an address within that for the root node region.

    Component regions are 16MB for CMN-600/650 and 64MB for CMN-700.

    cmn_loc is generally a cmn_devmem_find.CMNLocator object.
    It supplies the peripheral base address, and for CMN-600,
    the address for the root node.
    """
    #DTM_WP_PKT_GEN            = 0x0100   # capture a packet (TBD: 0x400 on CMN-700)
    #DTM_WP_CC_EN              = 0x1000   # enable cycle count (TBD: 0x4000 on CMN-700)

    def __init__(self, cmn_loc, check_writes=False, verbose=0, restore_dtc_status=False, secure_accessible=None, diag_trace=None, defer_discovery=False):
        self._restore_dtc_status = restore_dtc_status     # tested in destructor, so set now
        self.verbose = verbose
        if verbose:
            self.log("CMN discovery (verbose=%d)" % verbose, level=1)
        if diag_trace is None:
            diag_trace = DIAG_WRITES if (verbose >= 3) else DIAG_DEFAULT
        self.diag_trace = diag_trace
        xdiag = os.environ.get("CMN_DEVMEM_DIAG", None)
        if xdiag is not None:
            global g_trace_fd
            if g_trace_fd is None:
                g_trace_fd = open(xdiag, "a")
                atexit.register(lambda: g_trace_fd.close())
        self.secure_accessible = secure_accessible    # if None, will be found from CFG
        self.cmn_seq = cmn_loc.cmn_seq             # instance number within the system (semi-arbitrary numbering)
        self._c2c_links = []
        self.periphbase = cmn_loc.periphbase
        rootnode_offset = cmn_loc.rootnode_offset
        self.node_skiplist = cmn_loc.node_skiplist
        self.rootnode_offset = rootnode_offset
        # For CMN-600, root node offset must be within max size of a CMN-600. For later versions it must be 0.
        assert rootnode_offset >= 0 and rootnode_offset < 0x4000000
        self.himem = self.periphbase       # will be updated as we discover nodes
        if verbose >= 1:
            self.log("PERIPHBASE=0x%x, CONFIG=0x%x" % (self.periphbase, self.periphbase+rootnode_offset), level=1)
        if self.node_skiplist is not None:
            self.log("Node skiplist provided (%u entries)" % len(self.node_skiplist), level=1)
        # CMNProductConfig object will be created when we read CMN_CFG_PERIPH_01
        # from the root node
        self.product_config = None
        self.frequency = None
        self._home_node_type = None     # populated from existing discovery metadata
        self.D = devmem.DevMem(write=False, check=check_writes, space=cmn_loc.mem_space)
        self.D.cmn_mesh_name = cmn_loc.name
        self.is_local = self.D.is_local    # False when accessing via remote debugger etc.
        self.offset_node = {}     # nodes indexed by register space offset
        # How do we find the dimensions?
        # We could look at the maximum X,Y across all XPs. But to decode X,Y
        # from node_info we need the dimensions.
        # So, we defer getting XP coordinates, until we count the XPs, then heuristically
        # say that more than 16 XPs means 3 bits and more than 256 XPs means 4 bits.
        self.coord_bits = None
        self.dimX = None
        self.dimY = None
        self.coord_XP = {}        # XPs indexed by (X,Y)
        self.logical_id_XP = {}   # XPs indexed by logical ID
        self.logical_id = {}      # Nodes indexed by (type, logical_id)
        self.debug_nodes = []     # DTC(s), in domain order. A large mesh might have more than one.
        self.extra_ports = NotTestable("shouldn't calculate device ids before all XPs seen")
        # Discovery phase.
        self.creating = True

        # we can't map nodes until we know the node size, but we don't
        # know that until we've mapped the root config node...
        # create a temporary 16K mapping to get out of that.
        temp_m = self.D.map(self.periphbase+rootnode_offset, 0x4000)

        id01 = temp_m.read64(CMN_CFG_PERIPH_01)
        product_id = (BITS(id01, 32, 4) << 8) | BITS(id01, 0, 8)

        id23 = temp_m.read64(CMN_CFG_PERIPH_23)
        revision_code = BITS(id23, 4, 4)

        if product_id == cmn_base.PART_CMN600 and revision_code == 1:
            # Work around a bug in a specific CMN implementation:
            # product_id mis-identifies as CMN-600: we need to find something
            # that is safe to read but indicates it's definitely not CMN-600.
            # Check the later CHI version fields: in CMN-600 these are RES0.
            unit_info = temp_m.read64(CMN_any_UNIT_INFO)
            s3_chi_r0_r1 = BITS(unit_info, 60, 3)
            s3_chi_r2 = BITS(unit_info, 56, 3)
            if s3_chi_r0_r1 >= 2 or s3_chi_r2 >= 2:
                product_id = cmn_base.PART_CMN_ALTA

        if cmn_loc.product_id is not None:
            assert cmn_loc.product_id == product_id, "expecting %s, found %s" % (cmn_config.product_id_str(cmn_loc.product_id), cmn_base.product_id_str(product_id))
        # For now, if we see CMN-600AE, pretend it's CMN-600, to not break tests in code.
        if product_id == cmn_base.PART_CMN600AE:
            product_id = cmn_base.PART_CMN600
        # We can't get chi_version() until we've read unit_info (por_info_global) and revision (periph_2/3)
        self.product_config = cmn_config.CMNConfig(product_id=product_id, revision_code=revision_code)
        del temp_m

        self.rootnode = self.create_node(rootnode_offset)

        # Now it's safe to discover things whose identifiers are revision-dependent

        # Load the PMU event database, if available
        pmu_event_fn = cmn_events.event_file_name(product_id)
        if os.path.isfile(pmu_event_fn):
            if verbose > 0:
                self.log("loading PMU events from %s" % pmu_event_fn)
            self.pmu_events = cmn_events.load_events(pmu_event_fn)
            if verbose > 0:
                self.log("loaded %s" % self.pmu_events)
        else:
            self.pmu_events = None

        self.unit_info = self.rootnode.read64(CMN_any_UNIT_INFO)   # por_info_global
        self.unit_info1 = None

        self.multiple_dtms = BIT(self.unit_info, (59 if self.part_ge_S3r2() else 63))
        if verbose > 0 and self.multiple_dtms:
            self.log("multiple DTMs enabled")

        # If any CPUs are offline, don't discover external children of XPs which have RN-F ports
        self.skip_external_if_RNF = self.is_local and any_cpus_offline()

        # For S3, we need to check if this CMN has enabled device isolation,
        # which may cause problems when discovering child nodes.
        self.isolation_enabled = BIT(self.unit_info, 44)    # S3 onwards
        self.isolation_warned = False
        if verbose and self.isolation_enabled:
            self.log("node isolation is enabled - discovery might be affected")

        # Some registers are only accessible at a higher privilege level.
        # Pre CCA this was Secure. With CCA it's Root, unless LEGACY_TZ_EN.
        # TBD currently we don't discover LEGACY_TZ_EN.
        self.root_security = "ROOT" if self.part_ge_S3() else "S"

        self.vc_num = [1, 1, 1, 1]        # instances per CHI channel
        if self.part_ge_700():
            self.unit_info1 = self.rootnode.read64(CMN_any_UNIT_INFO1)
        if self.part_ge_650():
            # Fields are 2-bit through CMN S3 r0, change to 3-bit in CMN S3 r2
            if not self.part_ge_700():
                self.vc_num[1] = max(1, BITS(self.unit_info,  52, 2))
                self.vc_num[3] = max(1, BITS(self.unit_info,  50, 2))
            elif not self.part_ge_S3r2():
                self.vc_num[0] = max(1, BITS(self.unit_info1, 0, 2))
                self.vc_num[1] = max(1, BITS(self.unit_info,  52, 2))
                self.vc_num[2] = max(1, BITS(self.unit_info1, 2, 2))
                self.vc_num[3] = max(1, BITS(self.unit_info,  50, 2))
            else:
                self.vc_num[0] = max(1, BITS(self.unit_info1, 0, 3))
                self.vc_num[1] = max(1, BITS(self.unit_info1, 9, 3))
                self.vc_num[2] = max(1, BITS(self.unit_info1, 3, 3))
                self.vc_num[3] = max(1, BITS(self.unit_info1, 6, 3))

        # CMN-600/650/700 and CMN S3 TRMs:
        # por_info_global has chi_req_rsvdc_width[7:0],
        # chi_req_addr_width[15:8], and physical_address_width[23:16].
        self.product_config.rsvdc_width = BITS(self.unit_info, 0, 8)
        self.product_config.req_pa_width = BITS(self.unit_info, 8, 8)
        self.product_config.pa_width = BITS(self.unit_info, 16, 8)
        self.product_config.mpam_enabled = self.part_ge_650() and (BIT(self.unit_info, 49) != 0)
        if self.product_config.mpam_enabled:
            self.product_config.mpam_partid_width = 9

        self.mecid_width = 0

        self.product_config.chi_version = self.chi_version()
        assert self.product_config.chi_version >= 2, "failed to detect CHI version: info=0x%x" % self.unit_info
        if not self.part_ge_S3():
            self.DTM_BASE = CMN_DTM_BASE_OLD   # 0x2000
        elif self.product_config.product_id == cmn_base.PART_CMN_S3 and self.product_config.revision_major == 0:
            self.DTM_BASE = CMN_DTM_BASE_S3r0  # 0xD900
        else:
            self.DTM_BASE = CMN_DTM_BASE_S3r1  # 0xA000
        if verbose:
            self.log("CMN configuration: %s" % self.product_config, level=1)

        if self.unit_info1 is not None:
            if self.product_config.is_before_gen(cmn_config.CMN_GEN_S3r2):
                self.product_config.mte_enabled = bool(BIT(self.unit_info1, 19))
            else:
                self.product_config.mte_enabled = bool(BIT(self.unit_info1, 25))
        if self.product_config.is_at_least_gen(cmn_config.CMN_GEN_S3r1):
            if self.product_config.is_before_gen(cmn_config.CMN_GEN_S3r2):
                iohub_enable = BIT(self.unit_info1, 28)
                chi_mecid_width = BITS(self.unit_info1, 26, 2)
                mpam12 = BIT(self.unit_info1, 25)
            else:
                iohub_enable = BIT(self.unit_info1, 34)
                chi_mecid_width = BITS(self.unit_info1, 32, 2)
                mpam12 = BIT(self.unit_info1, 31)
            if self.product_config.mpam_enabled:
                self.product_config.mpam_partid_width = 12 if mpam12 else 9
            self.mecid_width = [0, 12, 16, 0][chi_mecid_width]

        #
        # Now traverse the CMN space to discover all the nodes. We can optionally
        # defer device discovery.
        #
        self.defer_device_discovery = defer_discovery or int(os.environ.get("CMN_DEFER", 0))
        if self.node_skiplist and not self.defer_device_discovery:
            self.log("Forcing lazy device discovery, to allow skiplist validation", level=0)
            self.defer_device_discovery = True
        if verbose:
            self.log("device discovery is %s" % ("lazy" if self.defer_device_discovery else "eager"), level=1)
        self.n_XPs_discovered_devices = 0
        self.rootnode.discover_children()
        self.creating = False
        #
        # We've discovered the XPs but we generally don't yet know their X,Y coordinates,
        # since we don't know coord_bits.
        self.n_XPs = len(self.logical_id_XP)
        # For some XPs, the coordinates are independent of coord_bits. These include (0,0) and (0,1).
        # Using the conventional logical_id assignment, (0,1) will have logical_id == dimX.
        any_extra_ports_seen = False
        for xp in self.XPs():
            if xp.logical_id() >= self.n_XPs:
                raise CMNDiscoveryError(self, "XP logical id #%u but only %u XPs" % (xp.logical_id(), self.n_XPs))
            if xp.n_device_ports() > 2:
                any_extra_ports_seen = True
        self.extra_ports = any_extra_ports_seen
        for xp in self.XPs():
            if BITS(xp.node_info,19,8) == 0x01:   # XP at (0,1), regardless of coord_bits
                self.dimX = xp.logical_id()
                break
        if self.dimX is None:
            self.dimX = self.n_XPs
        assert (self.n_XPs % self.dimX) == 0, "%u XPs but X dimension is %u" % (self.n_XPs, self.dimX)
        self.dimY = self.n_XPs // self.dimX
        assert self.n_XPs == (self.dimX * self.dimY), "unexpected: %u x %u mesh but %u XPs" % (self.dimX, self.dimY, self.n_XPs)
        self.coord_bits = cmn_base.id_coord_bits(self.dimX, self.dimY)
        for xp in self.XPs():
            (X,Y) = xp.XY()
            self.coord_XP[(X,Y)] = xp
        # Some offsets change from CMN-650 onwards
        if self.product_config.is_before_gen(cmn_config.CMN_GEN_650):
            self.DTM_WP_RSVDC_BSEL_SHIFT = None
            self.DTM_WP_EXCLUSIVE    = 0x0020
            self.DTM_WP_COMBINE      = 0x0040
            self.DTM_WP_PKT_GEN      = 0x0100   # capture a packet
            self.DTM_WP_PKT_TYPE_SHIFT = 9
            self.DTM_WP_CC_EN        = 0x1000   # enable cycle count
            self.DTM_WP_CTRIG        = 0x2000
            self.DTM_WP_DBGTRIG      = 0x4000
            self.DTM_WP_CHN_NUM_SHIFT = None
        else:
            self.DTM_WP_RSVDC_BSEL_SHIFT = 6
            self.DTM_WP_EXCLUSIVE    = 0x0100
            self.DTM_WP_COMBINE      = 0x0200
            self.DTM_WP_PKT_GEN      = 0x0400   # capture a packet
            self.DTM_WP_PKT_TYPE_SHIFT = 11
            self.DTM_WP_CC_EN        = 0x4000   # enable cycle count
            self.DTM_WP_CTRIG        = 0x8000
            self.DTM_WP_DBGTRIG      = 0x10000
            self.DTM_WP_CHN_NUM_SHIFT = 19
        if restore_dtc_status:
            self.restore_dtc_status_on_deletion()
        if self.secure_accessible is None:
            sa = self.rootnode.read64(CMN_any_SECURE_ACCESS)   # por_cfgm_secure_access
            self.secure_accessible = (BIT(sa, 0) == 1)
        if self.verbose >= 2:
            sa = self.rootnode.read64(CMN_any_SECURE_ACCESS)
            self.log("Access to Secure registers: 0x%x (%s) (at 0x%x)" % (sa, self.secure_accessible, self.rootnode.node_base_addr+CMN_any_SECURE_ACCESS))

        if self.node_skiplist is not None:
            self.validate_skiplist()
        if self.verbose:
            self.log("Mesh discovery complete%s" % (" (device discovery is lazy)" if self.defer_device_discovery else ""), level=1)

    def c2c_links(self):
        """Iterate recorded links incident on this mesh without discovery."""
        return iter(self._c2c_links)

    def is_live(self):
        """
        This model provides register access and status queries.
        No discovery or register access is needed to determine this.
        """
        return True

    def has_cpu_mappings(self):
        return False

    def validate_skiplist(self):
        """
        If a device node skiplist has been provided, check now that each skiplist entry
        occurs under some XP. This should be done before device discovery.
        """
        self.log("validating skiplist...")
        skiplist_to_find = {x: None for x in self.node_skiplist}
        for xp in self.XPs():
            for child in xp.child_pointers():
                offs = BITS(child, 0, 30)
                addr = self.periphbase + offs
                if addr in skiplist_to_find:
                    key = addr
                elif offs in skiplist_to_find:
                    key = offs
                else:
                    continue
                assert skiplist_to_find[key] is None, "Skip node 0x%x found at %s and %s" % (key, skiplist_to_find[key], xp)
                skiplist_to_find[key] = xp
        if self.verbose >= 1:
            print("Skiplist nodes found:")
        skiplist_entries_not_found = []
        for se in self.node_skiplist:
            xp = skiplist_to_find[se]
            if xp is None:
                skiplist_entries_not_found.append(se)
            elif self.verbose >= 1:
                print("  0x%09x  %s" % (se, xp))
        if skiplist_entries_not_found:
            print("", file=sys.stderr)
            print("%s: some skiplist entries were not found:" % self, file=sys.stderr)
            for se in self.node_skiplist:
                if skiplist_to_find[se] is None:
                    print("  0x%x" % (se), file=sys.stderr)
            print("Correct skiplist and re-run discovery.", file=sys.stderr)
            sys.exit(1)
        self.log("skiplist validated", level=1)

    def contains_addr(self, addr):
        assert not self.creating
        return self.periphbase <= addr and addr < self.himem

    def part_ge_650(self):
        # everything except CMN-600
        return self.product_config.is_at_least_gen(cmn_config.CMN_GEN_650)

    def part_ge_700(self):
        # everything except CMN-600 and CMN-650
        return self.product_config.is_at_least_gen(cmn_config.CMN_GEN_700)

    def part_ge_S3(self):
        # everything from S3 onwards
        return self.product_config.is_at_least_gen(cmn_config.CMN_GEN_S3)

    def part_ge_S3r1(self):
        return self.product_config.is_at_least_gen(cmn_config.CMN_GEN_S3r1)

    def part_ge_S3r2(self):
        return self.product_config.is_at_least_gen(cmn_config.CMN_GEN_S3r2)

    def __str__(self):
        """
        Return a descriptive string for the CMN mesh as a whole
        """
        s = "%s at 0x%x" % (self.product_str(), self.periphbase)
        if self.rootnode_offset != 0:
            s += ":0x%x" % self.rootnode_offset
        if self.dimX is not None:
            s += " (%ux%u)" % (self.dimX, self.dimY)
        return s

    def __del__(self):
        if self._restore_dtc_status:
            for d in self.debug_nodes:
                if d in self.enabled_debug_nodes:
                    d.dtc_enable()
                else:
                    d.dtc_disable()

    def restore_dtc_status_on_deletion(self):
        self._restore_dtc_status = True
        self.enabled_debug_nodes = [d for d in self.debug_nodes if d.dtc_is_enabled()]

    def source_line(self, depth=2):
        """
        For diagnosing CMN programming problems, annotate log messages with script source line
        """
        st = traceback.extract_stack(limit=10)     # get a StackSummary
        fr = st[-1-depth]
        if sys.version_info[0] >= 3:
            fr = (fr.filename, fr.lineno, None, fr.line)
        return "%s.%u: %s" % (os.path.basename(fr[0]), fr[1], fr[3])

    def log(self, msg, prefix="CMN <TIME>: ", end=None, level=2):
        """
        Print a logging message. We do a level check here, but it might also be a
        good idea to check at the call site to avoid constructing the message.

        Use level=1 for warning messages that should be output in discovery
        (where someone is likely to be interested in the message) but not in
        other tools (where someone just wants to get a job done).

        Use level=0 for warning messages that should always be output.
        """
        if self.verbose >= level:
            if prefix is None:
                prefix = ""
            if "<TIME>" in prefix:
                prefix = prefix.replace("<TIME>", str(datetime.datetime.now()))
            print("%s%s" % (prefix, msg), end=end)

    def product_str(self):
        """
        Describe the product. This must be robust and usable early in discovery or after a failed discovery,
        since it may be used in error messages and exception strings.
        """
        s = self.product_config.product_name(revision=True)
        try:
            s += " " + self.chi_version_str()
            if self.product_config.mpam_enabled:
                s += " with MPAM"
        except Exception:
            pass
        return s

    def chi_version(self):
        """
        Discover the CHI version, where 1 is A, 2 is B etc.
        """
        if not self.part_ge_650():
            # In CMN-600 there's a single CHI-C flag
            return 2 + BIT(self.unit_info, 49)
        elif not self.part_ge_S3r2():
            return BITS(self.unit_info, 60, 3)
        else:
            return BITS(self.unit_info, 56, 3)

    def chi_version_str(self):
        return "CHI-%s" % "?ABCDEFGH"[self.chi_version()]

    def node_size(self):
        return 0x10000 if self.part_ge_700() else 0x4000

    def create_node(self, node_offset, parent=None, is_external=False):
        """
        Create a node, either the root node (parent=None) or an XP, or a device node.
        """
        assert self.creating or self.defer_device_discovery
        node_base_addr = self.periphbase + node_offset
        if self.node_skiplist is not None:
            # Previous checks in discover_children should ensure we never reach here,
            # but double-check, as accessing a skipped node will likely crash the system.
            assert node_base_addr not in self.node_skiplist and node_offset not in self.node_skiplist, "%s: trying to map skipped node 0x%x" % (self, node_base_addr)
        m = self.D.map(node_base_addr, self.node_size())
        node_info = m.read64(CMN_any_NODE_INFO)
        node_type = BITS(node_info, 0, 16)
        self._record_home_node_type(node_type)
        if parent is None:
            # Expecting the configuration node. If we see something else,
            # the root node offset was probably wrong.
            # This is fatal, since without the configuration node we can't proceed further.
            if node_type != CMN_NODE_CFG:
                s = str(self)
                raise CMNDiscoveryError(self, "expected root node: 0x%x (%s)" % (node_base_addr, cmn_node_type_str(node_type)))
        elif node_type == CMN_NODE_CFG:
            # Unexpectedly returned to the configuration node while traversing child list.
            # Perhaps this is a zero offset in the child list?
            # For CMN-600 at least, a non-CFG node might be valid at offset 0 from PERIPHBASE.
            self.log("Encountered configuration node as child of %s" % (parent), level=1)
            return None
        assert (node_type == CMN_NODE_CFG) == (parent is None)
        # For some node types, we create a subclass object.
        if node_type == CMN_NODE_DT:
            # Debug/Trace Controller - one or more of these, generally in a corner of the mesh
            n = CMNNodeDT(self, node_offset, map=None, parent=parent, write=False, node_info=node_info)
            assert n not in self.debug_nodes
            # Legacy API: callers expect debug_nodes to be a list.
            # But we now want it sorted by DTC domain.
            dom = n.dtc_domain()
            if (dom == 0) != (n.port.has_properties(CMN_PROP_HND)):
                raise CMNDiscoveryError(self, "DTC disagrees about status (dom=%u, port=%u):" % (dom, n.port.connected_type))
            while dom > len(self.debug_nodes):
                self.debug_nodes.append(None)     # placeholder
            self.debug_nodes = self.debug_nodes[:dom] + [n] + self.debug_nodes[dom+1:]
        elif node_type == CMN_NODE_XP:
            # Crosspoint - parent of other nodes
            if BITS(node_info, 16, 3) != 0:
                raise CMNDiscoveryError(self, "expected 3 LSB of XP coordinates to be 0")
            n = CMNNodeXP(self, node_offset, map=None, parent=parent, write=True, node_info=node_info)
            nid = n.logical_id()
            if nid in self.logical_id_XP:
                self.log("XPs have duplicate logical ID 0x%x: %s, %s" % (nid, self.logical_id_XP[nid], n), level=1)
            self.logical_id_XP[nid] = n
            if not self.defer_device_discovery:
                n.discover_children()
        elif node_info == 0:
            # Under XPs with RN-F ports, we sometimes see a valid child offset that points to zeroes
            n = None
        else:
            n = CMNNodeDev(self, node_offset, map=m, parent=parent, is_external=is_external, node_info=node_info)
        if n is not None and node_has_logical_id(node_type):
            nid = n.logical_id()
            nk = (node_type, nid)
            if nk in self.logical_id:
                self.log("Nodes of type 0x%x have duplicate logical ID 0x%x: %s, %s" % (node_type, nid, self.logical_id[nk], n), level=1)
            self.logical_id[nk] = n
        return n

    def discovered_all_devices(self):
        """
        Check if we've done device-discovery on all XPs in the mesh.
        """
        return self.n_XPs_discovered_devices == self.n_XPs

    def discover_all_devices(self, props=None):
        """
        We may have deferred device-discovery, but then need to iterate over
        devices of a certain type. So we can force device-discovery here.
        """
        if not self.discovered_all_devices():
            for xp in self.XPs():
                if not xp.discovered_children and (props is None or xp.has_any_ports(props)):
                    xp.discover_children()

    def XP_at(self, X, Y):
        """
        Return the XP at given coordinates
        """
        return self.coord_XP[(X,Y)]

    def xy_id(self, x, y):
        return (x << (3 + self.coord_bits)) | (y << 3)

    def id_xy(self, id):
        return (BITS(id, 3+self.coord_bits, self.coord_bits),
                BITS(id, 3, self.coord_bits))

    def XP(self, id):
        """
        Return the XP with the given node id. Node id must be an exact XP id (bits 2:0 zero).
        """
        if (id & 7) != 0:
            return None
        for xp in self.XPs():
            if xp.node_id() == id:
                return xp
        return None

    def XP_port_device(self, id):
        """
        Return (XP, port number, device number) for a given device id.
        """
        xp = self.XP(id & ~7)
        if xp is None:
            return (None, None, None)
        (port, dev) = xp.id_port_device(id)
        return (xp, port, dev)

    def port_at_id(self, id):
        dev = self.device_at_id(id)
        return dev.port if dev is not None else None

    def device_at_id(self, id, create=False):
        """
        Get the CMNDevice object represented by a given id.
        """
        return cmn_base.cmn_device_at_id(self, id, create=create)

    def ports(self, properties=CMN_PROP_none):
        for xp in self.XPs():
            for port in xp.ports(properties=properties):
                yield port

    def xp_ports(self):
        for port in self.ports():
            yield (port.XP(), port.port_number)

    def topology_nodes(self, include_root=False, include_xps=True, include_devices=True):
        """
        Iterate over discovered topology objects in a stable traversal order.
        """
        if include_root:
            yield self.rootnode
        for xp in self.XPs():
            if include_xps:
                yield xp
            if include_devices:
                for port in xp.ports():
                    for node in port.nodes():
                        yield node

    def register_nodes(self, properties=CMN_PROP_none):
        """
        Yield all discovered register-backed nodes, including the root and XPs.
        This preserves the historical cmn_devmem nodes() traversal.
        """
        self.discover_all_devices()
        for node in sorted(self.offset_node.values()):
            if properties in [None, CMN_PROP_none] or node.has_properties(properties):
                yield node

    def nodes(self, properties=CMN_PROP_none, props=None):
        """
        Yield explicit device nodes, matching the shared topology model.
        """
        if props is not None:
            properties = props
        self.discover_all_devices()
        for xp in self.XPs():
            for port in xp.ports():
                for node in port.nodes():
                    if properties in [None, CMN_PROP_none] or node.has_properties(properties):
                        yield node

    def devices(self, properties=CMN_PROP_none, props=None):
        """
        Yield device slots (CMNDevice objects) matching properties.
        Unlike nodes(), this includes external attachments such as RN-F and SN-F.
        """
        if props is not None:    # legacy
            properties = props
        self.discover_all_devices(properties)
        for port in self.ports(properties=properties):
            for dev in port.devices(properties=properties):
                yield dev

    def ids(self, properties=CMN_PROP_none):
        for port in self.ports(properties=properties):
            for id in port.ids():
                yield id

    def rnf_ids(self):
        for id in self.ids(properties=CMN_PROP_RNF):
            yield id

    def sn_ids(self):
        for id in self.ids(properties=CMN_PROP_SN):
            yield id

    def node_by_id_type(self, id, type):
        dev = self.device_at_id(id, create=True)
        if dev is None:
            return None
        for node in dev.device_nodes:
            if node.type() == type:
                return node
        return None

    def nodes_of_type(self, type):
        # DEPRECATED
        for n in self.register_nodes():
            if n.type() == type:
                yield n

    def node_by_type_and_logical_id(self, node_type, nid):
        if node_type == CMN_NODE_XP:
            return self.logical_id_XP[nid]
        else:
            self.discover_all_devices()
            nk = (node_type, nid)
            return self.logical_id[nk]

    def home_node_type(self):
        """Return the recorded home-node type code, or None; no discovery."""
        return self._home_node_type

    def _record_home_node_type(self, node_type):
        """Record existing topology metadata, rejecting mixed home types in one mesh."""
        if not cmn_node_type_has_properties(node_type, CMN_PROP_HNF):
            return
        if self._home_node_type is not None and self._home_node_type != node_type:
            raise cmn_base.CMNBadStructure("CMN#%s: conflicting home-node types: %s and %s" %
                                  (self.cmn_seq, cmn_node_type_str(self._home_node_type),
                                   cmn_node_type_str(node_type)))
        self._home_node_type = node_type

    def home_nodes(self):
        for n in self.nodes():
            if n.has_properties(CMN_PROP_HNF):
                yield n

    def XPs(self):
        """
        Iterate over all XPs, ordered by coordinates.
        It's assumed that all XPs have been discovered, but not necessarily all devices.
        """
        for xp in sorted(self.logical_id_XP.values(), key=lambda xp: xp.node_id()):
            yield xp

    def DTMs(self):
        for xp in self.XPs():
            for dtm in xp.DTMs():
                yield dtm

    def DTCs(self):
        """
        Yield DTCs in DTC domain order, starting with the special DTC0.
        This relies on device discovery having been done.
        """
        self.discover_all_devices(CMN_PROP_HNT)
        for d in self.debug_nodes:
            yield d

    def DTC0s(self):
        """
        Yield "main" DTCs that control debug/trace for a group of DTC domains.
        """
        self.discover_all_devices(CMN_PROP_HND)
        for dtc in self.debug_nodes:
            if dtc.is_DTC0():
                yield dtc

    def DTC0(self):
        """
        Return the "main" DTC, the one that enables debug/trace across the whole mesh.
        Every mesh has one. The only way this will return None is if the device node was isolated.
        As of CMN S3, a mesh may have more than one.
        """
        self.discover_all_devices(CMN_PROP_HND)
        return self.debug_nodes[0] if self.debug_nodes else None

    def dtc_enable(self, cc=None, pmu=None, clock_disable_gating=None):
        for d in self.DTC0s():
            d.dtc_enable(cc=cc, pmu=pmu, clock_disable_gating=clock_disable_gating)

    def dtc_disable(self):
        for d in self.DTC0s():
            d.dtc_disable()

    def pmu_enable(self):
        for d in self.DTC0s():
            d.pmu_enable()

    def clock_disable_gating(self, disable_gating=True):
        for d in self.DTC0s():
            d.clock_disable_gating(disable_gating)

    def estimate_frequency(self, td=0.02):
        """
        Estimate the CMN's current clock frequency, using the DTC cycle counter.
        We read three times in an effort to factor out the overhead.
        """
        dtc = self.DTC0()
        dtc.dtc_enable()
        dtc.pmu_enable()
        old = dtc.clock_disable_gating(disable_gating=True)
        t0 = dtc.pmu_cc()
        time.sleep(td)
        t1 = dtc.pmu_cc()
        time.sleep(td*2)
        t2 = dtc.pmu_cc()
        dtc.clock_disable_gating(disable_gating=old)
        return (dtc.pmu_cc_subtract(t2, t1) - dtc.pmu_cc_subtract(t1, t0)) / td


def hn_cache_geometry(n):
    """
    Retrieve the cache details for a home node, and create a
    CacheGeometry object.
    """
    assert n.has_properties(CMN_PROP_HNF)
    info = n.read64(CMN_any_UNIT_INFO)
    cg = cmn_base.CacheGeometry()
    cg.n_ways = BITS(info, 8, 5)     # For CMN SLC, 16 or 12
    slc_size_key = BITS(info, 0, 4)
    sf_size_key = BITS(info, 4, 3)
    if not n.C.part_ge_700():
        cg.sf_n_ways = 16
    else:
        cg.sf_n_ways = BITS(info, 54, 6)
    cg.sf_n_sets_log2 = sf_size_key + 9
    if slc_size_key:
        if not n.C.part_ge_700():
            # Sets: None, 128, 256, 512, 1K, 2K, 4K (12-way), 4K
            slc_sets_log2 = [None, 7, 8, 9, 10, 11, 12, 12]
        else:
            slc_sets_log2 = [None, 7, 8, 9, 10, 11, 11, 12, 12, 9]
        cg.n_sets_log2 = slc_sets_log2[slc_size_key]
    else:
        cg.n_sets_log2 = None
    return cg


def cmn_instance(opts=None):
    return cmn_devmem_find.cmn_single_locator(opts)


def cmn_from_opts(opts):
    """
    Given some command-line options, return a list of CMNs.
    """
    if opts.verbose:
        print("Discovering CMN devices...")
    clocs = list(cmn_devmem_find.cmn_locators(opts))
    if not clocs:
        print("No CMN interconnects found: CMN not present, or system is virtualized", file=sys.stderr)
        sys.exit(1)
    if opts.list_cmn:
        print("CMN devices in memory map:")
        for c in clocs:
            print("  %s" % (c))
        sys.exit()
    diag_trace = (DIAG_READS | DIAG_WRITES) if opts.cmn_diag else 0
    CS = [CMN(cl, verbose=opts.verbose, diag_trace=diag_trace, secure_accessible=opts.secure_access, defer_discovery=opts.cmn_defer) for cl in clocs]
    return CS


def main(argv):
    import argparse
    try:
        parser = argparse.ArgumentParser(description="CMN device-memory diagnostics", allow_abbrev=False)
    except TypeError:
        parser = argparse.ArgumentParser(description="CMN device-memory diagnostics")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--dt-enable", action="store_true", help="enable debug/trace")
    parser.add_argument("--diagram", action="store_true", help="show discovered CMN mesh")
    parser.add_argument("--sketch", action="store_true", help="show small CMN mesh diagram")
    parser.add_argument("--no-color", action="store_true", help="don't use color output")
    parser.add_argument("--force-color", action="store_true", help="force color output even if not to tty")
    parser.add_argument("--dump", action="store_true", help="dump CMN registers")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    CS = cmn_from_opts(opts)

    if opts.dump:
        print("CMNDUMP 0.1")
        for C in CS:
            print("# %s" % C)
            for node in C.register_nodes():
                print("NODE 0x%x %s" % (node.node_base_addr, node))
                for i in range(0, C.node_size(), 8):
                    v = node.read64(i)
                    if v != 0:
                        print("R 0x%x 0x%016x" % ((node.node_base_addr + i), v))

    #
    # Above was getting a list of CMNs to operate on.
    # Below is actually doing the operations.
    #
    for C in CS:
        print(C)
        if opts.diagram or opts.sketch:
            import cmn_diagram
            C.discover_all_devices()
            D = cmn_diagram.CMNDiagram(C, small=opts.sketch)
            print(D.str_color(no_color=opts.no_color, force_color=opts.force_color,
                              for_file=sys.stdout), end="")
        if opts.dt_enable:
            # Force enable DTC(s), in case they were disabled
            for dtc in C.DTCs():
                dtc.dtc_enable()
            for dtm in C.DTMs():
                dtm.dtm_enable()


if __name__ == "__main__":
    main(sys.argv[1:])
