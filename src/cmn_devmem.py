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

import devmem
import cmn_devmem_find
from cmn_devmem_regs import *
import cmn_base
from cmn_enum import *
import cmn_events

from cmn_diagram import CMNDiagram


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


def node_has_logical_id(nt):
    """
    Check if this node type has a "logical id" field.
    Logical ids are numbered sequentially from 0 for a given node type.
    For DTCs, the logical id is the DTC domain number.
    """
    return nt != CMN_NODE_RNSAM


class NotTestable:
    def __init__(self, msg):
        self.msg = msg

    def __bool__(self):
        assert False, self.msg


def node_type_has_pmu_events(nt):
    return nt not in [CMN_NODE_DT, CMN_NODE_RNSAM] and not cmn_node_type_has_properties(nt, CMN_PROP_MPAM)


def pmu_event_sel_offset(nt):
    if nt == CMN_NODE_CCLA:
        return [0x2008]
    elif nt == CMN_NODE_CCLA_RNI or nt == CMN_NODE_HNP:
        return [0x2000, 0x2008]
    elif not node_type_has_pmu_events(nt):
        return []
    else:
        return [0x2000]


class CMNNode:
    """
    A single CMN node, at some offset in the overall peripheral space.
    Spans a 16K range of configuration registers.

    Subclassed for XP and DT.
    """
    def __init__(self, cmn, node_offset, map=None, write=False, parent=None, is_external=False):
        self.C = cmn
        self.diag_trace = DIAG_DEFAULT       # defer to owning CMN object
        self.parent = parent
        self.is_external = is_external
        assert node_offset not in self.C.offset_node, "node already discovered: %s" % self.C.offset_node[node_offset]
        self.C.offset_node[node_offset] = self
        self.node_base_addr = cmn.periphbase + node_offset
        if self.C.verbose >= 2:
            self.C.log("created node at 0x%x" % self.node_base_addr, level=2)
        if map is not None:
            self.m = map
        else:
            self.m = self.C.D.map(self.node_base_addr, self.C.node_size(), write=write)
        himem = self.node_base_addr + self.C.node_size()
        if himem > self.C.himem:
            self.C.himem = himem
        self.node_info = 0x0000     # in case we throw in the next line
        self.node_info = self.read64(CMN_any_NODE_INFO)
        self.PMU_EVENT_SEL = pmu_event_sel_offset(self.type())
        if self.is_child():
            if (self.node_id() >> 3) != (parent.node_id() >> 3):
                self.C.log("Parent XP %s child %s has odd coordinates" % (parent, self), level=0)
        self.child_info = self.read64(CMN_any_CHILD_INFO)
        #print("%s%s" % ((self.level()*"  "), self))

    def do_trace_reads(self):
        return (self.diag_trace | self.C.diag_trace) & DIAG_READS

    def do_trace_writes(self):
        return (self.diag_trace | self.C.diag_trace) & DIAG_WRITES

    def ensure_writeable(self):
        if not self.m.writing:
            self.m = self.m.ensure_writeable()

    def set_secure_access(self, is_secure):
        self.m.set_secure_access(is_secure)

    def read64(self, off):
        if self.do_trace_reads():
            print()
            print("at %s" % self.C.source_line())
            self.C.log("%s: read 0x%x (0x%x)" % (str(self), off, self.node_base_addr+off), end="")
        data = self.m.read64(off)
        if self.do_trace_reads():
            self.C.log(" => 0x%x" % data, prefix=None)
        return data

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
            print("at %s" % self.C.source_line())
            self.C.log("%s: write 0x%x := 0x%x" % (str(self), off, data))
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
        """
        self.children = []
        self.n_children = BITS(self.child_info, 0, 16)
        child_off = BITS(self.child_info, 16, 16)
        assert self.n_children < 200, "CMN discovery found too many node children"
        cobits = 30 if self.C.part_ge_650() else 28
        for i in range(0, self.n_children):
            child = self.read64(child_off + (i*8))
            child_offset = BITS(child, 0, cobits)
            child_node = self.C.create_node(child_offset, parent=self, is_external=BIT(child, 31))
            if child_node is None:
                # Probably a child of a RN-F port
                continue
            self.children.append(child_node)

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
        return BITS(self.node_info, 16, 16)

    def logical_id(self):
        """
        The logical ID is programmed by the mesh configurator.
        It should be unique for nodes of a particular type.
        For a DTC, this is actually a 2-bit field, dtc_domain.
        """
        if not node_has_logical_id(self.type()):
            return None
        return BITS(self.node_info, 32, 16)

    def is_XP(self):
        return self.type() == CMN_NODE_XP

    def XP(self):
        """
        For any node, return its crosspoint. For XPs, this is the node itself.
        """
        return self if self.is_XP() else self.parent

    def is_child(self):
        return self.parent is not None and self.parent.is_XP()

    def is_home_node(self):
        return self.type() in [CMN_NODE_HNF, CMN_NODE_HNS]

    def cache_geometry(self):
        # move to subclass, if/when we have a HN subclass
        assert self.is_home_node()
        return hn_cache_geometry(self)

    def has_pmu_events(self):
        """
        Can this node generate PMU events? I.e. does it have por_xxx_pmu_event_sel?
        """
        node_type_has_pmu_events(self.type())

    def XY(self):
        id = self.node_id()
        cb = self.C.coord_bits
        assert cb is not None, "can't get coordinates until mesh size is known"
        Y = BITS(id, 3, cb)
        X = BITS(id, 3+cb, cb)
        return (X, Y)

    def coords(self):
        """
        Return device coordinates as a tuple (X, Y, P, D).
        For an XP, P and D will be zero.
        Otherwise, P is the port number, and D is the device number.
        D is generally zero, but for CAL-attached devices it may be 0 or 1.
        """
        id = self.node_id()
        (X, Y) = self.XY()
        # Old rule (as per docs):
        #   If the CMN has at least one XP with more than 2 device ports,
        #   all device ids use 2 bits for the port and one for the device.
        #   Otherwise it's 1 bit for the port and 2 for the device.
        # Actual rule:
        #   If this XP hsa more than 2 device ports, use 2 bits for the port.
        if self.parent is not None and self.XP().n_device_bits() == 1:
            D = BIT(id, 0)
            P = BITS(id, 1, 2)
        else:
            D = BITS(id, 0, 2)
            P = BIT(id, 2)
        return (X, Y, P, D)

    def device_port(self):
        assert not self.is_XP()
        (X, Y, P, D) = self.coords()
        return P

    def device_number(self):
        assert not self.is_XP()
        (X, Y, P, D) = self.coords()
        return D

    def show(self):
        # Node-specific subclass can override
        pass

    def extra_str(self):
        # Node-specific subclass can override
        return ""

    def __lt__(self, node):
        return self.node_base_addr < node.node_base_addr

    def __str__(self):
        lid = self.logical_id()
        s = "%s" % cmn_node_type_str(self.type())
        if lid is not None:
            s += "#%u" % lid
        if self.is_external:
            s += "(ext)"
        s += ":0x%x" % self.node_id()
        if self.C.verbose:
            s = "@0x%x:%s" % (self.node_base_addr, s)
        if self.C.coord_bits is not None:
            (X, Y, P, D) = self.coords()
            if self.is_XP():
                s += ":(%u,%u)" % (X, Y)
            else:
                s += ":(%u,%u,%u,%u)" % (X, Y, P, D)
        if self.C.verbose >= 2:
            s += ":info=0x%x" % self.node_info
        return s


#
# DT-specific
#

N_WATCHPOINTS = 4
N_FIFO_ENTRIES = 4


class CMNNodeXP(CMNNode):
    """
    Crosspoint node. This has special behavior as follows:
     - manages child nodes on its ports P0 and P1, possibly several on both.
     - contains a Debug/Trace Monitor (DTM)
    """
    def __init__(self, *args, **kwargs):
        CMNNode.__init__(self, *args, **kwargs)
        self.dtm = CMNDTM(self)

    def port_nodes(self, rP):
        """
        Yield all a port's device nodes, ordered by device number.
        (There may be multiple device nodes for a given device number.)
        """
        for rD in range(0, 4):
            for n in self.port_device_nodes(rP, rD):
                yield n

    def port_device_nodes(self, rP, rD):
        """
        Yield all a port's device nodes, for a given device number.
        Note that a RN-F port will only have a RN-SAM device node,
        and a SN-F port will not have any device nodes at all.
        """
        for n in self.children:
            (X, Y, P, D) = n.coords()
            if P == rP and D == rD:
                yield n

    def n_device_ports(self):
        """
        The number of device ports on this XP. In general it is not guaranteed that
        devices exist on every port. For CMN-6xx, each XP is assumed to have 2 ports.
        For CMN-700, the number of device ports is discoverable from the XP's info register
        (some XPs might have 3 or 4), but even so, some might be unused.
        It is possible for there to be a device on P1 but not on P0.
        """
        if self.C.part_ge_700():
            return BITS(self.node_info, 48, 4)
        else:
            return 2

    def port_info(self, rP, n=0):
        """
        Get the port info (por_mxp_p<n>_info).
        This includes the number of devices connected to the port.
        """
        if not self.C.part_ge_700():
            assert n == 0
            off = 0x900 + (rP * 8)
        else:
            assert n <= 1
            off = 0x900 + (rP * 16) + (n * 8)
        return self.read64(off)

    def port_device_type(self, rP):
        """
        Return a "connected device type" value indicating the type of device(s)
        attached to this port. This is not the same as the node type.
        """
        pinfo = self.read64(CMN_XP_DEVICE_PORT_CONNECT_INFO_P(rP))
        dt = BITS(pinfo, 0, 5)
        if dt == 0:
            return None    # indicates there is no device on this port
        return dt

    def port_device_type_str(self, rP):
        """
        The string for the port's "connected device type".
        """
        dt = self.port_device_type(rP)
        if dt is not None:
            return cmn_port_device_type_str(dt)
        else:
            return "?"

    def port_has_cal(self, rP):
        """
        Return True if a port has a CAL allowing multiple devices to be connected.
        In earlier CMNs a CAL would connect two identical devices.
        In later CMNs, CALs can connect up to four devices, or two different RNs.
        """
        pinfo = self.read64(CMN_XP_DEVICE_PORT_CONNECT_INFO_P(rP))
        return BIT(pinfo, CMN_XP_DEVICE_PORT_CAL_CONNECTED_BIT)

    def n_device_bits(self):
        """
        In the device node id, the split between port id and device id
        (whether it is 2:1 or 1:2) depends on the number of ports on the
        individual XP - contrary to the implication of the CMN TRM.
        """
        return 1 if self.n_device_ports() > 2 else 2

    def port_base_id(self, rP):
        return self.node_id() + (rP << self.n_device_bits())

    def dtc_domain(self):
        """
        Return the DTC domain number of this XP, if known.
        TBD: Recent CMN allows an XP to have multiple DTMs, with a corrresponding
        dtm_unit_info register for each one - implying an XP's DTMs could be in
        different domains. We have not observed this.
        """
        if self.C.product_config.product_id == cmn_base.PART_CMN600:
            if len(self.C.debug_nodes) == 1:
                return 0       # this mesh has only one DTC
            else:
                # In a CMN-600 with multiple DTCs, we can't discover the assignment.
                return None
        elif self.C.product_config.product_id == cmn_base.PART_CMN650:
            return BITS(self.read64(CMN650_DTM_UNIT_INFO), 0, 2)
        else:
            return BITS(self.read64(CMN700_DTM_UNIT_INFO), 0, 2)

    def check_reg_is_writeable(self, off):
        """
        Some DTM configuration registers are only writeable when the DTM is disabled.
        """
        if off >= self.C.DTM_BASE+0x100 and off <= self.C.DTM_BASE+0x2ff and (off-self.C.DTM_BASE) not in [CMN_DTM_CONTROL_off, CMN_DTM_FIFO_ENTRY_READY_off] and self.dtm._dtm_is_enabled:
            assert False, "try to write DTM programming register when DTM is enabled"


class CMNDTM:
    """
    Debug/trace functionality within an XP.
    Split out from XP partly motivated by register offsets having changed in S3.
    """
    def __init__(self, xp):
        self.xp = xp
        self.base = xp.C.DTM_BASE
        self.C = xp.C
        # We maintain a cached copy of the DTM enable bit so we can fault writes
        # to DTM configuration registers when enabled.
        self._dtm_is_enabled = None
        self._dtm_is_enabled = self.dtm_is_enabled()

    def __str__(self):
        return "%s DTM" % (self.xp)

    def dtm_read64(self, off):
        return self.xp.read64(self.base+off)

    def dtm_write64(self, off, value, check=None):
        return self.xp.write64(self.base+off, value, check=check)

    def dtm_set64(self, off, value, check=None):
        return self.xp.set64(self.base+off, value, check=check)

    def dtm_clear64(self, off, value, check=None):
        return self.xp.clear64(self.base+off, value, check=check)

    def dtm_test64(self, off, value):
        return self.xp.test64(self.base+off, value)

    def dtc_domain(self):
        return self.xp.dtc_domain()

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

    def dtm_is_enabled(self):
        """
        Check whether por_dtm_control.dtm_enable is set, indicating that DTM is enabled.
        "Once this bit is set, other DT configuration registers must not be modified."
        """
        e = self.dtm_test64(CMN_DTM_CONTROL_off, CMN_DTM_CONTROL_DTM_ENABLE)
        if self._dtm_is_enabled is not None:
            assert e == self._dtm_is_enabled, "%s: cached DTM emable state out of sync" % self
        return e

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

    def dtm_fifo_entry(self, e):
        """
        Get a FIFO entry, returning it as (byte string, cycle count)
        """
        assert 0 <= e and e <= N_FIFO_ENTRIES
        ws = []
        for w in range(0, 3):
            ws.append(self.dtm_read64(CMN_DTM_FIFO_ENTRY_off(e, w)))
        #print("FIFO: 0x%016x 0x%016x 0x%016x" % (ws[0], ws[1], ws[2]))
        # The cycle count is at a fixed bit offset in register #2, but the
        # offset varies by part number, reflecting the FIFO data size
        if self.C.product_config.product_id == cmn_base.PART_CMN600:
            dwidth = 144
        elif self.C.product_config.product_id == cmn_base.PART_CMN650:
            dwidth = 160
        else:
            dwidth = 176
        doff = dwidth - 128
        cc = BITS(ws[2], doff, 16)
        b = struct.pack("<QQQ", ws[0], ws[1], ws[2])[:(dwidth//8)]
        return (b, cc)

    def dtm_wp_details(self, wp):
        """
        Return a tuple indicating the current configuration of a watchpoint,
        so that it can be decoded.
          (nodeid, dev:0..3, wp#, channel:0..3, format:0..7, cc)
        Counterpart of dtm_set_watchpoint()
        """
        assert 0 <= wp and wp <= N_WATCHPOINTS
        cfg = self.dtm_read64(CMN_DTM_WP0_CONFIG_off+(wp*24))
        VC = BITS(cfg, 1, 2)
        dev = BIT(cfg, 0)
        if self.xp.n_device_ports() > 2:
            dev |= (BIT(cfg, 17) << 1)
        type = BITS(cfg, self.C.DTM_WP_PKT_TYPE_SHIFT, 3)
        cc = BIT(cfg, self.C.DTM_WP_PKT_TYPE_SHIFT+3)
        return (self.xp.node_id(), dev, wp, VC, type, cc)

    def dtm_atb_packet_header(self, wp, lossy=0):
        """
        Construct a trace packet header, as if for a packet output on ATB.
        """
        (nid, dev, wp, VC, type, cc) = self.dtm_wp_details()
        if self.C.product_config.product_id == cmn_base.PART_CMN600:
            h = (VC << 30) | (dev << 29) | (wp << 27) | (type << 24) | (nid << 8) | 0x40 | (cc << 4) | lossy
        else:
            h = (VC << 28) | (wp << 24) | ((nid >> 3) << 11) | (dev << 8) | 0x40 | (cc << 4) | (type << 1) | lossy
        return h

    def pmu_enable(self):
        self.dtm_set64(CMN_DTM_PMU_CONFIG_off, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_disable(self):
        self.dtm_clear64(CMN_DTM_PMU_CONFIG_off, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_is_enabled(self):
        return self.dtm_test64(CMN_DTM_PMU_CONFIG_off, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_event_input_selector_str(self, eis):
        """
        Given a DTM event selector, return a descriptive string.
        """
        if eis <= 0x03:
            # DTM is counting matches by one of its own watchpoints.
            s = "Watchpoint %u" % eis
        elif eis <= 0x07:
            # DTM is counting events within the XP, as selected by its own pmu_event_sel.
            xpen = eis - 4
            xpe = BITS(self.read64(CMN_any_PMU_EVENT_SEL),(xpen*8),8)
            chn = ["REQ","RSP","SNP","DAT","?4","?5","?6","?7"][BITS(xpe,5,3)]
            ifc = ["E","W","N","S","P0","P1","?6","?7"][BITS(xpe,2,3)]
            evt = ["none", "txvalid", "txstall", "partial"][BITS(xpe,0,2)]
            xpes = "xp-%s-%s-%s" % (ifc, chn, evt)
            s = "XP PMU Event %u (event=0x%02x: %s)" % (xpen, xpe, xpes)
        elif eis >= 0x10:
            # DTM is counting events from one of its connected devices,
            # selected by port number, device number, and event.
            # The actual event will be selected by the device's pmu_event_sel.
            # (Note that for a given (port, device) pair, there must be at
            # most one device capable of exporting PMU events.)
            port = (eis >> 4) - 1
            device = BITS(eis, 2, 2)
            eix = (eis & 3)
            s = "Port %u Device %u PMU Event %u" % (port, device, eix)
            (device_node, pix, event_number, filter) = self.device_pmu_event(port, device, eix)
            if device_node is not None:
                s += " - %s[%u] event 0x%x" % (device_node, pix, event_number)
                if self.C.pmu_events is not None:
                    ev = self.C.pmu_events.get_event(device_node.type(), event_number, pmu_index=pix, filter=filter)
                    if ev is not None:
                        s += " - %s" % ev.name()
        else:
            s = "?(eis=0x%x)" % eis
        return s

    def dtm_set_control(self, control=0, atb=False, tag=False, enable=False):
        """
        Configure the DTM, which controls all watchpoints an PMU.
        Note that this function isn't read/modify/write.
        """
        if not atb:
            control |= CMN_DTM_CONTROL_TRACE_NO_ATB
        if tag:
            control |= CMN_DTM_CONTROL_TRACE_TAG_ENABLE
        if enable:
            control |= CMN_DTM_CONTROL_DTM_ENABLE
        self.write64(CMN_DTM_CONTROL, control)
        self._dtm_is_enabled = enable

    def dtm_set_watchpoint(self, wp, val=0, mask=0xffffffffffffffff, config=0, gen=True, group=None, format=None, chn=None, dev=None, cc=False, exclusive=False, combine=False):
        """
        Configure a watchpoint on the XP. The DTM should be disabled.
        The mask is the bits we don't care about. I.e. 0 is exact match, 0xffffffffffffffff is don't care.
        """
        if gen:
            config |= self.C.DTM_WP_PKT_GEN
        if combine:
            config |= self.C.DTM_WP_COMBINE
        if format is not None:
            config |= (format << self.C.DTM_WP_PKT_TYPE_SHIFT)
        if chn is not None:
            assert chn in [0, 1, 2, 3]
            config |= (chn << 1)
        if dev is not None:
            dev0 = dev & 1
            config |= (dev0 << 0)
            if dev >= 2:
                # dev_sel is actually the port number, not the device number
                assert dev < self.xp.n_device_ports(), "%s: invalid dev_sel=%u" % (self, dev)
                dev1 = dev >> 1
                config |= (dev1 << 17)
        if group is not None:
            config |= (group << 4)     # for CMN-650 and CMN-700 this is a 2-bit field[5:4]
        if cc:
            # note: must also be enabled in the DTM
            config |= self.C.DTM_WP_CC_EN
        if exclusive:
            config |= self.C.DTM_WP_EXCLUSIVE
        self.dtm_write64(CMN_DTM_WP0_VAL_off+(wp*24), val)
        self.dtm_write64(CMN_DTM_WP0_MASK_off+(wp*24), mask)
        self.dtm_write64(CMN_DTM_WP0_CONFIG_off+(wp*24), config)

    def device_pmu_event(self, port, device, eix):
        """
        Assuming that we're counting a device event, find the actual device node
        that is exporting the event, and the event number (and filter).
        The DTM pmu_event_sel will indicate port and device.
        But this isn't always enough to identify the actual device involved.
        Sometimes there are multiple nodes with the same (port, device)
        combination, each capable of exporting events.
        In general, we must iterate through the connected devices and
        find one that is exporting an event.
        """
        for n in self.xp.port_device_nodes(port, device):
            for soff in n.PMU_EVENT_SEL:
                pmu_sel = n.read64(soff)
                pmu_filter = BITS(pmu_sel, 32, 8)
                en = BITS(pmu_sel, eix*8, 8)
                if en > 0:
                    pix = (soff - CMN_any_PMU_EVENT_SEL) >> 3
                    return (n, pix, en, pmu_filter)
        return (None, None, None, None)

    def show_dtm(self, show_pmu=True):
        dtm_control = self.dtm_read64(CMN_DTM_CONTROL_off)
        fifo = self.dtm_read64(CMN_DTM_FIFO_ENTRY_READY_off)
        dom = self.dtc_domain()
        print("  %s:" % self, end="")
        if dom is not None:
            print(" (DTC%u)" % dom, end="")
        print(" DTM control: 0x%08x" % (dtm_control), end="")
        if dtm_control & CMN_DTM_CONTROL_DTM_ENABLE:
            print(" (enabled)", end="")
        if dtm_control & CMN_DTM_CONTROL_TRACE_TAG_ENABLE:
            print(" (trace tag)", end="")
        if dtm_control & CMN_DTM_CONTROL_SAMPLE_PROFILE_ENABLE:
            print(" (sample profile)", end="")
        if dtm_control & CMN_DTM_CONTROL_TRACE_NO_ATB:
            print(" (to FIFO)", end="")
        else:
            print(" (to ATB)", end="")
        print(", FIFO: 0x%x" % (fifo))
        if not (dtm_control & CMN_DTM_CONTROL_TRACE_NO_ATB):
            fifo = 0xf    # if tracing to ATB, show all FIFO contents
        for wp in range(0, N_WATCHPOINTS):
            wctl = self.dtm_read64(CMN_DTM_WP0_CONFIG_off+(wp*24))
            wval = self.dtm_read64(CMN_DTM_WP0_VAL_off+(wp*24))
            wmsk = self.dtm_read64(CMN_DTM_WP0_MASK_off+(wp*24))
            if wctl or wval or wmsk:
                chn = BITS(wctl, 1, 3)
                port = BIT(wctl, 0)      # wp_dev_sel
                if self.C.product_config.product_id == cmn_base.PART_CMN600:
                    grp = BITS(wctl, 4, 1)
                else:
                    grp = BITS(wctl, 4, 2)
                pkt_type = BITS(wctl, self.C.DTM_WP_PKT_TYPE_SHIFT, 3)     # 9 for CMN-600, 11 otherwise
                print("    WP #%u: ctrl=0x%016x comp=0x%016x mask=0x%016x" % (wp, wctl, wval, wmsk), end="")
                print(" P%u %s type=%u" % (port, ["REQ","RSP","SNP","DAT"][chn], pkt_type), end="")    # sic: values 4..7 are reserved
                if grp:
                    print(" grp=%u" % grp, end="")
                if wctl & self.C.DTM_WP_COMBINE:
                    print(" combine", end="")
                if wctl & self.C.DTM_WP_EXCLUSIVE:
                    print(" exclusive", end="")
                if wctl & self.C.DTM_WP_PKT_GEN:
                    print(" pkt_gen", end="")
                if wctl & self.C.DTM_WP_CC_EN:
                    print(" cc", end="")
                print()
        if fifo != 0:
            # Show FIFO contents. Note that in read mode (TRACECTL[3]==1), each FIFO entry is
            # allocated to the corresponding WP - i.e. each WP has a 1-entry FIFO.
            for e in range(0,N_FIFO_ENTRIES):
                if fifo & (1 << e):
                    (data, cc) = self.dtm_fifo_entry(e)
                    print("    FIFO #%u: %s cc=0x%04x" % (e, hexstr(data), cc))
        if show_pmu:
            pmu_config = self.dtm_read64(CMN_DTM_PMU_CONFIG_off)
            if pmu_config:
                pmu_pmevcnt = self.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
                print("    PMU config: 0x%016x" % (pmu_config))
                print("    PMU counts: 0x%016x" % (pmu_pmevcnt))
                show_dtm_pmu_config(self)
            # DTM may be counting events from connected devices.
            for p in range(0, self.xp.n_device_ports()):
                for n in self.xp.port_nodes(p):
                    for soff in n.PMU_EVENT_SEL:
                        pmu_sel = n.read64(soff)
                        print("      %016x  %s" % (pmu_sel, n))
                        pmu_filter = BITS(pmu_sel, 32, 8)
                        for e in range(0, 4):
                            esel = BITS(pmu_sel, e*8, 8)
                            if esel != 0:
                                print("        E%u: 0x%x" % (e, esel), end="")
                                if self.C.pmu_events is not None:
                                    pix = (soff - CMN_any_PMU_EVENT_SEL) >> 3
                                    ev = self.C.pmu_events.get_event(n.type(), esel, pmu_index=pix, filter=pmu_filter)
                                    if ev is not None:
                                        print(" - %s" % ev.name(), end="")
                                print()


class CMNNodeDT(CMNNode):
    """
    DTC (debug/trace controller) node. There is one per DTC domain.
    The one located in the HN-D is designated as DTC0.
    """
    def atb_traceid(self):
        return BITS(self.read64(CMN_DTC_TRACEID),0,7)

    def set_atb_traceid(self, x):
        if self.C.verbose:
            self.C.log("ATB ID 0x%02x: %s" % (x, self))
        self.write64(CMN_DTC_TRACEID, x)

    def dtc_domain(self):
        """
        The domain number for this DTC. We'd expect it to be the
        same as the domain number for the DTC's XP's DTM.
        """
        return BITS(self.node_info, 32, 2)

    def dtc_enable(self, cc=None, pmu=None, clock_disable_gating=None):
        """
        Enable the DTC. Optionally also enable other DTC features,
        e.g.
          - cycle-counting for trace
          - PMU
          - always-on clock (i.e. disable clock-gating)
        """
        self.C.log("DTC enable: %s" % self)
        self.set64(CMN_DTC_CTL, CMN_DTC_CTL_DT_EN)
        if cc:
            self.set64(CMN_DTC_TRACECTRL, CMN_DTC_TRACECTRL_CC_ENABLE)
        if pmu:
            self.pmu_enable()
        if clock_disable_gating is not None:
            self.clock_disable_gating(clock_disable_gating)

    def dtc_disable(self):
        self.C.log("DTC disable: %s" % self)
        self.clear64(CMN_DTC_CTL, CMN_DTC_CTL_DT_EN)

    def dtc_is_enabled(self):
        return self.test64(CMN_DTC_CTL, CMN_DTC_CTL_DT_EN)

    def pmu_enable(self):
        self.set64(CMN_DTC_PMCR, CMN_DTC_PMCR_PMU_EN)

    def pmu_disable(self):
        self.clear64(CMN_DTC_PMCR, CMN_DTC_PMCR_PMU_EN)

    def pmu_is_enabled(self):
        return self.test64(CMN_DTC_PMCR, CMN_DTC_PMCR_PMU_EN)

    def pmu_clear(self):
        for i in range(0,8,2):
            self.write64(CMN_DTC_PMEVCNT + 8*i, 0)
            self.write64(CMN_DTC_PMEVCNTSR + 8*i, 0)

    def pmu_cc(self):
        return self.read64(CMN_DTC_PMCCNTR)

    def pmu_snapshot(self):
        """
        Cause the DTC to send a PMU snapshot instruction to the DTMs.
        Return the status flags, or None if the snapshot did not complete.
        """
        status = None
        if self.C.verbose:
            self.C.log("PMU snapshot from %s" % (self))
        c0 = self.pmu_cc()
        s0 = self.read64(CMN_DTC_PMSSR)
        self.write64(CMN_DTC_PMSRR, CMN_DTC_PMSRR_SS_REQ, check=False)
        s1 = self.read64(CMN_DTC_PMSSR)
        # "The DTC updates por_dt_pmssr.ss_status after receiving PMU snapshot
        #  packets. Software can poll this register field to check if the snapshot
        #  process is complete." We also check that the snapshot is not active.
        for i in range(0, 10):
            ssr = self.read64(CMN_DTC_PMSSR)
            if not (ssr & CMN_DTC_PMSSR_SS_CFG_ACTIVE):
                status = BITS(ssr, 0, 9)           # Return the status (0..7: counters, 8: cycle counter)
                break
        assert status is not None, "%s: snapshot did not complete after %u reads" % (self, i)
        c1 = self.pmu_cc()
        if self.C.verbose:
            self.C.log("PMU snapshot complete: 0x%x (cyc=0x%x) => 0x%x (cyc=0x%x) => 0x%x, %u reads" % (s0, c0, s1, c1, ssr, i))
        return status

    def clock_disable_gating(self, disable_gating=True):
        """
        We need to set the "disable clock-gating" bit... this allows
        the clock to run all the time.
        Return the previous setting.
        """
        return self.setclear64(CMN_DTC_CTL, CMN_DTC_CTL_CG_DISABLE, disable_gating)

    def extra_str(self):
        return "DTC%u" % self.dtc_domain()

    def show(self, pfx=""):
        """
        DTC-specific printing
        """
        print("%s%s: " % (pfx, self))
        auth = self.read64(CMN_DTC_AUTHSTATUS_DEVARCH)
        print("%s  DTC auth: 0x%x" % (pfx, auth))
        ctl = self.read64(CMN_DTC_CTL)
        print("%s  DTC control: 0x%x" % (pfx, ctl), end="")
        if ctl & CMN_DTC_CTL_DT_EN:
            print(" (enabled)", end="")
        else:
            print(" (disabled)", end="")
        if ctl & CMN_DTC_CTL_DBGTRIGGER_EN:
            print(" (dbgtrigger)", end="")
        if ctl & CMN_DTC_CTL_ATBTRIGGER_EN:
            print(" (ATB trigger)", end="")
        if ctl & CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER:
            print(" (wait for triggers: %u)" % BITS(ctl,4,6), end="")
        if ctl & CMN_DTC_CTL_CG_DISABLE:
            print(" (clock-gating disabled)", end="")
        else:
            print(" (clock-gating enabled)", end="")
        print()
        tracectrl = self.read64(CMN_DTC_TRACECTRL)
        print("%s  ATB trace control: 0x%x" % (pfx, tracectrl), end="")
        if BITS(tracectrl,5,3):
            print(" (TS:%uK cycles)" % (1 << BITS(tracectrl,5,3)), end="")
        if tracectrl & CMN_DTC_TRACECTRL_CC_ENABLE:
            print(" (cc_enable)", end="")
        print()
        print("%s  ATB trace id: 0x%02x" % (pfx, self.atb_traceid()))
        # Show global PMU configuration and counter values
        # Read the counter values twice, to indicate if they are (rapidly) changing
        pmcr = self.read64(CMN_DTC_PMCR)
        print("%s  DTC PMU control: 0x%x" % (pfx, pmcr), end="")
        if pmcr & CMN_DTC_PMCR_PMU_EN:
            print(" (enabled)", end="")
        print()
        for rbase in [CMN_DTC_PMEVCNT, CMN_DTC_PMEVCNTSR]:
            ecs = [self.read64(rbase + 8*i) for i in range(0,8,2)]
            if rbase == CMN_DTC_PMEVCNT:
                pass
            else:
                ssr = self.read64(CMN_DTC_PMSSR)
                print("%s  DTC PMU snapshot status: 0x%08x" % (pfx, ssr))
            for i in range(0, 8, 2):
                cv = self.read64(rbase + 8*i)
                c0a = (ecs[i >> 1] & 0xffffffff)
                c1a = (ecs[i >> 1] >> 32)
                c0b = (cv & 0xffffffff)
                c1b = (cv >> 32)
                c0x = (c0a != c0b)
                c1x = (c1a != c1b)
                if (i % 4) == 0:
                    print("%s  " % (pfx), end="")
                print("  #%u: 0x%08x%s  #%u: 0x%08x%s" % (i, c0b, " *"[c0x], i+1, c1b, " *"[c1x]), end="")
                if (i % 4) == 2:
                    print()


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

    def __init__(self, cmn_loc, check_writes=False, verbose=0, restore_dtc_status=False, secure_accessible=None):
        self.verbose = verbose
        self.diag_trace = DIAG_WRITES if (verbose >= 2) else DIAG_DEFAULT
        self._restore_dtc_status = restore_dtc_status
        self.secure_accessible = secure_accessible    # if None, will be found from CFG
        self.periphbase = cmn_loc.periphbase
        rootnode_offset = cmn_loc.rootnode_offset
        assert rootnode_offset >= 0 and rootnode_offset < 0x4000000
        self.himem = self.periphbase       # will be updated as we discover nodes
        if verbose:
            print("CMN: PERIPHBASE=0x%x, CONFIG=0x%x" % (self.periphbase, self.periphbase+rootnode_offset))
        # CMNProductConfig object will be created when we read CMN_CFG_PERIPH_01
        # from the root node
        self.product_config = None
        self.D = devmem.DevMem(write=False, check=check_writes)
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
        self.logical_id = {}      # Non-XP nodes indexed by (type, logical_id)
        self.debug_nodes = []     # DTC(s). A large mesh might have more than one.
        self.extra_ports = NotTestable("shouldn't calculate device ids before all XPs seen")
        # Discovery phase.
        self.creating = True
        # we can't map nodes until we know the node size, but we don't
        # know that until we've mapped the root config node...
        # create a temporary 16K mapping to get out of that.
        temp_m = self.D.map(self.periphbase+rootnode_offset, 0x4000)
        id01 = temp_m.read64(CMN_CFG_PERIPH_01)
        product_id = (BITS(id01, 32, 4) << 8) | BITS(id01, 0, 8)
        if cmn_loc.product_id is not None:
            assert cmn_loc.product_id == product_id, "expecting %s, found %s" % (cmn_base.product_id_str(cmn_loc.product_id), cmn_base.product_id_str(product_id))
        # We can't get chi_version() until we've read unit_info (por_info_global)
        self.product_config = cmn_base.CMNConfig(product_id=product_id)
        del temp_m
        # Load the PMU event database, if available
        pmu_event_fn = cmn_events.event_file_name(product_id)
        if os.path.isfile(pmu_event_fn):
            if verbose:
                self.log("loading PMU events from %s" % pmu_event_fn)
            self.pmu_events = cmn_events.load_events(pmu_event_fn)
            if verbose:
                self.log("loaded %s" % self.pmu_events)
        else:
            self.pmu_events = None
        self.rootnode = self.create_node(rootnode_offset)
        self.unit_info = self.rootnode.read64(CMN_any_UNIT_INFO)   # por_info_global
        # The release is e.g. r0p0, r1p2
        self.product_config.revision = BITS(self.rootnode.read64(CMN_CFG_PERIPH_23), 4, 4)
        self.product_config.mpam_enabled = self.part_ge_650() and (BIT(self.unit_info, 49) != 0)
        self.product_config.chi_version = self.chi_version()
        assert self.product_config.chi_version >= 2, "failed to detect CHI version: info=0x%x" % self.unit_info
        if self.product_config.product_id != cmn_base.PART_CMN_S3:
            self.DTM_BASE            = CMN_DTM_BASE_OLD
        else:
            self.DTM_BASE            = CMN_DTM_BASE_S3
        #
        # Now traverse the CMN space to discover all the nodes.
        #
        self.rootnode.discover_children()
        self.creating = False
        #
        # We've discovered the XPs but we generally don't yet know their X,Y coordinates,
        # since we don't know coord_bits.
        n_XPs = len(list(self.XPs()))
        # For some XPs, the coordinates are independent of coord_bits. These include (0,0) and (0,1).
        # Using the conventional logical_id assignment, (0,1) will have logical_id == dimX.
        any_extra_ports_seen = False
        for xp in self.XPs():
            assert xp.logical_id() < n_XPs
            if xp.n_device_ports() > 2:
                any_extra_ports_seen = True
        self.extra_ports = any_extra_ports_seen
        for xp in self.XPs():
            if BITS(xp.node_info,19,8) == 0x01:   # XP at (0,1), regardless of coord_bits
                self.dimX = xp.logical_id()
                break
        if self.dimX is None:
            self.dimX = n_XPs
        assert (n_XPs % self.dimX) == 0, "%u XPs but X dimension is %u" % (n_XPs, self.dimX)
        self.dimY = n_XPs // self.dimX
        self.coord_bits = cmn_base.id_coord_bits(self.dimX, self.dimY)
        md = max(self.dimX, self.dimY)
        if md >= 9:
            self.coord_bits = 4
        elif md >= 5:
            self.coord_bits = 3
        else:
            self.coord_bits = 2
        for xp in self.XPs():
            (X,Y) = xp.XY()
            self.coord_XP[(X,Y)] = xp
        # Some offsets change from CMN-650 onwards
        if self.product_config.product_id == cmn_base.PART_CMN600:
            self.DTM_WP_EXCLUSIVE    = 0x0020
            self.DTM_WP_COMBINE      = 0x0040
            self.DTM_WP_PKT_GEN      = 0x0100   # capture a packet
            self.DTM_WP_PKT_TYPE_SHIFT = 9
            self.DTM_WP_CC_EN        = 0x1000   # enable cycle count
        else:
            self.DTM_WP_EXCLUSIVE    = 0x0100
            self.DTM_WP_COMBINE      = 0x0200
            self.DTM_WP_PKT_GEN      = 0x0400   # capture a packet
            self.DTM_WP_PKT_TYPE_SHIFT = 11
            self.DTM_WP_CC_EN        = 0x4000   # enable cycle count
        if restore_dtc_status:
            self.restore_dtc_status_on_deletion()
        if self.secure_accessible is None:
            sa = self.rootnode.read64(CMN_any_SECURE_ACCESS)   # por_cfgm_secure_access
            self.secure_accessible = (BIT(sa, 0) == 1)
        if self.verbose:
            sa = self.rootnode.read64(CMN_any_SECURE_ACCESS)
            print("Access to Secure registers: 0x%x (%s) (at 0x%x)" % (sa, self.secure_accessible, self.rootnode.node_base_addr+CMN_any_SECURE_ACCESS))

    def contains_addr(self, addr):
        assert not self.creating
        return self.periphbase <= addr and addr < self.himem

    def part_ge_650(self):
        # everything except CMN-600
        return self.product_config.product_id != cmn_base.PART_CMN600

    def part_ge_700(self):
        # everything except CMN-600 and CMN-650
        return self.product_config.product_id not in [cmn_base.PART_CMN600, cmn_base.PART_CMN650]

    def __str__(self):
        s = "%s at 0x%x" % (self.product_str(), self.periphbase)
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
        return "%s.%u: %s" % (os.path.basename(fr.filename), fr.lineno, fr.line)

    def log(self, msg, prefix="CMN: ", end=None, level=1):
        """
        Print a logging message. We do a level check here, but it might also be a
        good idea to check at the call site to avoid constructing the message.

        Use level=0 for warning messages that should always be output.
        """
        if self.verbose >= level:
            if prefix is None:
                prefix = ""
            print("%s%s" % (prefix, msg), end=end)

    def product_str(self):
        s = self.product_config.product_name(revision=True)
        s += " " + self.chi_version_str()
        if self.product_config.mpam_enabled:
            s += " with MPAM"
        return s

    def chi_version(self):
        """
        Discover the CHI version, where 1 is A, 2 is B etc.
        """
        if not self.part_ge_650():
            # In CMN-600 there's a single CHI-C flag
            return 2 + BIT(self.unit_info, 49)
        else:
            return BITS(self.unit_info, 60, 3)

    def chi_version_str(self):
        return "CHI-%s" % "?ABCDEFGH"[self.chi_version()]

    def node_size(self):
        return 0x10000 if self.part_ge_700() else 0x4000

    def create_node(self, node_offset, parent=None, is_external=False):
        """
        Create a node, either the root node (parent=None) or an XP, or a child node.
        """
        assert self.creating
        node_base_addr = self.periphbase + node_offset
        m = self.D.map(node_base_addr, self.node_size())
        node_info = m.read64(CMN_any_NODE_INFO)
        node_type = BITS(node_info, 0, 16)
        if parent is None:
            # Expecting the configuration node. If we see something else,
            # the root node offset was probably wrong.
            assert node_type == CMN_NODE_CFG, "expected root node: 0x%x (%s)" % (node_base_addr, cmn_node_type_str(node_type))
        else:
            assert node_type != CMN_NODE_CFG, "unexpected root node at 0x%x" % node_base_addr
        assert (node_type == CMN_NODE_CFG) == (parent is None)
        # For some node types, we create a subclass object.
        if node_type == CMN_NODE_DT:
            # Debug/Trace Controller - one or more of these, generally in a corner of the mesh
            n = CMNNodeDT(self, node_offset, map=None, parent=parent, write=False)
            assert n not in self.debug_nodes
            self.debug_nodes.append(n)
        elif node_type == CMN_NODE_XP:
            # Crosspoint - parent of other nodes
            assert BITS(node_info, 16, 3) == 0, "expected 3 LSB of XP coordinates to be 0"
            n = CMNNodeXP(self, node_offset, map=None, parent=parent, write=True)
            nid = n.logical_id()
            if nid in self.logical_id_XP:
                self.log("XPs have duplicate logical ID 0x%x: %s, %s" % (nid, self.logical_id_XP[nid], n), level=0)
            self.logical_id_XP[nid] = n
            n.discover_children()
        elif node_info == 0:
            # Under XPs with RN-F ports, we sometimes see a valid child offset that points to zeroes
            n = None
        else:
            n = CMNNode(self, node_offset, map=m, parent=parent, is_external=is_external)
        if n is not None and node_type != CMN_NODE_XP and node_has_logical_id(node_type):
            nid = n.logical_id()
            nk = (node_type, nid)
            if nk in self.logical_id:
                self.log("Nodes of type 0x%x have duplicate logical ID 0x%x: %s, %s" % (node_type, nid, self.logical_id[nk], n), level=0)
            self.logical_id[nk] = n
        return n

    def XP_at(self, X, Y):
        """
        Return the XP at given coordinates
        """
        return self.coord_XP[(X,Y)]

    def XP(self, id):
        """
        Return the XP with the given node id
        """
        for xp in self.XPs():
            if xp.node_id() == id:
                return xp
        assert False, "bad XP node id: 0x%x" % id

    def nodes(self):
        return sorted(self.offset_node.values())

    def nodes_of_type(self, type):
        for n in self.nodes():
            if n.type() == type:
                yield n

    def home_nodes(self):
        for n in self.nodes():
            if n.is_home_node():
                yield n

    def XPs(self):
        return self.nodes_of_type(CMN_NODE_XP)

    def DTMs(self):
        for xp in self.XPs():
            yield xp.dtm

    def dtc_enable(self, cc=None, pmu=None, clock_disable_gating=None):
        for d in self.debug_nodes:
            d.dtc_enable(cc=cc, pmu=pmu, clock_disable_gating=clock_disable_gating)

    def dtc_disable(self):
        for d in self.debug_nodes:
            d.dtc_disable()

    def pmu_enable(self):
        for d in self.debug_nodes:
            d.pmu_enable()

    def clock_disable_gating(self, disable_gating=True):
        for d in self.debug_nodes:
            d.clock_disable_gating(disable_gating)

    def estimate_frequency(self, td=0.02):
        """
        Estimate the CMN's current clock frequency, using the DTC cycle counter.
        We read three times in an effort to factor out the overhead.
        """
        dtc = self.debug_nodes[0]
        dtc.dtc_enable()
        old = dtc.clock_disable_gating(disable_gating=True)
        t0 = dtc.pmu_cc()
        time.sleep(td)
        t1 = dtc.pmu_cc()
        time.sleep(td*2)
        t2 = dtc.pmu_cc()
        dtc.clock_disable_gating(disable_gating=old)
        return ((t2 - t1) - (t1 - t0)) / td


def show_dtm_pmu_config(dtm):
    # Show dynamic configuration of the XP as an event collector (not generator)
    pmu_config = dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
    if pmu_config != 0:
        print("      PMU config: 0x%016x  counters: 0x%016x" % (pmu_config, dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)))
        for i in range(0,4):
            eis = BITS(pmu_config, 32+i*8, 8)     # on CMN-6xx it's only 6 bits
            egc = BITS(pmu_config, 16+i*4, 3)
            paired = [0, (BIT(pmu_config, 1) | BIT(pmu_config, 3)), BIT(pmu_config, 3), (BIT(pmu_config, 2) | BIT(pmu_config, 3))][i]
            print("       %s%u:" % (" +"[paired], i), end="")
            if BIT(pmu_config, 4+i):
                print(" [global %u]" % egc, end="")
            print(" event 0x%02x: %s" % (eis, dtm.pmu_event_input_selector_str(eis)))


def hn_cache_geometry(n):
    """
    Retrieve the cache details for a home node, and create a
    CacheGeometry object.
    """
    assert n.is_home_node()
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


def pmu_counts(x, cfg):
    """
    Yield PMU event counts from an event counter register,
    taking counter combinations into account.
    """
    if cfg & CMN_DTM_PMU_CONFIG_PMEVENTALL_COMBINED:
        yield x
    else:
        if cfg & CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED:
            yield BITS(x, 0, 32)
        else:
            yield BITS(x, 0, 16)
            yield BITS(x, 16, 16)
        if cfg & CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED:
            yield BITS(x, 32, 32)
        else:
            yield BITS(x, 32, 16)
            yield BITS(x, 48, 16)


class CMNDiagramPerf(CMNDiagram):
    """
    CMN diagram with PMU counter annotations
    """
    def __init__(self, cmn, small=False):
        self.pmu_config = {}
        CMNDiagram.__init__(self, cmn, small=small, update=False)
        for xp in cmn.XPs():
            self.pmu_config[xp] = xp.dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
        self.pmu = {}
        self.capture_pmu()
        self.update()

    def capture_pmu(self):
        for xp in self.C.XPs():
            self.pmu[xp] = xp.dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)

    def port_label_color(self, xp, p):
        (dev_label, dev_color) = CMNDiagram.port_label_color(self, xp, p)
        if xp.port_device_type_str(p) == "HN-D":
            # Does this have a DTC node, and if so, is it enabled?
            for nd in xp.port_nodes(p):
                if nd in self.C.debug_nodes and nd.dtc_is_enabled():
                    dev_color += "!"
        return (dev_label, dev_color)

    def update(self):
        CMNDiagram.update(self)
        for xp in self.C.XPs():
            if xp.dtm.pmu_is_enabled():
                (cx, cy) = self.XP_xy(xp)
                # Get the current PMU values, and calculate the deltas.
                cfg = self.pmu_config[xp]
                opd = self.pmu[xp]          # Previous snapshot
                npd = xp.dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
                tab = 0
                for (ov, nv) in zip(pmu_counts(opd, cfg), pmu_counts(npd, cfg)):
                    dv = nv - ov
                    if dv < 0:
                        # TBD: only expect to see this for non-concatenated counters,
                        # but if we did see it for concatenated, the adjustment is wrong
                        dv += 0x10000
                    dv >>= opts.counter_scale
                    dcolor = None
                    if dv > opts.counter_threshold:
                        dcolor = "red!"
                    self.at(cx+tab, cy-1, "%4x" % dv, color=dcolor)
                    tab += 5
                self.pmu[xp] = npd          # Update the snapshot


def cmn_enable_pmu(C):
    """
    Set up the PMUs to count interesting events. Each XP has a DTM with four counters.
    Each counter can be programmed to count either an XP event or an imported
    event from one of its connected nodes (HN-F, SN-F etc. or the XP itself);
    that node needs to be programmed to export a selected event.
    For example, to count HN-F cache misses:
      - program HN-F to export HN_CACHE_MISS event as node event #0
      - program XP DTM counter #0 to count HN-F's exported event #0
    """
    for dtm in C.DTMs():
        dtm.dtm_write64(CMN_DTM_PMU_CONFIG_off, 0)
    for hnf in C.home_nodes():
        hnf_evt0 = opts.e0
        hnf_evt1 = opts.e1
        hnf.write64(CMN_any_PMU_EVENT_SEL, (hnf_evt1 << 8) | (hnf_evt0))
        xp = hnf.XP()
        pc = xp.dtm.dtm_read64(CMN_DTM_PMU_CONFIG_off)
        pc &= 0xffffffffffffff00   # mask out chaining bits etc.
        def xp_pmu_event(p,d,e):
            return ((p+1) << 4) | (d << 2) | e
        # Construct event selectors for HN-F events
        evt0 = xp_pmu_event(hnf.device_port(), hnf.device_number(), 0)
        evt1 = xp_pmu_event(hnf.device_port(), hnf.device_number(), 1)
        o_wide = True
        if not o_wide:
            # each XP can count up to four events - and we have two from each SLC
            if BITS(pc,32,16) == 0:
                # not yet used this XP's counters 0 and 1
                # make counters 2 and 3 count the SLC's event 2 (no-event) - avoid XP counting anything else
                evd = xp_pmu_event(hnf.device_port(), hnf.device_number(), 2)
                pc |= (evd << 56) | (evd << 48) | (evt1 << 40) | (evt0 << 32)
            else:
                pc = (evt1 << 56) | (evt0 << 48) | (pc & 0x0000ffffffffffff)
        else:
            pc = (evt1 << 56) | (evt1 << 48) | (evt0 << 40) | (evt0 << 32)
            pc |= CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED | CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED
        pc |= CMN_DTM_PMU_CONFIG_PMU_EN
        if C.verbose:
            print("%s counting %s event %x" % (xp, hnf, pc))
        xp.dtm.dtm_write64(CMN_DTM_PMU_CONFIG_off, pc)
    C.pmu_enable()
    C.dtc_enable()


def cmn_sample_pmu(C):
    """
    Assuming that PMU events are being actively counted, show the rate of change.
    We read PMU counters from the individual XP DTMs, not the DTC overflow counters.
    """
    snap = {}
    for dtm in C.DTMs():
        snap[dtm] = dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
    time.sleep(0.01)
    delta = {}
    def dsub(a,b):
        r = a - b
        if r < 0:
            r += 65536
        return r
    # Read the PMU counters again and get the delta
    for dtm in C.DTMs():
        cr = dtm.dtm_read64(CMN_DTM_PMU_PMEVCNT_off)
        delta[dtm] = [dsub(BITS(cr,i*16,16), BITS(snap[dtm],i*16,16)) for i in range(0,4)]
    for dtm in C.DTMs():
        print("%s: %s" % (dtm, delta[dtm]))


def cmn_instance(opts=None):
    return cmn_devmem_find.cmn_single_locator(opts)


def cmn_from_opts(opts):
    """
    Given some command-line options, return a list of CMNs.
    """
    clocs = list(cmn_devmem_find.cmn_locators(opts))
    if not clocs:
        print("No CMN interconnects found: CMN not present, or system is virtualized", file=sys.stderr)
        sys.exit(1)
    if opts.list_cmn:
        print("CMN devices in memory map:")
        for c in clocs:
            print("  %s" % (c))
        sys.exit()
    CS = [CMN(cl, verbose=opts.verbose, secure_accessible=opts.secure_access) for cl in clocs]
    if opts.cmn_diag:
        for C in CS:
            C.diag_trace |= (DIAG_READS | DIAG_WRITES)
    return CS


if __name__ == "__main__":
    import argparse
    def inthex(s):
        return int(s,16)
    parser = argparse.ArgumentParser(description="CMN mesh interconnect explorer")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--dt-stat", action="store_true", help="show debug/trace status")
    parser.add_argument("--dt-enable", action="store_true", help="enable debug/trace")
    parser.add_argument("--dt-disable-cg", type=int, help="disable (or enable) DTC clock gating")
    parser.add_argument("--diagram", action="store_true", help="show CMN diagram")
    parser.add_argument("--sketch", action="store_true", help="show small CMN diagram")
    parser.add_argument("--watch", action="store_true", help="watch changes in state")
    parser.add_argument("--watch-interval", type=float, default=0.1, help="interval for watching")
    parser.add_argument("--counter-scale", type=int, default=0)
    parser.add_argument("--counter-threshold", type=inthex, default=0x100)
    parser.add_argument("--no-color", action="store_true", help="don't use color output")
    parser.add_argument("--force-color", action="store_true", help="force color output even if not to tty")
    parser.add_argument("--pmu-enable", action="store_true", help="enable PMU events for SLC")
    parser.add_argument("--e0", type=inthex, default=1)
    parser.add_argument("--e1", type=inthex, default=3)
    parser.add_argument("--pmu-sample", action="store_true", help="show PMU counts")
    parser.add_argument("--pmu-snapshot", action="store_true", help="initiate a PMU snapshot")
    parser.add_argument("--dtc", type=int, default=0, help="select DTC node/domain, default DTC#0")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    if opts.watch and not (opts.diagram or opts.sketch):
        opts.diagram = True
    CS = cmn_from_opts(opts)

    #
    # Above was getting a list of CMNs to operate on.
    # Below is actually doing the operations.
    #
    for C in CS:
        print(C)
        if opts.dt_stat:
            for dtm in C.DTMs():
                dtm.show_dtm()
            for dtc in C.debug_nodes:
                dtc.show()
        if opts.diagram or opts.sketch:
            D = CMNDiagramPerf(C, small=(opts.sketch))
            if opts.watch:
                cmn_enable_pmu(C)
                D.hide_cursor()
                while True:
                    print(D.str_color(no_color=opts.no_color, force_color=opts.force_color, for_file=sys.stdout), end="")
                    time.sleep(opts.watch_interval)
                    print(D.cursor_up(), end="")
                    D.clear()
                    D.update()
            else:
                print(D.str_color(no_color=opts.no_color, force_color=opts.force_color, for_file=sys.stdout), end="")
        if opts.dt_enable:
            # Force enable DTC(s), in case they were disabled
            for dtc in C.debug_nodes:
                dtc.dtc_enable()
        if opts.dt_disable_cg is not None:
            C.clock_disable_gating(opts.dt_disable_cg)
        if opts.pmu_enable:
            cmn_enable_pmu(C)
            opts.pmu_stat = True
        if opts.pmu_sample:
            cmn_sample_pmu(C)
        if opts.pmu_snapshot:
            for dtc in C.debug_nodes:
                was_enabled = dtc.dtc_is_enabled()
                dtc.dtc_enable()
                dtc.pmu_enable()
                status = dtc.pmu_snapshot()
                print("PMU snapshot from %s: status=0x%x" % (dtc, status))
                dtc.show()
                dtc.pmu_disable()
                if not was_enabled:
                    dtc.dtc_disable()
