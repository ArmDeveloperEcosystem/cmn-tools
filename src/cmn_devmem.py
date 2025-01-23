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

import os, sys, struct, time
import traceback

import iommap as mmap
import cmn_devmem_find as cmn_find
import cmn_base
from cmn_enum import *

from cmn_diagram import CMNDiagram


def BITS(x,p,n):
    return (x >> p) & ((1<<n)-1)

def BIT(x,p):
    return (x >> p) & 1

def hexstr(x):
    s = ""
    # be portable for Python2/3
    for ix in range(len(x)):
        s += ("%02x" % ord(x[ix:ix+1]))
    return s

assert hexstr(b"\x12\x34") == "1234"


# Diagnostic options for debugging CMN programming issues
DIAG_DEFAULT  = 0x00
DIAG_READS    = 0x01     # Trace all device reads
DIAG_WRITES   = 0x02     # Trace all device writes


class DevMem:
    def __init__(self):
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.fd = None
        self.fd = open("/dev/mem", "r+b")
        self.fno = self.fd.fileno()

    def __del__(self):
        if self.fd is not None:
            self.fd.close()

    def map(self, physaddr, size, write=False):
        assert (size % self.page_size) == 0
        if write:
            prot = (mmap.PROT_READ|mmap.PROT_WRITE)
        else:
            prot = mmap.PROT_READ
        m = mmap.mmap(self.fno, size, mmap.MAP_SHARED, prot, offset=physaddr)
        return m


def map_read64(m, off):
    assert (off % 8) == 0, "invalid offset: 0x%x" % off
    raw = m[off:off+8]
    x = struct.unpack("<Q", raw)[0]
    return x


# Register offsets
# 'any' generally means offset is valid for any node type, or any node type except XP.
CMN_any_NODE_INFO       = 0x0000
CMN_any_CHILD_INFO      = 0x0080
CMN_any_UNIT_INFO       = 0x0900
CMN_any_PMU_EVENT_SEL   = 0x2000     # for some nodes it's 0x2008

CMN_CFG_PERIPH_01       = 0x0008
CMN_CFG_PERIPH_23       = 0x0010

CMN_any_SECURE_ACCESS   = 0x0980



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


class CMNNode:
    """
    A single CMN node, at some offset in the overall peripheral space.
    Spans a 16K range of configuration registers.
    """
    def __init__(self, cmn, node_offset, map=None, write=False, parent=None, is_external=False):
        self.C = cmn
        self.diag_trace = DIAG_DEFAULT       # defer to owning CMN object
        self.parent = parent
        self.is_external = is_external
        assert node_offset not in self.C.offset_node, "node already discovered: %s" % self.C.offset_node[node_offset]
        self.C.offset_node[node_offset] = self
        self.write = write
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
        self.child_info = self.read64(CMN_any_CHILD_INFO)
        #print("%s%s" % ((self.level()*"  "), self))

    def do_trace_reads(self):
        return (self.diag_trace | self.C.diag_trace) & DIAG_READS

    def do_trace_writes(self):
        return (self.diag_trace | self.C.diag_trace) & DIAG_WRITES

    def ensure_writeable(self):
        if not self.write:
            self.m = self.C.D.map(self.node_base_addr, self.C.node_size(), write=True)
            self.write = True

    def read64(self, off):
        if self.do_trace_reads():
            print()
            print("at %s" % self.C.source_line())
            self.C.log("%s: read 0x%x (0x%x)" % (str(self), off, self.node_base_addr+off), end="")
        data = map_read64(self.m, off)
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
        self.ensure_writeable()
        self.check_reg_is_writeable(off)
        if check is None:
            check = self.C.check_writes
        if self.do_trace_writes():
            print("at %s" % self.C.source_line())
            self.C.log("%s: write 0x%x := 0x%x" % (str(self), off, data))
        self.m[off:off+8] = struct.pack("Q", data)
        if check:
            ndata = self.read64(off)
            assert ndata == data, "%s: at 0x%04x wrote 0x%x, read back 0x%x" % (self, off, data, ndata)

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
        lv = 0
        node = self
        while node.parent is not None:
            node = node.parent
            lv += 1
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
            child_node = self.C.create_node(child_offset, parent=self)
            if child_node is None:
                # Probably a child of a RN-F port
                continue
            child_node.is_external = BIT(child, 31)
            self.children.append(child_node)

    def type(self):
        return BITS(self.node_info, 0, 16)

    def type_str(self):
        return cmn_node_type_str(self.type())

    def node_id(self):
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

    def is_home_node(self):
        return self.type() in [CMN_NODE_HNF, CMN_NODE_HNS]

    def XY(self):
        id = self.node_id()
        cb = self.C.coord_bits
        assert cb is not None, "can't get coordinates until mesh size is known"
        Y = BITS(id,3,cb)
        X = BITS(id,3+cb,cb)
        return (X,Y)

    def coords(self):
        """
        Return device coordinates as a tuple (X, Y, P, D).
        For an XP, P and D will be zero.
        Otherwise, P is the port number, and D is the device number.
        D is generally zero, but for CAL-attached devices it may be 0 or 1.
        """
        id = self.node_id()
        (X, Y) = self.XY()
        # If the CMN has at least one XP with more than 2 device ports,
        # all device ids use 2 bits for the port and one for the device.
        # Otherwise it's 1 bit for the port and 2 for the device.
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


# Debug/Trace Monitor registers in XP.
CMN_DTM_CONTROL             = 0x2100
CMN_DTM_CONTROL_DTM_ENABLE             = 0x01
CMN_DTM_CONTROL_TRACE_TAG_ENABLE       = 0x02     # set TraceTag on a match
CMN_DTM_CONTROL_SAMPLE_PROFILE_ENABLE  = 0x04     # use PMSIRR/PMSICR countdown
CMN_DTM_CONTROL_TRACE_NO_ATB           = 0x08     # trace to FIFO in XP
CMN650_DTM_UNIT_INFO           =  0x910    # CMN-650
CMN700_DTM_UNIT_INFO           =  0x960    # CMN-700
CMN_DTM_FIFO_ENTRY_READY    = 0x2118     # write 1 to clear
CMN_DTM_FIFO_ENTRY0_0       = 0x2120
def CMN_DTM_FIFO_ENTRY(fn,dn):
    return CMN_DTM_FIFO_ENTRY0_0 + (fn * 24) + (dn * 8)
CMN_DTM_WP0_CONFIG          = 0x21A0
CMN_DTM_WP0_VAL             = 0x21A8
CMN_DTM_WP0_MASK            = 0x21B0    # 1 bit means ignore
# CMN_DTM_WP1_CONFIG          = 0x21B8
CMN_DTM_PMU_PMSICR          = 0x2200    # sampling interval counter
CMN_DTM_PMU_PMSIRR          = 0x2208    # sampling interval reload (bits 7:0 must be zero)
CMN_DTM_PMU_CONFIG          = 0x2210
CMN_DTM_PMU_CONFIG_PMU_EN              = 0x01   # DTM PMU enable - other fields are valid only when this is set
CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED  = 0x02   # combine PMU counters 0 and 1
CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED  = 0x04   # combine PMU counters 2 and 3
CMN_DTM_PMU_CONFIG_PMEVENTALL_COMBINED = 0x08   # combine PMU counters 0,1,2 and 3
CMN_DTM_PMU_CONFIG_CNTR_RST           = 0x100   # clear live counters upon assertion of snapshot
CMN_DTM_PMU_PMEVCNT         = 0x2220    # DTM event counters 0 to 3: 16 bits each
CMN_DTM_PMU_PMEVCNTSR       = 0x2240    # DTM event counter shadow

# Port connectivity information.
# For CMN-600/650 this is max 2 ports with east/north immediately following.
# For CMN-700 it is up to 6 ports, with east/north following those.
CMN_XP_DEVICE_PORT_CONNECT_INFO_P0  = 0x08
CMN_XP_DEVICE_PORT_CONNECT_INFO_P1  = 0x10
def CMN_XP_DEVICE_PORT_CONNECT_INFO_P(p):
    return 0x08 + 8*p
CMN_XP_DEVICE_PORT_CAL_CONNECTED_BIT = 7

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
        # We maintain a cached copy of the DTM enable bit so we can fault writes
        # to DTM configuration registers when enabled.
        self._dtm_is_enabled = None
        self._dtm_is_enabled = self.dtm_is_enabled()

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
        TBD: Recent CMN allows an XP to have multiple DTMs, with a corresponding
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
        if off >= 0x2100 and off <= 0x22ff and off not in [CMN_DTM_CONTROL, CMN_DTM_FIFO_ENTRY_READY] and self._dtm_is_enabled:
            assert False, "try to write DTM programming register when DTM is enabled"

    def dtm_enable(self):
        """
        Enable debug watchpoint and PMU function; prior to writing this bit,
        all other DT configuration registers must be programmed; once this bit
        is set, other DT configuration registers must not be modified.
        """
        self.set64(CMN_DTM_CONTROL, 0x1)
        self._dtm_is_enabled = True

    def dtm_disable(self):
        self.clear64(CMN_DTM_CONTROL, 0x1)
        self._dtm_is_enabled = False

    def dtm_is_enabled(self):
        """
        Check whether por_dtm_control.dtm_enable is set, indicating that DTM is enabled.
        "Once this bit is set, other DT configuration registers must not be modified."
        """
        e = self.test64(CMN_DTM_CONTROL, CMN_DTM_CONTROL_DTM_ENABLE)
        if self._dtm_is_enabled is not None:
            assert e == self._dtm_is_enabled, "%s: cached DTM enable state out of sync" % self
        return e

    def dtm_clear_fifo(self):
        """
        Ensure the FIFO is empty, after reading its contents.
        Appears to be possible to do this even when the DTM is enabled.
        But it appears that data will still go into the FIFO if trace_no_atb is set.
        """
        #print("%s: DTM control = 0x%x" % (self, self.read64(CMN_DTM_CONTROL)))
        self.write64(CMN_DTM_FIFO_ENTRY_READY, 0xf, check=False)
        #self.write64(CMN_DTM_FIFO_ENTRY_READY, 0x0, check=True)
        fe = self.read64(CMN_DTM_FIFO_ENTRY_READY)
        if fe != 0:
            ctl = self.read64(CMN_DTM_CONTROL)
            self.C.log("%s: FIFO not empty after clearing: 0x%x (control=0x%x)" % (self, fe, ctl))

    def dtm_fifo_ready(self):
        return self.read64(CMN_DTM_FIFO_ENTRY_READY)

    def dtm_fifo_entry(self, e):
        """
        Get a FIFO entry, returning it as (byte string, cycle count)
        """
        assert 0 <= e and e <= N_FIFO_ENTRIES
        ws = []
        for w in range(0, 3):
            ws.append(self.read64(CMN_DTM_FIFO_ENTRY(e, w)))
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
        b = struct.pack("QQQ", ws[0], ws[1], ws[2])[:(dwidth//8)]
        return (b, cc)

    def dtm_wp_details(self, wp):
        """
        Return a tuple indicating the current configuration of a watchpoint,
        so that it can be decoded.
          (nodeid, dev:0..3, wp#, channel:0..3, format:0..7, cc)
        Counterpart of dtm_set_watchpoint()
        """
        assert 0 <= wp and wp <= N_WATCHPOINTS
        cfg = self.read64(CMN_DTM_WP0_CONFIG+(wp*24))
        VC = BITS(cfg, 1, 2)
        dev = BIT(cfg, 0)
        if self.n_device_ports() > 2:
            dev |= (BIT(cfg, 17) << 1)
        type = BITS(cfg, self.C.DTM_WP_PKT_TYPE_SHIFT, 3)
        cc = BIT(cfg, self.C.DTM_WP_PKT_TYPE_SHIFT+3)
        return (self.node_id(), dev, wp, VC, type, cc)

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
        self.set64(CMN_DTM_PMU_CONFIG, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_disable(self):
        self.clear64(CMN_DTM_PMU_CONFIG, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_is_enabled(self):
        return self.test64(CMN_DTM_PMU_CONFIG, CMN_DTM_PMU_CONFIG_PMU_EN)

    def pmu_event_input_selector_str(self, eis):
        if eis <= 0x03:
            return "Watchpoint %u" % eis
        elif eis <= 0x07:
            xpen = eis - 4
            xpe = BITS(self.read64(CMN_any_PMU_EVENT_SEL),(xpen*8),8)
            chn = ["REQ","RSP","SNP","DAT","?4","?5","?6","?7"][BITS(xpe,5,3)]
            ifc = ["E","W","N","S","P0","P1","?6","?7"][BITS(xpe,2,3)]
            evt = ["none", "txvalid", "txstall", "partial"][BITS(xpe,0,2)]
            xpes = "xp-%s-%s-%s" % (ifc, chn, evt)
            return "XP PMU Event %u (event=0x%02x: %s)" % (xpen, xpe, xpes)
        elif eis >= 0x10:
            port = (eis >> 4) - 1
            device = BITS(eis,2,2)
            return "Port %u Device %u PMU Event %u" % (port, device, (eis&3))
        else:
            return "?(eis=0x%x)" % eis

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
                assert dev < self.n_device_ports(), "%s: invalid dev_sel=%u" % (self, dev)
                dev1 = dev >> 1
                config |= (dev1 << 17)
        if group is not None:
            config |= (group << 4)     # for CMN-650 and CMN-700 this is a 2-bit field[5:4]
        if cc:
            # note: must also be enabled in the DTM
            config |= self.C.DTM_WP_CC_EN
        if exclusive:
            config |= self.C.DTM_WP_EXCLUSIVE
        self.write64(CMN_DTM_WP0_VAL+(wp*24), val)
        self.write64(CMN_DTM_WP0_MASK+(wp*24), mask)
        self.write64(CMN_DTM_WP0_CONFIG+(wp*24), config)

    def show_dtm(self, show_pmu=True):
        dtm_control = self.read64(CMN_DTM_CONTROL)
        fifo = self.read64(CMN_DTM_FIFO_ENTRY_READY)
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
            wctl = self.read64(CMN_DTM_WP0_CONFIG+(wp*24))
            wval = self.read64(CMN_DTM_WP0_VAL+(wp*24))
            wmsk = self.read64(CMN_DTM_WP0_MASK+(wp*24))
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
                if fifo & (1<<e):
                    (data, cc) = self.dtm_fifo_entry(e)
                    print("    FIFO #%u: %s cc=0x%04x" % (e, hexstr(data), cc))
        if show_pmu:
            pmu_config = self.read64(CMN_DTM_PMU_CONFIG)
            if pmu_config:
                pmu_pmevcnt = self.read64(CMN_DTM_PMU_PMEVCNT)
                print("    PMU config: 0x%016x" % (pmu_config))
                print("    PMU counts: 0x%016x" % (pmu_pmevcnt))
                show_dtm_pmu_config(self)


# Debug/Trace Controller registers (e.g. CMN-600 TRM Table 3-4)
CMN_DTC_CTL         = 0xA00
CMN_DTC_CTL_DT_EN                   = 0x01    # Enable debug, trace and PMU features
CMN_DTC_CTL_DBGTRIGGER_EN           = 0x02    # DBGWATCHTRIG enable
CMN_DTC_CTL_ATBTRIGGER_EN           = 0x04    # ATB trigger enable
CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER     = 0x08    # Wait for cross trigger before trace enable
CMN_DTC_CTL_CG_DISABLE             = 0x400    # Disable DT architectural clock gates
CMN_DTC_TRACECTRL   = 0xA30
CMN_DTC_TRACECTRL_CC_ENABLE        = 0x100    # Cycle count enable
CMN_DTC_TRACEID     = 0xA48
CMN_DTC_PMEVCNT    = 0x2000    # AB at 0x2000, CD at 0x2010, EF at 0x2020, GH at 0x2030
CMN_DTC_PMCCNTR    = 0x2040    # cycle counter (40-bit)
CMN_DTC_PMEVCNTSR  = 0x2050    # AB at 0x2050, CD at 0x2060, EF at 0x2070, GH at 0x2080 (shadow regs)
CMN_DTC_PMCCNTRSR  = 0x2090    # cycle counter (shadow register)
CMN_DTC_PMCR       = 0x2100    # PMU control register
CMN_DTC_PMCR_PMU_EN        = 0x01
CMN_DTC_PMCR_OVFL_INTR_EN  = 0x40
CMN_DTC_PMOVSR     = 0x2118    # PMU overflow status (read-only)
CMN_DTC_PMOVSR_CLR = 0x2120    # PMU overflow clear (write-only)
CMN_DTC_PMSSR      = 0x2128    # PMU snapshot status (read-only)
CMN_DTC_PMSSR_SS_STATUS     =  0x01ff   # Snapshot status (7:0 events; 8 cycles)
CMN_DTC_PMSSR_SS_CFG_ACTIVE =  0x8000   # PMU snapshot activated from configuration write
CMN_DTC_PMSSR_SS_PIN_ACTIVE = 0x10000   # PMU snapshot activated from PMUSNAPSHOTREQ
CMN_DTC_PMSRR      = 0x2130    # PMU snapshot request (write-only)
CMN_DTC_PMSRR_SS_REQ          = 0x01    # Write-only - request a snapshot
CMN_DTC_CLAIM      = 0x2DA0    # set (lower 32 bits) or clear (upper 32 bits) claim tags
CMN_DTC_AUTHSTATUS_DEVARCH = 0x2DB8


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
                c0a = (ecs[i>>1] & 0xffffffff)
                c1a = (ecs[i>>1] >> 32)
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

    The interconnect has a base address of the entire 256Mb (0x10000000) region,
    and an address within that for the root region.

    Component regions are 16Mb for CMN-600/650 and 64Mb for CMN-700.
    """
    #DTM_WP_PKT_GEN            = 0x0100   # capture a packet (TBD: 0x400 on CMN-700)
    #DTM_WP_CC_EN              = 0x1000   # enable cycle count (TBD: 0x4000 on CMN-700)

    def __init__(self, cmn_loc, check_writes=False, verbose=0, restore_dtc_status=False, secure_accessible=None):
        self.check_writes = check_writes
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
        self.D = DevMem()
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
        id01 = map_read64(temp_m, CMN_CFG_PERIPH_01)
        product_id = (BITS(id01, 32, 4) << 8) | BITS(id01, 0, 8)
        # We can't get chi_version() until we've read unit_info, and
        self.product_config = cmn_base.CMNConfig(product_id=product_id)
        del temp_m
        self.rootnode = self.create_node(rootnode_offset)
        self.unit_info = self.rootnode.read64(CMN_any_UNIT_INFO)
        # The release is e.g. r0p0, r1p2
        self.product_config.revision = BITS(self.rootnode.read64(CMN_CFG_PERIPH_23), 4, 4)
        self.product_config.mpam_enabled = self.part_ge_650() and BIT(self.unit_info, 49)
        self.product_config.chi_version = self.chi_version()
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
            sa = self.rootnode.read64(CMN_any_SECURE_ACCESS)
            self.secure_accessible = (sa == 1)
        if self.verbose:
            sa = self.rootnode.read64(CMN_any_SECURE_ACCESS)
            print("Access to Secure registers: 0x%x (at 0x%x)" % (sa, self.rootnode.node_base_addr+CMN_any_SECURE_ACCESS))

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
        if not self.part_ge_650():
            return 2 + BIT(self.unit_info, 49)
        else:
            return BITS(self.unit_info, 60, 3)

    def chi_version_str(self):
        return "CHI-%s" % "?ABCDEFGH"[self.chi_version()]

    def node_size(self):
        return 0x10000 if self.part_ge_700() else 0x4000

    def create_node(self, node_offset, parent=None):
        assert self.creating
        node_base_addr = self.periphbase + node_offset
        m = self.D.map(node_base_addr, self.node_size())
        node_info = map_read64(m, CMN_any_NODE_INFO)
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
            n = CMNNodeDT(self, node_offset, map=None, parent=parent, write=True)
            assert n not in self.debug_nodes
            self.debug_nodes.append(n)
        elif node_type == CMN_NODE_XP:
            # Crosspoint - parent of other nodes
            assert BITS(node_info, 16, 3) == 0, "expected 3 LSB of XP coordinates to be 0"
            n = CMNNodeXP(self, node_offset, map=None, parent=parent, write=True)
            assert n.logical_id() not in self.logical_id_XP, "XPs have duplicate logical_id 0x%x" % n.logical_id()
            self.logical_id_XP[n.logical_id()] = n
            n.discover_children()
        elif node_info == 0:
            # Under XPs with RN-F ports, we sometimes see a valid child offset that points to zeroes
            n = None
        else:
            n = CMNNode(self, node_offset, map=m, parent=parent)
        if n is not None and node_type != CMN_NODE_XP and node_has_logical_id(node_type):
            nid = n.logical_id()
            nk = (node_type, n.logical_id())
            assert nk not in self.logical_id, "Nodes have duplicate logical ID: %s, %s" % (self.logical_id[nk], n)
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

    def XPs(self):
        return self.nodes_of_type(CMN_NODE_XP)

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


def mem_size(n):
    if n >= 30:
        s = "%uG" % (1 << (n-30))
    elif n >= 20:
        s = "%uM" % (1 << (n-20))
    elif n >= 10:
        s = "%uK" % (1 << (n-10))
    else:
        s = "%u" % (1 << n)
    return s


def show_dtm_pmu_config(xp):
    # Show dynamic configuration of the XP as an event collector (not generator)
    pmu_config = xp.read64(CMN_DTM_PMU_CONFIG)
    if pmu_config != 0:
        print("      PMU config: 0x%016x  counters: 0x%016x" % (pmu_config, xp.read64(CMN_DTM_PMU_PMEVCNT)))
        for i in range(0,4):
            eis = BITS(pmu_config,32+i*8,8)     # on CMN-6xx it's only 6 bits
            egc = BITS(pmu_config,16+i*4,3)
            paired = [0,BIT(pmu_config,1)|BIT(pmu_config,3),BIT(pmu_config,3),BIT(pmu_config,2)|BIT(pmu_config,3)][i]
            print("       %s%u:" % (" +"[paired], i), end="")
            if BIT(pmu_config,4+i):
                print(" [global %u]" % egc, end="")
            print(" event 0x%02x: %s" % (eis, xp.pmu_event_input_selector_str(eis)))


def show_cmn(cmn, verbose=0):
    """
    Iterate through the crosspoints, ports and nodes of the CMN,
    printing a description to stdout.
    """
    print("%s:" % cmn.product_str())
    print("  info: 0x%016x:" % cmn.unit_info, end="")
    print(" REQ=%u-bit, PA=%u-bit" % (BITS(cmn.unit_info, 8, 8), BITS(cmn.unit_info, 16, 8)), end="")
    print(", %s" % cmn.chi_version_str(), end="")
    if BIT(cmn.unit_info, 48):
        print(", R2", end="")
    if cmn.product_config.mpam_enabled:
        print(", MPAM", end="")
    print()
    print("  %s" % cmn.rootnode)
    for xp in cmn.XPs():
        n_ports = xp.n_device_ports()
        print("    %s: n_ports=%u" % (xp, n_ports), end="")
        dtc_domain = xp.dtc_domain()
        if dtc_domain is not None:
            print(", dtc_domain=%d" % xp.dtc_domain(), end="")
        print()
        # Show XP information
        xp.show()
        if False:
            show_dtm_pmu_config(xp)
        # Show the XP's child devices. Although these are discovered directly from the XP,
        # we group them by their device port.
        for p in range(0, n_ports):
            port_info = xp.port_info(p)
            connected_device_info = xp.read64(CMN_XP_DEVICE_PORT_CONNECT_INFO_P(p))
            connected_device_type = BITS(connected_device_info, 0, 5)
            print("      P%u:" % p, end="")
            print(" %s" % cmn_port_device_type_str(connected_device_type), end="")
            if BIT(connected_device_info, 7):
                print(" (CAL)", end="")
            num_dev = BITS(port_info, 0, 3)
            print(" devices=%u" % num_dev, end="")
            if verbose:
                print(" [port_info=0x%x, port_connect_info=0x%x]" % (port_info, connected_device_info), end="")
            print()
            # On a port, there may be multiple nodes, which are
            # enumerated as child nodes of the XP.
            # This multiplicity arises for two reasons:
            #  - some devices present multiple functional interfaces, e.g.
            #    a RN-D presents as both an RN-D and an RN-SAM.
            #    These will have identical coordinates.
            #  - a CAL may be used to connect two distinct devices of the same type,
            #    e.g. two HN-Fs. Their coordinates will differ in the 'device' number.
            for n in xp.port_nodes(p):
                info = n.read64(CMN_any_UNIT_INFO)
                print("        %s (info: 0x%x)" % (n, info))
                assert n.XP() == xp
                if n.is_home_node():
                    slc_size = BITS(info, 0, 4)
                    slc_ways = BITS(info, 8, 5)
                    sf_size = BITS(info, 4, 3)
                    if not cmn.part_ge_700():
                        num_poc_entries = BITS(info, 32, 7)
                        sf_ways = 16
                    else:
                        num_poc_entries = BITS(info, 31, 8)
                        sf_ways = BITS(info, 54, 6)
                    if slc_size:
                        if not cmn.part_ge_700():
                            slc_sizes = [None, "128K", "256K", "512K", "1M", "2M", "3M", "4M"]
                        else:
                            slc_sizes = [None, "128K", "256K", "512K", "1M", "1.5M", "2M", "3M", "4M", "384K"]
                        print("          SLC: %s %u-way tag:%u data:%u" % (slc_sizes[slc_size], slc_ways, BITS(info,16,3), BITS(info,20,3)))
                    print("          SF: %s per way, %u-way" % (mem_size(sf_size+15), sf_ways))
                    print("          POCQ entries: %u" % (num_poc_entries))
                    if cmn.product_config.mpam_enabled:
                        mpam_ns_pmg = BITS(info, 43, 1) + 1
                        mpam_ns_partid = 1 << BITS(info, 39, 4)
                        print("          MPAM(NS): %u PMG, %u PARTID" % (mpam_ns_pmg, mpam_ns_partid))
                    if cmn.secure_accessible:
                        aux_ctl = n.read64(0xA08)
                        print("          aux_ctl: 0x%x" % aux_ctl)
                elif n.type() == CMN_NODE_HNI:
                    num_excl = BITS(info,0,8)
                    num_ax_reqs = BITS(info,8,8)
                    num_wr_data_buf = BITS(info,16,5)
                    width = 128 << BIT(info,24)
                    a4s_num = BITS(info,25,2)
                    print("          AXI: %u-bit, %u AXI4 requests, %u write buffers, %u stream" % (width, num_ax_reqs, num_wr_data_buf, a4s_num))
                    print("          Exclusive monitors: %u" % (num_excl))
                elif n.type() == CMN_NODE_RND:
                    num_rd_bufs = BITS(info,20,10)
                    width = 128 << BIT(info,30)
                    a4s_num = BITS(info,33,2)
                    print("          AXI: %u-bit, %u read buffers, %u stream" % (width, num_rd_bufs, a4s_num))
                elif n.type() == CMN_NODE_SBSX:
                    width = 128 << BIT(info,0)
                    num_wr_data_buf = BITS(info,16,5)
                    print("          AXI: %u-bit, %u write buffers" % (width, num_wr_data_buf))
                elif n.type() == CMN_NODE_RNSAM:
                    num_nhm = BITS(info,32,6)
                    num_sys_cache_group = BITS(info,16,4)
                    num_hnf = BITS(info,0,8)
                    print("          Hashed targets: %u, cache groups: %u, non-hash groups: %u" % (num_hnf, num_sys_cache_group, num_nhm))
                elif n.type() == CMN_NODE_DT:
                    n.show(pfx="        ")
                elif n.type() == CMN_NODE_CXHA:
                    rdb_depth = BITS(info, 9, 9)
                    wdb_depth = BITS(info, 18, 9)
                    print("          Read buffer: %u, write buffer: %u" % (rdb_depth, wdb_depth))
                    request_tracker_depth = BITS(info, 0, 9)
                    print("          Request tracker depth: %u" % (request_tracker_depth))
                    # other config is Secure only
                elif n.type() == CMN_NODE_CXRA:
                    rdb_depth = BITS(info, 25, 9)
                    wdb_depth = BITS(info, 34, 9)
                    print("          Read buffer: %u, write buffer: %u" % (rdb_depth, wdb_depth))
                    request_tracker_depth = BITS(info, 16, 9)
                    print("          Request tracker depth: %u" % (request_tracker_depth))
                    # other config is Secure only
                elif n.type() == CMN_NODE_CXLA:
                    pass      # not much interesting non-Secure info
                elif n.type() == CMN_NODE_DN:
                    pass      # not much interesting non-Secure info
                else:
                    print("          <no information for node: %s>" % (n))
                if n.type() in [CMN_NODE_HNF, CMN_NODE_HNS]:
                    # Show events generated by this node - meaning will depend on node type.
                    # We should really show this for XPs as well.
                    events = n.read64(CMN_any_PMU_EVENT_SEL)
                    if events != 0:
                        print("          events: 0x%016x" % events)
                elif n.type() == CMN_NODE_RNSAM:
                    if cmn.secure_accessible:
                        def nonhash(r):
                            nhm = [0xC08, 0xC10, 0xC18, 0xC20, 0xC28, 0xCA0, 0xCA8, 0xCB0, 0xCB8, 0xCC0]
                            nhn = [0xC30, 0xC38, 0xC40, 0xCE0, 0xCE8]
                            i2 = n.read64(nhm[r//2])
                            info = BITS(i2, (r&1)*32, 32)
                            n4 = n.read64(nhn[r//4])
                            nodeid = BITS(n4, (r&3)*12, 11)
                            return (info, nodeid)
                        for r in range(0, 20):
                            (info, nodeid) = nonhash(r)
                            if True or (info & 1):
                                ty = BITS(info, 2, 2)
                                base = BITS(info, 9, 22) << 26
                                size = BITS(info, 4, 5)
                                print("            NHMR %3u: type=%u base=0x%016x size=%u node=0x%x" % (r, ty, base, size, nodeid))
                        if False:
                            for r in range(0xC58, 0xC98, 8):
                                print("    0x%x = 0x%x" % (r, n.read64(r)))
                            for r in range(0xD08, 0xD48, 8):
                                print("    0x%x = 0x%x" % (r, n.read64(r)))


def list_logical(c, verbose=0):
    """
    List nodes grouped by logical id
    """
    nodes = {}
    for (t, lid) in c.logical_id.keys():
        if t not in nodes:
            nodes[t] = {}
        assert lid not in nodes[t]     # not expected: logical id clash would have been detected already
        nodes[t][lid] = c.logical_id[(t, lid)]
    for t in sorted(nodes):
        print("  Node type: %s" % cmn_node_type_str(t))
        for lid in sorted(nodes[t]):
            print("   %3u: %s" % (lid, nodes[t][lid]))


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
            self.pmu_config[xp] = xp.read64(CMN_DTM_PMU_CONFIG)
        self.pmu = {}
        self.capture_pmu()
        self.update()

    def capture_pmu(self):
        for xp in self.C.XPs():
            self.pmu[xp] = xp.read64(CMN_DTM_PMU_PMEVCNT)

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
            if xp.pmu_is_enabled():
                (cx, cy) = self.XP_xy(xp)
                # Get the current PMU values, and calculate the deltas.
                cfg = self.pmu_config[xp]
                opd = self.pmu[xp]          # Previous snapshot
                npd = xp.read64(CMN_DTM_PMU_PMEVCNT)
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


def cmn_instance(opts=None):
    return cmn_find.cmn_single_locator(opts)


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
    for xp in C.XPs():
        xp.write64(CMN_DTM_PMU_CONFIG, 0)
    for hnf in C.nodes_of_type(CMN_NODE_HNF):
        hnf_evt0 = opts.e0
        hnf_evt1 = opts.e1
        hnf.write64(CMN_any_PMU_EVENT_SEL, (hnf_evt1 << 8) | (hnf_evt0))
        xp = hnf.XP()
        pc = xp.read64(CMN_DTM_PMU_CONFIG)
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
        xp.write64(CMN_DTM_PMU_CONFIG, pc)
    C.pmu_enable()
    C.dtc_enable()


def cmn_sample_pmu(C):
    """
    Assuming that PMU events are being actively counted, show the rate of change.
    We read PMU counters from the individual XP DTMs, not the DTC overflow counters.
    """
    snap = {}
    for xp in C.XPs():
        snap[xp] = xp.read64(CMN_DTM_PMU_PMEVCNT)
    time.sleep(0.01)
    delta = {}
    def dsub(a,b):
        r = a - b
        if r < 0:
            r += 65536
        return r
    # Read the PMU counters again and get the delta
    for xp in C.XPs():
        cr = xp.read64(CMN_DTM_PMU_PMEVCNT)
        delta[xp] = [dsub(BITS(cr,i*16,16), BITS(snap[xp],i*16,16)) for i in range(0,4)]
    for xp in C.XPs():
        print("%s: %s" % (xp, delta[xp]))


if __name__ == "__main__":
    import argparse
    def inthex(s):
        return int(s,16)
    parser = argparse.ArgumentParser(description="CMN mesh interconnect explorer")
    cmn_find.add_cmnloc_arguments(parser)
    parser.add_argument("--list-cmn", action="store_true", help="list all CMN devices in system")
    parser.add_argument("--list-logical", action="store_true", help="list nodes by logical id")
    parser.add_argument("--list", action="store_true", help="list CMN nodes")
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
    parser.add_argument("--secure-access", action="store_true", help="assume Secure registers are accessible")
    parser.add_argument("--diag", action="store_true")    # internal diagnostics
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    if opts.watch and not (opts.diagram or opts.sketch):
        opts.diagram = True
    clocs = list(cmn_find.cmn_locators(opts))
    if not clocs:
        print("No CMN interconnects found: CMN not present, or system is virtualized", file=sys.stderr)
        sys.exit(1)
    if opts.list_cmn:
        print("CMN devices in memory map:")
        for c in clocs:
            print("  %s" % (c))
        sys.exit()
    CS = [CMN(cl, verbose=opts.verbose, secure_accessible=opts.secure_access) for cl in clocs]

    if opts.diag:
        for C in CS:
            C.diag_trace |= (DIAG_READS|DIAG_WRITES)
    #
    # Above was getting a list of CMNs to operate on.
    # Below is actually doing the operations.
    #
    for C in CS:
        print(C)
        if opts.list:
            show_cmn(C, verbose=opts.verbose)
        if opts.list_logical:
            list_logical(C, verbose=opts.verbose)
        if opts.dt_stat:
            for xp in C.XPs():
                xp.show_dtm()
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
