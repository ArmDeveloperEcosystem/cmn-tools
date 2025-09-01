#!/usr/bin/python

"""
CMN (Coherent Mesh Network) node lister

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Shows detailed information about CMN, by accessing the CMN device directly.
"""

from __future__ import print_function


import os
import sys


from cmn_devmem import CMN, cmn_from_opts
from cmn_devmem_regs import *
import cmn_devmem_find
from cmn_enum import *
import cmn_select
import cmn_dtstat
from cmn_sam import *
import cmn_routing


o_register_slices = False


def BITS(x,p,n):
    return (x >> p) & ((1 << n)-1)


def BIT(x,p):
    return (x >> p) & 1


def lookup(m, k, name):
    return m[k] if k in m else ("?%s=%s" % (name, k))


class CMNLister:
    def __init__(self, cmn, verbose=0, port_props=None, node_props=None, node_match=None):
        self.cmn = cmn
        self.verbose = verbose
        self.port_props = port_props
        self.node_props = node_props
        self.node_match = node_match

    def show_cmn(self, cmn=None):
        """
        Iterate through the crosspoints, ports and nodes of the CMN,
        printing a description to stdout.
        """
        if cmn is not None:
            self.cmn = cmn
        print("%s:" % self.cmn)
        print("  %s" % cmn.rootnode)
        if not (self.node_match is not None and not self.node_match.match_node(self.cmn.rootnode)):
            self.show_cmn_itself()
        for xp in self.cmn.XPs():
            self.show_xp(xp)

    def show_cmn_itself(self):
        cmn = self.cmn
        print("      info: 0x%016x:" % cmn.unit_info, end="")
        print(" REQ=%u-bit, PA=%u-bit" % (BITS(cmn.unit_info, 8, 8), BITS(cmn.unit_info, 16, 8)), end="")
        print(", %s" % cmn.chi_version_str(), end="")
        if BIT(cmn.unit_info, 48):
            print(", R2", end="")
        if cmn.product_config.mpam_enabled:
            print(", MPAM", end="")
        if cmn.multiple_dtms:
            print(", multiple-DTMs", end="")
        if cmn.isolation_enabled:
            print(", device-isolation", end="")
        print()
        if cmn.part_ge_700():
            info1 = cmn.rootnode.read64(0x908)
            print("      info1: 0x%x" % info1, end="")
            print(", REQ=%u" % BITS(info1, 0, 2), end="")
            print(", SNP=%u" % BITS(info1, 2, 2), end="")
            if BIT(info1, 19):
                print(", MTE", end="")
            if BIT(info1, 23):
                print(", compact-HN-tables", end="")
            print()
        # Print read-only configuration registers - mostly opaque
        print("      periph_id:", end="")
        for r in range(0x8, 0x28, 8):
            pid = cmn.rootnode.read64(r)
            print(" 0x%x 0x%x" % (BITS(pid, 0, 32), BITS(pid, 32, 32)), end="")
        print()
        print("      component_id:", end="")
        for r in range(0x28, 0x38, 8):
            cid = cmn.rootnode.read64(r)
            print(" 0x%x 0x%x" % (BITS(cid, 0, 32), BITS(cid, 32, 32)), end="")
        print()

    def show_xp(self, xp, pfx="    "):
        if self.node_match is not None and not self.node_match.match_node(xp):
            pass
        else:
            self.show_xp_itself(xp, pfx=pfx)
        if self.node_match is not None and not self.node_match.can_match_devices_at_xp(xp):
            pass
        else:
            self.show_xp_nodes(xp, pfx=(pfx + "  "))

    def show_xp_itself(self, xp, pfx="    "):
        cmn = xp.C
        verbose = self.verbose
        sec = xp.read64(CMN_any_SECURE_ACCESS)
        n_ports = xp.n_device_ports()
        print(pfx + "%s: n_ports=%u" % (xp, n_ports), end="")
        dtc_domain = xp.dtc_domain()
        if dtc_domain is not None:
            print(", dtc_domain=%d" % xp.dtc_domain(), end="")
        if sec != 0:
            print(", security=0x%x" % sec, end="")
        # print(", child_info=0x%x" % xp.child_info, end="")
        if o_register_slices:
            # Show info about the east and north mesh links.
            for (i, dir) in enumerate(["east", "north"]):
                mcs = xp.mesh_credited_slices(i)
                if mcs > 0:
                    print(", %s-mcs=%u" % (dir, mcs), end="")
        print()
        pfx += "  "
        # Show XP information
        xp.show()
        self.show_node_event_sel(xp, pfx=pfx)
        if verbose >= 1:
            # Show XP DTM information
            for dtm in xp.DTMs():
                cmn_dtstat.print_dtm(dtm, pfx=pfx)
        if xp.C.secure_accessible:
            if xp.C.part_ge_650():
                printed_ovr = False
                MAX_XY_OVERRIDE = 8
                for i in range(0, MAX_XY_OVERRIDE):
                    xyo = xp.read64(0xC90 + (i*8))
                    if BIT(xyo, 63):
                        if not printed_ovr:
                            print(pfx + "XY override:")
                            printed_ovr = True
                        for j in range(0, 2):
                            ho = BITS(xyo, 32*j, 32)
                            print("        0x%3x -> 0x%3x" % (BITS(ho, 16, 11), BITS(ho, 4, 11)), end="")
                            if BIT(ho, 0):
                                print(" xy-override", end="")
                            if BIT(ho, 1):
                                print(" yx_turn", end="")
                            if BIT(ho, 2):
                                print(" cal-tgt", end="")
                            print()

    def show_xp_nodes(self, xp, pfx="      "):
        """
        Show the XP's child devices. Although these are discovered directly from the XP,
        we group them by their device port.
        """
        for p in range(0, xp.n_device_ports()):
            port = xp.port_object(p)
            if port.has_properties(self.port_props):
                self.show_port_itself(port, pfx=pfx)
                self.show_port_nodes(port, pfx=(pfx+"  "))

    def show_port_itself(self, port, pfx="      "):
        p = port.rP
        print(pfx + "P%u at 0x%x:" % (p, port.base_id()), end="")
        if True:
            port_info = port.port_info()
            port_info_1 = port.port_info(1) if port.xp.C.part_ge_700() else None
            connected_device_info = port.connect_info
            connected_device_type = port.device_type()
            if connected_device_type is None:
                # The TRM says 0 is "reserved", but it evidently means the port is not connected.
                # Ports are connected or not, by the implementer. With n_ports=2,
                # we've observed all combinations of P0+P1, P0 only, P1 only, no ports.
                print(" no devices")
                return
            print(" %s" % cmn_port_device_type_str(connected_device_type), end="")
            # For a port with a CAL, num_dev indicates CAL2 vs CAL4.
            # A CCG has num_dev=1 but also has child nodes with device numbers 0 and 1.
            num_dev = BITS(port_info, 0, 3)
            if BIT(connected_device_info, 7):
                print(" (CAL%u)" % num_dev, end="")
            elif num_dev != 1:
                print(" devices=%u" % num_dev, end="")
            if self.verbose:
                print(" [port_info=0x%x, port_connect_info=0x%x]" % (port_info, connected_device_info), end="")
                if port_info_1 is not None:
                    print(" [port_info_1=0x%x]" % (port_info_1), end="")
            print()
            pfx += "  "
            if o_register_slices:
                if BITS(connected_device_info, 16, 16) or BITS(connected_device_info, 8, 4):
                    print(pfx + "Device credited slices:", end="")
                    for d in range(num_dev):
                        dcs = BITS(connected_device_info, 16+(d*4), 4)
                        if dcs > 0:
                            print(" D%u:%u" % (d, dcs), end="")
                    calcs = BITS(connected_device_info, 8, 4)
                    if calcs > 0:
                        print(" CAL:%u" % (calcs), end="")
                    print()
            if port.xp.C.part_ge_700():
                port_ldid_info = port.xp.read64(CMN_XP_DEVICE_PORT_CONNECT_LDID_INFO_P(p))
                if port_ldid_info != 0:
                    print(pfx + "LDIDs:", end="")
                    for dev in range(0, num_dev):
                        print(" D%u:0x%x" % (dev, BITS(port_ldid_info, dev*16, 12)), end="")
                    print()
            if port.xp.C.secure_accessible:
                qos_ctl = port.xp.read64(0xA80 + p*32)
                qos_lat = port.xp.read64(0xA88 + p*32)
                qos_lsc = port.xp.read64(0xA90 + p*32)
                qos_lrg = port.xp.read64(0xA98 + p*32)
                if (qos_ctl | qos_lat | qos_lsc | qos_lrg):
                    print(pfx + "QoS: ", end="")
                    print("ctl=0x%x, lat=0x%x, lsc=0x%x, lrg=0x%x" % (qos_ctl, qos_lat, qos_lsc, qos_lrg), end="")
                    if cmn.product_config.mpam_enabled:
                        mpam_ovr = port.xp.read64(0xA10 + p*8)
                        if BIT(mpam_ovr, 0):
                            print(" mpam=0x%x" % mpam_ovr, end="")
                    print()

    def show_port_nodes(self, port, pfx="        "):
        # On a port, there may be multiple nodes, which are
        # enumerated as child nodes of the XP.
        # This multiplicity arises for two reasons:
        #  - some devices present multiple functional interfaces, e.g.
        #    a RN-D presents as both an RN-D and an RN-SAM.
        #    These will have identical coordinates.
        #  - a CAL may be used to connect two distinct devices of the same type,
        #    e.g. two HN-Fs. Their coordinates will differ in the 'device' number.
        last_device = None
        for n in port.nodes():
            if not cmn_node_type_has_properties(n.type(), self.node_props):
                continue
            if self.node_match is not None and not self.node_match.match_node(n):
                if self.verbose:
                    print(pfx + "%s: skipped as does not match %s" % (n, self.node_match))
                continue
            dn = n.device_number()
            if dn != last_device:
                print(pfx + "D%u at 0x%x" % (dn, port.base_id() + dn))
                last_device = dn
            self.show_node(n, pfx=(pfx+"  "))

    def show_node(self, n, pfx="        "):
        cmn = self.cmn
        xp = n.XP()
        info = n.read64(CMN_any_UNIT_INFO)
        info1 = None
        info2 = None
        if cmn.part_ge_700():
            info1 = n.read64(CMN_any_UNIT_INFO1)
            if n.type() in [CMN_NODE_CCLA, CMN_NODE_CCG_HA]:
                info2 = n.read64(0x910)
        sec = n.read64(CMN_any_SECURE_ACCESS)
        print(pfx + "%s (node info: 0x%x, unit info: 0x%x" % (n, n.node_info, info), end="")
        if info1 is not None:
            print(",info1=0x%x" % info1, end="")
        if info2 is not None:
            print(",info2=0x%x" % info2, end="")
        print(")", end="")
        if sec:
            print(", security=0x%x" % sec, end="")
        print()
        pfx += "  "
        if n.XY() != xp.XY():
            # Has been seen with CXLA (external) nodes on CMN-600
            print(pfx + "** node has anomalous coordinates: %s, expected %s" % (str(n.XY()), str(xp.XY())))
        if n.is_home_node():
            cg = n.cache_geometry()
            if not cmn.part_ge_700():
                num_poc_entries = BITS(info, 32, 7)
            else:
                num_poc_entries = BITS(info, 31, 8)
            if cg.exists():
                print(pfx + "SLC: %s tag:%u data:%u" % (cg.cache_str(), BITS(info,16,3), BITS(info,20,3)))
            print(pfx + "SF: %s" % cg.sf_str())
            print(pfx + "POCQ entries: %u" % (num_poc_entries))
            pwbase = 0x1C00 if cmn.part_ge_650() else 0x1000
            pwsr = n.read64(pwbase + 0x08)
            if pwsr != 0x138:
                # We expect power to be ON FAM, with dynamic transitions enabled
                print(pfx + "Power: ", end="")
                print(lookup({8: "ON", 7: "FUNC_RET", 2: "MEM_RET", 0: "OFF"}, BITS(pwsr, 0, 4), "status"), end="")
                print(" " + lookup({3: "FAM", 2: "HAM", 1: "SFONLY", 0: "NOSFSLC"}, BITS(pwsr, 4, 4), "mode"), end="")
                if BIT(pwsr, 8):
                    print(" dynamic", end="")
                print()
            print(pfx + "Power arch=0x%x id=0x%x" % (n.read64(pwbase + 0xfc8), n.read64(pwbase + 0xfb0)))
            if cmn.product_config.mpam_enabled:
                mpam_ns_pmg = BITS(info, 43, 1) + 1
                mpam_ns_partid = 1 << BITS(info, 39, 4)
                print(pfx + "MPAM(NS): %u PMG, %u PARTID" % (mpam_ns_pmg, mpam_ns_partid))
            if cmn.secure_accessible:
                aux_ctl = n.read64(CMN_any_AUX_CTL)
                print(pfx + "aux_ctl: 0x%x" % aux_ctl)
                pwpr = n.read64(0x1000)    # power policy register
                print(pfx + "pwpr: 0x%x" % pwpr, end="")
                print(" %s" % {0: "OFF", 2: "MEM_RET", 7: "FUNC_RET", 8: "ON"}[BITS(pwpr, 0, 4)], end="")
                print(" %s" % ["NOSFSLC", "SFONLY", "HAM", "FAM"][BITS(pwpr, 4, 4)], end="")
                if BIT(pwpr, 8):
                    print(" dynamic", end="")
                print()
        elif n.type() in [CMN_NODE_HNI, CMN_NODE_HNP]:
            num_excl = BITS(info,0,8)
            num_ax_reqs = BITS(info,8,8)
            num_wr_data_buf = BITS(info,16,5)
            width = 128 << BIT(info,24)
            a4s_num = BITS(info,25,2)
            print(pfx + "AXI: %u-bit, %u AXI4 requests, %u write buffers, %u stream" % (width, num_ax_reqs, num_wr_data_buf, a4s_num))
            print(pfx + "Exclusive monitors: %u" % (num_excl))
            if cmn.secure_accessible:
                cfg = n.read64(0xA00)
                aux = n.read64(0xA08)
                print(pfx + "cfg: 0x%016x" % cfg)
                print(pfx + "aux: 0x%016x" % aux)
        elif n.type() == CMN_NODE_RND:
            num_rd_bufs = BITS(info,20,10)
            width = 128 << BIT(info,30)
            a4s_num = BITS(info,33,2)
            print(pfx + "AXI: %u-bit, %u read buffers, %u stream" % (width, num_rd_bufs, a4s_num))
            if cmn.secure_accessible:
                cfg = n.read64(0xA00)
                aux = n.read64(0xA08)
                print(pfx + "cfg: 0x%016x" % cfg)
                print(pfx + "aux: 0x%016x" % aux)
        elif n.type() == CMN_NODE_SBSX:
            width = 128 << BIT(info,0)
            num_wr_data_buf = BITS(info,16,5)
            print(pfx + "AXI: %u-bit, %u write buffers" % (width, num_wr_data_buf))
        elif n.type() == CMN_NODE_RNSAM:
            # Only Non-Secure-readable summary here. Detailed configuration is printed later.
            num_nhm = BITS(info,32,6)
            num_sys_cache_group = BITS(info,16,4)
            num_hnf = BITS(info,0,8)
            print(pfx + "Hashed targets: %u, cache groups: %u, non-hash groups: %u" % (num_hnf, num_sys_cache_group, num_nhm))
        elif n.type() == CMN_NODE_DT:
            cmn_dtstat.print_dtc(n, pfx=pfx)
        elif n.type() == CMN_NODE_CXHA:
            rdb_depth = BITS(info, 9, 9)
            wdb_depth = BITS(info, 18, 9)
            print(pfx + "Read buffer: %u, write buffer: %u" % (rdb_depth, wdb_depth))
            request_tracker_depth = BITS(info, 0, 9)
            print(pfx + "Request tracker depth: %u" % (request_tracker_depth))
            # other config is Secure only
        elif n.type() == CMN_NODE_CXRA:
            rdb_depth = BITS(info, 25, 9)
            wdb_depth = BITS(info, 34, 9)
            print(pfx + "Read buffer: %u, write buffer: %u" % (rdb_depth, wdb_depth))
            request_tracker_depth = BITS(info, 16, 9)
            print(pfx + "Request tracker depth: %u" % (request_tracker_depth))
            # other config is Secure only
        elif n.type() == CMN_NODE_CXLA:
            db_present = BIT(info, 0)
            db_fifo_depth = BITS(info, 16, 5)
            if db_present:
                print(pfx + "Domain bridge FIFO depth: %u" % (db_fifo_depth))
            if cmn.secure_accessible:
                aux_ctl = n.read64(CMN_any_AUX_CTL)
                smp_mode_en = BIT(aux_ctl, 47)
                if smp_mode_en:
                    print(pfx + "SMP mode enabled")
        elif n.type() == CMN_NODE_DN:
            pass      # not much interesting non-Secure info
        elif n.type() in [CMN_NODE_MPAM_NS, CMN_NODE_HNS_MPAM_NS] or (n.type() in [CMN_NODE_MPAM_S, CMN_NODE_HNS_MPAM_S] and cmn.secure_accessible):
            idr = n.read64(0x1000)
            aidr = n.read64(0x1020)
            iidr = n.read64(0x1018)
            print(pfx + "MPAM architecture %u.%u, idr=0x%x, iidr=0x%x" % (BITS(aidr, 4, 4), BITS(aidr, 0, 4), idr, iidr))
        else:
            print(pfx + "<no information for node: %s>" % (n))
        self.show_node_event_sel(n)
        if n.is_home_node():
            if cmn.secure_accessible:
                self.show_home_node_secure_config(n)
                self.show_home_node_sam(n)
        elif n.type() == CMN_NODE_RNSAM:
            if cmn.secure_accessible:
                self.show_rn_sam(n)

    def show_node_event_sel(self, n, pfx="          "):
        """
        Show PMU events generated by this node - meaning will depend on node type.
        """
        for esel in n.PMU_EVENT_SEL:
            events = n.read64(esel)
            if events != 0:
                print(pfx + "events: 0x%016x" % events, end="")
                if esel > n.PMU_EVENT_SEL_BASE:
                    print(" (selector %u)" % ((esel-n.PMU_EVENT_SEL_BASE)>>3), end="")
                print()

    def show_home_node_secure_config(self, n, pfx="          "):
        """
        Show home-node Secure config, other than address-mapping: mostly QoS.
        """
        hn_qos_band = n.read64(0xA80)
        hn_qos_resv = n.read64(0xA88)
        hn_starv = n.read64(0xA90)
        print(pfx + "QoS bands:")
        for (i, qc) in enumerate(["L", "M", "H", "HH"]):
            (lo, hi) = (BITS(hn_qos_band, i*8, 4), BITS(hn_qos_band, i*8+4, 4))
            pocq = BITS(hn_qos_resv, i*8, 8)
            print(pfx + "  %3s  %2u..%2u  POCQ=%3u" % (qc, lo, hi, pocq))
        print(pfx + "QoS max wins:", end="")
        for (i, qs) in enumerate(["M/L", "H/L", "HH/L", "H/M", "HH/M", "HH/H"]):
            print(" %s:%u" % (qs, BITS(hn_starv, i*8, 7)), end="")
        print()
        print(pfx + "POCQ reserved for SF evictions: %3u" % (BITS(hn_qos_resv, 32, 8)))
        slc_lock = n.read64(0xC00)
        print(pfx + "HN-Fs: %u, locked ways: %u" % (BITS(slc_lock, 8, 7), BITS(slc_lock, 0, 4)))

    def show_home_node_sam(self, n, pfx="          "):
        # HN mapping:
        #   Range-based mapping, then...
        #   Either direct mapping, or multi-SN striped mapping
        hn_sam_ctl = n.read64(0xD00)
        hn_sam_ctl2 = n.read64(0xD28) if n.C.part_ge_700() else 0x0
        print(pfx + "HN SAM control: 0x%x" % hn_sam_ctl)
        # Show range-based mapping first, as it takes priority
        for reg in hn_sam_regions(n):
            print(pfx + "  region %u: %s" % (reg.index, reg.range_str()), end="")
            print(" SN:0x%x" % reg.nodeid, end="")
            print()
        sns = 0
        if BIT(hn_sam_ctl, 36):
            sns = 3
        elif BIT(hn_sam_ctl, 37):
            sns = 6
        elif BIT(hn_sam_ctl, 38):
            sns = 5
        elif BIT(hn_sam_ctl2, 0):
            sns = 2
        elif BIT(hn_sam_ctl2, 1):
            sns = 4
        elif BIT(hn_sam_ctl2, 2):
            sns = 8
        if sns:
            print(pfx + "  %u-SN:" % sns, end="")
            for i in range(0, sns):
                if i < 3:
                    snid = BITS(hn_sam_ctl, i*12, 11)
                else:
                    hn_sam_6sn = n.read64(0xD20)
                    snid = BITS(hn_sam_6sn, (i-3)*12, 11)
                print(" 0x%x" % snid, end="")
            print()
        else:
            print(pfx + "  direct-mapped: SN:0x%x" % BITS(hn_sam_ctl, 0, 11))
        if not n.C.part_ge_700():
            def hn_rn_phys_id(n):
                for r in range(0xD28, 0xF00, 8):
                    yield r
                for r in range(0xF70, 0xF98, 8):
                    yield r
            # Show RNs for this HN
            print(pfx + "RNs:")
            for (i, r) in enumerate(hn_rn_phys_id(n)):
                pi = n.read64(r)
                if pi != 0:
                    for rn in [BITS(pi, 0, 32), BITS(pi, 32, 32)]:
                        if BIT(rn, 31):
                            print(pfx + "  0x%03x" % (BITS(rn, 0, 11)), end="")
                            if BIT(rn, 16):
                                print(" remote", end="")
                            if BIT(rn, 30):
                                print(" CPA%u" % BITS(rn, 17, 2), end="")
                            print()

    def show_rn_sam(self, n, pfx="            "):
        """
        Show address mapping for RN, comprising:
         - non-hashed memory regions, targeting a specific node e.g. I/O or CCG
         - hashed memory regions, targeting HN-Fs.
         - hashed memory regions can be partitioned into SCG (system cache groups)
         - GIC region (optional)
        Hashed target regions can additionally specify SN-F mapping, for PrefetchTgt.
        """
        status = n.read64(0xC00 if not n.C.part_ge_700() else 0x1100)
        if not BIT(status, 1):
            print(pfx + "  STALL requests - not ready")
        if BIT(status, 0):
            print(pfx + "  use default target id")
        target_type_str_map = ["HN-F", "HN-I", "CXRA", "?3"]
        gic = n.read64(0xD58 if not n.C.part_ge_700() else 0x1108)
        if BIT(gic, 0):
            print(pfx + "GIC: 0x%x" % gic)
        print(pfx + "Non-hashed memory regions:")
        for reg in rn_sam_nonhash_regions(n):
            print(pfx + "  NHMR %3u: %s" % (reg.index, reg.range_str()), end="")
            print(" 0x%x %s" % (reg.nodeid, reg.target_type_str), end="")
            print()
        print(pfx + "Hashed memory regions:")
        for reg in rn_sam_hashed_regions(n):
            i = reg.index
            print(pfx + "  HMR  %3u: %s" % (reg.index, reg.range_str()), end="")
            if reg.hn_count > 0:
                print(" HNs:%u" % reg.hn_count, end="")
            if reg.CAL:
                print(" CAL%u" % reg.CAL, end="")
            if reg.sn_mode != 1:
                print(" %u-SN" % reg.sn_mode, end="")
            if not reg.hashed and reg.nodeid is not None:
                # "Using an SCG region register for an HN-I/D/T target.
                #  This scenario might be useful if all the non-hashed region
                #  registers have already been used."
                print(" nonhash node=0x%x" % reg.nodeid, end="")
            print(" %s" % reg.target_type_str, end="")
            print()
            if reg.hashed and reg.nodeids is not None:
                print(pfx + "  HNs: %s" % (','.join([("0x%x" % hn) for hn in reg.nodeids])))
        #hash_addr_mask = n.read64(0xF18)
        #print(pfx + "Hash mask: 0x%016x" % hash_addr_mask)
        if not n.C.part_ge_700():
            for (i, r) in enumerate(range(0xD08, 0xD48, 8)):
                v = n.read64(r)
                if v != 0:
                    print(pfx + "sn_nodeid_reg%u: 0x%x" % (i, v))
            for (i, r) in enumerate(range(0xE08, 0xE18, 8)):
                print(pfx + "cml_port_agg%u: 0x%x" % (i, n.read64(r)))


def list_logical(c, verbose=0):
    """
    List nodes grouped by logical id
    """
    nodes = {}
    c.discover_all_devices()
    print("%s devices by logical id:" % c)
    for (t, lid) in c.logical_id.keys():
        if t not in nodes:
            nodes[t] = {}
        assert lid not in nodes[t]     # not expected: logical id clash would have been detected already
        nodes[t][lid] = c.logical_id[(t, lid)]
    for t in sorted(nodes.keys(), key=cmn_node_type_str):
        print("  Node type: %s (%u nodes)" % (cmn_node_type_str(t), len(nodes[t])))
        for lid in sorted(nodes[t]):
            print("   %3u: %s" % (lid, nodes[t][lid]))


class Statistics:
    def __init__(self):
        self.n = 0
        self.total = 0
        self.v_min = None
        self.v_max = None

    def mean(self):
        return float(self.total) / self.n

    def add(self, v):
        self.n += 1
        self.total += v
        if self.v_min is None or v < self.v_min:
            self.v_min = v
        if self.v_max is None or v > self.v_max:
            self.v_max = v

    def __str__(self):
        s = "mean %.2f min %.2f max %.2f" % (self.mean(), self.v_min, self.v_max)
        return s


def print_routing(CS, verbose=0):
    """
    Print a summary of routing-related latencies
    """
    for C in CS:
        print("Routing information for %s:" % C)
        rnf_mean_home = {}
        rnf_mean_rnf = {}
        s_all_rnf_to_home = Statistics()
        s_all_rnf_via_home = Statistics()
        for node_from in C.nodes(CMN_PROP_XP):
            if not node_from.has_any_ports(CMN_PROP_RNF):
                continue
            if verbose >= 2:
                print("  %s:" % node_from)
            s_rnf_to_home = Statistics()
            for node_to in C.nodes(CMN_PROP_HNF):
                r = cmn_routing.Route(node_from, node_to)
                s_rnf_to_home.add(r.cost())
                if verbose >= 2:
                    print("    %s" % r)
            rnf_mean_home[node_from] = s_rnf_to_home.mean()
            s_all_rnf_to_home.add(s_rnf_to_home.mean())
        for node_from in C.nodes(CMN_PROP_XP):
            if not node_from.has_any_ports(CMN_PROP_RNF):
                continue
            s_rnf_to_rnf = Statistics()
            s_rnf_via_home = Statistics()
            for node_to in C.nodes(CMN_PROP_XP):
                if not node_to.has_any_ports(CMN_PROP_RNF):
                    continue
                s_rnf_via_home.add(rnf_mean_home[node_from] + rnf_mean_home[node_to])
                r = cmn_routing.Route(node_from, node_to)
                s_rnf_to_rnf.add(r.cost())
            m_rnf = s_rnf_to_rnf.mean()
            m_rnf_via_home = s_rnf_via_home.mean()
            s_all_rnf_via_home.add(m_rnf_via_home)
            rnf_mean_rnf[node_from] = m_rnf
            if verbose:
                print("  %6.2f %6.2f %6.2f  %s" % (rnf_mean_home[node_from], m_rnf, m_rnf_via_home, node_from))
        print("  RN-F to home node:     %s" % s_all_rnf_to_home)
        print("  RN-F to RN-F via home: %s" % s_all_rnf_via_home)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN mesh interconnect explorer")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--list-logical", action="store_true", help="list nodes by logical id")
    parser.add_argument("--list", action="store_true", help="list CMN nodes")
    parser.add_argument("--routing", action="store_true", help="show hop counts and routing information")
    parser.add_argument("--node-type", type=cmn_properties, default=CMN_PROP_none, help="node properties")
    parser.add_argument("--port-type", type=cmn_properties, default=CMN_PROP_none, help="port properties")
    parser.add_argument("--node-match", type=cmn_select.CMNSelect, action="append", help="node selection")
    parser.add_argument("--register-slices", action="store_true", help="show device/mesh credited slices")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    if not (opts.list or opts.list_logical or opts.routing):
        opts.list = True
    o_register_slices = opts.register_slices
    match = cmn_select.cmn_select_merge(opts.node_match)
    L = CMNLister(None, verbose=opts.verbose, port_props=opts.port_type, node_props=opts.node_type, node_match=match)
    CS = cmn_from_opts(opts)
    for C in CS:
        if opts.list:
            L.show_cmn(C)
        if opts.list_logical:
            list_logical(C, verbose=opts.verbose)
    if opts.routing:
        print_routing(CS, verbose=opts.verbose)
