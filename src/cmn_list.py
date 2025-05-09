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
import cmn_dtstat


def BITS(x,p,n):
    return (x >> p) & ((1 << n)-1)


def BIT(x,p):
    return (x >> p) & 1


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
    if cmn.multiple_dtms:
        print(", multiple-DTMs", end="")
    if cmn.isolation_enabled:
        print(", device-isolation", end="")
    print()
    print("  %s" % cmn.rootnode)
    for xp in cmn.XPs():
        sec = xp.read64(CMN_any_SECURE_ACCESS)
        n_ports = xp.n_device_ports()
        print("    %s: n_ports=%u" % (xp, n_ports), end="")
        dtc_domain = xp.dtc_domain()
        if dtc_domain is not None:
            print(", dtc_domain=%d" % xp.dtc_domain(), end="")
        if sec != 0:
            print(", security=0x%x" % sec, end="")
        print()
        # Show XP information
        xp.show()
        # Show XP DTM information
        for dtm in xp.DTMs():
            cmn_dtstat.print_dtm(dtm, pfx="      ")
        # Show the XP's child devices. Although these are discovered directly from the XP,
        # we group them by their device port.
        for p in range(0, n_ports):
            port_info = xp.port_info(p)
            port_info_1 = xp.port_info(p, 1) if cmn.part_ge_700() else None
            connected_device_info = xp.read64(CMN_XP_DEVICE_PORT_CONNECT_INFO_P(p))
            connected_device_type = BITS(connected_device_info, 0, 5)
            print("      P%u:" % p, end="")
            if connected_device_type == 0:
                # The TRM says "reserved", but it evidently means the port is not connected.
                # Ports are connected or not, by the implementer. With n_ports=2,
                # we've observed all combinations of P0+P1, P0 only, P1 only, no ports.
                print(" no devices")
                continue
            print(" %s" % cmn_port_device_type_str(connected_device_type), end="")
            # For a port with a CAL, num_dev indicates CAL2 vs CAL4.
            # A CCG has num_dev=1 but also has child nodes with device numbers 0 and 1.
            num_dev = BITS(port_info, 0, 3)
            if BIT(connected_device_info, 7):
                print(" (CAL%u)" % num_dev, end="")
            elif num_dev != 1:
                print(" devices=%u" % num_dev, end="")
            if verbose:
                print(" [port_info=0x%x, port_connect_info=0x%x]" % (port_info, connected_device_info), end="")
                if port_info_1 is not None:
                    print(" [port_info_1=0x%x]" % (port_info_1), end="")
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
                sec = n.read64(CMN_any_SECURE_ACCESS)
                print("        %s (node info: 0x%x, unit info: 0x%x)" % (n, n.node_info, info), end="")
                if sec:
                    print(", security=0x%x" % sec, end="")
                print()
                assert n.XP() == xp           # True by construction from traversal
                if n.XY() != xp.XY():
                    # Has been seen with CXLA (external) nodes on CMN-600
                    print("            ** node has anomalous coordinates: %s, expected %s" % (str(n.XY()), str(xp.XY())))
                if n.is_home_node():
                    cg = n.cache_geometry()
                    if not cmn.part_ge_700():
                        num_poc_entries = BITS(info, 32, 7)
                    else:
                        num_poc_entries = BITS(info, 31, 8)
                    if cg.exists():
                        print("          SLC: %s tag:%u data:%u" % (cg.cache_str(), BITS(info,16,3), BITS(info,20,3)))
                    print("          SF: %s" % cg.sf_str())
                    print("          POCQ entries: %u" % (num_poc_entries))
                    if cmn.product_config.mpam_enabled:
                        mpam_ns_pmg = BITS(info, 43, 1) + 1
                        mpam_ns_partid = 1 << BITS(info, 39, 4)
                        print("          MPAM(NS): %u PMG, %u PARTID" % (mpam_ns_pmg, mpam_ns_partid))
                    if cmn.secure_accessible:
                        aux_ctl = n.read64(CMN_any_AUX_CTL)
                        print("          aux_ctl: 0x%x" % aux_ctl)
                        pwpr = n.read64(0x1000)    # power policy register
                        print("          pwpr: 0x%x" % pwpr, end="")
                        print(" %s" % {0: "OFF", 2: "MEM_RET", 7: "FUNC_RET", 8: "ON"}[BITS(pwpr, 0, 4)], end="")
                        print(" %s" % ["NOSFSLC", "SFONLY", "HAM", "FAM"][BITS(pwpr, 4, 4)], end="")
                        if BIT(pwpr, 8):
                            print(" dynamic", end="")
                        print()
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
                    cmn_dtstat.print_dtc(n, pfx="          ")
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
                    db_present = BIT(info, 0)
                    db_fifo_depth = BITS(info, 16, 5)
                    if db_present:
                        print("          Domain bridge FIFO depth: %u" % (db_fifo_depth))
                    if cmn.secure_accessible:
                        aux_ctl = n.read64(CMN_any_AUX_CTL)
                        smp_mode_en = BIT(aux_ctl, 47)
                        if smp_mode_en:
                            print("          SMP mode enabled")
                elif n.type() == CMN_NODE_DN:
                    pass      # not much interesting non-Secure info
                elif n.type() in [CMN_NODE_MPAM_NS, CMN_NODE_HNS_MPAM_NS] or (n.type() in [CMN_NODE_MPAM_S, CMN_NODE_HNS_MPAM_S] and cmn.secure_accessible):
                    idr = n.read64(0x1000)
                    aidr = n.read64(0x1020)
                    iidr = n.read64(0x1018)
                    print("          MPAM architecture %u.%u, idr=0x%x, iidr=0x%x" % (BITS(aidr, 4, 4), BITS(aidr, 0, 4), idr, iidr))
                else:
                    print("          <no information for node: %s>" % (n))
                if n.is_home_node():
                    # Show events generated by this node - meaning will depend on node type.
                    # We should really show this for XPs as well.
                    events = n.read64(CMN_any_PMU_EVENT_SEL)
                    if events != 0:
                        print("          events: 0x%016x" % events)
                    if cmn.secure_accessible:
                        hn_qos_band = n.read64(0xA80)
                        hn_qos_resv = n.read64(0xA88)
                        print("          QoS bands:")
                        for (i, qc) in enumerate(["L", "M", "H", "HH"]):
                            (lo, hi) = (BITS(hn_qos_band, i*8, 4), BITS(hn_qos_band, i*8+4, 4))
                            pocq = BITS(hn_qos_resv, i*8, 8)
                            print("            %3s  %2u..%2u  POCQ=%3u" % (qc, lo, hi, pocq))
                        print("          POCQ reserved for SF evictions: %3u" % (BITS(hn_qos_resv, 32, 8)))
                elif n.type() == CMN_NODE_RNSAM:
                    if cmn.secure_accessible:
                        print("          RNSAM details:")
                        def nonhash(r):
                            nhm = [0xC08, 0xC10, 0xC18, 0xC20, 0xC28, 0xCA0, 0xCA8, 0xCB0, 0xCB8, 0xCC0]
                            nhn = [0xC30, 0xC38, 0xC40, 0xCE0, 0xCE8]
                            i2 = n.read64(nhm[r // 2])
                            info = BITS(i2, (r & 1)*32, 32)
                            n4 = n.read64(nhn[r // 4])
                            nodeid = BITS(n4, (r & 3)*12, 11)
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
        if cmn.secure_accessible:
            print("      Port QoS:")
            for p in range(0, n_ports):
                print("        P%u: " % p, end="")
                qos_ctl = xp.read64(0xA80 + p*32)
                qos_lat = xp.read64(0xA88 + p*32)
                qos_lsc = xp.read64(0xA90 + p*32)
                qos_lrg = xp.read64(0xA98 + p*32)
                print("ctl=0x%x, lat=0x%x, lsc=0x%x, lrg=0x%x" % (qos_ctl, qos_lat, qos_lsc, qos_lrg), end="")
                if cmn.product_config.mpam_enabled:
                    mpam_ovr = xp.read64(0xA10 + p*8)
                    if BIT(mpam_ovr, 0):
                        print(" mpam=0x%x" % mpam_ovr, end="")
                print()


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


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN mesh interconnect explorer")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("--list-logical", action="store_true", help="list nodes by logical id")
    parser.add_argument("--list", action="store_true", help="list CMN nodes")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    if not (opts.list or opts.list_logical):
        opts.list = True
    CS = cmn_from_opts(opts)
    for C in CS:
        print(C)
        if opts.list:
            show_cmn(C, verbose=opts.verbose)
        if opts.list_logical:
            list_logical(C, verbose=opts.verbose)
