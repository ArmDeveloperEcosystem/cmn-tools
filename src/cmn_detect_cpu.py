#!/usr/bin/python3

"""
Detect where CPUs are located in the CMN mesh, by generating traffic.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

At the end of this procedure, for each CPU we should have identified:

 - its node id, which appears in SRCID/TGTID in CHI packets,
   and also indicates which XP port it is connected to

 - its LPID, which distinguishes between CPUs in a cluster

The (node-id, LPID) tuple should uniquely identify a CPU; if it does not,
traffic from multiple CPUs is not distinguishable.

For an RN-F port with a CAL, RN-Fs will be distinguished by node id.
If associated CPUs do not also have distinct LPIDs, they cannot be
distinguished by watchpoints on the device port itself. This may
complicate some kinds of traffic analysis.
"""

from __future__ import print_function

import os, sys, multiprocessing, json
import cmn_base
import cmn_json
import cmn_traffic_gen
from cmn_enum import *
import cmn_diagram

import cmnwatch

# Verbosity levels (command-line defaults to 1 when running interactive):
#   0: very quiet
#   1: default: stages in discovery, summary etc.
#   2: messages about CPU locations being discovered
#   3: internal tracing
o_verbose = 0

o_time = 1.0      # Measurement run time - increase if system is noisy
o_factor = 5
o_retries = 3

o_force_lpid = False
o_force_srcid = False

g_diagram = None


class CMN_RNFPort:
    """
    An RN-F device port. This might have a CAL with two or more RN-F devices.
    Each RN-F device might be a DSU or similar cluster with multiple CPUs.
    """
    def __init__(self, port):
        assert isinstance(port, cmn_base.CMNPort)
        self.port = port
        self.xp_id = port.xp.node_id()
        self.cpus = []       # all CPUs on this RN-F port, via CAL and/or DSU

    def perf_events(self, **matches):
        w = cmnwatch.Watchpoint(cmn_version=self.port.CMN().product_config, up=True, **matches)
        flds = "nodeid=%u,bynodeid=1,wp_dev_sel=%u" % (self.xp_id, self.port.port)
        return w.perf_events(flds, cmn_instance=self.port.CMN().seq)

    def __str__(self):
        s = "CMN:%u/XP:0x%x/P%u" % (self.port.CMN().seq, self.xp_id, self.port.port)
        return s


def max_index(x):
    """
    Given a list of event counts, return the index of the count that is
    much bigger than the rest. If there's no clear winner, return None.
    """
    if len(x) == 1:
        return 0        # degenerate case
    mx = max(x)
    ix = x.index(mx)
    del x[ix]
    mr = max(x)
    if mx <= (mr*o_factor):
        return None
    return ix


def get_max_event(cpu, events, time=o_time):
    """
    Given a CPU and a set of performance event descriptors, generate traffic
    on the CPU and return the index of whichever event is the clear winner.
    """
    t = time
    for i in range(o_retries):
        er = cmn_traffic_gen.cpu_gen_traffic(cpu, events, time=t)
        if o_verbose >= 3:
            print("CPU %3u: %s" % (cpu, er))
        ix = max_index(er)
        if ix is not None:
            return ix
        t = t * 2
        if o_verbose >= 1:
            print("retrying...")
    print("no clear winner after %u retries, system too busy?" % o_retries, file=sys.stderr)
    sys.exit(1)


def discover_cpu_rnf_port(S, cpu):
    """
    First discover which RN-F port the CPU is attached to, by monitoring all
    the RN-F ports (across all meshes) and looking for uploaded traffic.
    """
    ix = get_max_event(cpu, S.rnf_port_events, time=o_time)
    rnf = S.rnf_ports[ix]
    if o_verbose >= 1:
        print("CPU #%u on %s" % (cpu, rnf))
    S.cpu_rnf_port[cpu] = rnf
    if cpu not in rnf.cpus:
        rnf.cpus.append(cpu)
    return rnf


def discover_cpu_lpid(S, cpu):
    """
    Where multiple CPUs are attached to a single RN-F, try to establish which
    LPID the CPU is using. It is not guaranteed that CPUs use distinct LPIDs.
    """
    assert cpu in S.cpu_rnf_port
    rnf = S.cpu_rnf_port[cpu]
    if o_verbose >= 2:
        print("discovering LPID for CPU%u on RN-F %s" % (cpu, rnf))
    # This CPU is sharing an interface. Discover its LPID.
    # TBD: we could do better by matching LPID under mask, e.g. 0b0xxx for 0..7
    # TBD: there are actually 32 possible LPIDs!
    events = []
    for lpid in range(16):
        events += rnf.perf_events(lpid=lpid)
    lpid = get_max_event(cpu, events, time=o_time)
    if o_verbose:
        print("CPU #%u on %s LPID %u" % (cpu, rnf, lpid))
    S.cpu_lpid[cpu] = lpid
    return lpid


def pick_any_hnf_port(S, seq):
    """
    Pick any HN-F/HN-S port in the mesh, so that we can set a
    download-watchpoint on it.
    """
    cmn = S.CMNs[seq]
    for p in cmn.ports():
        if p.connected_type in [CMN_PORT_DEVTYPE_HNF, CMN_PORT_DEVTYPE_HNS]:
            return p
    assert False, "CMN %s has no home-node ports!" % cmn


def discover_cpu_srcid(S, cpu):
    """
    A CPU is connected to an RN-F, and we must discover its SRCID.
    Generally we only get here when the CPU is connected via a CAL,
    and the low bits of the SRCID distinguish the device (or DSU).
    We can't discover SRCID using an upload watchpoint, since upload
    watchpoints can't filter on SRCID. Instead, we need to monitor
    traffic (distinguished by SRCID) elsewhere in the interconnect -
    the obvious candidate is download-watchpoints at one or more
    HN-F ports. We might assume that any HN-F port in the same
    mesh will do, since access should be balanced. We don't even
    care if the HN-F port has a CAL.
    """
    rp = S.cpu_rnf_port[cpu]
    cmn = rp.port.CMN()
    if o_verbose >= 2:
        print("discovering SRCID for CPU#%u on %s" % (cpu, rp))
    bid = rp.port.base_id()
    if rp.port.cal:
        ids = [bid, bid+1]
    else:
        ids = [bid]
    hnf = pick_any_hnf_port(S, cmn.seq)
    if o_verbose >= 2:
        print("setting download-watchpoints on %s" % hnf)
    events = []
    for id in ids:
        w = cmnwatch.Watchpoint(cmn_version=cmn.product_config, up=False, srcid=id)
        flds = "nodeid=%u,bynodeid=1,wp_dev_sel=%u" % (hnf.XP().node_id(), hnf.port)
        e = w.perf_events(flds, cmn_instance=cmn.seq)
        assert len(e) == 1
        events += e
    ix = get_max_event(cpu, events, time=o_time)
    id = ids[ix]
    if o_verbose:
        print("%s CPU#%u SRCID=0x%x" % (rp, cpu, id))
    S.cpu_id[cpu] = id
    return id


def discover_cpus(S, cpu=None):
    for c in iter_cpus(S):
        discover_cpu_rnf_port(S, c)
        if g_diagram is not None:
            S.set_cpu(c, S.cpu_rnf_port[c].port, id=None)
            g_diagram.update()
            print(g_diagram.cursor_up() + g_diagram.str_color(), end="")
    S.discard_cpu_mappings()
    # Check if some RN-Fs have multiple CPUs
    is_multiple = 0
    for rp in S.rnf_ports:
        if len(rp.cpus) == 0:
            # not necessarily an error - could be fused out
            if o_verbose:
                print("RN-F port has no CPUs: %s" % rp)
        elif len(rp.cpus) >= 2:
            # CPUs multplexed on to a RN-F port: need distinguishing by device and/or LPID
            if o_verbose >= 2 or (o_verbose >= 1 and not is_multiple):
                print("RN-F port has multiple CPUs: %s" % rp)
            is_multiple += 1
    if is_multiple or o_force_lpid:
        if o_verbose:
            print("Discovering LPIDs...")
        for c in iter_cpus(S):
            discover_cpu_lpid(S, c)
    # It might still not be possible to distinguish CPUs by (port, LPID),
    # perhaps because they're connected via a CAL. In this case they
    # should have distinct device ids, which appear as CHI SRCID/TGTID,
    # but cannot be filtered on in upload/download watchpoints.
    is_multiple = 0
    rnf_with_cal = False
    for rp in S.rnf_ports:
        rp.lpid_cpu = {}
        rp.lpid_clash = False
        # really, we only need to do this if there's more than 1 CPU on the RN-F port...
        if rp.port.cal:
            rnf_with_cal = True
        for cpu in rp.cpus:
            lpid = S.cpu_lpid[cpu]
            if lpid in rp.lpid_cpu:
                if (o_verbose >= 2) or (o_verbose and not is_multiple) or not rp.port.cal:
                    print("%s: CPU#%u and CPU#%u both have LPID=%u" % (rp, rp.lpid_cpu[lpid][0], cpu, lpid))
                if not rp.port.cal:
                    print("%s: multiple CPUs with same LPID on non-CAL port: cannot disambiguate" % (rp), file=sys.stderr)
                is_multiple += 1
                rp.lpid_clash = True
            else:
                rp.lpid_cpu[lpid] = []
            rp.lpid_cpu[lpid].append(cpu)
    if is_multiple or rnf_with_cal or o_force_srcid:
        if o_verbose:
            print("Discovering CHI SRCIDs...")
        for rp in S.rnf_ports:
            # Find which of the possible device SRCIDs are used by each CPU
            # We could guard this with rp.lpid_clash, but we need to set the id
            # all the CPUs. Perhaps one of the CPUs on a CAL was fused out.
            for cpu in rp.cpus:
                 discover_cpu_srcid(S, cpu)
    else:
        for c in iter_cpus(S):
            S.cpu_id[c] = S.cpu_rnf_port[c].port.base_id()
    # We've now hopefully discovered a unique (port, id, lpid) combination for each CPU.
    for c in iter_cpus(S):
        S.set_cpu(c, S.cpu_rnf_port[c].port, id=S.cpu_id[c], lpid=S.cpu_lpid.get(c, None))


def prepare_system(S):
    """
    Add some fields to the System object, for use in CPU discovery.
    """
    S.n_cpu = multiprocessing.cpu_count()
    S.online_cpus = list_online_cpus()
    if S.online_cpus[-1] != S.n_cpu - 1:
        print("Some CPUs may be offline: CPU numbers from %u to %u but %u are online" % (S.online_cpus[0], S.online_cpus[-1], S.n_cpu))
    S.rnf_ports = []
    # Our observations about where each CPU is,
    # progressively populated by watchpoint counting.
    S.cpu_rnf_port = {}     # CMN_RNFPort object
    S.cpu_lpid = {}         # LPID for each cpu
    S.cpu_id = {}           # device id (SRCID/TGTID) for each CPU
    for cmn in S.CMNs:
        for xp in cmn.XPs():
            for p in range(xp.n_device_ports()):
                if xp.port_device_type_str(p).startswith("RN-F"):
                    rnf = CMN_RNFPort(xp.port[p])
                    S.rnf_ports.append(rnf)
    if o_verbose:
        print("%u CPUs, %u RN-F ports" % (S.n_cpu, len(S.rnf_ports)))
    # We usually see a consistent number of CPUs per RN-F port, but not always
    if S.rnf_ports and (S.n_cpu % len(S.rnf_ports)) != 0:
        """
        A homogeneous system would have perhaps 1 or 2 CPUs per RN-F.
        If the number does not divide equally, it could indicate that:
         - some CPUs have been fused out
         - the system is heterogeneous by design, e.g. control vs. data plane CPUs
        """
        print("Number of CPUs per RN-F port is not integral: %u CPUs on %u RN-Fs" % (S.n_cpu, len(S.rnf_ports)))
    if o_verbose >= 2:
        print("RN-F ports:")
        print([str(rp) for rp in S.rnf_ports])
    # Construct one monitoring event per watchpoint
    S.rnf_port_events = []
    for rnf in S.rnf_ports:
        rnfpe = rnf.perf_events()
        assert rnfpe, "bad RN-F port events: %s" % rnfpe
        assert len(rnfpe) == 1
        S.rnf_port_events += rnfpe
        if o_verbose >= 3:
            print("%s: %s" % (rnf, rnfpe))
    assert S.rnf_port_events


def cpu_is_online(n):
    try:
        with open(("/sys/devices/system/cpu/cpu%u/online" % n), "r") as f:
            on = int(f.read().strip())
        return on == 1
    except FileNotFoundError:
        return None


def list_online_cpus():
    """
    Get a sorted list of all online CPUs.
    """
    oc = []
    for d in os.listdir("/sys/devices/system/cpu"):
        if d.startswith("cpu"):
            try:
                n = int(d[3:])
            except Exception:
                continue
            if cpu_is_online(n):
                oc.append(n)
    assert oc
    return sorted(oc)


def iter_cpus(S):
    for cpu in S.online_cpus:
        yield cpu


def print_cpus(S):
    print("Discovered CPUs:")
    for cpu in iter_cpus(S):
        print("  CPU %3u: " % cpu, end="")
        if cpu not in S.cpu_rnf_port:
            print("unknown RN-F", end="")
        else:
            rnf = S.cpu_rnf_port[cpu]
            print("%s" % rnf, end="")
            if cpu in S.cpu_lpid:
                print(" LPID=%u" % S.cpu_lpid[cpu], end="")
            print(" SRCID=0x%x" % S.cpu_id[cpu], end="")
        print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Discover where CPUs are located in system mesh")
    parser.add_argument("--json", type=str, default=cmn_json.cmn_config_filename(), help="JSON system description")
    parser.add_argument("--update", action="store_true", help="update JSON system description")
    parser.add_argument("--discard", action="store_true", help="discard any previous CPU mappings")
    parser.add_argument("-o", "--output", type=str, help="output JSON filename")
    parser.add_argument("--cpu", type=int, help="discover one CPU")
    parser.add_argument("--time", type=float, default=1.0, help="measurement time")
    parser.add_argument("-N", type=int, help="number of CPUs")
    parser.add_argument("--diagram", action="store_true", help="visualize CPU discovery")
    parser.add_argument("--force-discover", action="store_true")
    parser.add_argument("--lmbench-bin", type=str, default=None, help="bin directory for lmbench")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="increase verbosity")
    opts = parser.parse_args()
    cmn_traffic_gen.o_lmbench = opts.lmbench_bin
    o_verbose = opts.verbose
    o_time = opts.time
    o_force_lpid = opts.force_discover
    o_force_srcid = opts.force_discover
    cmn_traffic_gen.o_verbose = opts.verbose >= 3
    S = cmn_json.system_from_json_file(opts.json)
    if S.has_cpu_mappings():
        print("%s: already has CPU mappings - " % opts.json, end="")
        if not opts.discard:
            print("use --discard to discard")
            sys.exit()
        print("discarding")
        S.discard_cpu_mappings()
    prepare_system(S)
    if opts.cpu is not None:
        o_verbose = max(o_verbose, 2)
        on = cpu_is_online(opts.cpu)
        if not on:
            print("CPU#%u is %s" % (opts.cpu, ["offline", "invalid"][on is None]), file=sys.stderr)
            sys.exit(1)
        discover_cpu_rnf_port(S, opts.cpu)
        discover_cpu_lpid(S, opts.cpu)
        discover_cpu_srcid(S, opts.cpu)
    else:
        if opts.diagram:
            o_verbose = 0
            cmn_traffic_gen.o_verbose = 0
            g_diagram = cmn_diagram.CMNDiagram(S.CMNs[0], small=True)
            print(g_diagram.str_color(), end="")
        discover_cpus(S)
        print_cpus(S)
        output_temp = False
        if opts.output:
            ofn = opts.output
        elif opts.update or opts.discard:
            ofn = opts.json
        else:
            # Don't discard all that hard work - pick an output file, in the current
            # directory, but make sure not to overwrite anything.
            output_temp = True
            i = 0
            while True:
                ofn = "./cmn-system" + ("-%u" if i >= 1 else "") + ".json"
                if not os.path.exists(ofn):
                    break
                i += 1
        if ofn is not None:
            print("Writing JSON file with CPU locations: %s" % ofn)
            cmn_json.json_dump_file_from_system(S, ofn)
        if output_temp:
            print("now copy %s to %s or rerun with --update" % (ofn, cmn_json.cmn_config_filename()))
