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

import os
import random
import sys
import time
import multiprocessing

import app_data
import cmn_json
import cmn_traffic_gen
from cmn_enum import *
import cmn_diagram
import cmn_perfcheck
import cmnwatch


# Verbosity levels (command-line defaults to 1 when running interactive):
#   0: very quiet
#   1: default: stages in discovery, summary etc.
#   2: messages about CPU locations being discovered
#   3: internal tracing
o_verbose = 0

o_time = 0.5      # Measurement run time - increase if system is noisy
o_factor = 5.0
o_retries = 3
o_retry_multiplier = 3.0

o_method = "atomic"
o_force_lpid = False
o_force_srcid = False
o_atomic_opcode = "AtomicStoreEOR"
o_atomic_batch = 4
o_atomic_contenders = 2
o_atomic_line_size = 64
o_atomic_page_lines = 64
o_atomic_min_count = 1

g_diagram = None
g_progress = None


def atomic_failure_exceptions():
    return (SystemExit, cmn_traffic_gen.TrafficMeasurementError)


def switch_discovery_method(method, why=None):
    global g_progress, o_method
    if why is not None:
        print(why, file=sys.stderr)
    o_method = method
    if g_progress is not None:
        g_progress = DetectProgress(g_progress.path, g_progress.json_fn, method)
        g_progress.begin(False)


def fallback_from_atomic_to_interval(why):
    switch_discovery_method("interval",
                            "Atomic discovery failed before any CPUs were identified (%s), falling back to interval method"
                            % why)


def progress_filename():
    return app_data.app_data_cache("cmn-detect-progress", app="arm")


def system_boot_time():
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except Exception:
        pass
    return None


def progress_file_is_stale(path, boot_time=None):
    if boot_time is None:
        boot_time = system_boot_time()
    if boot_time is None or not os.path.exists(path):
        return False
    try:
        return os.path.getmtime(path) < boot_time
    except OSError:
        return False


class DetectProgress:
    def __init__(self, path, json_fn, method):
        self.path = path
        self.json_fn = os.path.abspath(json_fn)
        self.method = method
        self.rnf = {}
        self.lpid = {}
        self.srcid = {}
        self.have_matching_run = False

    def _append(self, fields):
        line = "\t".join([str(f) for f in fields]) + "\n"
        new_file = not os.path.exists(self.path)
        with open(self.path, "a") as f:
            f.write(line)
            f.flush()
        if new_file:
            app_data.change_to_real_user_if_sudo(self.path)

    def begin(self, resume):
        if resume:
            return
        self._append(["meta", self.json_fn, self.method])

    def load(self):
        current = False
        if not os.path.exists(self.path):
            return False
        self.rnf = {}
        self.lpid = {}
        self.srcid = {}
        with open(self.path) as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                fields = line.split('\t')
                rec = fields[0]
                if rec == "meta":
                    current = (len(fields) >= 3 and fields[1] == self.json_fn and fields[2] == self.method)
                    if current:
                        self.rnf = {}
                        self.lpid = {}
                        self.srcid = {}
                    continue
                if not current:
                    continue
                if rec == "rnf" and len(fields) >= 5:
                    cpu = int(fields[1], 0)
                    self.rnf[cpu] = (int(fields[2], 0), int(fields[3], 0), int(fields[4], 0))
                elif rec == "lpid" and len(fields) >= 3:
                    self.lpid[int(fields[1], 0)] = int(fields[2], 0)
                elif rec == "srcid" and len(fields) >= 3:
                    self.srcid[int(fields[1], 0)] = int(fields[2], 0)
        self.have_matching_run = current
        return current

    def record_rnf(self, cpu, rnf):
        self.rnf[cpu] = (rnf.port.CMN().cmn_seq, rnf.port.xp.node_id(), rnf.port.port_number)
        self._append(["rnf", cpu, self.rnf[cpu][0], "0x%x" % self.rnf[cpu][1], self.rnf[cpu][2]])

    def record_lpid(self, cpu, lpid):
        self.lpid[cpu] = lpid
        self._append(["lpid", cpu, lpid])

    def record_srcid(self, cpu, srcid):
        self.srcid[cpu] = srcid
        self._append(["srcid", cpu, "0x%x" % srcid])

    def _find_rnf(self, S, cmn_seq, xp_id, port_number):
        for rnf in S.rnf_ports:
            if (rnf.port.CMN().cmn_seq == cmn_seq and rnf.port.xp.node_id() == xp_id and
                    rnf.port.port_number == port_number):
                return rnf
        return None

    def apply(self, S):
        for (cpu, loc) in sorted(self.rnf.items()):
            rnf = self._find_rnf(S, loc[0], loc[1], loc[2])
            if rnf is None:
                continue
            S.cpu_rnf_port[cpu] = rnf
            if cpu not in rnf.cpus:
                rnf.cpus.append(cpu)
        for (cpu, lpid) in self.lpid.items():
            if cpu in S.cpu_rnf_port:
                S.cpu_lpid[cpu] = lpid
        for (cpu, srcid) in self.srcid.items():
            if cpu in S.cpu_rnf_port:
                S.cpu_id[cpu] = srcid

    def remove(self):
        if os.path.exists(self.path):
            os.remove(self.path)


def cpu_mapping_tuple(cpu_obj):
    return (
        cpu_obj.port.CMN().cmn_seq,
        cpu_obj.port.xp.node_id(),
        cpu_obj.port.port_number,
        cpu_obj.id,
        cpu_obj.lpid
    )


def snapshot_cpu_mappings(S):
    return dict((cpu_obj.cpu, cpu_mapping_tuple(cpu_obj)) for cpu_obj in S.cpus())


def discovered_cpu_mapping_tuple(S, cpu):
    rnf = S.cpu_rnf_port[cpu]
    return (
        rnf.port.CMN().cmn_seq,
        rnf.port.xp.node_id(),
        rnf.port.port_number,
        S.cpu_id[cpu],
        S.cpu_lpid.get(cpu, 0)
    )


def mapping_str(m):
    return "M%u/XP:0x%x/P%u SRCID=0x%x LPID=%u" % m


def verify_cpu_mappings(S, expected, cpus=None):
    """
    Compare discovered CPU mappings with a previous mapping snapshot.
    Return a list of mismatch strings.
    """
    mismatches = []
    if cpus is None:
        cpus = sorted(set(expected.keys()) | set(S.cpu_rnf_port.keys()))
    for cpu in cpus:
        exp = expected.get(cpu, None)
        got = discovered_cpu_mapping_tuple(S, cpu) if cpu in S.cpu_rnf_port else None
        if exp != got:
            mismatches.append((cpu, exp, got))
    return mismatches


def expected_cpu_mapping(expected, cpu):
    if expected is None:
        return None
    return expected.get(cpu, None)


def expected_rnf_port(S, expected_mapping):
    if expected_mapping is None:
        return None
    key = expected_mapping[:3]
    if hasattr(S, "rnf_port_map"):
        return S.rnf_port_map.get(key, None)
    for rnf in S.rnf_ports:
        if ((rnf.port.CMN().cmn_seq, rnf.port.xp.node_id(), rnf.port.port_number) == key):
            return rnf
    return None


def exact_guess_matches(cpu, logical_events, entry=None):
    try:
        ix = get_exact_event(cpu, logical_events, time=o_time, min_count=o_atomic_min_count, entry=entry)
    except SystemExit:
        return False
    return ix == 0


def verify_cpu_rnf_port_guess_atomic(S, cpu, expected_mapping):
    rnf = expected_rnf_port(S, expected_mapping)
    if rnf is None:
        return False
    entry = atomic_entry_for_cpu(S, cpu)
    if not exact_guess_matches(cpu, [atomic_rnf_events(rnf, entry)], entry=entry):
        return False
    if o_verbose >= 2:
        print("CPU #%u on %s (cached guess verified)" % (cpu, rnf))
    S.cpu_rnf_port[cpu] = rnf
    if cpu not in rnf.cpus:
        rnf.cpus.append(cpu)
    if g_progress is not None:
        g_progress.record_rnf(cpu, rnf)
    return True


def verify_cpu_lpid_guess_atomic(S, cpu, expected_mapping):
    if expected_mapping is None:
        return False
    lpid = expected_mapping[4]
    rnf = S.cpu_rnf_port[cpu]
    entry = atomic_entry_for_cpu(S, cpu)
    if not exact_guess_matches(cpu, [[atomic_rnf_events(rnf, entry, lpid=lpid)]], entry=entry):
        return False
    if o_verbose >= 2:
        print("CPU #%u on %s LPID %u (cached guess verified)" % (cpu, rnf, lpid))
    S.cpu_lpid[cpu] = lpid
    if g_progress is not None:
        g_progress.record_lpid(cpu, lpid)
    return True


def verify_cpu_srcid_guess_atomic(S, cpu, expected_mapping):
    if expected_mapping is None:
        return False
    id = expected_mapping[3]
    rp = S.cpu_rnf_port[cpu]
    cmn = rp.port.CMN()
    entry = atomic_entry_for_cpu(S, cpu)
    logical_events = srcid_logical_events_atomic_mesh(cmn, [id], all_hnf_ports(S, cmn.cmn_seq), entry=entry)
    if not exact_guess_matches(cpu, logical_events, entry=entry):
        return False
    if o_verbose >= 2:
        print("%s CPU#%u SRCID=0x%x (cached guess verified)" % (rp, cpu, id))
    S.cpu_id[cpu] = id
    if g_progress is not None:
        g_progress.record_srcid(cpu, id)
    return True


class CMN_RNFPort:
    """
    An RN-F device port. This might have a CAL with two or more RN-F devices.
    Each RN-F device might be a DSU or similar cluster with multiple CPUs.
    """
    def __init__(self, port):
        self.port = port
        self.xp_id = port.XP().node_id()
        self.cpus = []       # all CPUs on this RN-F port, via CAL and/or DSU

    def perf_events(self, **matches):
        w = cmnwatch.Watchpoint(cmn_version=self.port.CMN().product_config, up=True, **matches)
        flds = "nodeid=0x%x,bynodeid=1,wp_dev_sel=%u" % (self.xp_id, self.port.port_number)
        return w.perf_events(flds, cmn_instance=self.port.CMN().cmn_seq)

    def __str__(self):
        s = "M%u/XP:0x%x/P%u" % (self.port.CMN().cmn_seq, self.xp_id, self.port.port_number)
        return s


def max_index(x):
    """
    Given a list of event counts, return the index of the count that is
    much bigger (by a factor of 'o_factor') than the rest.
    If there's no clear winner, return None.
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


def initial_measurement_time(n_events, time=o_time):
    if n_events <= 0:
        return time
    t_min = min(0.01, time)
    return min(time, t_min * n_events)


def sole_index(x, min_count=1):
    """
    Return the index of the single event that has counted at least min_count
    instances. If none, or more than one, meet the threshold, return None.
    """
    hits = [i for (i, c) in enumerate(x) if c >= min_count]
    if len(hits) != 1:
        return None
    return hits[0]


def normalize_logical_events(logical_events):
    nle = []
    for le in logical_events:
        if le and isinstance(le[0], str):
            nle.append([le])
        else:
            nle.append(le)
    return nle


def flatten_logical_events(logical_events):
    logical_events = normalize_logical_events(logical_events)
    events = []
    groups = []
    for le in logical_events:
        g = []
        for wes in le:
            assert wes
            g.append(len(events))
            events += wes
        groups.append(g)
    return (events, groups)


def group_counts(raw_counts, groups):
    return [sum([raw_counts[ix] for ix in g]) for g in groups]


def get_max_event(cpu, events, time=o_time):
    """
    Given a CPU and a set of performance event descriptors, generate traffic
    on the CPU and return the index of whichever event is the clear winner.
    """
    t = initial_measurement_time(len(events), time=time)
    for i in range(o_retries+1):
        try:
            er = cmn_traffic_gen.cpu_gen_traffic(cpu, events, time=t)
        except cmn_traffic_gen.TrafficMeasurementInconclusive as e:
            if o_verbose >= 1:
                print("retrying after inconclusive measurement (%s)..." % e)
            t = t * o_retry_multiplier
            continue
        if o_verbose >= 3:
            print("CPU %3u: %s" % (cpu, er))
        ix = max_index(er)
        if ix is not None:
            return ix
        t = t * o_retry_multiplier
        if o_verbose >= 1:
            print("retrying (%u/%u)..." % (i, o_retries))
    print("no clear winner after %u retries, system too busy?" % o_retries, file=sys.stderr)
    sys.exit(1)


def get_max_logical_event(cpu, logical_events, time=o_time):
    """
    Given a CPU and a list of logical events, each possibly represented by one
    or more watchpoints, return the index of whichever logical event wins.
    """
    (events, groups) = flatten_logical_events(logical_events)
    t = initial_measurement_time(len(events), time=time)
    for i in range(o_retries+1):
        try:
            er = cmn_traffic_gen.cpu_gen_traffic(cpu, events, time=t)
        except cmn_traffic_gen.TrafficMeasurementInconclusive as e:
            if o_verbose >= 1:
                print("retrying after inconclusive measurement (%s)..." % e)
            t = t * o_retry_multiplier
            continue
        gc = group_counts(er, groups)
        if o_verbose >= 3:
            print("CPU %3u grouped-counts: raw=%s groups=%s" % (cpu, er, gc))
        ix = max_index(gc)
        if ix is not None:
            return ix
        t = t * o_retry_multiplier
        if o_verbose >= 1:
            print("retrying (%u/%u)..." % (i, o_retries))
    print("no clear grouped winner after %u retries, system too busy?" % o_retries, file=sys.stderr)
    sys.exit(1)


def exact_group_indices(counts_by_entry, min_count=1):
    return [sole_index(c, min_count=min_count) for c in counts_by_entry]


def get_exact_event_batch(entries, logical_events_by_entry, time=o_time, min_count=1):
    """
    Given a batch of atomic traffic entries and logical events for each entry,
    generate traffic once and return the selected logical event for each entry.
    """
    t = None
    for i in range(o_retries+1):
        events = []
        groups_by_entry = []
        for logical_events in logical_events_by_entry:
            (ee, groups) = flatten_logical_events(logical_events)
            groups = [[ix + len(events) for ix in g] for g in groups]
            groups_by_entry.append(groups)
            events += ee
        if t is None:
            t = initial_measurement_time(len(events), time=time)
        try:
            er = cmn_traffic_gen.cpus_gen_atomic_traffic(entries, events=events, time=t)
        except cmn_traffic_gen.TrafficMeasurementInconclusive as e:
            if o_verbose >= 1:
                print("retrying exact match after inconclusive measurement (%s)..." % e)
            t = t * o_retry_multiplier
            continue
        counts_by_entry = [group_counts(er, groups) for groups in groups_by_entry]
        if o_verbose >= 3:
            print("exact batch counts: raw=%s groups=%s" % (er, counts_by_entry))
        indices = exact_group_indices(counts_by_entry, min_count=min_count)
        if None not in indices:
            return indices
        t = t * o_retry_multiplier
        if o_verbose >= 1:
            print("retrying exact match (%u/%u)..." % (i, o_retries))
    print("no unique exact watchpoint match after %u retries" % o_retries, file=sys.stderr)
    sys.exit(1)


def get_exact_event(cpu, logical_events, time=o_time, min_count=1, entry=None):
    if entry is None:
        entry = cmn_traffic_gen.atomic_entry(cpu)
    return get_exact_event_batch([entry], [logical_events], time=time, min_count=min_count)[0]


def atomic_batch_capacity(S):
    if o_atomic_contenders < 0:
        return 1
    if o_atomic_contenders == 0:
        return min(o_atomic_batch, o_atomic_page_lines)
    return max(1, min(o_atomic_batch, o_atomic_page_lines, len(S.online_cpus) // (1 + o_atomic_contenders)))


def atomic_byte_offset(cpu, slot):
    return 1 + ((cpu + slot) % (o_atomic_line_size - 1))


def atomic_page_offset(entry):
    return (entry["line_index"] * o_atomic_line_size) + entry["byte_offset"]


def atomic_addr(page_offset, n_bits=52):
    mask = ((1 << n_bits) - 1) ^ ((1 << 12) - 1)
    return cmnwatch.unconvert_value_mask(page_offset, mask)


def build_atomic_entries(S, cpus):
    cpus = list(cpus)
    others = [cpu for cpu in S.online_cpus if cpu not in cpus]
    entries = []
    for (slot, cpu) in enumerate(cpus):
        contenders = others[(slot * o_atomic_contenders):((slot + 1) * o_atomic_contenders)]
        entry = cmn_traffic_gen.atomic_entry(cpu, line_index=slot, byte_offset=atomic_byte_offset(cpu, slot), contenders=contenders)
        entries.append(entry)
    return entries


def atomic_entry_for_cpu(S, cpu):
    return build_atomic_entries(S, [cpu])[0]


def iter_atomic_batches(S, cpus=None):
    if cpus is None:
        cpus = list(iter_cpus(S))
    cpus = list(cpus)
    cap = atomic_batch_capacity(S)
    for i in range(0, len(cpus), cap):
        batch = cpus[i:i+cap]
        yield build_atomic_entries(S, batch)


def atomic_rnf_events(rnf, entry, **matches):
    kwds = {"opcode": o_atomic_opcode, "addr": atomic_addr(atomic_page_offset(entry))}
    kwds.update(matches)
    return rnf.perf_events(**kwds)


def hnf_ports(S, cmn_seq):
    return hnf_ports_subset(S, cmn_seq)


def all_hnf_ports(S, cmn_seq):
    return list(S.CMNs[cmn_seq].ports(properties=CMN_PROP_HNF))


def hnf_ports_subset(S, cmn_seq):
    if not hasattr(S, "selected_hnf_ports"):
        S.selected_hnf_ports = {}
    if cmn_seq not in S.selected_hnf_ports:
        ports = all_hnf_ports(S, cmn_seq)
        if len(ports) > 8:
            ports = random.sample(ports, 8)
        S.selected_hnf_ports[cmn_seq] = ports
    return S.selected_hnf_ports[cmn_seq]


def srcid_logical_events(cmn, ids, hnfs, entry=None):
    logical_events = []
    for id in ids:
        id_events = []
        for hnf in hnfs:
            if entry is None:
                if o_verbose >= 3:
                    print("setting download-watchpoint on %s for SRCID=0x%x" % (hnf, id))
                w = cmnwatch.Watchpoint(cmn_version=cmn.product_config, up=False, srcid=id)
            else:
                w = cmnwatch.Watchpoint(cmn_version=cmn.product_config, chn="REQ", up=False,
                                        opcode=o_atomic_opcode, addr=atomic_addr(atomic_page_offset(entry)), srcid=id)
            id_events.append(w.perf_events(cmn_instance=cmn.cmn_seq, nodeid=hnf.XP().node_id(), dev=hnf.port_number))
        logical_events.append(id_events)
    return logical_events


def srcid_logical_events_atomic_mesh(cmn, ids, hnfs, entry):
    logical_events = []
    devs = sorted(set([hnf.port_number for hnf in hnfs]))
    for id in ids:
        id_events = []
        for dev in devs:
            w = cmnwatch.Watchpoint(cmn_version=cmn.product_config, chn="REQ", up=False,
                                    opcode=o_atomic_opcode, addr=atomic_addr(atomic_page_offset(entry)), srcid=id)
            id_events.append(w.perf_events(cmn_instance=cmn.cmn_seq, dev=dev))
        logical_events.append(id_events)
    return logical_events


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
    if g_progress is not None:
        g_progress.record_rnf(cpu, rnf)
    return rnf


def discover_cpu_rnf_port_atomic(S, cpu):
    """
    Discover which RN-F port the CPU is attached to by counting exact matches
    of a tagged uncommon atomic request on each RN-F upload port.
    """
    entry = atomic_entry_for_cpu(S, cpu)
    logical_events = [atomic_rnf_events(rnf, entry) for rnf in S.rnf_ports]
    ix = get_exact_event(cpu, logical_events, time=o_time, min_count=o_atomic_min_count, entry=entry)
    rnf = S.rnf_ports[ix]
    if o_verbose >= 1:
        print("CPU #%u on %s" % (cpu, rnf))
    S.cpu_rnf_port[cpu] = rnf
    if cpu not in rnf.cpus:
        rnf.cpus.append(cpu)
    if g_progress is not None:
        g_progress.record_rnf(cpu, rnf)
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
    if g_progress is not None:
        g_progress.record_lpid(cpu, lpid)
    return lpid


def discover_cpu_lpid_atomic(S, cpu):
    """
    Discover the CPU's LPID by counting exact matches of tagged atomic traffic.
    """
    assert cpu in S.cpu_rnf_port
    rnf = S.cpu_rnf_port[cpu]
    if o_verbose >= 2:
        print("discovering LPID for CPU%u on RN-F %s" % (cpu, rnf))
    entry = atomic_entry_for_cpu(S, cpu)
    logical_events = [atomic_rnf_events(rnf, entry, lpid=lpid) for lpid in range(16)]
    lpid = get_exact_event(cpu, logical_events, time=o_time, min_count=o_atomic_min_count, entry=entry)
    if o_verbose:
        print("CPU #%u on %s LPID %u" % (cpu, rnf, lpid))
    S.cpu_lpid[cpu] = lpid
    if g_progress is not None:
        g_progress.record_lpid(cpu, lpid)
    return lpid


def discover_cpu_rnf_ports_atomic_batch(S, entries):
    logical_events_by_entry = []
    for entry in entries:
        logical_events_by_entry.append([atomic_rnf_events(rnf, entry) for rnf in S.rnf_ports])
    indices = get_exact_event_batch(entries, logical_events_by_entry, time=o_time, min_count=o_atomic_min_count)
    for (entry, ix) in zip(entries, indices):
        cpu = entry["cpu"]
        rnf = S.rnf_ports[ix]
        if o_verbose >= 1:
            print("CPU #%u on %s" % (cpu, rnf))
        S.cpu_rnf_port[cpu] = rnf
        if cpu not in rnf.cpus:
            rnf.cpus.append(cpu)
        if g_progress is not None:
            g_progress.record_rnf(cpu, rnf)


def discover_cpu_lpids_atomic_batch(S, entries):
    logical_events_by_entry = []
    for entry in entries:
        cpu = entry["cpu"]
        rnf = S.cpu_rnf_port[cpu]
        if o_verbose >= 2:
            print("discovering LPID for CPU%u on RN-F %s" % (cpu, rnf))
        logical_events_by_entry.append([atomic_rnf_events(rnf, entry, lpid=lpid) for lpid in range(16)])
    indices = get_exact_event_batch(entries, logical_events_by_entry, time=o_time, min_count=o_atomic_min_count)
    for (entry, lpid) in zip(entries, indices):
        cpu = entry["cpu"]
        rnf = S.cpu_rnf_port[cpu]
        if o_verbose:
            print("CPU #%u on %s LPID %u" % (cpu, rnf, lpid))
        S.cpu_lpid[cpu] = lpid
        if g_progress is not None:
            g_progress.record_lpid(cpu, lpid)


def pick_any_hnf_port(S, cmn_seq):
    """
    Pick any HN-F/HN-S port in the mesh, so that we can set a
    download-watchpoint on it.
    """
    cmn = S.CMNs[cmn_seq]
    for p in cmn.ports(properties=CMN_PROP_HNF):
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
    ids = list(rp.port.ids())
    hnfs = hnf_ports_subset(S, cmn.cmn_seq)
    logical_events = srcid_logical_events(cmn, ids, hnfs)
    try:
        ix = get_max_logical_event(cpu, logical_events, time=o_time)
    except SystemExit:
        all_hnfs = all_hnf_ports(S, cmn.cmn_seq)
        if len(hnfs) == len(all_hnfs):
            raise
        if o_verbose >= 1:
            print("retrying SRCID discovery for CPU#%u using all HN-F ports" % cpu)
        logical_events = srcid_logical_events(cmn, ids, all_hnfs)
        ix = get_max_logical_event(cpu, logical_events, time=o_time)
    id = ids[ix]
    if o_verbose:
        print("%s CPU#%u SRCID=0x%x" % (rp, cpu, id))
    S.cpu_id[cpu] = id
    if g_progress is not None:
        g_progress.record_srcid(cpu, id)
    return id


def discover_cpu_srcid_atomic(S, cpu):
    """
    Discover the CPU's SRCID by matching exact tagged atomic requests at a
    HN-F download watchpoint.
    """
    rp = S.cpu_rnf_port[cpu]
    cmn = rp.port.CMN()
    if o_verbose >= 2:
        print("discovering SRCID for CPU#%u on %s" % (cpu, rp))
    ids = list(rp.port.ids())
    entry = atomic_entry_for_cpu(S, cpu)
    logical_events = srcid_logical_events_atomic_mesh(cmn, ids, all_hnf_ports(S, cmn.cmn_seq), entry=entry)
    ix = get_exact_event(cpu, logical_events, time=o_time, min_count=o_atomic_min_count, entry=entry)
    id = ids[ix]
    if o_verbose:
        print("%s CPU#%u SRCID=0x%x" % (rp, cpu, id))
    S.cpu_id[cpu] = id
    if g_progress is not None:
        g_progress.record_srcid(cpu, id)
    return id


def discover_cpus(S, cpu=None, expected=None):
    cpus = [cpu] if cpu is not None else list(iter_cpus(S))
    if o_method == "atomic":
        pending = [c for c in cpus if c not in S.cpu_rnf_port]
        try:
            for c in list(pending):
                exp = expected_cpu_mapping(expected, c)
                if exp is None:
                    continue
                if verify_cpu_rnf_port_guess_atomic(S, c, exp):
                    pending.remove(c)
            for entries in iter_atomic_batches(S, cpus=pending):
                discover_cpu_rnf_ports_atomic_batch(S, entries)
                if g_diagram is not None:
                    for entry in entries:
                        c = entry["cpu"]
                        S.set_cpu(c, S.cpu_rnf_port[c].port, id=None)
                    g_diagram.update()
                    print(g_diagram.cursor_up() + g_diagram.str_color(), end="")
                    S.discard_cpu_mappings()
        except atomic_failure_exceptions() as e:
            if pending and not [c for c in cpus if c in S.cpu_rnf_port]:
                fallback_from_atomic_to_interval(e)
                return discover_cpus(S, cpu=cpu, expected=None)
            raise
    else:
        for c in cpus:
            if c in S.cpu_rnf_port:
                continue
            discover_cpu_rnf_port(S, c)
            if g_diagram is not None:
                S.set_cpu(c, S.cpu_rnf_port[c].port, id=None)
                g_diagram.update()
                print(g_diagram.cursor_up() + g_diagram.str_color(), end="")
    S.discard_cpu_mappings()
    # Check if some RN-Fs have multiple CPUs
    is_multiple = 0
    for rp in S.rnf_ports:
        rp_cpus = [c for c in rp.cpus if c in cpus]
        if len(rp_cpus) == 0:
            # not necessarily an error - could be fused out
            if o_verbose >= 2 and cpu is None:
                print("RN-F port has no CPUs: %s" % rp)
        elif len(rp_cpus) >= 2:
            # CPUs multplexed on to a RN-F port: need distinguishing by device and/or LPID
            if o_verbose >= 2 or (False and o_verbose >= 1 and not is_multiple):
                print("RN-F port has multiple CPUs: %s" % rp)
            is_multiple += 1
    # When CALs are in use anywhere in the system, establish explicit SRCIDs
    # for every CPU. Otherwise only multi-CPU RN-F ports need SRCID probing.
    # Once SRCIDs are known, only fall back to LPID when ids still clash.
    cal_in_use = any([rp.port.cal for rp in S.rnf_ports])
    need_srcid = []
    for rp in S.rnf_ports:
        rp_cpus = [c for c in rp.cpus if c in cpus]
        if cal_in_use or len(rp_cpus) >= 2 or o_force_srcid:
            need_srcid += [cpu for cpu in rp_cpus if cpu not in need_srcid]
    if need_srcid:
        if o_verbose:
            print("Discovering CHI SRCIDs...")
        for cpu in need_srcid:
            if cpu in S.cpu_id:
                continue
            exp = expected_cpu_mapping(expected, cpu)
            if o_method == "atomic" and verify_cpu_srcid_guess_atomic(S, cpu, exp):
                continue
            if o_method == "atomic":
                discover_cpu_srcid_atomic(S, cpu)
            else:
                discover_cpu_srcid(S, cpu)
    for c in cpus:
        if c not in S.cpu_id:
            S.cpu_id[c] = S.cpu_rnf_port[c].port.base_id()
    need_lpid = []
    is_multiple = 0
    for rp in S.rnf_ports:
        rp.id_cpu = {}
        rp.id_clash = False
        rp_cpus = [c for c in rp.cpus if c in cpus]
        for cpu in rp_cpus:
            id = S.cpu_id[cpu]
            if id in rp.id_cpu:
                if (o_verbose >= 2) or (o_verbose and not is_multiple):
                    print("%s: CPU#%u and CPU#%u both have SRCID=0x%x" % (rp, rp.id_cpu[id][0], cpu, id))
                is_multiple += 1
                rp.id_clash = True
            else:
                rp.id_cpu[id] = []
            rp.id_cpu[id].append(cpu)
        if len(rp_cpus) >= 2 and not rp.id_clash and not o_force_lpid:
            for cpu in rp_cpus:
                S.cpu_lpid[cpu] = 0
        elif rp.id_clash or o_force_lpid:
            need_lpid += [cpu for cpu in rp_cpus if cpu not in need_lpid]
    if need_lpid:
        if o_verbose:
            print("Discovering LPIDs...")
        if o_method == "atomic":
            pending_lpid = []
            for c in need_lpid:
                exp = expected_cpu_mapping(expected, c)
                if not verify_cpu_lpid_guess_atomic(S, c, exp):
                    pending_lpid.append(c)
            for entries in iter_atomic_batches(S, cpus=pending_lpid):
                discover_cpu_lpids_atomic_batch(S, entries)
        else:
            for c in need_lpid:
                if c in S.cpu_lpid:
                    continue
                discover_cpu_lpid(S, c)
    # We've now hopefully discovered a unique (port, id, lpid) combination for each CPU.
    for c in cpus:
        S.set_cpu(c, S.cpu_rnf_port[c].port, id=S.cpu_id[c], lpid=S.cpu_lpid.get(c, None))


def prepare_system(S):
    """
    Add some fields to the System object, for use in CPU discovery.
    """
    S.n_cpu = multiprocessing.cpu_count()
    S.online_cpus = list_online_cpus()
    if S.online_cpus[-1] != S.n_cpu - 1:
        print("Some CPUs may be offline: CPU numbers from %u to %u but %u are online" %
              (S.online_cpus[0], S.online_cpus[-1], S.n_cpu))
    S.rnf_ports = []
    # Our observations about where each CPU is,
    # progressively populated by watchpoint counting.
    S.cpu_rnf_port = {}     # CMN_RNFPort object
    S.cpu_lpid = {}         # LPID for each cpu
    S.cpu_id = {}           # device id (SRCID/TGTID) for each CPU
    S.rnf_ports = [CMN_RNFPort(p) for p in S.ports(properties=CMN_PROP_RNF)]
    if not S.rnf_ports:
        print("No RN-F ports found in system!", file=sys.stderr)
        sys.exit(1)
    if o_verbose:
        print("%u CPUs, %u RN-F ports" % (S.n_cpu, len(S.rnf_ports)))
    if o_method == "atomic":
        if atomic_batch_capacity(S) < 1:
            fallback_from_atomic_to_interval("Atomic batching requires at least one runnable issuer")
        if o_atomic_contenders > 0 and len(S.online_cpus) < (1 + o_atomic_contenders):
            fallback_from_atomic_to_interval("Atomic method needs at least %u online CPUs for %u contenders" %
                                             (1 + o_atomic_contenders, o_atomic_contenders))
        if o_atomic_batch > o_atomic_page_lines:
            fallback_from_atomic_to_interval("Atomic batch size exceeds page capacity of %u lines" %
                                             o_atomic_page_lines)
    # We usually see a consistent number of CPUs per RN-F port, but not always
    if (S.n_cpu % len(S.rnf_ports)) != 0:
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
    S.rnf_port_map = {}
    for rnf in S.rnf_ports:
        S.rnf_port_map[(rnf.port.CMN().cmn_seq, rnf.port.xp.node_id(), rnf.port.port_number)] = rnf
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


def print_mismatches(mismatches):
    for (cpu, exp, got) in mismatches:
        print("CPU %3u: " % cpu, end="")
        if exp is None:
            print("not in JSON, discovered %s" % mapping_str(got))
        elif got is None:
            print("expected %s, not rediscovered" % mapping_str(exp))
        else:
            print("expected %s, discovered %s" % (mapping_str(exp), mapping_str(got)))


def mismatch_summary(mismatches):
    changed = []
    added = []
    removed = []
    for (cpu, exp, got) in mismatches:
        if exp is None:
            added.append(cpu)
        elif got is None:
            removed.append(cpu)
        else:
            changed.append(cpu)
    parts = []
    if changed:
        parts.append("%u changed" % len(changed))
    if added:
        parts.append("%u added" % len(added))
    if removed:
        parts.append("%u removed" % len(removed))
    summary = "CPU mapping changes detected"
    if parts:
        summary += ": " + ", ".join(parts)
    cpus = sorted([cpu for (cpu, _exp, _got) in mismatches])
    if cpus and len(cpus) <= 4:
        summary += " (CPU%s %s)" % ("" if len(cpus) == 1 else "s", ", ".join([str(cpu) for cpu in cpus]))
    return summary


def apply_expected_cpu_mappings(S, expected, cpus=None):
    if expected is None:
        return
    if cpus is not None:
        cpus = set(cpus)
    for (cpu, mapping) in expected.items():
        if cpus is not None and cpu not in cpus:
            continue
        rnf = expected_rnf_port(S, mapping)
        if rnf is None:
            continue
        S.cpu_rnf_port[cpu] = rnf
        if cpu not in rnf.cpus:
            rnf.cpus.append(cpu)
        S.cpu_id[cpu] = mapping[3]
        S.cpu_lpid[cpu] = mapping[4]


def write_mismatch_json(S, fn="./cmn-system-mismatch.json"):
    try:
        S.cpu_timestamp = time.time()
        cmn_json.json_dump_file_from_system(S, fn)
        print("Wrote discovered CPU mappings to %s" % fn, file=sys.stderr)
        return fn
    except Exception as e:
        print("Could not write mismatch JSON %s: %s" % (fn, e), file=sys.stderr)
        return None


def main(argv):
    global g_diagram, g_progress, o_atomic_batch, o_atomic_contenders, o_atomic_min_count, o_factor
    global o_force_lpid, o_force_srcid, o_method, o_retries, o_retry_multiplier, o_time, o_verbose
    import argparse
    parser = argparse.ArgumentParser(description="Discover where CPUs are located in system mesh",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--json", type=str, default=cmn_json.cmn_config_filename(), help="JSON system description")
    parser.add_argument("--update", action="store_true", help="refresh cached CPU mappings in the JSON system description")
    parser.add_argument("--discard", action="store_true", help="discard any previous CPU mappings")
    parser.add_argument("--verify", action="store_true", help="verify any existing CPU mappings by rediscovering them")
    parser.add_argument("--no-use-checkpoint", action="store_true", help="ignore any previous discovery checkpoint")
    parser.add_argument("-o", "--output", type=str, help="output JSON filename")
    parser.add_argument("--cpu", type=int, help="discover one CPU")
    parser.add_argument("--time", type=float, default=o_time, help="measurement time")
    parser.add_argument("--method", choices=["interval", "atomic"], default=o_method, help="CPU discovery method")
    parser.add_argument("--detection-level", type=float, default=o_factor, help="traffic detection sensitivity")
    parser.add_argument("--retries", type=int, default=o_retries, help="number of times to retry")
    parser.add_argument("--retry-multiplier", type=float, default=o_retry_multiplier, help="retry time multiplier")
    parser.add_argument("--atomic-batch", type=int, default=o_atomic_batch, help="number of CPUs to probe in one atomic batch")
    parser.add_argument("--atomic-contenders", type=int, default=o_atomic_contenders, help="number of contender threads per probed CPU")
    parser.add_argument("--atomic-min-count", type=int, default=o_atomic_min_count, help="minimum exact-match count")
    parser.add_argument("-N", type=int, help="number of CPUs")
    parser.add_argument("--diagram", action="store_true", help="visualize CPU discovery")
    parser.add_argument("--force-discover", action="store_true")
    parser.add_argument("--perf-bin", type=str, default="perf", help="path to perf command")
    parser.add_argument("--lmbench-bin", type=str, default=None, help="bin directory for lmbench")
    parser.add_argument("--keep-exe", action="store_true", help="keep the generated traffic helper executable")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="increase verbosity")
    opts = parser.parse_args(argv)
    cmn_traffic_gen.o_perf_bin = opts.perf_bin
    cmn_perfcheck.o_perf_bin = opts.perf_bin
    cmn_traffic_gen.o_lmbench = opts.lmbench_bin
    cmn_traffic_gen.o_keep_exe = opts.keep_exe
    o_verbose = opts.verbose
    o_time = opts.time
    o_method = opts.method
    o_force_lpid = opts.force_discover
    o_force_srcid = opts.force_discover
    o_retries = opts.retries
    o_retry_multiplier = opts.retry_multiplier
    o_atomic_batch = opts.atomic_batch
    o_atomic_contenders = opts.atomic_contenders
    o_atomic_min_count = opts.atomic_min_count
    o_factor = opts.detection_level
    cmn_traffic_gen.o_verbose = max(0, opts.verbose - 1)
    if not cmn_perfcheck.check_cmn_pmu_events():
        print("CPU detection requires kernel support for CMN PMU events",
              file=sys.stderr)
        sys.exit(1)
    S = cmn_json.system_from_json_file(opts.json)
    expected_cpu_mappings = None
    if S.has_cpu_mappings():
        print("%s: already has CPU mappings - " % opts.json, end="")
        if opts.verify or opts.update:
            print("checking for updates" if opts.update else "verifying")
            expected_cpu_mappings = snapshot_cpu_mappings(S)
            S.discard_cpu_mappings()
        elif not opts.discard:
            print("use --discard to discard")
            sys.exit()
        else:
            print("discarding")
            S.discard_cpu_mappings()
    elif opts.verify:
        print("%s: has no CPU mappings to verify" % opts.json, file=sys.stderr)
        sys.exit(1)
    prepare_system(S)
    if opts.update and opts.cpu is not None and expected_cpu_mappings is not None:
        apply_expected_cpu_mappings(S, expected_cpu_mappings,
                                    cpus=[cpu for cpu in expected_cpu_mappings if cpu != opts.cpu])
    g_progress = DetectProgress(progress_filename(), opts.json, o_method)
    completed_detection = False
    try:
        resume = False
        if not opts.no_use_checkpoint:
            if progress_file_is_stale(g_progress.path):
                print("Discarding stale discovery checkpoint from previous boot: %s" % g_progress.path)
                g_progress.remove()
            else:
                resume = g_progress.load()
        g_progress.begin(resume)
        if resume:
            g_progress.apply(S)
            print("Reusing discovery checkpoint from %s (use --no-use-checkpoint to ignore it)" % g_progress.path)
        update_needs_full_discovery = opts.update and expected_cpu_mappings is None
        if opts.cpu is not None and update_needs_full_discovery:
            print("No cached CPU mappings present, ignoring --cpu and doing full discovery for --update")
        if opts.cpu is not None and not update_needs_full_discovery:
            o_verbose = max(o_verbose, 2)
            on = cpu_is_online(opts.cpu)
            if not on:
                print("CPU#%u is %s" % (opts.cpu, ["offline", "invalid"][on is None]), file=sys.stderr)
                sys.exit(1)
            seeded_expected = expected_cpu_mappings if (opts.verify and o_method == "atomic") else None
            if opts.update and o_method == "atomic":
                seeded_expected = expected_cpu_mappings
            discover_cpus(S, cpu=opts.cpu, expected=seeded_expected)
            completed_detection = True
            if opts.verify:
                mismatches = verify_cpu_mappings(S, expected_cpu_mappings, cpus=[opts.cpu])
                if mismatches:
                    print("CPU mapping verification failed:", file=sys.stderr)
                    print_mismatches(mismatches)
                    S.set_cpu(opts.cpu, S.cpu_rnf_port[opts.cpu].port, id=S.cpu_id[opts.cpu], lpid=S.cpu_lpid.get(opts.cpu, 0))
                    write_mismatch_json(S)
                    sys.exit(1)
                print("CPU mapping verified for CPU %u" % opts.cpu)
            elif opts.update:
                mismatches = verify_cpu_mappings(S, expected_cpu_mappings, cpus=[opts.cpu]) if expected_cpu_mappings is not None else []
                if expected_cpu_mappings is None:
                    print("Writing JSON file with CPU locations: %s" % opts.json)
                    S.cpu_timestamp = time.time()
                    cmn_json.json_dump_file_from_system(S, opts.json)
                elif mismatches:
                    print(mismatch_summary(mismatches))
                    print("Writing updated CPU locations: %s" % opts.json)
                    S.cpu_timestamp = time.time()
                    cmn_json.json_dump_file_from_system(S, opts.json)
                else:
                    print("CPU mapping unchanged for CPU %u" % opts.cpu)
        else:
            if opts.diagram:
                o_verbose = 0
                cmn_traffic_gen.o_verbose = 0
                g_diagram = cmn_diagram.CMNDiagram(S.CMNs[0], small=True)
                print(g_diagram.str_color(), end="")
            seeded_expected = expected_cpu_mappings if (opts.verify and o_method == "atomic") else None
            if opts.update and o_method == "atomic":
                seeded_expected = expected_cpu_mappings
            discover_cpus(S, expected=seeded_expected)
            completed_detection = True
            if opts.verify:
                mismatches = verify_cpu_mappings(S, expected_cpu_mappings)
                if mismatches:
                    print("CPU mapping verification failed:", file=sys.stderr)
                    print_mismatches(mismatches)
                    write_mismatch_json(S)
                    sys.exit(1)
                print("CPU mappings verified")
            elif opts.update:
                mismatches = verify_cpu_mappings(S, expected_cpu_mappings) if expected_cpu_mappings is not None else []
                if expected_cpu_mappings is None:
                    print("Writing JSON file with CPU locations: %s" % opts.json)
                    S.cpu_timestamp = time.time()
                    cmn_json.json_dump_file_from_system(S, opts.json)
                elif mismatches:
                    print(mismatch_summary(mismatches))
                    print("Writing updated CPU locations: %s" % opts.json)
                    S.cpu_timestamp = time.time()
                    cmn_json.json_dump_file_from_system(S, opts.json)
                else:
                    print("CPU mappings unchanged")
            else:
                print_cpus(S)
            output_temp = False
            if opts.verify or opts.update:
                ofn = None
            elif opts.output:
                ofn = opts.output
            elif opts.update or opts.discard:
                ofn = opts.json
            else:
                # Don't discard all that hard work - pick an output file, in the current
                # directory, but make sure not to overwrite anything.
                output_temp = True
                i = 0
                while True:
                    ofn = "./cmn-system" + (("-%u" % i) if i >= 1 else "") + ".json"
                    if not os.path.exists(ofn):
                        break
                    i += 1
            if ofn is not None:
                print("Writing JSON file with CPU locations: %s" % ofn)
                S.cpu_timestamp = time.time()
                cmn_json.json_dump_file_from_system(S, ofn)
            if output_temp:
                print("now copy %s to %s or rerun with --update" % (ofn, cmn_json.cmn_config_filename()))
    finally:
        if completed_detection and g_progress is not None:
            g_progress.remove()


if __name__ == "__main__":
    main(sys.argv[1:])
