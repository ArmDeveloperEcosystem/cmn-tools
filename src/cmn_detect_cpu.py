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
import copy
import hashlib
import random
import sys
import time
from collections import namedtuple

import app_data
import cmn_json
import cmn_traffic_gen
from cmn_enum import *
import cmn_diagram
import cmn_perfstat
import cmnwatch


ATOMIC_OPCODE = "AtomicStoreEOR"
ATOMIC_LINE_SIZE = 64
ATOMIC_PAGE_LINES = 64


class CPUDiscoveryOptions:
    """Configuration for one discovery run, independent of command-line parsing."""

    def __init__(self, time=0.5, method="atomic", detection_level=5.0,
                 retries=3, retry_multiplier=3.0, atomic_batch=4,
                 atomic_contenders=2, atomic_min_count=1, force_discover=False,
                 verbose=0, perf_bin="perf", lmbench_bin=None, keep_exe=False):
        self.time = time
        self.method = method
        self.detection_level = detection_level
        self.retries = retries
        self.retry_multiplier = retry_multiplier
        self.atomic_batch = atomic_batch
        self.atomic_contenders = atomic_contenders
        self.atomic_min_count = atomic_min_count
        self.force_discover = force_discover
        self.verbose = verbose
        self.perf_bin = perf_bin
        self.lmbench_bin = lmbench_bin
        self.keep_exe = keep_exe


class TrafficMeasurements:
    """
    Share one Perf instance across a discovery run's checks and traffic counting.
    Other runs' measurement settings are never changed, even temporarily.
    """

    def __init__(self, options, perf=None):
        self.lmbench_bin = options.lmbench_bin
        self.keep_exe = options.keep_exe
        self.verbose = max(0, options.verbose - 1)
        self.perf = perf if perf is not None else cmn_perfstat.Perf(perf_bin=options.perf_bin, verbose=self.verbose)

    def check_cmn_events(self):
        return self.perf.check_cmn_events()

    def cpu_gen_traffic(self, cpu, events, time):
        return cmn_traffic_gen.cpu_gen_traffic(cpu, events=events, time=time,
                perf=self.perf, lmbench_bin=self.lmbench_bin,
                keep_exe=self.keep_exe, verbose=self.verbose)

    def cpus_gen_atomic_traffic(self, entries, events, time):
        return cmn_traffic_gen.cpus_gen_atomic_traffic(entries, events=events, time=time,
                perf=self.perf, keep_exe=self.keep_exe, verbose=self.verbose)


class CPUDiscoveryDiagram(cmn_diagram.CMNDiagram):
    """Show observations without installing temporary CPU mappings in System."""

    def __init__(self, discovery, cmn):
        self.discovery = discovery
        cmn_diagram.CMNDiagram.__init__(self, cmn, small=True)

    def port_cpu_numbers(self, po):
        return sorted([cpu for cpu, rnf in self.discovery.cpu_rnf_port.items()
                       if rnf.port is po])


def atomic_failure_exceptions():
    """Exceptions which make atomic discovery unavailable or inconclusive."""
    return (SystemExit, cmn_traffic_gen.TrafficMeasurementError)


def progress_filename():
    return app_data.app_data_cache("cmn-detect-progress", app="arm")


def file_fingerprint(path):
    """
    Return a content fingerprint for a discovery input file.

    A checkpoint is safe to reuse only with the topology from which it was
    produced. Hashing the file, rather than relying on its timestamp, also
    detects an in-place rewrite during the same boot. A stable marker keeps
    DetectProgress usable in tests and lets a missing file fail to match a
    later-created file.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()
    except (IOError, OSError):
        return "missing"


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
    """
    Append and restore restartable CPU-discovery checkpoints.

    The file is an append-only sequence of tab-separated runs. A ``meta``
    record starts a run and identifies its absolute topology JSON pathname,
    discovery method, and JSON content fingerprint. Following ``rnf``,
    ``srcid`` and ``lpid`` records are applied only when the final run has the
    same complete identity. This prevents measurements from another topology
    or method being mistaken for progress in the current run.
    """
    def __init__(self, path, json_fn, method):
        self.path = path
        self.json_fn = os.path.abspath(json_fn)
        self.json_fingerprint = file_fingerprint(self.json_fn)
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
        """Append a run header unless load() selected a run to resume."""
        if resume:
            return
        self._append(["meta", self.json_fn, self.method, self.json_fingerprint])

    def load(self):
        """Load the latest run matching this topology content and method."""
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
                    current = (len(fields) >= 4 and fields[1] == self.json_fn and
                               fields[2] == self.method and fields[3] == self.json_fingerprint)
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

    def _find_rnf(self, discovery, cmn_seq, xp_id, port_number):
        for rnf in discovery.rnf_ports:
            if (rnf.port.CMN().cmn_seq == cmn_seq and rnf.port.xp.node_id() == xp_id and
                    rnf.port.port_number == port_number):
                return rnf
        return None

    def apply(self, discovery):
        """Seed discovery state with records whose RN-F still exists."""
        for (cpu, loc) in sorted(self.rnf.items()):
            rnf = self._find_rnf(discovery, loc[0], loc[1], loc[2])
            if rnf is None:
                continue
            discovery.cpu_rnf_port[cpu] = rnf
            if cpu not in rnf.cpus:
                rnf.cpus.append(cpu)
        for (cpu, lpid) in self.lpid.items():
            if cpu in discovery.cpu_rnf_port:
                discovery.cpu_lpid[cpu] = lpid
        for (cpu, srcid) in self.srcid.items():
            if cpu in discovery.cpu_rnf_port:
                discovery.cpu_id[cpu] = srcid

    def remove(self):
        if os.path.exists(self.path):
            os.remove(self.path)


CPUMapping = namedtuple("CPUMapping",
                        ["cmn_seq", "xp_node_id", "port_number", "srcid", "lpid"])


def as_cpu_mapping(m):
    if m is None:
        return None
    if not isinstance(m, CPUMapping):
        m = CPUMapping(*m)
    return m


def cpu_mapping(cpu_obj):
    return CPUMapping(
        cpu_obj.port.CMN().cmn_seq,
        cpu_obj.port.xp.node_id(),
        cpu_obj.port.port_number,
        cpu_obj.id,
        cpu_obj.lpid
    )


def snapshot_cpu_mappings(S):
    return dict((cpu_obj.cpu, cpu_mapping(cpu_obj)) for cpu_obj in S.cpus())


def mapping_str(m):
    m = as_cpu_mapping(m)
    lpid = "unknown" if m.lpid is None else str(m.lpid)
    return "M%u/XP:0x%x/P%u SRCID=0x%x LPID=%s" % (
        m.cmn_seq, m.xp_node_id, m.port_number, m.srcid, lpid)


def expected_cpu_mapping(expected, cpu):
    if expected is None:
        return None
    return as_cpu_mapping(expected.get(cpu, None))


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


def max_index(x, factor=5.0):
    """
    Given a list of event counts, return the index of the count that is
    much bigger (by a factor of 'factor') than the rest.
    If there's no clear winner, return None.
    """
    if len(x) == 1:
        return 0        # degenerate case
    mx = max(x)
    ix = x.index(mx)
    # Do not mutate the caller's measurement results while finding the best
    # competing count: callers may need the raw counts for diagnostics.
    mr = max(x[:ix] + x[ix+1:])
    if mx <= (mr*factor):
        return None
    return ix


def initial_measurement_time(n_events, time=0.5):
    """
    Start short, but allow more time when perf must schedule many events.

    Retries lengthen the measurement if this optimistic first interval is too
    noisy. Capping it at the requested time avoids making the first attempt
    unexpectedly more expensive than a normal measurement.
    """
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
    """
    Normalize logical events to ``logical -> watchpoint -> perf event`` lists.

    A watchpoint may expand to several perf events. Keeping those together as
    one logical candidate lets discovery compare hardware identities rather
    than individual counters.
    """
    nle = []
    for le in logical_events:
        if le and isinstance(le[0], str):
            nle.append([le])
        else:
            nle.append(le)
    return nle


def flatten_logical_events(logical_events):
    """Flatten logical events for perf and retain indices needed to regroup."""
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
    """Sum expanded perf counters back into their logical candidates."""
    return [sum([raw_counts[ix] for ix in g]) for g in groups]


def exact_group_indices(counts_by_entry, min_count=1):
    """Return the unique matching logical event for every atomic issuer."""
    return [sole_index(c, min_count=min_count) for c in counts_by_entry]


def atomic_byte_offset(cpu, slot):
    """Choose a non-zero byte that helps distinguish entries sharing a page."""
    return 1 + ((cpu + slot) % (ATOMIC_LINE_SIZE - 1))


def atomic_page_offset(entry):
    """Return the tagged byte's offset in the atomic traffic page."""
    return (entry["line_index"] * ATOMIC_LINE_SIZE) + entry["byte_offset"]


def atomic_addr(page_offset, n_bits=52):
    """Build the watchpoint value/mask matching an offset in any mapped page."""
    mask = ((1 << n_bits) - 1) ^ ((1 << 12) - 1)
    return cmnwatch.unconvert_value_mask(page_offset, mask)


def atomic_rnf_events(rnf, entry, **matches):
    """Create upload watchpoints for one entry's tagged atomic request."""
    kwds = {"opcode": ATOMIC_OPCODE, "addr": atomic_addr(atomic_page_offset(entry))}
    kwds.update(matches)
    return rnf.perf_events(**kwds)


def srcid_logical_events_atomic_mesh(cmn, ids, hnfs, entry):
    """
    Build mesh-wide exact atomic matches for each candidate SRCID.

    Atomic traffic is tagged by opcode and page offset, so matching by HN-F
    device number across the mesh is sufficient and avoids multiplying events
    by every home-node position.
    """
    logical_events = []
    devs = sorted(set([hnf.port_number for hnf in hnfs]))
    for id in ids:
        id_events = []
        for dev in devs:
            w = cmnwatch.Watchpoint(cmn_version=cmn.product_config, chn="REQ", up=False,
                                    opcode=ATOMIC_OPCODE, addr=atomic_addr(atomic_page_offset(entry)), srcid=id)
            id_events.append(w.perf_events(cmn_instance=cmn.cmn_seq, dev=dev))
        logical_events.append(id_events)
    return logical_events


def pick_any_hnf_port(S, cmn_seq):
    """
    Pick any HN-F/HN-S port in the mesh, so that we can set a
    download-watchpoint on it.
    """
    cmn = S.CMNs[cmn_seq]
    for p in cmn.ports(properties=CMN_PROP_HNF):
        return p
    assert False, "CMN %s has no home-node ports!" % cmn


def cpu_is_online(n):
    """Return True/False for a valid CPU, or None if the CPU does not exist."""
    try:
        with open(("/sys/devices/system/cpu/cpu%u/online" % n), "r") as f:
            on = int(f.read().strip())
        return on == 1
    except (IOError, OSError):
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


def print_cpu_report(S):
    """
    Summarize detected CPU mappings and identify RN-F nodes which have no CPU.

    RN-F identity includes the CMN instance because node ids are only unique
    within a mesh. Count CAL devices separately: they share a port, but are
    distinct RN-F nodes with distinct CHI node ids.
    """
    cpus = list(S.cpus())
    cpu_count_by_rnf = {}
    for cpu in cpus:
        key = (cpu.port.CMN().cmn_seq, cpu.id)
        cpu_count_by_rnf[key] = cpu_count_by_rnf.get(key, 0) + 1

    rnf_nodes = []
    for port in S.ports(properties=CMN_PROP_RNF):
        for node_id in port.ids():
            rnf_nodes.append((port.CMN().cmn_seq, node_id))
    rnf_nodes = sorted(rnf_nodes)
    unused_rnf_nodes = [key for key in rnf_nodes if key not in cpu_count_by_rnf]
    shared = any([n > 1 for n in cpu_count_by_rnf.values()])
    nonzero_lpid = any([cpu.lpid is not None and cpu.lpid != 0 for cpu in cpus])

    print("CPU detection report:")
    print("  CPUs detected: %u" % len(cpus))
    print("  CPUs share RN-F nodes: %s" % ("yes" if shared else "no"))
    print("  Non-zero LPIDs in use: %s" % ("yes" if nonzero_lpid else "no"))
    if unused_rnf_nodes:
        print("  RN-F nodes without active CPUs: %u" % len(unused_rnf_nodes))
        for (cmn_seq, node_id) in unused_rnf_nodes:
            print("    CMN#%u RN-F 0x%x" % (cmn_seq, node_id))
    else:
        print("  RN-F nodes without active CPUs: none")


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


def write_mismatch_json(S, fn="./cmn-system-mismatch.json"):
    try:
        S.cpu_timestamp = time.time()
        cmn_json.json_dump_file_from_system(S, fn)
        print("Wrote discovered CPU mappings to %s" % fn, file=sys.stderr)
        return fn
    except Exception as e:
        print("Could not write mismatch JSON %s: %s" % (fn, e), file=sys.stderr)
        return None


class CPUDiscovery:
    """Own the state and measurements of one CPU-discovery run."""

    def __init__(self, system, options=None, backend=None, progress=None, diagram=None):
        self.system = system
        self.options = copy.copy(options) if options is not None else CPUDiscoveryOptions()
        self.backend = backend if backend is not None else TrafficMeasurements(self.options)
        self.progress = progress
        self.diagram = diagram
        self.n_cpu = None
        self.online_cpus = []
        self.rnf_ports = []
        self.rnf_port_events = []
        self.rnf_port_map = {}
        self.cpu_rnf_port = {}
        self.cpu_lpid = {}
        self.cpu_id = {}
        self.selected_hnf_ports = {}
        self.completed_cpus = None

    def update_diagram(self):
        if self.diagram is not None:
            self.diagram.clear()
            self.diagram.update()
            print(self.diagram.cursor_up() + self.diagram.str_color(), end="")

    def commit_cpu_mappings(self, preserve_others=False):
        """Install completed observations, optionally retaining unselected CPUs.

        Discovery and checkpoint restoration never modify the System's mappings.
        Call this only after discovery succeeds and its results are accepted.
        """
        if self.completed_cpus is None:
            raise RuntimeError("CPU discovery has not completed")
        mappings = [(cpu, self.cpu_rnf_port[cpu].port, self.cpu_id[cpu],
                     self.cpu_lpid.get(cpu, None)) for cpu in self.completed_cpus]
        if preserve_others and self.system.has_cpu_mappings():
            mappings += [(co.cpu, co.port, co.id, co.lpid) for co in self.system.cpus()
                         if co.cpu not in self.completed_cpus]
        self.system.discard_cpu_mappings()
        for cpu, port, srcid, lpid in mappings:
            self.system.set_cpu(cpu, port, id=srcid, lpid=lpid)

    def switch_discovery_method(self, method, why=None):
        """Switch methods and start a separate checkpoint run for the new method."""
        if why is not None:
            print(why, file=sys.stderr)
        self.options.method = method
        if self.progress is not None:
            self.progress = DetectProgress(self.progress.path, self.progress.json_fn, method)
            self.progress.begin(False)

    def fallback_from_atomic_to_interval(self, why):
        """Use traffic-volume discovery when tagged atomic traffic cannot be used."""
        self.switch_discovery_method("interval",
                                "Atomic discovery failed before any CPUs were identified (%s), falling back to interval method"
                                % why)

    def discovered_cpu_mapping(self, cpu):
        rnf = self.cpu_rnf_port[cpu]
        return CPUMapping(
            rnf.port.CMN().cmn_seq,
            rnf.port.xp.node_id(),
            rnf.port.port_number,
            self.cpu_id[cpu],
            self.cpu_lpid.get(cpu, None)
        )

    def verify_cpu_mappings(self, expected, cpus=None):
        """
        Compare discovered CPU mappings with a previous mapping snapshot.
        Return a list of mismatch strings.
        """
        mismatches = []
        if cpus is None:
            cpus = sorted(set(expected.keys()) | set(self.cpu_rnf_port.keys()))
        for cpu in cpus:
            exp = expected.get(cpu, None)
            got = self.discovered_cpu_mapping(cpu) if cpu in self.cpu_rnf_port else None
            if as_cpu_mapping(exp) != as_cpu_mapping(got):
                mismatches.append((cpu, exp, got))
        return mismatches

    def expected_rnf_port(self, expected_mapping):
        if expected_mapping is None:
            return None
        expected_mapping = as_cpu_mapping(expected_mapping)
        key = (expected_mapping.cmn_seq, expected_mapping.xp_node_id,
               expected_mapping.port_number)
        return self.rnf_port_map.get(key, None)

    def exact_guess_matches(self, cpu, logical_events, entry=None):
        try:
            ix = self.get_exact_event(cpu, logical_events, time=self.options.time, min_count=self.options.atomic_min_count, entry=entry)
        except SystemExit:
            return False
        return ix == 0

    def verify_cpu_rnf_port_guess_atomic(self, cpu, expected_mapping):
        rnf = self.expected_rnf_port(expected_mapping)
        if rnf is None:
            return False
        entry = self.atomic_entry_for_cpu(cpu)
        if not self.exact_guess_matches(cpu, [atomic_rnf_events(rnf, entry)], entry=entry):
            return False
        if self.options.verbose >= 2:
            print("CPU #%u on %s (cached guess verified)" % (cpu, rnf))
        self.cpu_rnf_port[cpu] = rnf
        if cpu not in rnf.cpus:
            rnf.cpus.append(cpu)
        if self.progress is not None:
            self.progress.record_rnf(cpu, rnf)
        return True

    def verify_cpu_lpid_guess_atomic(self, cpu, expected_mapping):
        if expected_mapping is None:
            return False
        lpid = as_cpu_mapping(expected_mapping).lpid
        if lpid is None:
            return False
        rnf = self.cpu_rnf_port[cpu]
        entry = self.atomic_entry_for_cpu(cpu)
        if not self.exact_guess_matches(cpu, [[atomic_rnf_events(rnf, entry, lpid=lpid)]], entry=entry):
            return False
        if self.options.verbose >= 2:
            print("CPU #%u on %s LPID %u (cached guess verified)" % (cpu, rnf, lpid))
        self.cpu_lpid[cpu] = lpid
        if self.progress is not None:
            self.progress.record_lpid(cpu, lpid)
        return True

    def verify_cpu_srcid_guess_atomic(self, cpu, expected_mapping):
        if expected_mapping is None:
            return False
        id = as_cpu_mapping(expected_mapping).srcid
        rp = self.cpu_rnf_port[cpu]
        cmn = rp.port.CMN()
        entry = self.atomic_entry_for_cpu(cpu)
        logical_events = srcid_logical_events_atomic_mesh(cmn, [id], self.all_hnf_ports(cmn.cmn_seq), entry=entry)
        if not self.exact_guess_matches(cpu, logical_events, entry=entry):
            return False
        if self.options.verbose >= 2:
            print("%s CPU#%u SRCID=0x%x (cached guess verified)" % (rp, cpu, id))
        self.cpu_id[cpu] = id
        if self.progress is not None:
            self.progress.record_srcid(cpu, id)
        return True

    def get_max_event(self, cpu, events, time=None):
        """
        Given a CPU and a set of performance event descriptors, generate traffic
        on the CPU and return the index of whichever event is the clear winner.
        """
        if time is None:
            time = self.options.time
        t = initial_measurement_time(len(events), time=time)
        for i in range(self.options.retries+1):
            try:
                er = self.backend.cpu_gen_traffic(cpu, events, time=t)
            except cmn_traffic_gen.TrafficMeasurementInconclusive as e:
                if self.options.verbose >= 1:
                    print("retrying after inconclusive measurement (%s)..." % e)
                t = t * self.options.retry_multiplier
                continue
            if self.options.verbose >= 3:
                print("CPU %3u: %s" % (cpu, er))
            ix = max_index(er, factor=self.options.detection_level)
            if ix is not None:
                return ix
            t = t * self.options.retry_multiplier
            if self.options.verbose >= 1:
                print("retrying (%u/%u)..." % (i, self.options.retries))
        print("no clear winner after %u retries, system too busy?" % self.options.retries, file=sys.stderr)
        sys.exit(1)

    def get_max_logical_event(self, cpu, logical_events, time=None):
        """
        Given a CPU and a list of logical events, each possibly represented by one
        or more watchpoints, return the index of whichever logical event wins.
        """
        (events, groups) = flatten_logical_events(logical_events)
        if time is None:
            time = self.options.time
        t = initial_measurement_time(len(events), time=time)
        for i in range(self.options.retries+1):
            try:
                er = self.backend.cpu_gen_traffic(cpu, events, time=t)
            except cmn_traffic_gen.TrafficMeasurementInconclusive as e:
                if self.options.verbose >= 1:
                    print("retrying after inconclusive measurement (%s)..." % e)
                t = t * self.options.retry_multiplier
                continue
            gc = group_counts(er, groups)
            if self.options.verbose >= 3:
                print("CPU %3u grouped-counts: raw=%s groups=%s" % (cpu, er, gc))
            ix = max_index(gc, factor=self.options.detection_level)
            if ix is not None:
                return ix
            t = t * self.options.retry_multiplier
            if self.options.verbose >= 1:
                print("retrying (%u/%u)..." % (i, self.options.retries))
        print("no clear grouped winner after %u retries, system too busy?" % self.options.retries, file=sys.stderr)
        sys.exit(1)

    def get_exact_event_batch(self, entries, logical_events_by_entry, time=None, min_count=1):
        """
        Given a batch of atomic traffic entries and logical events for each entry,
        generate traffic once and return the selected logical event for each entry.
        """
        if time is None:
            time = self.options.time
        t = None
        for i in range(self.options.retries+1):
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
                er = self.backend.cpus_gen_atomic_traffic(entries, events=events, time=t)
            except cmn_traffic_gen.TrafficMeasurementInconclusive as e:
                if self.options.verbose >= 1:
                    print("retrying exact match after inconclusive measurement (%s)..." % e)
                t = t * self.options.retry_multiplier
                continue
            counts_by_entry = [group_counts(er, groups) for groups in groups_by_entry]
            if self.options.verbose >= 3:
                print("exact batch counts: raw=%s groups=%s" % (er, counts_by_entry))
            indices = exact_group_indices(counts_by_entry, min_count=min_count)
            if None not in indices:
                return indices
            t = t * self.options.retry_multiplier
            if self.options.verbose >= 1:
                print("retrying exact match (%u/%u)..." % (i, self.options.retries))
        print("no unique exact watchpoint match after %u retries" % self.options.retries, file=sys.stderr)
        sys.exit(1)

    def get_exact_event(self, cpu, logical_events, time=None, min_count=1, entry=None):
        """Single-CPU wrapper for the batched exact atomic matcher."""
        if entry is None:
            entry = cmn_traffic_gen.atomic_entry(cpu)
        return self.get_exact_event_batch([entry], [logical_events], time=time, min_count=min_count)[0]

    def atomic_batch_capacity(self):
        """
        Return how many issuers can be measured without sharing helper CPUs.

        Each normal entry needs one issuer and ``self.options.atomic_contenders`` other online
        CPUs. Entries also need separate cache lines in the traffic page. Negative
        contender counts are an internal single-entry mode; zero means no helper
        CPUs are reserved.
        """
        if self.options.atomic_contenders < 0:
            return 1
        if self.options.atomic_contenders == 0:
            return min(self.options.atomic_batch, ATOMIC_PAGE_LINES)
        return max(1, min(self.options.atomic_batch, ATOMIC_PAGE_LINES, len(self.online_cpus) // (1 + self.options.atomic_contenders)))

    def build_atomic_entries(self, cpus):
        """
        Assign each issuer a private cache line, byte tag, and helper CPUs.

        Separate lines let a batch be attributed per issuer. Contenders are taken
        only from CPUs outside the batch so a CPU never generates both an issuer's
        tagged operation and another entry's contention traffic.
        """
        cpus = list(cpus)
        others = [cpu for cpu in self.online_cpus if cpu not in cpus]
        entries = []
        for (slot, cpu) in enumerate(cpus):
            contenders = others[(slot * self.options.atomic_contenders):((slot + 1) * self.options.atomic_contenders)]
            entry = cmn_traffic_gen.atomic_entry(cpu, line_index=slot, byte_offset=atomic_byte_offset(cpu, slot), contenders=contenders)
            entries.append(entry)
        return entries

    def atomic_entry_for_cpu(self, cpu):
        """Build the single entry used to verify or discover one CPU."""
        return self.build_atomic_entries([cpu])[0]

    def iter_atomic_batches(self, cpus=None):
        """Yield batches bounded by traffic-page space and available helper CPUs."""
        if cpus is None:
            cpus = list(self.iter_cpus())
        cpus = list(cpus)
        cap = self.atomic_batch_capacity()
        for i in range(0, len(cpus), cap):
            batch = cpus[i:i+cap]
            yield self.build_atomic_entries(batch)

    def hnf_ports(self, cmn_seq):
        return self.hnf_ports_subset(cmn_seq)

    def all_hnf_ports(self, cmn_seq):
        return list(self.system.CMNs[cmn_seq].ports(properties=CMN_PROP_HNF))

    def hnf_ports_subset(self, cmn_seq):
        """
        Select and cache a small spread of home-node ports for interval discovery.

        SRCID discovery creates one watchpoint group per candidate and HN-F, so
        using every HN-F can exceed perf capacity and makes each attempt costly.
        Eight ports normally sample enough distributed traffic to identify a clear
        winner. The random sample avoids a permanent bias toward low-numbered
        ports; self.discover_cpu_srcid() retries with every HN-F if it is inconclusive.
        The selection is cached so retries and CPUs in one mesh use the same set.
        """
        if cmn_seq not in self.selected_hnf_ports:
            ports = self.all_hnf_ports(cmn_seq)
            if len(ports) > 8:
                ports = random.sample(ports, 8)
            self.selected_hnf_ports[cmn_seq] = ports
        return self.selected_hnf_ports[cmn_seq]

    def srcid_logical_events(self, cmn, ids, hnfs, entry=None):
        """Build one logical download-watchpoint group for each candidate SRCID."""
        logical_events = []
        for id in ids:
            id_events = []
            for hnf in hnfs:
                if entry is None:
                    if self.options.verbose >= 3:
                        print("setting download-watchpoint on %s for SRCID=0x%x" % (hnf, id))
                    w = cmnwatch.Watchpoint(cmn_version=cmn.product_config, up=False, srcid=id)
                else:
                    w = cmnwatch.Watchpoint(cmn_version=cmn.product_config, chn="REQ", up=False,
                                            opcode=ATOMIC_OPCODE, addr=atomic_addr(atomic_page_offset(entry)), srcid=id)
                id_events.append(w.perf_events(cmn_instance=cmn.cmn_seq, nodeid=hnf.XP().node_id(), dev=hnf.port_number))
            logical_events.append(id_events)
        return logical_events

    def discover_cpu_rnf_port(self, cpu):
        """
        First discover which RN-F port the CPU is attached to, by monitoring all
        the RN-F ports (across all meshes) and looking for uploaded traffic.
        """
        ix = self.get_max_event(cpu, self.rnf_port_events, time=self.options.time)
        rnf = self.rnf_ports[ix]
        if self.options.verbose >= 1:
            print("CPU #%u on %s" % (cpu, rnf))
        self.cpu_rnf_port[cpu] = rnf
        if cpu not in rnf.cpus:
            rnf.cpus.append(cpu)
        if self.progress is not None:
            self.progress.record_rnf(cpu, rnf)
        return rnf

    def discover_cpu_rnf_port_atomic(self, cpu):
        """
        Discover which RN-F port the CPU is attached to by counting exact matches
        of a tagged uncommon atomic request on each RN-F upload port.
        """
        entry = self.atomic_entry_for_cpu(cpu)
        logical_events = [atomic_rnf_events(rnf, entry) for rnf in self.rnf_ports]
        ix = self.get_exact_event(cpu, logical_events, time=self.options.time, min_count=self.options.atomic_min_count, entry=entry)
        rnf = self.rnf_ports[ix]
        if self.options.verbose >= 1:
            print("CPU #%u on %s" % (cpu, rnf))
        self.cpu_rnf_port[cpu] = rnf
        if cpu not in rnf.cpus:
            rnf.cpus.append(cpu)
        if self.progress is not None:
            self.progress.record_rnf(cpu, rnf)
        return rnf

    def discover_cpu_lpid(self, cpu):
        """
        Where multiple CPUs are attached to a single RN-F, try to establish which
        LPID the CPU is using. It is not guaranteed that CPUs use distinct LPIDs.
        """
        assert cpu in self.cpu_rnf_port
        rnf = self.cpu_rnf_port[cpu]
        if self.options.verbose >= 2:
            print("discovering LPID for CPU%u on RN-F %s" % (cpu, rnf))
        # This CPU is sharing an interface. Discover its LPID.
        # TBD: we could do better by matching LPID under mask, e.g. 0b0xxx for 0..7
        # TBD: there are actually 32 possible LPIDs!
        events = []
        for lpid in range(16):
            events += rnf.perf_events(lpid=lpid)
        lpid = self.get_max_event(cpu, events, time=self.options.time)
        if self.options.verbose:
            print("CPU #%u on %s LPID %u" % (cpu, rnf, lpid))
        self.cpu_lpid[cpu] = lpid
        if self.progress is not None:
            self.progress.record_lpid(cpu, lpid)
        return lpid

    def discover_cpu_lpid_atomic(self, cpu):
        """
        Discover the CPU's LPID by counting exact matches of tagged atomic traffic.
        """
        assert cpu in self.cpu_rnf_port
        rnf = self.cpu_rnf_port[cpu]
        if self.options.verbose >= 2:
            print("discovering LPID for CPU%u on RN-F %s" % (cpu, rnf))
        entry = self.atomic_entry_for_cpu(cpu)
        logical_events = [atomic_rnf_events(rnf, entry, lpid=lpid) for lpid in range(16)]
        lpid = self.get_exact_event(cpu, logical_events, time=self.options.time, min_count=self.options.atomic_min_count, entry=entry)
        if self.options.verbose:
            print("CPU #%u on %s LPID %u" % (cpu, rnf, lpid))
        self.cpu_lpid[cpu] = lpid
        if self.progress is not None:
            self.progress.record_lpid(cpu, lpid)
        return lpid

    def discover_cpu_rnf_ports_atomic_batch(self, entries):
        """Discover and checkpoint RN-F ports for one batch of tagged issuers."""
        logical_events_by_entry = []
        for entry in entries:
            logical_events_by_entry.append([atomic_rnf_events(rnf, entry) for rnf in self.rnf_ports])
        indices = self.get_exact_event_batch(entries, logical_events_by_entry, time=self.options.time, min_count=self.options.atomic_min_count)
        for (entry, ix) in zip(entries, indices):
            cpu = entry["cpu"]
            rnf = self.rnf_ports[ix]
            if self.options.verbose >= 1:
                print("CPU #%u on %s" % (cpu, rnf))
            self.cpu_rnf_port[cpu] = rnf
            if cpu not in rnf.cpus:
                rnf.cpus.append(cpu)
            if self.progress is not None:
                self.progress.record_rnf(cpu, rnf)

    def discover_cpu_lpids_atomic_batch(self, entries):
        """Discover and checkpoint LPIDs for one batch whose RN-Fs are known."""
        logical_events_by_entry = []
        for entry in entries:
            cpu = entry["cpu"]
            rnf = self.cpu_rnf_port[cpu]
            if self.options.verbose >= 2:
                print("discovering LPID for CPU%u on RN-F %s" % (cpu, rnf))
            logical_events_by_entry.append([atomic_rnf_events(rnf, entry, lpid=lpid) for lpid in range(16)])
        indices = self.get_exact_event_batch(entries, logical_events_by_entry, time=self.options.time, min_count=self.options.atomic_min_count)
        for (entry, lpid) in zip(entries, indices):
            cpu = entry["cpu"]
            rnf = self.cpu_rnf_port[cpu]
            if self.options.verbose:
                print("CPU #%u on %s LPID %u" % (cpu, rnf, lpid))
            self.cpu_lpid[cpu] = lpid
            if self.progress is not None:
                self.progress.record_lpid(cpu, lpid)

    def discover_cpu_srcid(self, cpu):
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
        rp = self.cpu_rnf_port[cpu]
        cmn = rp.port.CMN()
        if self.options.verbose >= 2:
            print("discovering SRCID for CPU#%u on %s" % (cpu, rp))
        ids = list(rp.port.ids())
        hnfs = self.hnf_ports_subset(cmn.cmn_seq)
        logical_events = self.srcid_logical_events(cmn, ids, hnfs)
        try:
            ix = self.get_max_logical_event(cpu, logical_events, time=self.options.time)
        except SystemExit:
            all_hnfs = self.all_hnf_ports(cmn.cmn_seq)
            if len(hnfs) == len(all_hnfs):
                raise
            if self.options.verbose >= 1:
                print("retrying SRCID discovery for CPU#%u using all HN-F ports" % cpu)
            logical_events = self.srcid_logical_events(cmn, ids, all_hnfs)
            ix = self.get_max_logical_event(cpu, logical_events, time=self.options.time)
        id = ids[ix]
        if self.options.verbose:
            print("%s CPU#%u SRCID=0x%x" % (rp, cpu, id))
        self.cpu_id[cpu] = id
        if self.progress is not None:
            self.progress.record_srcid(cpu, id)
        return id

    def discover_cpu_srcid_atomic(self, cpu):
        """
        Discover the CPU's SRCID by matching exact tagged atomic requests at a
        HN-F download watchpoint.
        """
        rp = self.cpu_rnf_port[cpu]
        cmn = rp.port.CMN()
        if self.options.verbose >= 2:
            print("discovering SRCID for CPU#%u on %s" % (cpu, rp))
        ids = list(rp.port.ids())
        entry = self.atomic_entry_for_cpu(cpu)
        logical_events = srcid_logical_events_atomic_mesh(cmn, ids, self.all_hnf_ports(cmn.cmn_seq), entry=entry)
        ix = self.get_exact_event(cpu, logical_events, time=self.options.time, min_count=self.options.atomic_min_count, entry=entry)
        id = ids[ix]
        if self.options.verbose:
            print("%s CPU#%u SRCID=0x%x" % (rp, cpu, id))
        self.cpu_id[cpu] = id
        if self.progress is not None:
            self.progress.record_srcid(cpu, id)
        return id

    def discover_cpus(self, cpu=None, expected=None):
        """
        Discover the physical identity of selected CPUs in three ordered phases.

        First locate each CPU's RN-F upload port. Then probe SRCID when a CAL is
        present, CPUs share a port, or the caller explicitly requests it. Finally,
        probe LPID only where CPUs still share both port and SRCID. Avoiding the
        later probes when earlier identities are already unique reduces device
        accesses and the chance of an inconclusive measurement.

        Atomic discovery tags uncommon requests so it can demand one exact match.
        ``expected`` mappings are treated only as guesses and remeasured before
        use. If atomic traffic fails before any RN-F is identified, restart with
        interval/traffic-volume discovery; after partial success, propagate the
        failure rather than silently combine results obtained by different
        methods. Existing checkpoint observations are skipped in either method.
        """
        self.completed_cpus = None
        cpus = [cpu] if cpu is not None else list(self.iter_cpus())
        if self.options.method == "atomic":
            pending = [c for c in cpus if c not in self.cpu_rnf_port]
            try:
                for c in list(pending):
                    exp = expected_cpu_mapping(expected, c)
                    if exp is None:
                        continue
                    if self.verify_cpu_rnf_port_guess_atomic(c, exp):
                        pending.remove(c)
                for entries in self.iter_atomic_batches(cpus=pending):
                    self.discover_cpu_rnf_ports_atomic_batch(entries)
                    self.update_diagram()
            except atomic_failure_exceptions() as e:
                if pending and not [c for c in cpus if c in self.cpu_rnf_port]:
                    self.fallback_from_atomic_to_interval(e)
                    return self.discover_cpus(cpu=cpu, expected=None)
                raise
        else:
            for c in cpus:
                if c in self.cpu_rnf_port:
                    continue
                self.discover_cpu_rnf_port(c)
                self.update_diagram()
        # Check if some RN-Fs have multiple CPUs
        is_multiple = 0
        for rp in self.rnf_ports:
            rp_cpus = [c for c in rp.cpus if c in cpus]
            if len(rp_cpus) == 0:
                # not necessarily an error - could be fused out
                if self.options.verbose >= 2 and cpu is None:
                    print("RN-F port has no CPUs: %s" % rp)
            elif len(rp_cpus) >= 2:
                # CPUs multplexed on to a RN-F port: need distinguishing by device and/or LPID
                if self.options.verbose >= 2 or (False and self.options.verbose >= 1 and not is_multiple):
                    print("RN-F port has multiple CPUs: %s" % rp)
                is_multiple += 1
        # When CALs are in use anywhere in the system, establish explicit SRCIDs
        # for every CPU. Otherwise only multi-CPU RN-F ports need SRCID probing.
        # Once SRCIDs are known, only fall back to LPID when ids still clash.
        cal_in_use = any([rp.port.cal for rp in self.rnf_ports])
        need_srcid = []
        for rp in self.rnf_ports:
            rp_cpus = [c for c in rp.cpus if c in cpus]
            if cal_in_use or len(rp_cpus) >= 2 or self.options.force_discover:
                need_srcid += [cpu for cpu in rp_cpus if cpu not in need_srcid]
        if need_srcid:
            if self.options.verbose:
                print("Discovering CHI SRCIDs...")
            for cpu in need_srcid:
                if cpu in self.cpu_id:
                    continue
                exp = expected_cpu_mapping(expected, cpu)
                if self.options.method == "atomic" and self.verify_cpu_srcid_guess_atomic(cpu, exp):
                    continue
                if self.options.method == "atomic":
                    self.discover_cpu_srcid_atomic(cpu)
                else:
                    self.discover_cpu_srcid(cpu)
        for c in cpus:
            if c not in self.cpu_id:
                self.cpu_id[c] = self.cpu_rnf_port[c].port.base_id()
        need_lpid = []
        is_multiple = 0
        for rp in self.rnf_ports:
            rp.id_cpu = {}
            rp.id_clash = False
            rp_cpus = [c for c in rp.cpus if c in cpus]
            for cpu in rp_cpus:
                id = self.cpu_id[cpu]
                if id in rp.id_cpu:
                    if (self.options.verbose >= 2) or (self.options.verbose and not is_multiple):
                        print("%s: CPU#%u and CPU#%u both have SRCID=0x%x" % (rp, rp.id_cpu[id][0], cpu, id))
                    is_multiple += 1
                    rp.id_clash = True
                else:
                    rp.id_cpu[id] = []
                rp.id_cpu[id].append(cpu)
            if len(rp_cpus) >= 2 and not rp.id_clash and not self.options.force_discover:
                for cpu in rp_cpus:
                    self.cpu_lpid[cpu] = 0
            elif rp.id_clash or self.options.force_discover:
                need_lpid += [cpu for cpu in rp_cpus if cpu not in need_lpid]
        if need_lpid:
            if self.options.verbose:
                print("Discovering LPIDs...")
            if self.options.method == "atomic":
                pending_lpid = []
                for c in need_lpid:
                    exp = expected_cpu_mapping(expected, c)
                    if not self.verify_cpu_lpid_guess_atomic(c, exp):
                        pending_lpid.append(c)
                for entries in self.iter_atomic_batches(cpus=pending_lpid):
                    self.discover_cpu_lpids_atomic_batch(entries)
            else:
                for c in need_lpid:
                    if c in self.cpu_lpid:
                        continue
                    self.discover_cpu_lpid(c)
        self.completed_cpus = list(cpus)

    def prepare(self, online_cpus=None):
        """
        Prepare CPU availability and event lists without changing the topology.

        An explicit CPU inventory avoids host queries, for captured systems or
        tests. The default inventory requires the Linux discovery environment.
        """
        self.online_cpus = list_online_cpus() if online_cpus is None else list(online_cpus)
        if not self.online_cpus:
            raise ValueError("CPU discovery requires at least one online CPU")
        if online_cpus is None:
            # Jython has no multiprocessing module. Only the host-inventory
            # path needs it, not reporting or discovery with an explicit list.
            import multiprocessing
            self.n_cpu = multiprocessing.cpu_count()
        else:
            self.n_cpu = max(self.online_cpus) + 1
        self.completed_cpus = None
        self.selected_hnf_ports = {}
        if self.online_cpus[-1] != self.n_cpu - 1:
            print("Some CPUs may be offline: CPU numbers from %u to %u but %u are online" %
                  (self.online_cpus[0], self.online_cpus[-1], self.n_cpu))
        self.rnf_ports = []
        # Our observations about where each CPU is,
        # progressively populated by watchpoint counting.
        self.cpu_rnf_port = {}     # CMN_RNFPort object
        self.cpu_lpid = {}         # LPID for each cpu
        self.cpu_id = {}           # device id (SRCID/TGTID) for each CPU
        self.rnf_ports = [CMN_RNFPort(p) for p in self.system.ports(properties=CMN_PROP_RNF)]
        if not self.rnf_ports:
            print("No RN-F ports found in system!", file=sys.stderr)
            sys.exit(1)
        if self.options.verbose:
            print("%u CPUs, %u RN-F ports" % (self.n_cpu, len(self.rnf_ports)))
        if self.options.method == "atomic":
            if self.atomic_batch_capacity() < 1:
                self.fallback_from_atomic_to_interval("Atomic batching requires at least one runnable issuer")
            if self.options.atomic_contenders > 0 and len(self.online_cpus) < (1 + self.options.atomic_contenders):
                self.fallback_from_atomic_to_interval("Atomic method needs at least %u online CPUs for %u contenders" %
                                                 (1 + self.options.atomic_contenders, self.options.atomic_contenders))
            if self.options.atomic_batch > ATOMIC_PAGE_LINES:
                self.fallback_from_atomic_to_interval("Atomic batch size exceeds page capacity of %u lines" %
                                                 ATOMIC_PAGE_LINES)
        # We usually see a consistent number of CPUs per RN-F port, but not always
        if (self.n_cpu % len(self.rnf_ports)) != 0:
            """
            A homogeneous system would have perhaps 1 or 2 CPUs per RN-F.
            If the number does not divide equally, it could indicate that:
             - some CPUs have been fused out
             - the system is heterogeneous by design, e.g. control vs. data plane CPUs
            """
            print("Number of CPUs per RN-F port is not integral: %u CPUs on %u RN-Fs" % (self.n_cpu, len(self.rnf_ports)))
        if self.options.verbose >= 2:
            print("RN-F ports:")
            print([str(rp) for rp in self.rnf_ports])
        # Construct one monitoring event per watchpoint
        self.rnf_port_events = []
        self.rnf_port_map = {}
        for rnf in self.rnf_ports:
            self.rnf_port_map[(rnf.port.CMN().cmn_seq, rnf.port.xp.node_id(), rnf.port.port_number)] = rnf
            rnfpe = rnf.perf_events()
            assert rnfpe, "bad RN-F port events: %s" % rnfpe
            assert len(rnfpe) == 1
            self.rnf_port_events += rnfpe
            if self.options.verbose >= 3:
                print("%s: %s" % (rnf, rnfpe))
        assert self.rnf_port_events

    def iter_cpus(self):
        for cpu in self.online_cpus:
            yield cpu

    def print_cpus(self):
        print("Discovered CPUs:")
        for cpu in self.iter_cpus():
            print("  CPU %3u: " % cpu, end="")
            if cpu not in self.cpu_rnf_port:
                print("unknown RN-F", end="")
            else:
                rnf = self.cpu_rnf_port[cpu]
                print("%s" % rnf, end="")
                if cpu in self.cpu_lpid:
                    print(" LPID=%u" % self.cpu_lpid[cpu], end="")
                print(" SRCID=0x%x" % self.cpu_id[cpu], end="")
            print()

def main(argv, backend=None):
    """
    Parse the requested workflow, run discovery, and persist verified results.

    ``--verify`` always rediscovers without updating the input JSON. ``--update``
    uses old mappings as measured atomic guesses and writes only when mappings
    changed. A single-CPU update preserves all other cached mappings. Ordinary
    discovery writes a new output file rather than overwriting the topology.
    """
    import argparse
    defaults = CPUDiscoveryOptions()
    parser = argparse.ArgumentParser(description="Discover where CPUs are located in system mesh",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--json", type=str, default=cmn_json.cmn_config_filename(), help="JSON system description")
    parser.add_argument("--update", action="store_true", help="refresh cached CPU mappings in the JSON system description")
    parser.add_argument("--discard", action="store_true", help="discard any previous CPU mappings")
    parser.add_argument("--verify", action="store_true", help="verify any existing CPU mappings by rediscovering them")
    parser.add_argument("--report", action="store_true", help="report previously detected CPU mappings")
    parser.add_argument("--no-use-checkpoint", action="store_true", help="ignore any previous discovery checkpoint")
    parser.add_argument("-o", "--output", type=str, help="output JSON filename")
    parser.add_argument("--cpu", type=int, help="discover one CPU")
    parser.add_argument("--time", type=float, default=defaults.time, help="measurement time")
    parser.add_argument("--method", choices=["interval", "atomic"], default=defaults.method, help="CPU discovery method")
    parser.add_argument("--detection-level", type=float, default=defaults.detection_level, help="traffic detection sensitivity")
    parser.add_argument("--retries", type=int, default=defaults.retries, help="number of times to retry")
    parser.add_argument("--retry-multiplier", type=float, default=defaults.retry_multiplier, help="retry time multiplier")
    parser.add_argument("--atomic-batch", type=int, default=defaults.atomic_batch, help="number of CPUs to probe in one atomic batch")
    parser.add_argument("--atomic-contenders", type=int, default=defaults.atomic_contenders, help="number of contender threads per probed CPU")
    parser.add_argument("--atomic-min-count", type=int, default=defaults.atomic_min_count, help="minimum exact-match count")
    parser.add_argument("-N", type=int, help="number of CPUs")
    parser.add_argument("--diagram", action="store_true", help="visualize CPU discovery")
    parser.add_argument("--force-discover", action="store_true")
    parser.add_argument("--perf-bin", type=str, default="perf", help="path to perf command")
    parser.add_argument("--lmbench-bin", type=str, default=None, help="bin directory for lmbench")
    parser.add_argument("--keep-exe", action="store_true", help="keep the generated traffic helper executable")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="increase verbosity")
    opts = parser.parse_args(argv)
    # Reporting reads cached mappings only and therefore needs neither PMU
    # validation nor a discovery session.
    if opts.report:
        S = cmn_json.load_system_for_cli(opts.json, check_system=False)
        if not S.has_cpu_mappings():
            print("%s: has no CPU mappings to report" % opts.json, file=sys.stderr)
            sys.exit(1)
        print_cpu_report(S)
        return
    if backend is None:
        backend = TrafficMeasurements(opts)
    if not backend.check_cmn_events():
        print("CPU detection requires kernel support for CMN PMU events",
              file=sys.stderr)
        sys.exit(1)
    # Leave the System's existing mappings intact while discovery is in progress.
    # Verification compares against this snapshot; atomic update can also test
    # each old value as a fast, but never trusted, starting guess.
    S = cmn_json.load_system_for_cli(opts.json)
    expected_cpu_mappings = None
    if S.has_cpu_mappings():
        print("%s: already has CPU mappings - " % opts.json, end="")
        if opts.verify or opts.update:
            print("checking for updates" if opts.update else "verifying")
            expected_cpu_mappings = snapshot_cpu_mappings(S)
        elif not opts.discard:
            print("use --discard to discard")
            sys.exit()
        else:
            print("discarding")
    elif opts.verify:
        print("%s: has no CPU mappings to verify" % opts.json, file=sys.stderr)
        sys.exit(1)
    discovery = CPUDiscovery(S, options=opts, backend=backend)
    discovery.prepare()
    # Checkpoints are for interrupted discovery, not authoritative mappings.
    # Their method and input-file fingerprint must match before seeding observations.
    discovery.progress = DetectProgress(progress_filename(), opts.json, discovery.options.method)
    completed_detection = False
    try:
        resume = False
        if not opts.no_use_checkpoint:
            if progress_file_is_stale(discovery.progress.path):
                print("Discarding stale discovery checkpoint from previous boot: %s" % discovery.progress.path)
                discovery.progress.remove()
            else:
                resume = discovery.progress.load()
        discovery.progress.begin(resume)
        if resume:
            discovery.progress.apply(discovery)
            print("Reusing discovery checkpoint from %s (use --no-use-checkpoint to ignore it)" % discovery.progress.path)
        update_needs_full_discovery = opts.update and expected_cpu_mappings is None
        if opts.cpu is not None and update_needs_full_discovery:
            print("No cached CPU mappings present, ignoring --cpu and doing full discovery for --update")
        # A targeted update retains every other cached CPU when committing,
        # so writing the JSON cannot accidentally discard their mappings.
        if opts.cpu is not None and not update_needs_full_discovery:
            discovery.options.verbose = max(discovery.options.verbose, 2)
            on = cpu_is_online(opts.cpu)
            if not on:
                print("CPU#%u is %s" % (opts.cpu, ["offline", "invalid"][on is None]), file=sys.stderr)
                sys.exit(1)
            seeded_expected = expected_cpu_mappings if (opts.verify and discovery.options.method == "atomic") else None
            if opts.update and discovery.options.method == "atomic":
                seeded_expected = expected_cpu_mappings
            discovery.discover_cpus(cpu=opts.cpu, expected=seeded_expected)
            discovery.commit_cpu_mappings(preserve_others=opts.update)
            completed_detection = True
            if opts.verify:
                mismatches = discovery.verify_cpu_mappings(expected_cpu_mappings, cpus=[opts.cpu])
                if mismatches:
                    print("CPU mapping verification failed:", file=sys.stderr)
                    print_mismatches(mismatches)
                    write_mismatch_json(S)
                    sys.exit(1)
                print("CPU mapping verified for CPU %u" % opts.cpu)
            elif opts.update:
                mismatches = discovery.verify_cpu_mappings(expected_cpu_mappings, cpus=[opts.cpu]) if expected_cpu_mappings is not None else []
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
            # Full discovery shares the same verify/update policy as the
            # targeted path, but may also render progress and choose a safe
            # output name for an ordinary, non-updating invocation.
            if opts.diagram:
                discovery.options.verbose = 0
                discovery.backend.verbose = 0
                discovery.diagram = CPUDiscoveryDiagram(discovery, S.CMNs[0])
                print(discovery.diagram.str_color(), end="")
            seeded_expected = expected_cpu_mappings if (opts.verify and discovery.options.method == "atomic") else None
            if opts.update and discovery.options.method == "atomic":
                seeded_expected = expected_cpu_mappings
            discovery.discover_cpus(expected=seeded_expected)
            discovery.commit_cpu_mappings()
            completed_detection = True
            if opts.verify:
                mismatches = discovery.verify_cpu_mappings(expected_cpu_mappings)
                if mismatches:
                    print("CPU mapping verification failed:", file=sys.stderr)
                    print_mismatches(mismatches)
                    write_mismatch_json(S)
                    sys.exit(1)
                print("CPU mappings verified")
            elif opts.update:
                mismatches = discovery.verify_cpu_mappings(expected_cpu_mappings) if expected_cpu_mappings is not None else []
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
                discovery.print_cpus()
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
        if completed_detection and S.has_cpu_mappings():
            print_cpu_report(S)
    finally:
        if completed_detection and discovery.progress is not None:
            discovery.progress.remove()


if __name__ == "__main__":
    main(sys.argv[1:])
