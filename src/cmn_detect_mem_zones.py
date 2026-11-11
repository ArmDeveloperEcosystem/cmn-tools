#!/usr/bin/python3

"""
Discover CMN memory zones by measuring traffic between home and memory nodes.

A zone is a connected component of HN-F/HN-S and SN-F node IDs for which
REQ traffic was observed.  The tool uses the Linux arm_cmn PMU driver; it does
not read CMN configuration registers and does not update the system JSON.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import print_function

import sys
import os
import json
import time as modtime
import tempfile
import bisect
from collections import namedtuple

import app_data
import cmn_diagram
import cmn_json
import cmn_perfstat
import cmnwatch
from cmn_enum import CMN_PROP_HNF, CMN_PROP_SNF

try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)
try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)


Endpoint = namedtuple("Endpoint", ["kind", "cmn", "port", "node_id"])
ActivityProbe = namedtuple("ActivityProbe", ["kind", "cmn", "port", "node_ids"])
Observation = namedtuple("Observation", ["hn", "sn", "count"])
DistanceStats = namedtuple("DistanceStats", ["total", "count", "minimum", "maximum"])

DEFAULT_MEASUREMENT_TIME = 5.0
DEFAULT_BATCH_SIZE = 8
RETRY_GROUP_SIZES = [4, 1]
OBSERVATION_COLUMN_WIDTH = 6
CACHE_VERSION = 2
ZONE_COLORS = ["cyan", "green", "yellow", "blue", "magenta", "red", "white"]


def cache_filename():
    return app_data.app_data_cache("cmn-memory-zones.json", app="arm")


def cache_from_zones(zones, method, measurement_time,
                     min_count, unused_homes=None, unused_memories=None):
    unused_homes = unused_homes or {}
    unused_memories = unused_memories or {}
    meshes = {}
    for homes, memories in zones:
        mesh = homes[0].cmn.cmn_seq
        mesh_zones = meshes.setdefault(mesh, [])
        mesh_zones.append({
            "zone": len(mesh_zones),
            "home_nodes": [item.node_id for item in homes],
            "memory_nodes": [item.node_id for item in memories],
        })
    return {
        "version": CACHE_VERSION,
        "discovered_at": modtime.strftime("%Y-%m-%dT%H:%M:%SZ",
                                           modtime.gmtime()),
        "method": method,
        "measurement_time": measurement_time,
        "minimum_count": min_count,
        "meshes": [{
            "cmn_instance": mesh,
            "zones": meshes.get(mesh, []),
            "unused_home_nodes": sorted(unused_homes.get(mesh, [])),
            "unused_memory_nodes": sorted(unused_memories.get(mesh, [])),
        } for mesh in sorted(set(meshes.keys()) | set(unused_homes.keys()) |
                             set(unused_memories.keys()))],
    }


def validate_cache(data):
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
        raise ValueError("unsupported memory-zone cache version")
    if data.get("method") not in ["hn", "sn"]:
        raise ValueError("memory-zone cache has an invalid detection method")
    if not isinstance(data.get("discovered_at"), string_types):
        raise ValueError("memory-zone cache has no discovery time")
    if (not isinstance(data.get("measurement_time"), (int, float)) or
            data["measurement_time"] <= 0):
        raise ValueError("memory-zone cache has an invalid measurement time")
    if (not isinstance(data.get("minimum_count"), integer_types) or
            data["minimum_count"] < 0):
        raise ValueError("memory-zone cache has an invalid minimum count")
    meshes = data.get("meshes")
    if not isinstance(meshes, list):
        raise ValueError("memory-zone cache meshes must be a list")
    for mesh in meshes:
        if not isinstance(mesh, dict) or not isinstance(mesh.get("cmn_instance"), integer_types):
            raise ValueError("invalid mesh in memory-zone cache")
        if not isinstance(mesh.get("zones"), list):
            raise ValueError("memory-zone cache zones must be a list")
        for field in ["unused_home_nodes", "unused_memory_nodes"]:
            values = mesh.get(field)
            if (not isinstance(values, list) or
                    not all(isinstance(value, integer_types) and value >= 0
                            for value in values)):
                raise ValueError("invalid %s in memory-zone cache" % field)
        for zone in mesh["zones"]:
            if not isinstance(zone, dict) or not isinstance(zone.get("zone"), integer_types):
                raise ValueError("invalid zone in memory-zone cache")
            for field in ["home_nodes", "memory_nodes"]:
                values = zone.get(field)
                if (not isinstance(values, list) or not values or
                        not all(isinstance(value, integer_types) and value >= 0
                                for value in values)):
                    raise ValueError("invalid %s in memory-zone cache" % field)
    return data


def validate_cache_topology(data, system):
    """Require one complete, non-overlapping assignment for this topology."""
    cached_meshes = set()
    for mesh in data["meshes"]:
        cmn_seq = mesh["cmn_instance"]
        if cmn_seq < 0 or cmn_seq >= len(system.CMNs) or cmn_seq in cached_meshes:
            raise ValueError("memory-zone cache has an invalid CMN instance")
        cached_meshes.add(cmn_seq)
        cmn = system.CMNs[cmn_seq]
        expected_homes = set([item.node_id for item in endpoints(cmn, "HN")])
        expected_memories = set([item.node_id for item in endpoints(cmn, "SN")])
        cached_homes = []
        cached_memories = []
        zone_numbers = []
        for zone in mesh["zones"]:
            zone_numbers.append(zone["zone"])
            cached_homes += zone["home_nodes"]
            cached_memories += zone["memory_nodes"]
        cached_homes += mesh["unused_home_nodes"]
        cached_memories += mesh["unused_memory_nodes"]
        if len(zone_numbers) != len(set(zone_numbers)):
            raise ValueError("memory-zone cache has duplicate zone numbers")
        if (len(cached_homes) != len(set(cached_homes)) or
                set(cached_homes) != expected_homes):
            raise ValueError("memory-zone cache does not cover the topology HNs")
        if (len(cached_memories) != len(set(cached_memories)) or
                set(cached_memories) != expected_memories):
            raise ValueError("memory-zone cache does not cover the topology SNs")
    if cached_meshes != set(range(len(system.CMNs))):
        raise ValueError("memory-zone cache does not cover every CMN instance")
    return data


def load_cache(path, missing_ok=False):
    try:
        with open(path) as source:
            data = validate_cache(json.load(source))
    except (IOError, OSError) as error:
        if missing_ok and getattr(error, "errno", None) == 2:
            return None
        raise
    return data


def write_cache(path, data):
    """Atomically replace a cache file using a temporary in its directory."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".cmn-memory-zones-",
                                     suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(data, output, indent=2, sort_keys=True)
            output.write("\n")
        os.rename(temporary, path)
        app_data.change_to_real_user_if_sudo(path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def cache_is_complete(observations, min_count=1, active_homes=None,
                      active_memories=None, activity_counts=None):
    edges = detected_edges(observations, min_count=min_count)
    if active_homes is None:
        active_homes = set([item.hn for item in observations])
    else:
        active_homes = set(active_homes)
    if active_memories is None:
        active_memories = set([item.sn for item in observations])
    else:
        active_memories = set(active_memories)
    activity_scheduled = (activity_counts is None or
                          all(count is not None for count in activity_counts))
    return (activity_scheduled and
            all(item.count is not None for item in observations) and
            active_homes == set([edge[0] for edge in edges]) and
            active_memories == set([edge[1] for edge in edges]))


def classify_activity(plan, counts, min_count=1):
    if len(plan) != len(counts):
        raise ValueError("activity result count does not match its plan")
    active_homes = []
    active_memories = []
    unused_homes = {}
    unused_memories = {}
    unresolved = []
    for entry, count in zip(plan, counts):
        probe = entry[0]
        probe_endpoints = [Endpoint(probe.kind, probe.cmn, probe.port, node_id)
                           for node_id in probe.node_ids]
        if count is None:
            unresolved += probe_endpoints
        elif count >= min_count:
            if probe.kind == "HN":
                active_homes += probe_endpoints
            else:
                active_memories += probe_endpoints
        else:
            target = unused_homes if probe.kind == "HN" else unused_memories
            target.setdefault(probe.cmn.cmn_seq, set()).update(probe.node_ids)
    return (active_homes, active_memories, unused_homes, unused_memories,
            unresolved)


def cached_zone_map(data, cmn_seq):
    result = {}
    for mesh in data["meshes"]:
        if mesh["cmn_instance"] != cmn_seq:
            continue
        for zone in mesh["zones"]:
            for node_id in zone["home_nodes"] + zone["memory_nodes"]:
                result[node_id] = zone["zone"]
    return result


def cached_zone_endpoints(system, data, cmn_seq=None, hn_id=None, sn_id=None):
    """Resolve cached IDs to endpoint objects, retaining complete zones."""
    resolved = []
    for mesh in data["meshes"]:
        seq = mesh["cmn_instance"]
        if cmn_seq is not None and seq != cmn_seq:
            continue
        homes_by_id = dict((item.node_id, item)
                           for item in endpoints(system.CMNs[seq], "HN"))
        memories_by_id = dict((item.node_id, item)
                              for item in endpoints(system.CMNs[seq], "SN"))
        for zone in mesh["zones"]:
            if hn_id is not None and hn_id not in zone["home_nodes"]:
                continue
            if sn_id is not None and sn_id not in zone["memory_nodes"]:
                continue
            resolved.append((zone["zone"],
                             [homes_by_id[node_id]
                              for node_id in zone["home_nodes"]],
                             [memories_by_id[node_id]
                              for node_id in zone["memory_nodes"]]))
    return resolved


def numbered_zones(zones):
    """Assign the same per-mesh zone numbers used by the cache."""
    next_zone = {}
    result = []
    for homes, memories in zones:
        mesh = homes[0].cmn.cmn_seq
        number = next_zone.get(mesh, 0)
        next_zone[mesh] = number + 1
        result.append((number, homes, memories))
    return result


def cached_distance_tables(system, data, cmn_seq=None, hn_id=None,
                           sn_id=None):
    tables = []
    for mesh in data["meshes"]:
        seq = mesh["cmn_instance"]
        if cmn_seq is not None and seq != cmn_seq:
            continue
        zone_by_id = cached_zone_map(data, seq)
        homes = [item for item in endpoints(system.CMNs[seq], "HN")
                 if item.node_id in zone_by_id and
                 (hn_id is None or item.node_id == hn_id)]
        memories = [item for item in endpoints(system.CMNs[seq], "SN")
                    if item.node_id in zone_by_id and
                    (sn_id is None or item.node_id == sn_id)]
        def cell_value(hn, sn):
            hn_zone = zone_by_id.get(hn.node_id)
            if hn_zone is not None and hn_zone == zone_by_id.get(sn.node_id):
                return endpoint_distance(hn, sn)
            return "."
        tables.append((seq, endpoint_table(homes, memories, cell_value)))
    return tables


def print_distance_tables(tables):
    for mesh, lines in tables:
        print("HN-to-SN mesh distance (CMN#%u):" % mesh)
        for line in lines:
            print("  %s" % line)


def combine_distance_stats(statistics):
    """Combine disjoint pair populations without introducing cross-pairs."""
    statistics = list(statistics)
    if not statistics:
        return None
    return DistanceStats(
        sum(item.total for item in statistics),
        sum(item.count for item in statistics),
        min(item.minimum for item in statistics),
        max(item.maximum for item in statistics))


def distance_statistic_rows(zones):
    """Return zone, mesh and system rows with pair-weighted statistics."""
    by_mesh = {}
    for number, homes, memories in zones:
        stats = zone_distance_stats(homes, memories)
        mesh = homes[0].cmn.cmn_seq
        by_mesh.setdefault(mesh, []).append((number, stats))
    mesh_stats = []
    for mesh in sorted(by_mesh.keys()):
        stats = combine_distance_stats(
            [zone_stats for _number, zone_stats in by_mesh[mesh]])
        mesh_stats.append(stats)
    system_stats = combine_distance_stats(mesh_stats)
    rows = []
    if system_stats is None:
        return rows
    rows.append(("System", system_stats, "system"))
    for mesh in sorted(by_mesh.keys()):
        mesh_stats = combine_distance_stats(
            [zone_stats for _number, zone_stats in by_mesh[mesh]])
        rows.append(("  CMN#%u" % mesh, mesh_stats, "mesh"))
        for number, stats in by_mesh[mesh]:
            rows.append(("    Zone %u" % number, stats, "zone"))
    return rows


def print_zone_distances(zones):
    rows = distance_statistic_rows(zones)
    if not rows:
        return
    label_width = max([len("Scope")] + [len(row[0]) for row in rows])
    print("HN-to-SN distance statistics within memory zones "
          "(links plus credited slices):")
    print("  %-*s %10s %8s %8s" %
          (label_width, "Scope", "Average", "Minimum", "Maximum"))
    print("  %s %s %s %s" %
          ("-" * label_width, "-" * 10, "-" * 8, "-" * 8))
    for label, stats, kind in rows:
        print("  %-*s %10.3f %8u %8u" %
              (label_width, label, float(stats.total) / stats.count,
               stats.minimum, stats.maximum))


def print_cached_report(data, cmn_seq=None, hn_id=None, sn_id=None):
    printed = False
    for mesh in data["meshes"]:
        if cmn_seq is not None and mesh["cmn_instance"] != cmn_seq:
            continue
        for zone in mesh["zones"]:
            if hn_id is not None and hn_id not in zone["home_nodes"]:
                continue
            if sn_id is not None and sn_id not in zone["memory_nodes"]:
                continue
            print("Zone %u (CMN#%u):" %
                  (zone["zone"], mesh["cmn_instance"]))
            print("  HN: %s" % ", ".join(
                ["0x%x" % node_id for node_id in zone["home_nodes"]]))
            print("  SN: %s" % ", ".join(
                ["0x%x" % node_id for node_id in zone["memory_nodes"]]))
            printed = True
        report_unused_homes = (mesh["unused_home_nodes"] if
                               hn_id is None and sn_id is None else
                               ([hn_id] if hn_id in mesh["unused_home_nodes"]
                                else []))
        report_unused_memories = (mesh["unused_memory_nodes"] if
                                  hn_id is None and sn_id is None else
                                  ([sn_id] if sn_id in mesh["unused_memory_nodes"]
                                   else []))
        if report_unused_homes:
            print("Unused HN (CMN#%u): %s" %
                  (mesh["cmn_instance"], ", ".join(
                      ["0x%x" % node_id
                       for node_id in report_unused_homes])))
            printed = True
        if report_unused_memories:
            print("Unused SN (CMN#%u): %s" %
                  (mesh["cmn_instance"], ", ".join(
                      ["0x%x" % node_id
                       for node_id in report_unused_memories])))
            printed = True
    if not printed:
        print("No cached memory zone matches the selection.")


class MemoryZoneDiagram(cmn_diagram.CMNDiagram):
    """CMN diagram showing only home and memory nodes, colored by zone."""

    def __init__(self, cmn, cache, **kwargs):
        self.zone_by_id = cached_zone_map(cache, cmn.cmn_seq)
        cmn_diagram.CMNDiagram.__init__(self, cmn, **kwargs)

    def port_label_color(self, port):
        if port is None or not (port.has_properties(CMN_PROP_HNF) or
                                port.has_properties(CMN_PROP_SNF)):
            return (None, None)
        zones = sorted(set([self.zone_by_id[node_id] for node_id in port.ids()
                            if node_id in self.zone_by_id]))
        if not zones:
            return (None, None)
        assigned_ids = [node_id for node_id in port.ids()
                        if node_id in self.zone_by_id]
        kind = "H" if port.has_properties(CMN_PROP_HNF) else "S"
        label = kind + (self._id_fmt % min(assigned_ids))
        if len(assigned_ids) > 1:
            label += "x%u" % len(assigned_ids)
        label += ":Z%s" % "/".join([str(zone) for zone in zones])
        color = ZONE_COLORS[zones[0] % len(ZONE_COLORS)]
        return (label, color)


def print_cache_diagrams(system, data, cmn_seq=None, color="auto"):
    for cmn in system.cmn_instances(instance=cmn_seq):
        if not cached_zone_map(data, cmn.cmn_seq):
            continue
        print("\nCMN#%u memory zones:" % cmn.cmn_seq)
        diagram = MemoryZoneDiagram(cmn, data, small=True, compact=True,
                                    xwidth=-7, xheight=-2)
        print(diagram.str_color(no_color=(color == "never"),
                                force_color=(color == "always"),
                                for_file=sys.stdout), end="")


def endpoint_str(endpoint):
    return "M%u %s 0x%x" % (endpoint.cmn.cmn_seq, endpoint.kind,
                             endpoint.node_id)


def endpoints(cmn, kind):
    """Return addressable home or memory endpoints recorded in one mesh."""
    prop = CMN_PROP_HNF if kind == "HN" else CMN_PROP_SNF
    result = []
    for port in cmn.ports(properties=prop):
        for node_id in port.ids():
            result.append(Endpoint(kind, cmn, port, node_id))
    return sorted(result, key=lambda endpoint: endpoint.node_id)


def endpoint_activity_event(endpoint):
    """Construct an open REQ watchpoint at one HN or SN port."""
    watchpoint = cmnwatch.Watchpoint(
        cmn_version=endpoint.cmn.product_config, chn="REQ",
        up=(endpoint.kind == "HN"))
    return watchpoint.perf_event_string(
        cmn_instance=endpoint.cmn.cmn_seq,
        nodeid=endpoint.port.XP().node_id(),
        dev=endpoint.port.port_number)


def activity_plan(system, cmn_seq=None, hn_id=None, sn_id=None):
    """Return endpoint activity probes, respecting the requested selection."""
    if cmn_seq is not None and (cmn_seq < 0 or cmn_seq >= len(system.CMNs)):
        raise ValueError("CMN instance %u is not present" % cmn_seq)
    meshes = system.CMNs if cmn_seq is None else [system.CMNs[cmn_seq]]
    plan = []
    found_hn = hn_id is None
    found_sn = sn_id is None
    for cmn in meshes:
        for kind, prop, selected_id in [("HN", CMN_PROP_HNF, hn_id),
                                        ("SN", CMN_PROP_SNF, sn_id)]:
            for port in cmn.ports(properties=prop):
                node_ids = tuple([node_id for node_id in port.ids()
                                  if selected_id is None or
                                  node_id == selected_id])
                if not node_ids:
                    continue
                probe = ActivityProbe(kind, cmn, port, node_ids)
                plan.append((probe, None, endpoint_activity_event(probe)))
                if kind == "HN":
                    found_hn = True
                else:
                    found_sn = True
    if not found_hn:
        raise ValueError("HN node ID 0x%x is not present in the selected mesh(es)" % hn_id)
    if not found_sn:
        raise ValueError("SN node ID 0x%x is not present in the selected mesh(es)" % sn_id)
    return plan


def pair_plan(homes, memories, method="hn"):
    plan = []
    for hn in homes:
        for sn in memories:
            if hn.cmn is sn.cmn:
                plan.append((hn, sn, pair_event(hn, sn, method=method)))
    return plan


def pair_event(hn, sn, method="hn"):
    """Construct one logical REQ watchpoint event for an HN/SN pair."""
    if hn.cmn is not sn.cmn:
        raise ValueError("HN and SN must belong to the same mesh")
    if method == "hn":
        monitor = hn
        watchpoint = cmnwatch.Watchpoint(cmn_version=hn.cmn.product_config,
                                         chn="REQ", up=True,
                                         tgtid=sn.node_id)
    elif method == "sn":
        monitor = sn
        watchpoint = cmnwatch.Watchpoint(cmn_version=hn.cmn.product_config,
                                         chn="REQ", up=False,
                                         srcid=hn.node_id)
    else:
        raise ValueError("unknown measurement method: %s" % method)
    return watchpoint.perf_event_string(
        cmn_instance=monitor.cmn.cmn_seq,
        nodeid=monitor.port.XP().node_id(),
        dev=monitor.port.port_number)


def measurement_plan(system, method="hn", cmn_seq=None, hn_id=None,
                     sn_id=None):
    """Return pair labels and corresponding perf event arguments."""
    if cmn_seq is not None and (cmn_seq < 0 or cmn_seq >= len(system.CMNs)):
        raise ValueError("CMN instance %u is not present" % cmn_seq)
    meshes = (system.CMNs if cmn_seq is None else [system.CMNs[cmn_seq]])
    plan = []
    found_hn = hn_id is None
    found_sn = sn_id is None
    for cmn in meshes:
        all_homes = endpoints(cmn, "HN")
        all_memories = endpoints(cmn, "SN")
        homes = [item for item in all_homes
                 if hn_id is None or item.node_id == hn_id]
        memories = [item for item in all_memories
                    if sn_id is None or item.node_id == sn_id]
        found_hn = found_hn or bool(homes)
        found_sn = found_sn or bool(memories)
        if not all_homes:
            raise ValueError("CMN#%u has no HN-F/HN-S nodes" % cmn.cmn_seq)
        if not all_memories:
            raise ValueError("CMN#%u has no SN-F nodes" % cmn.cmn_seq)
        for hn in homes:
            for sn in memories:
                plan.append((hn, sn, pair_event(hn, sn, method=method)))
    if not found_hn:
        raise ValueError("HN node ID 0x%x is not present in the selected mesh(es)" % hn_id)
    if not found_sn:
        raise ValueError("SN node ID 0x%x is not present in the selected mesh(es)" % sn_id)
    return plan


def measure(system, perf=None, method="hn", cmn_seq=None, hn_id=None,
            sn_id=None, time=DEFAULT_MEASUREMENT_TIME,
            chunk_size=DEFAULT_BATCH_SIZE,
            plan=None, progress=None):
    """Measure small event batches, retrying events which perf did not schedule."""
    if plan is None:
        plan = measurement_plan(system, method=method, cmn_seq=cmn_seq,
                                hn_id=hn_id, sn_id=sn_id)
    if perf is None:
        perf = cmn_perfstat.Perf()
    counts = collect_plan_counts(plan, perf, time=time,
                                 chunk_size=chunk_size, progress=progress)
    return [Observation(entry[0], entry[1], count)
            for entry, count in zip(plan, counts)]


def collect_plan_counts(plan, perf, time=DEFAULT_MEASUREMENT_TIME,
                        chunk_size=DEFAULT_BATCH_SIZE, progress=None):
    """Measure a plan and retry entries for which perf reports no count."""
    counts = [None] * len(plan)
    batches = measurement_batches(plan, range(len(plan)), chunk_size)
    for batch_number, indices in enumerate(batches):
        events = [plan[index][2] for index in indices]
        if progress is not None:
            progress("measure", batch_number + 1, len(batches), events, time)
        batch_counts = perf.stat(events, time=time, chunk_size=None)
        if len(batch_counts) != len(indices):
            raise ValueError("perf returned an unexpected number of counts")
        for index, count in zip(indices, batch_counts):
            counts[index] = count
    pending = [index for index, count in enumerate(counts) if count is None]
    for retry, group_size in enumerate(RETRY_GROUP_SIZES):
        if not pending:
            break
        retry_time = time * (retry + 2)
        still_pending = []
        batches = measurement_batches(plan, pending, group_size)
        for batch_number, indices in enumerate(batches):
            events = [plan[index][2] for index in indices]
            if progress is not None:
                progress("retry", batch_number + 1, len(batches), events,
                         retry_time)
            retry_counts = perf.stat(events,
                                     time=retry_time, chunk_size=None)
            if len(retry_counts) != len(indices):
                raise ValueError("perf returned an unexpected number of retry counts")
            for index, count in zip(indices, retry_counts):
                if count is None:
                    still_pending.append(index)
                else:
                    counts[index] = count
        pending = still_pending
    return counts


def measurement_batches(plan, indices, batch_size):
    """Batch independently per mesh, allowing each PMU up to batch_size events."""
    by_mesh = {}
    for index in indices:
        mesh = plan[index][0].cmn.cmn_seq
        by_mesh.setdefault(mesh, []).append(index)
    batches = []
    while any(by_mesh.values()):
        batch = []
        for mesh in sorted(by_mesh.keys()):
            batch += by_mesh[mesh][:batch_size]
            del by_mesh[mesh][:batch_size]
        batches.append(batch)
    return batches


def print_measurement_progress(phase, batch_number, n_batches, events,
                               time, verbose=0):
    actions = {
        "measure": "Measuring zone candidates",
        "retry": "Retrying zone candidates",
        "activity": "Scanning endpoint activity",
        "activity-retry": "Retrying endpoint activity",
    }
    action = actions.get(phase, "Measuring")
    print("%s batch %u/%u: %u event%s for %.1f seconds..." %
          (action, batch_number, n_batches, len(events),
           "" if len(events) == 1 else "s", time))
    if verbose:
        for event in events:
            print("  %s" % event)
    sys.stdout.flush()


def print_activity_report(active_homes, active_memories, unused_homes,
                          unused_memories, unresolved):
    print("Activity scan: %u active HN%s, %u active SN%s" %
          (len(active_homes), "" if len(active_homes) == 1 else "s",
           len(active_memories), "" if len(active_memories) == 1 else "s"))
    for label, unused in [("unused HN", unused_homes),
                          ("unused SN", unused_memories)]:
        for mesh in sorted(unused.keys()):
            print("  CMN#%u %s: %s" %
                  (mesh, label, ", ".join(
                      ["0x%x" % node_id for node_id in sorted(unused[mesh])])))
    if unresolved:
        print("  activity not counted: %s" %
              ", ".join([endpoint_str(item) for item in unresolved]))


def detected_edges(observations, min_count=1):
    if min_count < 0:
        raise ValueError("minimum count must not be negative")
    return [(observation.hn, observation.sn) for observation in observations
            if observation.count is not None and
            observation.count >= min_count]


def memory_zones(observations, min_count=1):
    """Return bipartite connected components containing observed edges."""
    adjacency = {}
    for hn, sn in detected_edges(observations, min_count=min_count):
        adjacency.setdefault(hn, set()).add(sn)
        adjacency.setdefault(sn, set()).add(hn)
    zones = []
    unseen = set(adjacency.keys())
    while unseen:
        pending = [min(unseen, key=lambda item: (item.kind, item.node_id))]
        component = set()
        while pending:
            endpoint = pending.pop()
            if endpoint in component:
                continue
            component.add(endpoint)
            pending.extend(adjacency[endpoint] - component)
        unseen -= component
        homes = sorted([item for item in component if item.kind == "HN"],
                       key=lambda item: item.node_id)
        memories = sorted([item for item in component if item.kind == "SN"],
                          key=lambda item: item.node_id)
        zones.append((homes, memories))
    return sorted(zones, key=lambda zone: (zone[0][0].cmn.cmn_seq,
                                           zone[0][0].node_id))


def endpoint_distance(hn, sn):
    """Return XY-route mesh distance, including mesh credited slices."""
    if hn.cmn is not sn.cmn:
        raise ValueError("cannot measure distance across CMN instances")
    return mesh_coordinate_distance(hn.cmn, hn.port.XP().x,
                                    hn.port.XP().y, sn.port.XP().x,
                                    sn.port.XP().y)


def mesh_coordinate_distance(cmn, x_from, y_from, x_to, y_to):
    """Return link cost for the CMN XY route between two coordinates.

    Each link costs one, plus the mesh credited slices recorded on that link.
    Horizontal routing precedes vertical routing, matching cmn_routing.Route.
    """
    distance = abs(x_to - x_from) + abs(y_to - y_from)
    for x in range(min(x_from, x_to), max(x_from, x_to)):
        slices = cmn.XP_at(x, y_from).mesh_credited_slices(0)
        distance += 0 if slices is None else slices
    for y in range(min(y_from, y_to), max(y_from, y_to)):
        slices = cmn.XP_at(x_to, y).mesh_credited_slices(1)
        distance += 0 if slices is None else slices
    return distance


def sum_pairwise_absolute(left, right):
    """Sum abs(a-b) over two sequences without forming their product."""
    ordered = sorted(right)
    prefix = [0]
    for value in ordered:
        prefix.append(prefix[-1] + value)
    total = 0
    for value in left:
        split = bisect.bisect_left(ordered, value)
        total += (value * split) - prefix[split]
        total += (prefix[-1] - prefix[split]) - \
            (value * (len(ordered) - split))
    return total


def average_zone_distance(homes, memories):
    """Return average Manhattan distance over all HN/SN pairs in a zone."""
    total, count = zone_distance_total(homes, memories)
    return float(total) / count


def zone_distance_total(homes, memories):
    """Return total mesh distance and pair count for one zone."""
    statistics = zone_distance_stats(homes, memories)
    return (statistics.total, statistics.count)


def endpoint_coordinate_counts(endpoints):
    """Count endpoints at each XP coordinate."""
    counts = {}
    for endpoint in endpoints:
        coordinate = (endpoint.port.XP().x, endpoint.port.XP().y)
        counts[coordinate] = counts.get(coordinate, 0) + 1
    return counts


def zone_distance_populations(homes, memories):
    """Yield (distance, pair count) for unique coordinate pairs in a zone."""
    if not homes or not memories:
        raise ValueError("a memory zone must contain both HNs and SNs")
    if any(item.cmn is not homes[0].cmn for item in homes + memories):
        raise ValueError("a memory zone cannot span CMN instances")
    home_counts = endpoint_coordinate_counts(homes)
    memory_counts = endpoint_coordinate_counts(memories)
    cmn = homes[0].cmn
    for (hx, hy), home_count in home_counts.items():
        for (sx, sy), memory_count in memory_counts.items():
            yield (mesh_coordinate_distance(cmn, hx, hy, sx, sy),
                   home_count * memory_count)


def zone_distance_stats(homes, memories):
    """Return exact aggregate and extrema for one zone's permitted pairs."""
    total = 0
    count = 0
    minimum = None
    maximum = None
    for distance, population in zone_distance_populations(homes, memories):
        total += distance * population
        count += population
        if minimum is None or distance < minimum:
            minimum = distance
        if maximum is None or distance > maximum:
            maximum = distance
    return DistanceStats(total, count, minimum, maximum)


def endpoint_table(homes, memories, cell_value):
    """Render one HN-row/SN-column table using a caller-provided cell value."""
    labels = ["0x%x" % item.node_id for item in memories]
    column_widths = [OBSERVATION_COLUMN_WIDTH] * len(labels)
    row_width = max([len("HN\\SN")] +
                    [len("0x%x" % item.node_id) for item in homes])
    lines = [("%*s | " % (row_width, "HN\\SN")) +
             " ".join([label.rjust(width) for label, width in
                       zip(labels, column_widths)])]
    lines.append(("-" * row_width) + "-+-" +
                 "-".join(["-" * width for width in column_widths]))
    for hn in homes:
        cells = [str(cell_value(hn, sn)).center(width)
                 for sn, width in zip(memories, column_widths)]
        lines.append(("%*s | " % (row_width, "0x%x" % hn.node_id)) +
                     " ".join(cells))
    return lines


def observation_tables(observations, min_count=1):
    """Return compact per-mesh matrices with HN rows and SN columns."""
    meshes = sorted(set([item.hn.cmn.cmn_seq for item in observations]))
    tables = []
    for mesh in meshes:
        mesh_observations = [item for item in observations
                             if item.hn.cmn.cmn_seq == mesh]
        homes = sorted(set([item.hn for item in mesh_observations]),
                       key=lambda item: item.node_id)
        memories = sorted(set([item.sn for item in mesh_observations]),
                          key=lambda item: item.node_id)
        values = dict(((item.sn, item.hn), item.count)
                      for item in mesh_observations)
        def cell_value(hn, sn):
            count = values.get((sn, hn), None)
            if count is None:
                return " "
            if count >= min_count:
                return endpoint_distance(hn, sn)
            return "."
        lines = endpoint_table(homes, memories, cell_value)
        tables.append((mesh, lines))
    return tables


def print_report(observations, min_count=1, table=False,
                 show_assignments=True):
    zones = memory_zones(observations, min_count=min_count)
    edges = detected_edges(observations, min_count=min_count)
    if show_assignments:
        for index, (homes, memories) in enumerate(zones):
            print("Zone %u (CMN#%u):" % (index, homes[0].cmn.cmn_seq))
            print("  HN: %s" % ", ".join(["0x%x" % item.node_id
                                           for item in homes]))
            print("  SN: %s" % ", ".join(["0x%x" % item.node_id
                                           for item in memories]))
        if not zones:
            print("No HN-to-SN traffic was detected.")
    detected_homes = set([edge[0] for edge in edges])
    detected_memories = set([edge[1] for edge in edges])
    unresolved_homes = sorted(set([item.hn for item in observations]) -
                              detected_homes,
                              key=lambda item: (item.cmn.cmn_seq, item.node_id))
    unresolved_memories = sorted(set([item.sn for item in observations]) -
                                 detected_memories,
                                 key=lambda item: (item.cmn.cmn_seq,
                                                   item.node_id))
    if unresolved_homes:
        print("HN with no detected SN: %s" %
              ", ".join([endpoint_str(item) for item in unresolved_homes]))
    if unresolved_memories:
        print("SN with no detected HN: %s" %
              ", ".join([endpoint_str(item) for item in unresolved_memories]))
    if table:
        for mesh, lines in observation_tables(observations,
                                              min_count=min_count):
            print("HN-to-SN mesh distance (CMN#%u):" % mesh)
            for line in lines:
                print("  %s" % line)


def main(argv, perf=None):
    import argparse
    parser = argparse.ArgumentParser(
        description="Discover HN-F/HN-S to SN-F memory zones from REQ traffic",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--json", default=cmn_json.cmn_config_filename(),
                        help="JSON system description")
    parser.add_argument("--cache", default=cache_filename(),
                        help="memory-zone cache file")
    parser.add_argument("--no-cache", action="store_true",
                        help="ignore cached zones and run detection again")
    parser.add_argument("--cmn-instance", type=int, help="CMN instance number")
    parser.add_argument("--hn", type=lambda value: int(value, 0),
                        help="only inspect this HN node ID")
    parser.add_argument("--sn", type=lambda value: int(value, 0),
                        help="only inspect this SN node ID")
    parser.add_argument("--method", choices=["hn", "sn"], default="hn",
                        help="monitor upload at HNs or download at SNs")
    parser.add_argument("--time", type=float, default=DEFAULT_MEASUREMENT_TIME,
                        help="measurement duration per event batch in seconds")
    parser.add_argument("--min-count", type=int, default=1,
                        help="minimum count for a detected association")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_BATCH_SIZE,
                        help="maximum simultaneous events per CMN instance")
    parser.add_argument("--diagram", action="store_true",
                        help="show an ASCII memory-zone diagram")
    parser.add_argument("--distance", action="store_true",
                        help="show average HN-to-SN hops per zone, mesh and system")
    parser.add_argument("--table", action="store_true",
                        help="show HN/SN associations as a mesh-distance table")
    parser.add_argument("--color", choices=["auto", "always", "never"],
                        default="auto", help="diagram color output")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="show every pair measurement")
    opts = parser.parse_args(argv)
    if opts.time <= 0:
        parser.error("--time must be positive")
    if opts.min_count < 0:
        parser.error("--min-count must not be negative")
    if opts.chunk_size <= 0:
        parser.error("--chunk-size must be positive")
    system = cmn_json.load_system_for_cli(opts.json)
    if not opts.no_cache:
        try:
            cached = load_cache(opts.cache, missing_ok=True)
            if cached is not None:
                validate_cache_topology(cached, system)
        except ValueError as error:
            print("Ignoring memory-zone cache: %s" % error, file=sys.stderr)
            cached = None
        if cached is not None:
            print("Using cached memory zones from %s (use --no-cache to refresh)" %
                  opts.cache)
            if not (opts.table or opts.diagram or opts.distance):
                print_cached_report(cached, cmn_seq=opts.cmn_instance,
                                    hn_id=opts.hn, sn_id=opts.sn)
            if opts.distance:
                print_zone_distances(cached_zone_endpoints(
                    system, cached, cmn_seq=opts.cmn_instance,
                    hn_id=opts.hn, sn_id=opts.sn))
            if opts.table:
                print_distance_tables(cached_distance_tables(
                    system, cached, cmn_seq=opts.cmn_instance,
                    hn_id=opts.hn, sn_id=opts.sn))
            if opts.diagram:
                print_cache_diagrams(system, cached,
                                     cmn_seq=opts.cmn_instance,
                                     color=opts.color)
            return 0
    if perf is None:
        perf = cmn_perfstat.Perf(verbose=max(0, opts.verbose - 1))
    try:
        print("Preparing CMN endpoint activity watchpoints...")
        sys.stdout.flush()
        activity = activity_plan(system, cmn_seq=opts.cmn_instance,
                                 hn_id=opts.hn, sn_id=opts.sn)
        print("Prepared %u endpoint activity probes." % len(activity))
        sys.stdout.flush()
        activity_counts = collect_plan_counts(
            activity, perf, time=opts.time, chunk_size=opts.chunk_size,
            progress=lambda phase, number, total, events, duration:
                print_measurement_progress(
                    "activity" if phase == "measure" else "activity-retry",
                    number, total, events, duration,
                    verbose=opts.verbose))
        (active_homes, active_memories, unused_homes, unused_memories,
         unresolved_activity) = classify_activity(
             activity, activity_counts, min_count=opts.min_count)
        print_activity_report(active_homes, active_memories, unused_homes,
                              unused_memories, unresolved_activity)
        plan = pair_plan(active_homes, active_memories, method=opts.method)
        print("Prepared %u HN/SN candidate pairs; each batch measures for %.1f seconds." %
              (len(plan), opts.time))
        sys.stdout.flush()
        observations = measure(system, perf=perf, method=opts.method,
                               cmn_seq=opts.cmn_instance, hn_id=opts.hn,
                               sn_id=opts.sn, time=opts.time,
                               chunk_size=opts.chunk_size, plan=plan,
                               progress=lambda phase, number, total, events, duration:
                                   print_measurement_progress(
                                       phase, number, total, events, duration,
                                       verbose=opts.verbose))
    except (ValueError, cmnwatch.WatchpointError,
            cmn_perfstat.PerfNotAvailable) as error:
        parser.error(str(error))
    print_report(observations, min_count=opts.min_count, table=opts.table,
                 show_assignments=not (opts.table or opts.diagram or
                                       opts.distance))
    zones = memory_zones(observations, min_count=opts.min_count)
    if opts.distance:
        print_zone_distances(numbered_zones(zones))
    cache_data = cache_from_zones(zones, opts.method, opts.time,
                                  opts.min_count, unused_homes=unused_homes,
                                  unused_memories=unused_memories)
    full_discovery = (opts.cmn_instance is None and opts.hn is None and
                      opts.sn is None)
    if full_discovery and cache_is_complete(observations,
                                            min_count=opts.min_count,
                                            active_homes=active_homes,
                                            active_memories=active_memories,
                                            activity_counts=activity_counts):
        write_cache(opts.cache, cache_data)
        print("Cached memory zones in %s" % opts.cache)
    else:
        print("Memory-zone detection was partial or unresolved; cache not updated.")
    if opts.diagram:
        print_cache_diagrams(system, cache_data, cmn_seq=opts.cmn_instance,
                             color=opts.color)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
