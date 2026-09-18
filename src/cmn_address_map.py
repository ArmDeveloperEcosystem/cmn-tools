#!/usr/bin/python

"""
Build a system-wide physical address map from CMN RN-SAMs.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import csv
from itertools import groupby
import sys
import time

from address_map import AddressMap
import cmn_base
from cmn_devmem import cmn_from_opts
import cmn_devmem_find
from cmn_enum import (CMN_NODE_RNSAM, CMN_NODE_HNF, CMN_NODE_HNS,
                      CMN_NODE_CXRA, CMN_NODE_CCG_RA, CMN_PROP_HNF, CMN_PROP_CCG,
                      CMN_PROP_CHI, CMN_PROP_RNF,
                      cmn_port_device_type_has_properties)
from cmn_config import CMN_GEN_700
import cmn_json
import cmn_select
from cmn_sam import (CPAG, hn_sam_target_regions, rn_sam_hashed_regions,
                     rn_sam_nonhash_regions, rn_sam_cpa_groups)
from proc_iomem import IOmem_map


_GATEWAY_TARGET_TYPES = ["CXRA", "PCI-CXRA", "CCG-RA"]
_IO_TARGET_TYPES = ["HN-I", "HN-P", "HN-D", "HN-T", "HN-V"]


def _mesh_name(cmn):
    return "CMN#%u" % cmn.cmn_seq


class SAMTarget(object):
    """One target selected by a SAM entry."""

    def __init__(self, target_type, nodeid=None, cpag=None, gateway=False):
        self.target_type = target_type
        self.nodeid = nodeid
        self.cpag = cpag
        self.gateway = gateway

    def key(self):
        return (self.target_type,
                -1 if self.nodeid is None else self.nodeid,
                -1 if self.cpag is None else self.cpag,
                self.gateway)

    def homing_key(self):
        if self.gateway:
            return ("gateway",)
        return self.key()

    def __str__(self):
        if self.cpag is not None:
            return "CPAG#%u gateway" % self.cpag
        s = self.target_type
        if self.nodeid is not None:
            s += "@0x%x" % self.nodeid
        if self.gateway:
            s += " gateway"
        return s


class SAMRange(object):
    """A normalized inclusive range and target set from an RN or HN SAM."""

    def __init__(self, base, end, targets, priority=0, index=None,
                 table_name=None, hashed=None, cal=0,
                 clusters=0, nodes_per_cluster=0, cpa=(), secure=None, details=""):
        if base < 0 or base > end:
            raise ValueError("invalid SAM address bounds")
        self.base = base
        self.end = end
        self.target_order = tuple(targets)
        self.targets = tuple(sorted(self.target_order, key=lambda t: t.key()))
        self.hashed = (priority == 1) if hashed is None else hashed
        self.cal = cal or 0
        self.clusters = clusters or 0
        self.nodes_per_cluster = nodes_per_cluster or 0
        self.cpa = tuple(cpa)
        self.secure = secure
        self.details = details
        self.priority = priority
        self.index = index
        self.table_name = table_name

    def contains(self, addr):
        return self.base <= addr and addr <= self.end

    def selection_key(self):
        """Keep target order: changing table order changes address selection."""
        if self.hashed:
            targets = tuple([t.homing_key() for t in self.target_order])
        else:
            targets = tuple(sorted(set([t.homing_key() for t in self.targets])))
        return (self.hashed, targets, self.cal, self.clusters,
                self.nodes_per_cluster,
                tuple([-1 if c is None else c for c in self.cpa]),
                -1 if self.secure is None else self.secure, self.details)

    def key(self):
        return (self.priority, self.base, self.end, self.selection_key())

    def group_key(self):
        """Identity retained when adjacent address-map ranges are combined."""
        return (self.table_name or "", str(self.index), self.selection_key())

    def description(self):
        label = self.table_name or "SAM"
        if self.index is not None:
            label += "#%s" % self.index
        label += ": " + ("hashed/striped" if self.hashed else "direct")
        if self.clusters:
            label += "; hierarchical: %u clusters x %u targets" % (
                self.clusters, self.nodes_per_cluster)
        if self.cal:
            label += "; CAL%u" % self.cal
        if any([c is not None for c in self.cpa]):
            label += "; CPA outcomes: " + ", ".join([
                "local" if c is None else "CPAG#%u" % c for c in self.cpa])
        if self.secure is not None:
            label += "; region security encoding=%u" % self.secure
        if self.details:
            label += "; " + self.details
        return label


def _targets_from_region(reg):
    if reg.cpa_error:
        # Raw target IDs may be remote aliases when CPA is enabled.
        return [SAMTarget("unknown CPA routing")]
    target_type = reg.target_type_str
    targets = []
    if reg.hashed:
        if reg.nodeids is not None:
            if reg.target_cpags is not None and len(reg.target_cpags) != len(reg.nodeids):
                raise ValueError("CPA selection does not match the hashed target table")
            for ix, nodeid in enumerate(reg.nodeids):
                if reg.target_cpags is not None and reg.target_cpags[ix] is not None:
                    targets.append(SAMTarget("CPAG", cpag=reg.target_cpags[ix], gateway=True))
                    continue
                # CMN-700 TRM addendum (108055), SCG target ID selection
                # with CAL mode; CMN S3 TRM (107858), RN SAM CAL mode.
                # The table supplies one ID per CAL; selection changes the
                # low device-ID bits to reach each member of the CAL.
                offsets = (reg.cal_node_offsets if reg.cal_node_offsets is not None
                           else range(reg.CAL or 1))
                for device in offsets:
                    # Programmable S3 CAL maps are ORed into the table ID.
                    target_id = (nodeid | device if reg.cal_node_offsets is not None
                                 else nodeid ^ device)
                    targets.append(SAMTarget(target_type, nodeid=target_id,
                                             gateway=target_type in _GATEWAY_TARGET_TYPES))
        if reg.target_cpags is None:
            for cpag in reg.cpag:
                if cpag is not None:
                    targets.append(SAMTarget("CPAG", cpag=cpag, gateway=True))
    elif reg.cpag and reg.cpag[0] is not None:
        targets.append(SAMTarget("CPAG", cpag=reg.cpag[0], gateway=True))
    else:
        targets.append(SAMTarget(
            target_type, nodeid=reg.nodeid,
            gateway=(target_type in _GATEWAY_TARGET_TYPES)))
    return targets


def _normalize_region(reg, priority, table_name):
    details = reg.selection_details
    if reg.cpa_error:
        details = "; ".join([s for s in [details, reg.cpa_error] if s])
    return SAMRange(reg.base, reg.range_end(), _targets_from_region(reg),
                    priority=priority, index=reg.index,
                    table_name=table_name, hashed=reg.hashed, cal=reg.CAL,
                    clusters=reg.hier_n_clusters,
                    nodes_per_cluster=reg.hier_n_nodes, cpa=reg.cpag,
                    secure=reg.secure, details=details)


class SAMSnapshot(object):
    """The decoded address-routing table from one RN-SAM node."""

    def __init__(self, node, ranges, cpags=()):
        self.node = node
        self.ranges = list(ranges)
        self.cpags = dict([(g.index, g) for g in cpags])
        self.cpa_error = None

    @classmethod
    def from_node(cls, node, include_cpa=False):
        nonhash = list(rn_sam_nonhash_regions(node))
        hashed = list(rn_sam_hashed_regions(node))
        cpags, cpa_error = [], None
        if include_cpa:
            try:
                cpags = rn_sam_cpa_groups(node, nonhash, hashed)
            except (OSError, ValueError) as ex:
                cpa_error = str(ex)
                for reg in nonhash + hashed:
                    if (node.C.part_ge_700() and reg.target_cpags is None and
                            not any([c is not None for c in reg.cpag])):
                        reg.cpa_error = cpa_error
            errors = sorted(set([reg.cpa_error for reg in nonhash + hashed if reg.cpa_error]))
            cpa_error = cpa_error or ("; ".join(errors) if errors else None)
        ranges = [_normalize_region(reg, 0, "NHMR") for reg in nonhash]
        table = "HTG" if node.C.part_ge_700() else "SCG"
        ranges += [_normalize_region(reg, 1, table) for reg in hashed]
        result = cls(node, ranges, cpags=cpags)
        result.cpa_error = cpa_error
        return result

    def signature(self):
        return tuple(sorted([r.key() for r in self.ranges]))

    def lookup(self, addr):
        """
        Return the effective tuple of targets for addr, or None.

        Non-hashed entries have priority over hashed entries. Multiple
        matching entries at the same priority are retained so malformed or
        unusual tables can still be reported rather than asserted away.
        """
        result = self.lookup_with_priority(addr)
        return None if result is None else result[0]

    def lookup_with_priority(self, addr):
        """Return (effective targets, priority), or None when unmapped."""
        matches = self.lookup_ranges(addr)
        if not matches:
            return None
        priority = matches[0].priority
        targets = {}
        for r in matches:
            if r.priority == priority:
                for target in r.targets:
                    targets[target.key()] = target
        return (tuple([targets[k] for k in sorted(targets.keys())]),
                priority)

    def lookup_ranges(self, addr):
        """Return the winning regions, preserving each distinct target set."""
        matches = [r for r in self.ranges if r.contains(addr)]
        if not matches:
            return []
        priority = min([r.priority for r in matches])
        return [r for r in matches if r.priority == priority]


    def effective_ranges(self):
        """Yield disjoint ranges and winning entries for this source SAM."""
        bounds = sorted(set([v for r in self.ranges
                             for v in (r.base, r.end + 1)]))
        for start, limit in zip(bounds, bounds[1:]):
            groups = self.lookup_ranges(start)
            if groups:
                yield start, limit - 1, groups


class MeshSAMs(object):
    """All decoded RN-SAMs for a mesh and the selected consensus table."""

    def __init__(self, cmn, snapshots, selected):
        self.cmn = cmn
        self.snapshots = list(snapshots)
        self.selected = selected


def _targets_homing_key(targets):
    if targets is None:
        return None
    return tuple(sorted(set([target.homing_key() for target in targets])))


def _describe_sam_targets(targets):
    if targets is None:
        return "unmapped"
    homes = [target for target in targets if not target.gateway]
    parts = []
    hns = [target for target in homes if target.target_type == "HN-S"]
    if len(hns) >= 4:
        parts.append("HN-S x %u" % len(hns))
        homes = [target for target in homes
                 if target.target_type != "HN-S"]
    parts += [str(target) for target in homes]
    if any([target.gateway for target in targets]):
        parts.append("gateway")
    if not parts:
        return "no target"
    return ", ".join(parts)


def _report_snapshot_differences(snapshots, warn):
    boundaries = set()
    for snapshot in snapshots:
        for r in snapshot.ranges:
            boundaries.add(r.base)
            boundaries.add(r.end + 1)
    boundaries = sorted(boundaries)

    differences = []
    pending = None
    for i in range(0, len(boundaries) - 1):
        start = boundaries[i]
        end = boundaries[i + 1] - 1
        targets = [snapshot.lookup(start) for snapshot in snapshots]
        assignment = tuple([_targets_homing_key(t) for t in targets])
        if len(set(assignment)) <= 1:
            if pending is not None:
                differences.append(pending)
                pending = None
            continue
        if pending is not None and pending[1] + 1 == start and (
                pending[2] == assignment):
            pending = (pending[0], end, assignment, targets)
        else:
            if pending is not None:
                differences.append(pending)
            pending = (start, end, assignment, targets)
    if pending is not None:
        differences.append(pending)

    if not differences:
        warn("  target membership agrees, but table layout or hash selection "
             "settings differ")
        return

    for (start, end, assignment, targets) in differences:
        warn("  RN-SAM routing differs for 0x%x-0x%x:" % (start, end))
        groups = {}
        order = []
        for i in range(0, len(snapshots)):
            key = assignment[i]
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(i)
        for key in order:
            indexes = groups[key]
            nodes = ", ".join([str(snapshots[i].node) for i in indexes])
            warn("    %s -> %s" %
                 (nodes, _describe_sam_targets(targets[indexes[0]])))


def _select_consensus(cmn, snapshots, warn, verbose=0):
    if not snapshots:
        warn("WARNING: %s has no RN-SAM nodes" % _mesh_name(cmn))
        return None

    active = [snapshot for snapshot in snapshots if snapshot.ranges]
    if verbose >= 2:
        for snapshot in snapshots:
            if not snapshot.ranges:
                warn("%s: ignoring inactive RN-SAM with no regions: %s" %
                     (_mesh_name(cmn), snapshot.node))
    if not active:
        if verbose:
            warn("%s: all %u RN-SAMs are inactive (no regions)" %
                 (_mesh_name(cmn), len(snapshots)))
        return None
    snapshots = active

    groups = {}
    group_order = []
    for snapshot in snapshots:
        signature = snapshot.signature()
        if signature not in groups:
            groups[signature] = []
            group_order.append(signature)
        groups[signature].append(snapshot)

    selected_signature = group_order[0]
    for signature in group_order[1:]:
        if len(groups[signature]) > len(groups[selected_signature]):
            selected_signature = signature
    selected_group = groups[selected_signature]

    if len(groups) > 1:
        warn("WARNING: %s has %u inconsistent RN-SAM table variants; "
             "using the %u-node majority represented by %s" %
             (_mesh_name(cmn), len(groups), len(selected_group),
              selected_group[0].node))
        _report_snapshot_differences(snapshots, warn)
    elif verbose >= 1:
        warn("%s: %u RN-SAMs have a consistent %u-region map" %
             (_mesh_name(cmn), len(snapshots),
              len(selected_group[0].ranges)))
    return selected_group[0]


def scan_mesh(cmn, warn, verbose=0, include_cpa=False):
    """Read and compare every RN-SAM in one mesh."""
    if verbose:
        warn("%s: discovering nodes and scanning RN-SAMs" % _mesh_name(cmn))
    sam_nodes = [n for n in cmn.nodes()
                 if n.type() == CMN_NODE_RNSAM and not n.is_disabled()]
    snapshots = []
    for (i, node) in enumerate(sam_nodes):
        if verbose >= 2:
            warn("%s: reading RN-SAM %u/%u: %s" %
                 (_mesh_name(cmn), i + 1, len(sam_nodes), node))
        snapshot = SAMSnapshot.from_node(node, include_cpa=include_cpa)
        snapshots.append(snapshot)
        if snapshot.cpa_error:
            warn("WARNING: %s: CPA routing incomplete: %s" % (node, snapshot.cpa_error))
        for cpag in snapshot.cpags.values():
            if cpag.error:
                warn("WARNING: %s: CPAG#%u: %s" % (node, cpag.index, cpag.error))
        if verbose >= 2:
            warn("%s: %s: decoded %u region(s)" %
                 (_mesh_name(cmn), node, len(snapshot.ranges)))
    selected = _select_consensus(
        cmn, snapshots, warn=warn, verbose=verbose)
    return MeshSAMs(cmn, snapshots, selected)


class RoutedTarget(object):
    """A SAM target qualified by the mesh containing that target."""

    def __init__(self, cmn, target):
        self.cmn = cmn
        self.target = target

    def key(self):
        return (self.cmn.cmn_seq,) + self.target.key()

    def __str__(self):
        return "%s %s" % (_mesh_name(self.cmn), self.target)


def _format_home_targets(endpoints):
    hns_groups = {}
    for routed in endpoints:
        if routed.target.target_type == "HN-S":
            key = routed.cmn.cmn_seq
            hns_groups.setdefault(key, []).append(routed)

    result = []
    shown_hns = set()
    for routed in endpoints:
        if routed.target.target_type == "HN-S":
            seq = routed.cmn.cmn_seq
            group = hns_groups[seq]
            if len(group) >= 4:
                if seq not in shown_hns:
                    result.append("%s HN-S x %u" %
                                  (_mesh_name(routed.cmn), len(group)))
                    shown_hns.add(seq)
                continue
        result.append(str(routed))
    return ", ".join(result)


class SystemRoute(object):
    """Resolved homing information associated with one system address range."""

    def __init__(self, endpoints, gateways, mesh_routes,
                 nonhash_endpoints=None, target_groups=()):
        self.endpoints = tuple(sorted(endpoints, key=lambda t: t.key()))
        # Gateways are retained for verbose diagnostics, but are deliberately
        # excluded from home identity and normal output: they route requests,
        # they do not home addresses. Node reports retain their groups.
        self.gateways = tuple(sorted(gateways, key=lambda t: t.key()))
        self.mesh_routes = tuple(mesh_routes)
        self.target_groups = tuple(target_groups)
        self.sn_routes = []
        if nonhash_endpoints is None:
            nonhash_endpoints = []
        self.nonhash_endpoints = tuple(sorted(
            nonhash_endpoints, key=lambda t: t.key()))
        self.nonhash_endpoint_keys = set(
            [target.key() for target in self.nonhash_endpoints])
        self.home_meshes = tuple(sorted(set([
            target.cmn.cmn_seq for target in self.endpoints])))

    def key(self):
        return tuple([t.key() for t in self.endpoints])

    def map_key(self):
        """Routing identity including provenance needed by capture."""
        return (self.key(),
                tuple([t.key() for t in self.nonhash_endpoints]),
                tuple([(c.cmn_seq, g.group_key())
                       for c, g in self.target_groups]))

    def status(self):
        if not self.endpoints:
            return "unresolved"
        if len(self.home_meshes) > 1:
            return "inconsistent"
        return "ok"

    def __str__(self):
        if self.endpoints:
            s = _format_home_targets(self.endpoints)
        else:
            s = "unresolved home"
        if self.status() == "inconsistent":
            s += " [INCONSISTENT: multiple home meshes]"
        return s


class AnnotatedRoute(object):
    """A system route and iomem subdivision of its original SAM range."""

    def __init__(self, route, iomem_region=None, sam_start=None, sam_end=None):
        self.route = route
        self.iomem_region = iomem_region
        self.sam_start = sam_start
        self.sam_end = sam_end

    def key(self):
        if self.iomem_region is None:
            iomem_key = None
        else:
            iomem_key = (self.iomem_region.addr, self.iomem_region.aend,
                         self.iomem_region.name, self.iomem_region.level)
        return (self.route.map_key(), iomem_key)


def annotate_address_map(amap, iomap):
    """
    Split an AddressMap at /proc/iomem boundaries and attach annotations.

    Nested iomem entries are handled by selecting the most specific region for
    each resulting range.
    """
    annotated = AddressMap()
    for mapped in amap:
        boundaries = set([mapped.start, mapped.end + 1])
        for region in iomap.overlapping_regions(mapped.start, mapped.end):
            boundaries.add(max(mapped.start, region.addr))
            boundaries.add(min(mapped.end, region.aend) + 1)
        boundaries = sorted(boundaries)
        for i in range(0, len(boundaries) - 1):
            start = boundaries[i]
            end = boundaries[i + 1] - 1
            region = iomap.lookup(start)
            if region is not None and region.is_address_missing():
                region = None
            annotated.add(start, end, AnnotatedRoute(
                mapped.data, region, mapped.start, mapped.end))
    return annotated


def iomem_map_for_system(cmns, iomem_file, message):
    """Return a usable local iomem map, or None with an explanatory message."""
    if not cmns or not all([cmn.is_local for cmn in cmns]):
        message("Not annotating addresses: CMN target is not the local system")
        return None
    if iomem_file == "none":
        message("Not annotating addresses: /proc/iomem scanning is disabled")
        return None
    iomap = IOmem_map(iomem=iomem_file)
    if not iomap.addresses_valid:
        message("Not annotating addresses: /proc/iomem exposes region names "
                "but not physical addresses")
        return None
    return iomap


def build_system_address_map(mesh_sams):
    """
    Combine selected per-mesh SAM tables into a non-overlapping AddressMap.

    Gateway targets remain visible as intermediate routes. Non-gateway targets
    from all meshes are the ultimate system targets for the range.
    """
    selected = [m for m in mesh_sams if m.selected is not None]
    boundaries = set()
    for mesh in selected:
        for r in mesh.selected.ranges:
            boundaries.add(r.base)
            boundaries.add(r.end + 1)
    boundaries = sorted(boundaries)

    amap = AddressMap()
    pending_start = None
    pending_end = None
    pending_route = None
    for i in range(0, len(boundaries) - 1):
        start = boundaries[i]
        end = boundaries[i + 1] - 1
        endpoints = {}
        nonhash_endpoints = {}
        gateways = {}
        mesh_routes = []
        target_groups = []
        any_route = False
        for mesh in selected:
            lookup = mesh.selected.lookup_with_priority(start)
            targets = None if lookup is None else lookup[0]
            mesh_routes.append((mesh.cmn, targets))
            if targets is None:
                continue
            any_route = True
            groups = mesh.selected.lookup_ranges(start)
            target_groups.extend([(mesh.cmn, g) for g in groups])
            direct_keys = set([t.key() for g in groups if not g.hashed
                               for t in g.targets])
            for target in targets:
                routed = RoutedTarget(mesh.cmn, target)
                if target.gateway:
                    gateways[routed.key()] = routed
                else:
                    endpoints[routed.key()] = routed
                    if target.key() in direct_keys:
                        nonhash_endpoints[routed.key()] = routed
        if not any_route:
            route = None
        else:
            route = SystemRoute(
                list(endpoints.values()), list(gateways.values()), mesh_routes,
                nonhash_endpoints=list(nonhash_endpoints.values()),
                target_groups=target_groups)

        if route is not None and pending_route is not None and (
                pending_end + 1 == start and
                pending_route.map_key() == route.map_key()):
            pending_end = end
            continue
        if pending_route is not None:
            amap.add(pending_start, pending_end, pending_route)
        pending_start = start
        pending_end = end
        pending_route = route
    if pending_route is not None:
        amap.add(pending_start, pending_end, pending_route)
    return amap


def report_homing_inconsistencies(amap, message):
    """Report ranges that appear to be homed on more than one mesh."""
    for r in amap:
        if r.data.status() == "inconsistent":
            meshes = ", ".join(["CMN#%u" % n
                                for n in r.data.home_meshes])
            message("WARNING: 0x%x-0x%x appears homed on multiple meshes: %s" %
                    (r.start, r.end, meshes))




class SystemSAMs(object):
    """Decoded source SAMs and the system address map derived from them."""

    def __init__(self, meshes, address_map, hn_sams=None):
        self.meshes = list(meshes)
        self.address_map = address_map
        self.hn_sams = hn_sams if hn_sams is not None else {}


def scan_system_sams(cmns, verbose=0, error_file=None, include_sn=False,
                     all_sources=False, include_cpa=False):
    """Scan source SAMs, retaining per-source tables for group reporting."""
    if error_file is None:
        error_file = sys.stderr

    def message(s):
        print(s, file=error_file)

    meshes = []
    for cmn in cmns:
        meshes.append(scan_mesh(cmn, warn=message, verbose=verbose, include_cpa=include_cpa))
    if verbose:
        message("Combining SAM maps from %u mesh(es)" % len(meshes))
    amap = build_system_address_map(meshes)
    report_homing_inconsistencies(amap, message)
    hn_sams = {}
    if include_sn:
        home_map = amap
        if all_sources:
            # For the group report, include homes reached by any source SAM,
            # even when that source differs from the consensus table.
            sources = [MeshSAMs(m.cmn, [s], s) for m in meshes for s in m.snapshots]
            home_map = build_system_address_map(sources)
        hn_sams = scan_home_sams(cmns, home_map, message)
        amap = add_sn_routes(amap, hn_sams)
    if verbose:
        message("System address map contains %u range(s)" % len(amap))
    return SystemSAMs(meshes, amap, hn_sams)


def scan_system(cmns, verbose=0, error_file=None, include_sn=False):
    """Scan all meshes and return a system-wide AddressMap."""
    return scan_system_sams(cmns, verbose=verbose, error_file=error_file,
                            include_sn=include_sn).address_map


class SNRoute(object):
    """A conditional forwarding path from one home to an SN target group."""

    def __init__(self, home, group):
        self.home = home
        self.group = group
        self.targets = tuple([RoutedTarget(home.cmn, t) for t in group.targets])


def scan_home_sams(cmns, amap, message):
    """Read each reachable, discovered HN-F/HN-S once, on explicit request."""
    homes = {}
    for mapped in amap:
        for home in mapped.data.endpoints:
            if home.target.target_type in ["HN-F", "HN-S"]:
                homes[(home.cmn.cmn_seq, home.target.nodeid)] = home
    snapshots = {}
    for cmn in cmns:
        # nodes() retains cmn_devmem's existing isolation and skiplist guards.
        for node in cmn.nodes():
            if node.type() not in [CMN_NODE_HNF, CMN_NODE_HNS]:
                continue
            key = (cmn.cmn_seq, node.node_id())
            if key not in homes:
                continue
            if node.is_disabled():
                message("%s: disabled; not reading HN SAM" % homes[key])
                continue
            try:
                regions = hn_sam_target_regions(node)
                ranges = [_normalize_region(r, r.priority, r.table_name)
                          for r in regions]
                # Resolve the port type where available: an SN-side target
                # can be an external SN-F, an SBSX, or a gateway.
                for group in ranges:
                    for target in group.targets:
                        port = cmn.port_at_id(target.nodeid)
                        if port is not None:
                            target.target_type = port.connected_type_s
                snapshots[key] = SAMSnapshot(node, ranges)
            except (OSError, ValueError) as ex:
                message("WARNING: %s: SN routing unavailable: %s" %
                        (homes[key], ex))
    for key in sorted(homes):
        if key not in snapshots:
            message("WARNING: %s: no decoded HN SAM; downstream targets unknown" %
                    homes[key])
    return snapshots


def add_sn_routes(amap, hn_sams):
    """Intersect RN reachability with HN SAM ranges and precedence.

    A path is conditional: RN selection must reach its home, and that home
    must forward the transaction to an SN (for example, on a cache miss).
    No exact per-address hash result or independence of hash stages is assumed.
    """
    result = AddressMap()
    for mapped in amap:
        source = mapped.data
        boundaries = set([mapped.start, mapped.end + 1])
        home_sams = []
        for home in source.endpoints:
            sam = hn_sams.get((home.cmn.cmn_seq, home.target.nodeid))
            if sam is None:
                continue
            home_sams.append((home, sam))
            for group in sam.ranges:
                if group.base <= mapped.end and group.end >= mapped.start:
                    boundaries.add(max(mapped.start, group.base))
                    boundaries.add(min(mapped.end, group.end) + 1)
        boundaries = sorted(boundaries)
        for i in range(len(boundaries) - 1):
            start, end = boundaries[i], boundaries[i + 1] - 1
            route = SystemRoute(source.endpoints, source.gateways,
                                source.mesh_routes, source.nonhash_endpoints,
                                source.target_groups)
            for home, sam in home_sams:
                for group in sam.lookup_ranges(start):
                    route.sn_routes.append(SNRoute(home, group))
            result.add(start, end, route)
    return result


def _route_and_iomem(data):
    if isinstance(data, AnnotatedRoute):
        return (data.route, data.iomem_region)
    return (data, None)


def print_address_map(amap, verbose=0, file=None):
    if file is None:
        file = sys.stdout
    for r in amap:
        route, iomem_region = _route_and_iomem(r.data)
        line = "0x%016x-0x%016x: %s" % (r.start, r.end, route)
        if iomem_region is not None:
            line += "  iomem: %s" % iomem_region.describe(r.start)
        print(line, file=file)
        if verbose >= 2:
            for (cmn, targets) in route.mesh_routes:
                if targets is None:
                    desc = "unmapped"
                else:
                    desc = ", ".join([str(t) for t in targets])
                print("  %s SAM: %s" % (_mesh_name(cmn), desc), file=file)


def print_address_lookups(amap, addresses, file=None):
    """Look up and describe physical addresses in a discovered SAM map."""
    if file is None:
        file = sys.stdout
    for addr in addresses:
        mapped = amap.find(addr)
        if mapped is None:
            print("0x%x: not found" % addr, file=file)
            continue
        route, iomem_region = _route_and_iomem(mapped.data)
        line = "0x%x: %s" % (addr, route)
        if iomem_region is not None:
            line += "  iomem: %s" % iomem_region.describe(addr)
        print(line, file=file)


def _cached_address_matches(io_address_map, addr):
    """Return cached (home, region) pairs containing an address."""
    matches = []
    for home in io_address_map.homes:
        for region in home.regions:
            if region.start <= addr and addr <= region.end:
                matches.append((home, region))
    return matches


def _describe_cached_resource(resource, addr):
    """Describe a cached /proc/iomem resource in IOmem_region style."""
    assert resource.start <= addr and addr <= resource.end
    s = resource.name
    if addr > resource.start:
        s += "[0x%x]+0x%x" % (resource.start, addr - resource.start)
    return s


def print_cached_address_lookups(io_address_map, addresses, file=None):
    """Look up physical addresses in a cached non-hashed I/O map."""
    if file is None:
        file = sys.stdout
    for addr in addresses:
        matches = _cached_address_matches(io_address_map, addr)
        if not matches:
            print("0x%x: not found in cached I/O address map" % addr,
                  file=file)
            continue

        homes = {}
        resources = {}
        statuses = set()
        for home, region in matches:
            home_key = (home.mseq, home.node_id, home.type_s)
            homes[home_key] = "CMN#%u %s@0x%x" % (
                home.mseq, home.type_s, home.node_id)
            statuses.add(region.status)
            for resource in region.resources:
                if resource.start <= addr and addr <= resource.end:
                    key = (resource.start, resource.end, resource.name)
                    resources[key] = _describe_cached_resource(resource, addr)

        line = "0x%x: %s" % (
            addr, ", ".join([homes[k] for k in sorted(homes.keys())]))
        if statuses != set(["ok"]):
            line += " [%s]" % ", ".join(sorted(statuses))
        if resources:
            line += "  iomem: %s" % ", ".join(
                [resources[k] for k in sorted(resources.keys())])
        print(line, file=file)


def _io_node_sort_key(endpoint):
    nodeid = endpoint.target.nodeid
    return (endpoint.cmn.cmn_seq,
            -1 if nodeid is None else nodeid,
            endpoint.target.target_type)


def address_ranges_by_io_node(amap, nonhash_only=False):
    """Yield each I/O home node and its SAM ranges with named subranges."""
    groups = {}
    endpoints = {}
    for mapped in amap:
        route, iomem_region = _route_and_iomem(mapped.data)
        if isinstance(mapped.data, AnnotatedRoute):
            sam_start = mapped.data.sam_start
            sam_end = mapped.data.sam_end
        else:
            sam_start = mapped.start
            sam_end = mapped.end
        for endpoint in route.endpoints:
            if endpoint.target.target_type not in _IO_TARGET_TYPES:
                continue
            if nonhash_only and endpoint.key() not in (
                    route.nonhash_endpoint_keys):
                continue
            key = endpoint.key()
            endpoints[key] = endpoint
            node_ranges = groups.setdefault(key, {})
            sam_key = (sam_start, sam_end)
            if sam_key not in node_ranges:
                node_ranges[sam_key] = [sam_start, sam_end,
                                        route.status(), []]
            if iomem_region is not None and iomem_region.name:
                node_ranges[sam_key][3].append(
                    (mapped.start, mapped.end, iomem_region))
    ordered = sorted(endpoints.values(), key=_io_node_sort_key)
    for endpoint in ordered:
        ranges = list(groups[endpoint.key()].values())
        ranges.sort(key=lambda r: (r[0], r[1]))
        yield (endpoint, ranges)


def io_address_map_from_address_map(amap, discovery_time=None):
    """Build the persistent non-hashed I/O capture from a routed map."""
    if discovery_time is None:
        discovery_time = time.time()
    homes = []
    for endpoint, ranges in address_ranges_by_io_node(
            amap, nonhash_only=True):
        if endpoint.target.nodeid is None:
            raise ValueError("I/O home target has no node id: %s" % endpoint)
        captured_ranges = []
        for start, end, status, resources in ranges:
            captured_resources = []
            for resource_start, resource_end, iomem_region in resources:
                captured_resources.append(cmn_base.IOAddressResource(
                    resource_start, resource_end, iomem_region.name))
            captured_ranges.append(cmn_base.IOAddressRegion(
                start, end, status=status, resources=captured_resources))
        homes.append(cmn_base.IOAddressHome(
            endpoint.cmn.cmn_seq, endpoint.target.nodeid,
            endpoint.target.target_type, regions=captured_ranges))
    return cmn_base.IOAddressMap(discovery_time=discovery_time, homes=homes)


def check_io_address_map_topology(system, io_address_map):
    """Check that captured I/O homes resolve to ports in the system JSON."""
    for home in io_address_map.homes:
        if home.mseq < 0 or home.mseq >= len(system.CMNs):
            raise ValueError("I/O home refers to missing CMN#%u" % home.mseq)
        cmn = system.CMNs[home.mseq]
        if cmn.port_at_id(home.node_id) is None:
            raise ValueError(
                "I/O home %s@0x%x does not resolve to a port in CMN#%u" %
                (home.type_s, home.node_id, home.mseq))


def address_ranges_by_node(amap):
    """Yield every routed target, including gateways, and its effective ranges."""
    groups = {}
    endpoints = {}
    for mapped in amap:
        route, resource = _route_and_iomem(mapped.data)
        if isinstance(mapped.data, AnnotatedRoute):
            start, end = mapped.data.sam_start, mapped.data.sam_end
        else:
            start, end = mapped.start, mapped.end
        destinations = dict([(e.key(), e) for e in
                             route.endpoints + route.gateways])
        for sn_route in route.sn_routes:
            destinations.update([(e.key(), e) for e in sn_route.targets])
        for endpoint in destinations.values():
            key = endpoint.key()
            endpoints[key] = endpoint
            ranges = groups.setdefault(key, {})
            rkey = (start, end)
            if rkey not in ranges:
                ranges[rkey] = [start, end, route, []]
            if resource is not None and resource.name:
                ranges[rkey][3].append((mapped.start, mapped.end, resource))
    for endpoint in sorted(endpoints.values(), key=_io_node_sort_key):
        yield endpoint, sorted(groups[endpoint.key()].values(),
                               key=lambda r: (r[0], r[1]))


def print_address_map_by_node(amap, file=None, selector=None):
    """Explain direct and grouped routing to each selected destination."""
    if file is None:
        file = sys.stdout
    found = False
    for endpoint, ranges in address_ranges_by_node(amap):
        if selector is not None and not selector.match_device_id(
                endpoint.cmn, endpoint.target.nodeid):
            continue
        found = True
        print("%s:" % endpoint, file=file)
        for start, end, route, devices in ranges:
            line = "  SAM 0x%016x-0x%016x" % (start, end)
            if route.status() == "inconsistent":
                line += " [INCONSISTENT]"
            print(line, file=file)
            for cmn, group in route.target_groups:
                if cmn.cmn_seq != endpoint.cmn.cmn_seq:
                    continue
                if endpoint.target.key() not in [t.key() for t in group.targets]:
                    continue
                print("    RN-SAM %s" % group.description(), file=file)
                if group.hashed:
                    peers = sorted(set([str(t) for t in group.targets
                                        if t.key() != endpoint.target.key()]))
                    print("    peers in this group: %s" %
                          (", ".join(peers) if peers else "none"), file=file)
                elif len(group.targets) > 1:
                    print("    overlapping direct targets; not a hash set",
                          file=file)
            for sn_route in route.sn_routes:
                if endpoint.key() == sn_route.home.key():
                    print("    onward on HN forwarding: %s -> %s" %
                          (sn_route.group.description(),
                           ", ".join([str(t) for t in sn_route.targets])), file=file)
                elif endpoint.key() in [t.key() for t in sn_route.targets]:
                    print("    via %s, when selected by RN-SAM and forwarding" %
                          sn_route.home, file=file)
                    print("    HN-SAM %s" % sn_route.group.description(), file=file)
                    peers = [str(t) for t in sn_route.targets
                             if t.key() != endpoint.key()]
                    if sn_route.group.hashed:
                        print("    SN peers in this group: %s" %
                              (", ".join(peers) if peers else "none"), file=file)
            for dev_start, dev_end, iomem_region in devices:
                print("    0x%016x-0x%016x: %s" %
                      (dev_start, dev_end,
                       iomem_region.describe(dev_start)), file=file)
    if selector is not None and not found:
        print("No matching target in the scanned address map.", file=file)



def _merged_ranges(ranges):
    """Combine overlapping or adjacent inclusive address ranges."""
    result = []
    for start, end in sorted(set(ranges)):
        if result and start <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def _format_target_list(targets):
    """Count consecutive nodes of one type while retaining target-table order."""
    parts = []
    for (target_type, gateway, has_id), group in groupby(
            targets, key=lambda t: (t.target_type, t.gateway,
                                    t.nodeid is not None and t.cpag is None)):
        group = list(group)
        if has_id:
            parts.append("%u x %s at %s%s" % (
                len(group), target_type, ", ".join(["0x%03x" % t.nodeid for t in group]),
                " (gateway)" if gateway else ""))
        else:
            parts.extend([str(t) for t in group])
    return "; ".join(parts) or "none decoded"


def _rn_sam_source(node):
    """Label the traffic source associated with an RN-SAM using cached topology."""
    device = node.device_object
    source_type = "unknown source"
    if device is not None:
        port = device.port
        # A port may contain several CAL devices or both gateway agents.
        # Only explicit CHI nodes sharing this SAM's device slot describe it.
        types = set([n.type_str() for n in port.nodes(discover=False)
                     if n.node_id() == device.node_id() and n.has_properties(CMN_PROP_CHI)])
        if len(types) == 1:
            source_type = types.pop()
        elif cmn_port_device_type_has_properties(port.connected_type, CMN_PROP_RNF):
            # External RN-Fs have no explicit node; omit the CHI revision suffix.
            source_type = "RN-F"
        elif port.connected_type_s:
            source_type = port.connected_type_s
    return (source_type, node.node_id(), "")


def _format_group_sources(sources):
    """Use the node-list format, retaining each distinct forwarding path."""
    by_path = {}
    for node_type, nodeid, path in sources:
        by_path.setdefault(path, []).append(SAMTarget(node_type, nodeid=nodeid))
    return "; ".join([
        _format_target_list(sorted(by_path[path], key=lambda t: t.key())) + path
        for path in sorted(by_path)])


class HashedGroup(object):
    """A decoded target group and the source SAM entries that select it."""

    def __init__(self, cmn, stage, region=None, cpag=None):
        self.cmn = cmn
        self.stage = stage
        self.region = region
        self.cpag = cpag
        self.targets = (region.target_order if region is not None else tuple([
            SAMTarget("CCG-RA", nodeid=nid, gateway=True) for nid in cpag.nodeids or ()]))
        self.sources = {}       # (node type, node ID, forwarding path) -> ranges

    def key(self):
        # Unlike consensus homing, group identity must preserve gateway IDs.
        selection = self.region.group_key() if self.region is not None else self.cpag.key()
        return (self.cmn.cmn_seq, self.stage, selection,
                tuple([t.key() for t in self.targets]))

    def description(self):
        return self.region.description() if self.region is not None else self.cpag.description()

    def label(self):
        if self.cpag is not None:
            return "%s CML Port Aggregation Group (CPAG) #%u" % (
                _mesh_name(self.cmn), self.cpag.index)
        table = self.region.table_name
        if table == "HMR":
            table = ("SCG" if self.cmn.product_config.is_before_gen(CMN_GEN_700)
                     else "HTG")
        name = {"SCG": "System Cache Group (SCG)",
                "HTG": "Hashed Target Group (HTG)",
                "default": "default SN target group"}.get(table, "hashed target group")
        return "%s %s %s%s" % (
            _mesh_name(self.cmn), self.stage, name,
            " #%s" % self.region.index if self.region.index is not None else "")


def hashed_groups(sams):
    """Collect every RN-SAM group without replacing source tables by consensus.

    Sources retain effective ranges after direct overrides. Groups with no
    effective range are kept, so completely shadowed programming is visible.
    """
    groups = {}
    reached = set()
    unresolved = set()
    home_sources = {}
    meshes = dict([(m.cmn.cmn_seq, m.cmn) for m in sams.meshes])
    for mesh in sams.meshes:
        for snapshot in mesh.snapshots:
            if snapshot.cpa_error:
                unresolved.add(mesh.cmn.cmn_seq)
            source = _rn_sam_source(snapshot.node)
            effective = {}
            cpags = dict(snapshot.cpags)
            for region in snapshot.ranges:
                for target in region.targets:
                    if target.cpag is not None:
                        cpags.setdefault(target.cpag, CPAG(target.cpag))
            for cpag in cpags.values():
                group = HashedGroup(mesh.cmn, "CPAG", cpag=cpag)
                group = groups.setdefault(group.key(), group)
                group.sources.setdefault(source, [])
            for start, end, regions in snapshot.effective_ranges():
                for region in regions:
                    effective.setdefault(id(region), []).append((start, end))
                    for target in region.targets:
                        if target.nodeid is not None:
                            key = (mesh.cmn.cmn_seq, target.nodeid)
                            reached.add(key)
                            home_sources.setdefault(key, {}).setdefault(source, []).append((start, end))
                        if target.cpag is not None:
                            cpag = snapshot.cpags.get(target.cpag, CPAG(target.cpag))
                            group = HashedGroup(mesh.cmn, "CPAG", cpag=cpag)
                            group = groups.setdefault(group.key(), group)
                            group.sources.pop(source, None)
                            via = source[:2] + (" via %s#%s" % (region.table_name or "SAM", region.index),)
                            group.sources.setdefault(via, []).append((start, end))
                            if cpag.valid is False:
                                continue
                            if cpag.nodeids is None:
                                unresolved.add(mesh.cmn.cmn_seq)
                            else:
                                for nid in cpag.nodeids:
                                    reached.add((mesh.cmn.cmn_seq, nid))
            for region in snapshot.ranges:
                if not region.hashed:
                    continue
                group = HashedGroup(mesh.cmn, "RN-SAM", region)
                group = groups.setdefault(group.key(), group)
                group.sources.setdefault(source, []).extend(effective.get(id(region), []))
    # Keep every HN group, including ones that have no incoming RN range.
    # Intersect with each source separately, not the consensus address map.
    for home_key, snapshot in sorted(sams.hn_sams.items()):
        cmn = meshes[home_key[0]]
        node_type, nodeid = snapshot.node.type_str(), snapshot.node.node_id()
        label = str(SAMTarget(node_type, nodeid=nodeid))
        inactive_source = (node_type, nodeid, " (conditional forwarding)")
        for region in snapshot.ranges:
            if region.hashed:
                group = HashedGroup(cmn, "HN-SAM", region)
                group = groups.setdefault(group.key(), group)
                group.sources.setdefault(inactive_source, [])
        for start, end, regions in snapshot.effective_ranges():
            for rn_source, incoming in sorted(home_sources.get(home_key, {}).items()):
                intersections = [(max(start, a), min(end, b))
                                 for a, b in _merged_ranges(incoming)
                                 if a <= end and b >= start]
                if not intersections:
                    continue
                for region in regions:
                    for target in region.targets:
                        if target.nodeid is not None:
                            reached.add((cmn.cmn_seq, target.nodeid))
                    if region.hashed:
                        group = HashedGroup(cmn, "HN-SAM", region)
                        group = groups[group.key()]
                        group.sources.pop(inactive_source, None)
                        source = rn_source[:2] + (" via %s (conditional forwarding)" % label,)
                        group.sources.setdefault(source, []).extend(intersections)
    return sorted(groups.values(), key=lambda g: g.key()), reached, unresolved


def print_hashed_groups(sams, file=None):
    """Report hashed groups, source ranges and unmatched home/gateway nodes."""
    if file is None:
        file = sys.stdout
    groups, reached, unresolved = hashed_groups(sams)
    members = set()
    for group in groups:
        print("%s:" % group.label(), file=file)
        print("  %s" % group.description(), file=file)
        print("  targets in table order: %s" % _format_target_list(group.targets), file=file)
        for target in group.targets:
            if target.nodeid is not None:
                members.add((group.cmn.cmn_seq, target.nodeid))
        # Invert the per-source ranges so shared programming occupies one line.
        sources_by_range = {}
        inactive = []
        for source in sorted(group.sources):
            ranges = _merged_ranges(group.sources[source])
            for bounds in ranges:
                sources_by_range.setdefault(bounds, []).append(source)
            if not ranges:
                inactive.append(source)
        for start, end in sorted(sources_by_range):
            print("  0x%016x-0x%016x from %s" %
                  (start, end, _format_group_sources(sources_by_range[(start, end)])), file=file)
        if inactive:
            print("  no effective range from %s (no decoded incoming range or a higher-priority override)" %
                  _format_group_sources(inactive), file=file)
    if not groups:
        print("No decoded hashed groups.", file=file)
    print("Home nodes and request gateways outside hashed groups or without a decoded route:", file=file)
    found = False
    for mesh in sorted(sams.meshes, key=lambda m: m.cmn.cmn_seq):
        for port in mesh.cmn.ports():
            if not (port.has_properties(CMN_PROP_HNF) or port.has_properties(CMN_PROP_CCG)):
                continue
            # Inspect stored nodes only; group reporting must not trigger reads.
            for node in port.nodes(discover=False):
                if node.type() not in [CMN_NODE_HNF, CMN_NODE_HNS,
                                       CMN_NODE_CXRA, CMN_NODE_CCG_RA]:
                    continue
                key = (mesh.cmn.cmn_seq, node.node_id())
                if key in members and key in reached:
                    continue
                found = True
                if key in reached:
                    status = "outside hashed groups; a direct route exists"
                elif any([s.cpa_error for s in mesh.snapshots]):
                    status = "reachability unknown: CPA routing incomplete"
                elif mesh.cmn.cmn_seq in unresolved and port.has_properties(CMN_PROP_CCG):
                    status = "reachability unknown: CPAG members not decoded"
                else:
                    status = "no decoded route from the scanned SAMs"
                    if key in members:
                        status += "; member of a configured group"
                if node.is_disabled():
                    status += "; disabled"
                print("  %s %s@0x%x: %s" %
                      (_mesh_name(mesh.cmn), node.type_str(), node.node_id(), status), file=file)
    if not found:
        print("  none in the discovered topology", file=file)
    print("Coverage: decoded RN-SAM address regions%s; absence is not proof of hardware unreachability." %
          (" and conditional HN-SAM routes" if sams.hn_sams else ""), file=file)


def write_address_map_csv(amap, file=None):
    """Write one CSV row per final, optionally iomem-annotated range."""
    if file is None:
        file = sys.stdout
    writer = csv.writer(file, lineterminator="\n")
    writer.writerow([
        "start", "end", "size", "homes", "status",
        "iomem_name", "iomem_start", "iomem_offset"])
    for r in amap:
        route, iomem_region = _route_and_iomem(r.data)
        if iomem_region is None:
            iomem_fields = ["", "", ""]
        else:
            iomem_fields = [
                iomem_region.name,
                "0x%x" % iomem_region.addr,
                "0x%x" % (r.start - iomem_region.addr),
            ]
        writer.writerow([
            "0x%x" % r.start,
            "0x%x" % r.end,
            "0x%x" % (r.end + 1 - r.start),
            _format_home_targets(route.endpoints),
            route.status(),
        ] + iomem_fields)


def _address(s):
    try:
        return int(s, 0)
    except ValueError:
        import argparse
        raise argparse.ArgumentTypeError("invalid physical address: %s" % s)


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(
        description="build a system physical address map from CMN SAMs")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--csv", action="store_true",
                        help="write the address map as CSV")
    output.add_argument("--by-node", action="store_true",
                        help="explain all SAM ranges and target groups by destination node")
    output.add_argument("--hashed-groups", action="store_true",
                        help="list hashed target groups, source address ranges and unmatched homes/gateways")
    output.add_argument("--update", action="store_true",
                        help="update the I/O address map in the JSON system description")
    parser.add_argument("--include-sn", action="store_true",
                        help="also read HN-F/HN-S SAMs to explain downstream SN targets; "
                             "requires --by-node, --node or --hashed-groups")
    parser.add_argument("--node", type=cmn_select.CMNSelect, action="append",
                        help="common CMN selection expressions, e.g. m0:hn-f@0x20, "
                             "hn-f#0 or sn-f(0,_); implies --by-node")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--cached", action="store_true",
                        help="require lookup from the cached JSON I/O address map")
    source.add_argument("--live", action="store_true",
                        help="ignore cached address information and probe SAMs")
    parser.add_argument("--json", type=str,
                        default=cmn_json.cmn_config_filename(),
                        help="cached JSON system description to read or update (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase verbosity")
    parser.add_argument("address", type=_address, nargs="*",
                        help="physical address, in decimal or 0x-prefixed hex")
    opts = parser.parse_args(argv)
    if opts.node:
        if opts.csv or opts.update or opts.hashed_groups:
            parser.error("--node cannot be combined with --csv, --update or --hashed-groups")
        opts.by_node = True
    if opts.include_sn and not (opts.by_node or opts.hashed_groups):
        parser.error("--include-sn requires --by-node, --node or --hashed-groups")
    if opts.update and opts.cmn_instance is not None:
        parser.error("--update requires a whole-system scan; "
                     "do not use --cmn-instance")

    verbose = opts.verbose
    if opts.address and (opts.csv or opts.by_node or opts.update or opts.hashed_groups):
        parser.error("physical addresses cannot be combined with "
                     "--csv, --by-node, --hashed-groups or --update")
    if opts.cached and not opts.address:
        parser.error("--cached requires at least one physical address")
    if opts.address and not opts.live:
        system = cmn_json.load_system_for_cli(
            opts.json, missing_ok=True)
        if system is not None and system.io_address_map is not None:
            print_cached_address_lookups(system.io_address_map, opts.address)
            return 0
        if opts.cached:
            print("%s: no cached I/O address map; run "
                  "cmn_address_map.py --update" % opts.json,
                  file=sys.stderr)
            return 1

    if opts.csv:
        # CMN discovery diagnostics normally use stdout. Keep structured
        # output clean; scan progress below is still written to stderr.
        opts.verbose = 0
    cmns = cmn_from_opts(opts)
    opts.verbose = verbose
    if opts.hashed_groups:
        sams = scan_system_sams(cmns, verbose=verbose, include_sn=opts.include_sn,
                                all_sources=True, include_cpa=True)
        print_hashed_groups(sams)
        return 0
    amap = scan_system(cmns, verbose=verbose, include_sn=opts.include_sn)

    def message(s):
        print(s, file=sys.stderr)

    iomap = iomem_map_for_system(cmns, opts.cmn_iomem, message)
    if iomap is not None:
        if verbose:
            message("Annotating with %u /proc/iomem region(s)" %
                    len(iomap.regions))
        amap = annotate_address_map(amap, iomap)
    if opts.address:
        print_address_lookups(amap, opts.address)
    elif opts.csv:
        write_address_map_csv(amap)
    elif opts.by_node:
        print_address_map_by_node(
            amap, selector=cmn_select.cmn_select_merge(opts.node))
    elif opts.update:
        system = cmn_json.load_system_for_cli(opts.json)
        captured = io_address_map_from_address_map(amap)
        check_io_address_map_topology(system, captured)
        system.io_address_map = captured
        cmn_json.json_dump_file_from_system(system, opts.json)
        print("Updated I/O address map in %s" % opts.json,
              file=sys.stderr)
    else:
        print_address_map(amap, verbose=verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
