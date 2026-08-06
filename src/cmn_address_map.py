#!/usr/bin/python

"""
Build a system-wide physical address map from CMN RN-SAMs.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import csv
import sys
import time

from address_map import AddressMap
import cmn_base
from cmn_devmem import cmn_from_opts
import cmn_devmem_find
from cmn_enum import CMN_NODE_RNSAM
import cmn_json
from cmn_sam import rn_sam_hashed_regions, rn_sam_nonhash_regions
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
    """A normalized inclusive range from one RN-SAM table."""

    def __init__(self, base, end, targets, priority=0, index=None,
                 table_name=None):
        assert base <= end
        self.base = base
        self.end = end
        self.targets = tuple(sorted(targets, key=lambda t: t.key()))
        self.priority = priority
        self.index = index
        self.table_name = table_name

    def contains(self, addr):
        return self.base <= addr and addr <= self.end

    def key(self):
        return (self.priority, self.base, self.end,
                tuple(sorted(set([t.homing_key() for t in self.targets]))))


def _targets_from_region(reg):
    target_type = reg.target_type_str
    targets = []
    if reg.hashed:
        if reg.nodeids is not None:
            for nodeid in reg.nodeids:
                targets.append(SAMTarget(target_type, nodeid=nodeid))
        for cpag in reg.cpag:
            if cpag is not None:
                targets.append(SAMTarget("CPAG", cpag=cpag, gateway=True))
    else:
        targets.append(SAMTarget(
            target_type, nodeid=reg.nodeid,
            gateway=(target_type in _GATEWAY_TARGET_TYPES)))
    return targets


def _normalize_region(reg, priority, table_name):
    return SAMRange(reg.base, reg.range_end(), _targets_from_region(reg),
                    priority=priority, index=reg.index,
                    table_name=table_name)


class SAMSnapshot(object):
    """The decoded address-routing table from one RN-SAM node."""

    def __init__(self, node, ranges):
        self.node = node
        self.ranges = list(ranges)

    @classmethod
    def from_node(cls, node):
        ranges = []
        for reg in rn_sam_nonhash_regions(node):
            ranges.append(_normalize_region(reg, 0, "NHMR"))
        for reg in rn_sam_hashed_regions(node):
            ranges.append(_normalize_region(reg, 1, "HMR"))
        return cls(node, ranges)

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
        matches = [r for r in self.ranges if r.contains(addr)]
        if not matches:
            return None
        priority = min([r.priority for r in matches])
        targets = {}
        for r in matches:
            if r.priority == priority:
                for target in r.targets:
                    targets[target.key()] = target
        return (tuple([targets[k] for k in sorted(targets.keys())]),
                priority)


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
        warn("  table layouts differ, but effective routing agrees "
             "for all mapped addresses")
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


def scan_mesh(cmn, warn, verbose=0):
    """Read and compare every RN-SAM in one mesh."""
    if verbose:
        warn("%s: discovering nodes and scanning RN-SAMs" % _mesh_name(cmn))
    sam_nodes = [n for n in cmn.nodes() if n.type() == CMN_NODE_RNSAM]
    snapshots = []
    for (i, node) in enumerate(sam_nodes):
        if verbose >= 2:
            warn("%s: reading RN-SAM %u/%u: %s" %
                 (_mesh_name(cmn), i + 1, len(sam_nodes), node))
        snapshot = SAMSnapshot.from_node(node)
        snapshots.append(snapshot)
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
                 nonhash_endpoints=None):
        self.endpoints = tuple(sorted(endpoints, key=lambda t: t.key()))
        # Gateways are retained for verbose diagnostics, but are deliberately
        # excluded from map identity and normal output: they route requests,
        # they do not home addresses.
        self.gateways = tuple(sorted(gateways, key=lambda t: t.key()))
        self.mesh_routes = tuple(mesh_routes)
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
                tuple([t.key() for t in self.nonhash_endpoints]))

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
        return (self.route.key(), iomem_key)


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
        any_route = False
        for mesh in selected:
            lookup = mesh.selected.lookup_with_priority(start)
            targets = None if lookup is None else lookup[0]
            priority = None if lookup is None else lookup[1]
            mesh_routes.append((mesh.cmn, targets))
            if targets is None:
                continue
            any_route = True
            for target in targets:
                routed = RoutedTarget(mesh.cmn, target)
                if target.gateway:
                    gateways[routed.key()] = routed
                else:
                    endpoints[routed.key()] = routed
                    if priority == 0:
                        nonhash_endpoints[routed.key()] = routed
        if not any_route:
            route = None
        else:
            route = SystemRoute(
                list(endpoints.values()), list(gateways.values()), mesh_routes,
                nonhash_endpoints=list(nonhash_endpoints.values()))

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




def scan_system(cmns, verbose=0, error_file=None):
    """Scan all meshes and return a system-wide AddressMap."""
    if error_file is None:
        error_file = sys.stderr

    def message(s):
        print(s, file=error_file)

    meshes = []
    for cmn in cmns:
        meshes.append(scan_mesh(cmn, warn=message, verbose=verbose))
    if verbose:
        message("Combining SAM maps from %u mesh(es)" % len(meshes))
    amap = build_system_address_map(meshes)
    report_homing_inconsistencies(amap, message)
    if verbose:
        message("System address map contains %u range(s)" % len(amap))
    return amap


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


def print_address_map_by_node(amap, file=None):
    """Print I/O address ranges grouped by their ultimate CMN home node."""
    if file is None:
        file = sys.stdout
    for endpoint, ranges in address_ranges_by_io_node(amap):
        print("%s:" % endpoint, file=file)
        for start, end, status, devices in ranges:
            line = "  SAM 0x%016x-0x%016x" % (start, end)
            if status == "inconsistent":
                line += " [INCONSISTENT]"
            print(line, file=file)
            for dev_start, dev_end, iomem_region in devices:
                print("    0x%016x-0x%016x: %s" %
                      (dev_start, dev_end,
                       iomem_region.describe(dev_start)), file=file)


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
                        help="group I/O regions by destination CMN node")
    output.add_argument("--update", action="store_true",
                        help="update the I/O address map in the JSON system description")
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
    if opts.update and opts.cmn_instance is not None:
        parser.error("--update requires a whole-system scan; "
                     "do not use --cmn-instance")

    verbose = opts.verbose
    if opts.address and (opts.csv or opts.by_node or opts.update):
        parser.error("physical addresses cannot be combined with "
                     "--csv, --by-node or --update")
    if opts.cached and not opts.address:
        parser.error("--cached requires at least one physical address")
    if opts.address and not opts.live:
        system = cmn_json.system_from_json_file(
            opts.json, exit_if_not_found=False)
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
    amap = scan_system(cmns, verbose=verbose)

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
        print_address_map_by_node(amap)
    elif opts.update:
        system = cmn_json.system_from_json_file(opts.json)
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
