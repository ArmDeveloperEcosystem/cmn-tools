#!/usr/bin/python

"""Find RN-F DN domains by counting DVMOp requests at each DN port.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Run a workload that issues DVMOps throughout each measurement. The REQ
download watchpoint at a DN matches the RN-F SrcID and DVMOp opcode. A
unique, repeatable DN is recorded by its logical ID. Watchpoints are counted
through the Linux arm_cmn PMU driver and perf; this tool does not open
/dev/mem or generate a workload.

Arm CMN-700 TRM (102308), section 3.9.4, describes DN domains and the RN-F
request path: https://documentation-service.arm.com/static/64c001a8df6cd61d528c8a55
"""

from __future__ import print_function

import argparse
import copy
import json
import math
import os
import stat
import sys
import tempfile

import cmn_base
import cmn_config
import cmn_enum
import cmn_json
import cmn_perfstat
import cmnwatch


def positive_number(value):
    value = float(value)
    if math.isnan(value) or math.isinf(value) or value <= 0:
        raise ValueError("expected a positive finite number")
    return value


def parse_node_id(value):
    node_id = int(value, 0)
    return cmn_config.check_integer(node_id, "RN-F node ID",
                                    maximum=cmn_base.NODE_INFO_FIELD_MAX)


def dn_nodes(cmn):
    """Return enabled DNs, requiring an unambiguous logical ID and port."""
    nodes = sorted([n for n in cmn.nodes(cmn_enum.CMN_PROP_DN)
                    if not n.is_disabled()], key=lambda n: n.node_id())
    ids = set()
    ports = set()
    for node in nodes:
        lid = node.logical_id()
        if lid is None or lid in ids:
            raise ValueError("CMN#%u: missing or duplicate DN logical ID" % cmn.cmn_seq)
        if node.port in ports:
            raise ValueError("CMN#%u: multiple DNs share a watchpoint port" % cmn.cmn_seq)
        ids.add(lid)
        ports.add(node.port)
    return nodes


class DNProbePlan(object):
    """Perf watchpoints for one RN-F source, across all candidate DNs."""
    def __init__(self, source, dns):
        self.source = source
        self.dns = dns
        cmn = source.CMN()
        wp = cmnwatch.match_kwd(chn='req', up=False,
                                cmn_version=cmn.product_config,
                                opcode='DVMOp', srcid=source.node_id())
        if len(wp.grps()) != 1:
            raise ValueError('DN filter needs more than one watchpoint match group')
        by_xp = {}
        for dn in dns:
            event = wp.perf_event_string(cmn_instance=cmn.cmn_seq,
                                         nodeid=dn.port.XP().node_id(),
                                         dev=dn.port.port_number)
            by_xp.setdefault(dn.port.XP().node_id(), []).append((dn, event))
        # One watchpoint per XP in each batch avoids competing for the same
        # DTM. Keep batches small enough for the mesh's DTC counters as well.
        self.batches = []
        while any(by_xp.values()):
            batch = []
            for xp_id in sorted(by_xp):
                if by_xp[xp_id] and len(batch) < 4:
                    batch.append(by_xp[xp_id].pop(0))
            self.batches.append(batch)


def classify_counts(rounds, min_count, ratio):
    """Accept one DN only if it dominates every complete sampling round."""
    if not rounds:
        return None
    winner = None
    for counts in rounds:
        ranked = sorted(counts, key=lambda dn: counts[dn], reverse=True)
        if not ranked or counts[ranked[0]] < min_count:
            return None
        if len(ranked) > 1 and counts[ranked[0]] < ratio * counts[ranked[1]]:
            return None
        if winner is not None and winner is not ranked[0]:
            return None
        winner = ranked[0]
    return winner


def run_probe(plan, perf, duration, repeats, min_count, ratio):
    """Count DVMOps at each DN port using Linux PMU watchpoints."""
    rounds = []
    for unused in range(repeats):
        counts = dict((dn, 0) for dn in plan.dns)
        for batch in plan.batches:
            values = perf.stat([event for dn, event in batch],
                               time=duration, chunk_size=None)
            if len(values) != len(batch) or any(value is None for value in values):
                raise ValueError('perf did not count every DN watchpoint')
            for (dn, event), value in zip(batch, values):
                counts[dn] += value
        rounds.append(counts)
    winner = classify_counts(rounds, min_count, ratio)
    return {'cmn': plan.source.CMN(), 'source_id': plan.source.node_id(),
            'dn': winner, 'rounds': rounds}


def cached_mesh_map(system, cmns):
    """Match live meshes to cached meshes by physical base, not list order."""
    meshes = {}
    for live in cmns:
        matches = [c for c in system.CMNs
                   if live.periphbase is not None and c.periphbase == live.periphbase]
        if len(matches) != 1 or matches[0] in meshes.values():
            raise ValueError("cannot uniquely match live CMN#%u to cached topology" %
                             live.cmn_seq)
        cached = matches[0]
        if cached.product_config.product_id != live.product_config.product_id:
            raise ValueError("CMN#%u product differs from cached topology" % live.cmn_seq)
        meshes[live] = cached
    return meshes


def merge_cached_domains(description, cmns, assignments):
    """Add accepted device-slot DN domains, retaining unrelated JSON fields."""
    system = cmn_json.system_from_json(description)
    meshes = cached_mesh_map(system, cmns)
    elements = [e for e in description['elements']
                if e.get('type') == 'interconnect' and e.get('product') == 'CMN']
    updated = copy.deepcopy(description)
    updated_elements = [e for e in updated['elements']
                        if e.get('type') == 'interconnect' and e.get('product') == 'CMN']
    if len(elements) != len(system.CMNs):
        raise ValueError("cached mesh count differs from topology")
    seen = {}
    for live, source_id, domain in assignments:
        cmn_config.check_integer(source_id, "requester node ID",
                                 maximum=cmn_base.NODE_INFO_FIELD_MAX)
        cmn_config.check_integer(domain, "DN domain",
                                 maximum=cmn_base.NODE_INFO_FIELD_MAX)
        cached = meshes[live]
        key = (cached.cmn_seq, source_id)
        if key in seen and seen[key] != domain:
            raise ValueError("conflicting DN domains for CMN#%u ID 0x%x" % key)
        seen[key] = domain
        device = cached.device_at_id(source_id, create=True)
        if device is None:
            raise ValueError("cached topology has no requester at CMN#%u ID 0x%x" % key)
        xp = device.XP()
        port = device.port
        jc = updated_elements[system.CMNs.index(cached)]['config']
        jxp = next((row for row in jc['xps'] if (row['X'], row['Y']) == xp.XY()), None)
        if jxp is None:
            raise ValueError("cached topology has no XP for ID 0x%x" % source_id)
        jp = next((row for row in jxp['ports'] if row['port'] == port.port_number), None)
        if jp is None:
            raise ValueError("cached topology has no port for ID 0x%x" % source_id)
        slots = jp.setdefault('pdevices', [])
        jd = next((row for row in slots if row['device_number'] == device.device_number), None)
        if jd is None:
            jd = {'id': source_id, 'device_number': device.device_number}
            slots.append(jd)
        jd['dn_domain'] = domain
    cmn_json.system_from_json(updated)
    return updated


def update_cached_domains(path, cmns, assignments):
    """Re-read and atomically update the topology after measurements."""
    with open(path) as f:
        metadata = os.fstat(f.fileno())
        description = json.load(f)
    updated = merge_cached_domains(description, cmns, assignments)
    if updated != description:
        write_json(path, updated, metadata)
        print("Updated DN domains in %s" % path)


def write_json(path, value, metadata):
    """Replace the cache atomically while preserving its owner and mode."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp = tempfile.mkstemp(prefix='.cmn-dn-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            fd = None
            json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
            f.write('\n')
            current = os.fstat(f.fileno())
            if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                os.fchown(f.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(f.fileno(), stat.S_IMODE(metadata.st_mode))
        os.rename(temp, path)
    finally:
        if fd is not None:
            os.close(fd)
        if os.path.exists(temp):
            os.unlink(temp)


def argument_parser():
    parser = argparse.ArgumentParser(
        description=__doc__.split('\n\n')[0],
        epilog='Requires the Linux arm_cmn PMU driver and perf access. '
               'Keep DVMOp traffic active throughout sampling; an unobserved '
               'REQ channel instance leaves the source unresolved.')
    parser.add_argument('--rnf', type=parse_node_id, action='append', metavar='ID',
                        help='probe this RN-F CHI node ID (repeatable; default: all RN-Fs)')
    parser.add_argument('--cmn-instance', type=int,
                        help='probe only this cached CMN instance')
    parser.add_argument('--time', type=positive_number, default=1.0,
                        help='seconds per DN watchpoint batch (default: 1)')
    parser.add_argument('--repeats', type=int, default=2,
                        help='complete sampling rounds per RN-F (default: 2)')
    parser.add_argument('--min-count', type=int, default=1,
                        help='minimum DVMOps at the winning DN in each round (default: 1)')
    parser.add_argument('--ratio', type=positive_number, default=2.0,
                        help='minimum winner/runner-up count ratio (default: 2)')
    parser.add_argument('--json', help='cached topology to read and update (default: standard CMN cache)')
    parser.add_argument('--perf', default='perf',
                        help='perf executable (trusted local configuration; default: perf)')
    parser.add_argument('--no-update', action='store_true', help='report without updating the cache')
    parser.add_argument('--dry-run', action='store_true', help='show probe plan without running perf')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    return parser


def main(argv=None):
    parser = argument_parser()
    opts = parser.parse_args(argv)
    if opts.repeats < 1 or opts.min_count < 1 or opts.ratio <= 1:
        parser.error('repeats/min-count must be positive and ratio must exceed 1')
    try:
        cache_path = cmn_json.cmn_config_default(opts.json)
        system = cmn_json.system_from_json_file(cache_path, missing_ok=True)
        if system is None:
            raise ValueError('%s: cached topology not found; run cmn_discover first' % cache_path)
        cmns = system.CMNs
        if opts.cmn_instance is not None:
            if opts.cmn_instance < 0 or opts.cmn_instance >= len(cmns):
                raise ValueError('CMN instance %d is not present' % opts.cmn_instance)
            cmns = [cmns[opts.cmn_instance]]
        plans = []
        for cmn in cmns:
            dns = dn_nodes(cmn)
            if not dns:
                continue
            sources = sorted([d for d in cmn.devices(cmn_enum.CMN_PROP_RNF)
                              if opts.rnf is None or d.node_id() in opts.rnf],
                             key=lambda d: d.node_id())
            for source in sources:
                plans.append(DNProbePlan(source, dns))
        if not plans:
            raise ValueError('no RN-F and DN candidates found')
        for plan in plans:
            print('CMN#%u RN-F 0x%x: %u DNs, %u watchpoint batches, ~%.1fs' %
                  (plan.source.CMN().cmn_seq, plan.source.node_id(), len(plan.dns),
                   len(plan.batches), opts.repeats * len(plan.batches) * opts.time))
        if opts.dry_run:
            return 0
        print('Run a workload that issues DVMOps throughout the probe.')
        results = []
        perf = cmn_perfstat.Perf(perf_bin=opts.perf, verbose=max(0, opts.verbose - 1))
        for plan in plans:
            result = run_probe(plan, perf, opts.time, opts.repeats,
                               opts.min_count, opts.ratio)
            results.append(result)
            dn = result['dn']
            print('CMN#%u RN-F 0x%x: %s' %
                  (result['cmn'].cmn_seq, result['source_id'],
                   'DN#%u (node 0x%x)' % (dn.logical_id(), dn.node_id())
                   if dn is not None else 'unresolved'))
            if opts.verbose:
                for counts in result['rounds']:
                    print('  ' + ', '.join('DN#%u=%u' % (n.logical_id(), counts[n])
                                       for n in plan.dns))
        assignments = [(r['cmn'], r['source_id'], r['dn'].logical_id())
                       for r in results if r['dn'] is not None]
        if not opts.no_update and assignments:
            update_cached_domains(cache_path, cmns, assignments)
        return 0 if len(assignments) == len(results) else 2
    except KeyboardInterrupt:
        print('DN discovery interrupted.', file=sys.stderr)
        return 130
    except (TypeError, ValueError, IOError, OSError) as error:
        print('cmn_detect_dn: %s' % error, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
