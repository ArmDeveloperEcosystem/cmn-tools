#!/usr/bin/python

"""Infer CCG connections by tagging traffic to each local gateway in turn.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Uses cmn_devmem for both watchpoint programming and local PMU counting. No
kernel perf events, trace packets, FIFO accesses, or traffic generators are
used. Run a workload exercising the links while discovery is in progress.
Accepted links update the cached system description after hardware restoration.
Use --json to select that description, or --no-update for report-only discovery.

Each ProbePlan seeks the remote peer of one CCG port on a source mesh. That
CCG is the traffic destination: tags are set at selected upload ports on the
same mesh, matching the CCG's TgtID. After crossing the link, the request is
uploaded from the remote CCG into its mesh. Observers therefore also use
upload watchpoints, matching TraceTag=1 with tag generation disabled. All
CCG ports on other meshes are observed. Port/VC bindings are scheduled in DTM
batches so shared counters cover every selected port and channel instance.

run_probe() measures a background rate with tagging off, then enables each
batch of taggers and accumulates the excess at each observer port. classify()
requires the same observer to dominate in every repetition. detected_links()
combines these directional results into endpoint pairs, rejecting conflicts.

Arm CMN S3 TRM 107858_0203_05, sections 6.1.1, 6.2.2 and 8.3.14:
https://documentation-service.arm.com/static/67ac4cf66dbc975ccea92cd0
TraceTag propagates to associated transactions, so discovery requires a
repeatable peak above background rather than merely a nonzero observation.
por_dtm_pmu_config.pmevcntall_combined supplies a wide local counter without
consuming DTC event counters. One port/channel instance per DTM is measured
at a time; batches cover shared DTMs and replicated channels.
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
import time

import cmn_base
import cmn_config
import cmn_devmem
import cmn_devmem_find
import cmn_enum
import cmn_json
import cmn_select
import cmnwatch

try:
    monotonic = time.monotonic
except AttributeError:                 # Python 2 / embedded Jython
    monotonic = time.time

COUNTER_MASK = (1 << 64) - 1
CHANNELS = ['req', 'rsp', 'snp', 'dat']


def positive_number(value):
    value = float(value)
    if math.isnan(value) or math.isinf(value) or value <= 0:
        raise ValueError("expected a positive finite number")
    return value


def parse_target_id(value):
    node_id = int(value, 0)
    return cmn_config.check_integer(node_id, "target ID", maximum=cmn_base.NODE_INFO_FIELD_MAX)


def port_key(port):
    """Identify a physical port across meshes, independent of device ID or VC."""
    return (port.CMN().cmn_seq, port.base_id())


def port_description(port):
    return {"mseq": port.CMN().cmn_seq, "id": port.base_id(),
            "xp": port.XP().node_id(), "port": port.port_number}


def port_label(port):
    return "m%u:CCG@0x%x (XP 0x%x P%u)" % (port.CMN().cmn_seq, port.base_id(),
                                               port.XP().node_id(), port.port_number)


def selected_ports(cmn, selector):
    """Select whole ports: a device selects its port, an XP selects all its ports."""
    if selector is None:
        return sorted(cmn.ports(), key=port_key)
    ports = set(dev.port for dev in cmn_select.iter_cmn_devices(cmn, selector))
    for xp in cmn_select.iter_cmn_nodes(cmn, selector, include_devices=False):
        ports.update(xp.ports())
    return sorted(ports, key=port_key)


class BoundWatchpoint(object):
    """Bind a logical match to a port, channel instance and DTM watchpoint slot.

    Both taggers and observers use upload slot 0, on different meshes. Their
    roles determine the match fields and tag enable, independently of direction.
    The signature describes the programmed match, allowing DirectProbe to reuse
    it when a later plan supplies a new binding for the same match.
    """
    def __init__(self, port, wp, vc):
        self.port = port
        self.dtm = port.dtm
        self.slot = 0 if wp.up else 2
        groups = wp.grps()
        if len(groups) != 1:
            raise ValueError("discovery filter requires more than one match group")
        match = wp.wps[groups[0]]
        dev = port.port_number
        # The selector uses XP port numbers; the register uses DTM-local ones.
        if port.CMN().multiple_dtms:
            dev -= 2 * self.dtm.index
        self.physical = cmn_devmem.DTMWatchpoint(
            dtm=self.dtm, up=wp.up, chn=wp.chn, chn_num=vc, dev=dev,
            grp=match.grp, value=match.val, mask=match.mask, pkt_gen=False,
            cc=False, ctrig=False, dbgtrig=False, combine=False, exclusive=False)
        self.signature = (self.slot, self.physical.encode(), match.val, match.mask)


def _compile_upload_watchpoints(ports, channel, fields):
    """Bind an upload filter to every port/channel instance for either role."""
    filters = {}
    bindings = []
    for port in ports:
        cmn = port.CMN()
        # Reuse the logical filter within a mesh, where the field layout agrees.
        if cmn not in filters:
            filters[cmn] = cmnwatch.match_kwd(chn=channel, up=True,
                                             cmn_version=cmn.product_config, **fields)
        wp = filters[cmn]
        for vc in range(cmn.vc_num[wp.chn]):
            bindings.append(BoundWatchpoint(port, wp, vc))
    return bindings


def compile_tag_setters(ports, channel, tgtid):
    """Match source uploads destined for the CCG whose link is being probed.

    run_probe() enables tag generation on these DTMs during tagged samples.
    """
    return _compile_upload_watchpoints(ports, channel, {"tgtid": tgtid})


def compile_tag_monitors(ports, channel):
    """Match existing tags on uploads from remote CCGs into their meshes.

    The source CCG's TgtID is local to its mesh and does not constrain this
    filter. These DTMs count TraceTag=1 matches with tag generation disabled.
    """
    return _compile_upload_watchpoints(ports, channel, {"tracetag": 1})


def dtm_batches(bindings):
    """Schedule bindings sharing a DTM in separate measurement windows.

    Each measurement combines all four local counters into one 64-bit counter,
    so a DTM can count only one binding at a time. Different DTMs run together.
    For DTM A with bindings [a0, a1] and DTM B with [b0], return two batches:
    [[a0, b0], [a1]]. This covers every port/VC without counter contention.
    """
    by_dtm = {}
    order = []
    for binding in bindings:
        if binding.dtm not in by_dtm:
            order.append(binding.dtm)
            by_dtm[binding.dtm] = []
        by_dtm[binding.dtm].append(binding)
    return [[by_dtm[dtm][i] for dtm in order if i < len(by_dtm[dtm])]
            for i in range(max([len(v) for v in by_dtm.values()] or [0]))]


def target_id_filters(ids):
    """Use one wildcard filter only when it matches exactly the supplied IDs."""
    ids = list(ids)
    if not ids:
        raise ValueError("need at least one target ID")
    for node_id in ids:
        cmn_config.check_integer(node_id, "target ID")
    ids = sorted(set(ids))
    variable = 0
    for node_id in ids:
        variable |= node_id ^ ids[0]
    # All IDs agree outside 'variable'. Only merge a complete set of the
    # possible combinations within it, so no neighbouring port is tagged.
    if len(ids) == 1 << bin(variable).count('1'):
        return [cmnwatch.unconvert_value_mask(ids[0] & ~variable, variable)]
    return ids


class ProbePlan(object):
    """The complete measurement schedule for finding one source CCG's peer.

    target is the source-side link endpoint, whose device IDs select traffic.
    tag_ports are where that traffic is tagged; observers are candidate remote
    endpoints. Each batch contains BoundWatchpoints on distinct DTMs.

    tag_batches contains (TgtID filter, list of batches) pairs: a filter may
    cover several IDs belonging to the target, or just the requested --tgtid.
    observer_batches is a list of batches covering all remote ports and VCs.
    Every tagger batch must be measured against every observer batch.
    """
    def __init__(self, target, tag_ports, observers, tag_channel, monitor_channel, tgtid=None):
        self.target = target
        self.target_ids = sorted(target.ids())
        if not self.target_ids:
            raise ValueError("%s has no known CHI device IDs" % port_label(target))
        if tgtid is not None:
            cmn_config.check_integer(tgtid, "target ID", maximum=cmn_base.NODE_INFO_FIELD_MAX)
            if tgtid not in self.target_ids:
                raise ValueError("target ID 0x%x does not belong to %s" % (tgtid, port_label(target)))
            self.target_ids = [tgtid]
        self.tag_batches = [(tgtid, dtm_batches(compile_tag_setters(
            tag_ports, tag_channel, tgtid))) for tgtid in target_id_filters(self.target_ids)]
        self.observer_batches = dtm_batches(compile_tag_monitors(observers, monitor_channel))
        self.observers = observers

    def sample_counts(self, repeats=1):
        """Return baseline and tagged sample counts for the requested repetitions."""
        baselines = len(self.observer_batches) * repeats
        tagged = baselines * sum(len(batches) for unused, batches in self.tag_batches)
        return baselines, tagged

    def bindings(self):
        """Enumerate resources for saving hardware state, not in sampling order."""
        for unused, batches in self.tag_batches:
            for batch in batches:
                for binding in batch:
                    yield binding
        for batch in self.observer_batches:
            for binding in batch:
                yield binding


def plan_probes(cmns, source_meshes=None, tag_selector=None,
                tag_channel='req', monitor_channel='req', tgtid=None):
    """Compile every probe before changing hardware; retain physical mesh IDs."""
    if tag_channel not in ['req', 'rsp', 'dat']:
        raise ValueError("tag channel must have a TgtID: req, rsp or dat")
    if monitor_channel not in CHANNELS:
        raise ValueError("unknown monitoring channel")
    if tgtid is not None:
        cmn_config.check_integer(tgtid, "target ID", maximum=cmn_base.NODE_INFO_FIELD_MAX)
    cmns = sorted(cmns, key=lambda cmn: cmn.cmn_seq)
    available = set(cmn.cmn_seq for cmn in cmns)
    if len(available) != len(cmns):
        raise ValueError("duplicate CMN mesh numbers")
    sources = available if source_meshes is None else set(source_meshes)
    if not sources or not sources.issubset(available):
        raise ValueError("source mesh is absent from discovered CMNs")
    if tgtid is not None and len(sources) != 1:
        raise ValueError("--tgtid requires exactly one --source-mesh (or --cmn-instance)")
    gateways = dict((cmn.cmn_seq, sorted(cmn.ports(cmn_enum.CMN_PROP_CCG), key=port_key))
                    for cmn in cmns)
    if len([ports for ports in gateways.values() if ports]) < 2:
        raise ValueError("need CCG ports on at least two meshes")
    plans = []
    for cmn in cmns:
        if cmn.cmn_seq not in sources or not gateways[cmn.cmn_seq]:
            continue
        targets = gateways[cmn.cmn_seq]
        if tgtid is not None:
            targets = [port for port in targets if tgtid in port.ids()]
            if not targets:
                raise ValueError("mesh %u: target ID 0x%x is not a known CCG device ID" % (cmn.cmn_seq, tgtid))
            if len(targets) != 1:
                raise ValueError("mesh %u: target ID 0x%x belongs to multiple CCG ports" % (cmn.cmn_seq, tgtid))
        tag_ports = selected_ports(cmn, tag_selector)
        if not tag_ports:
            raise ValueError("mesh %u: tag selector matches no ports" % cmn.cmn_seq)
        # Source selection limits where tags are set, not where they are sought.
        observers = [port for seq in sorted(gateways) if seq != cmn.cmn_seq
                     for port in gateways[seq]]
        for target in targets:
            plans.append(ProbePlan(target, tag_ports, observers, tag_channel, monitor_channel, tgtid=tgtid))
    if not plans:
        raise ValueError("no source CCG ports selected")
    return plans


class DirectProbe(object):
    """Own direct PMU programming for a run, restoring state on all exits.

    DTC event counters and FIFO contents are untouched. The local 64-bit
    counters do not export rollovers. Only DTC DT/PMU enables are needed.
    The caller must have exclusive use of the affected CMN debug/PMU blocks.
    """
    def __init__(self, plans, sleep=time.sleep, clock=monotonic):
        dtms = []
        cmns = []
        for plan in plans:
            for binding in plan.bindings():
                if binding.dtm not in dtms:
                    dtms.append(binding.dtm)
                if binding.port.CMN() not in cmns:
                    cmns.append(binding.port.CMN())
        self.dtms = dtms
        self.cmns = cmns
        # Original state is saved once for the whole run. Track changed blocks
        # separately from active ones: even a failed write may need restoration.
        self.states = {}                 # DTM -> DTMState from cmn_devmem.
        self.changed_dtms = set()
        self.dtc_saved = []              # Rows: [DTC, DTCState, needs restoration].

        # active supplies the binding for each DTM in the next sample. The
        # programmed match survives stop(); running and tagged track enables.
        # Keeping these separate lets observers count across tagger changes
        # without reprogramming or reading back their configuration.
        self.active = []
        self.programmed = {}             # DTM -> BoundWatchpoint.signature.
        self.running = set()
        self.tagged = set()              # Subset of running that generates tags.
        self.sleep = sleep
        self.clock = clock

    def __enter__(self):
        # Finish every snapshot before the first programming write.
        self.states = dict((dtm, dtm.dtm_save()) for dtm in self.dtms)
        for cmn in self.cmns:
            dtcs = list(cmn.DTCs())
            if not dtcs:
                raise ValueError("mesh %u has no discovered DTC" % cmn.cmn_seq)
            for dtc in dtcs:
                self.dtc_saved.append([dtc, dtc.dtc_save(), False])
        try:
            for dtm in self.dtms:
                self.stop(dtm)
            for saved in self.dtc_saved:
                dtc, state, unused = saved
                # Mark before the write so partial failure also triggers cleanup.
                saved[2] = True
                dtc.dtc_enable(pmu=True, wait=False, state=state)
        except BaseException:
            self.close(suppress_errors=True)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close(suppress_errors=exc_type is not None)
        return False

    def stop(self, dtm):
        """Stop a DTM before programming; track even a partially failed write."""
        self.changed_dtms.add(dtm)
        state = self.states[dtm]
        dtm.dtm_update_control(control=state.control, enable=False, tag=False, sample=False)
        dtm.pmu_disable(config=state.pmu_config)
        self.running.discard(dtm)
        self.tagged.discard(dtm)

    def configure(self, taggers, observers):
        """Keep unchanged counters running and program only changed watchpoints."""
        active = taggers + observers
        wanted = dict((b.dtm, b.signature) for b in active)
        if len(wanted) != len(active):
            raise ValueError("a batch must have at most one watchpoint per DTM")
        # Stop bindings that are being replaced or dropped. An unchanged
        # observer stays running while the source switches to another batch.
        for binding in self.active:
            dtm = binding.dtm
            if dtm in self.running and wanted.get(dtm) != self.programmed.get(dtm):
                self.stop(dtm)
        for binding in active:
            dtm = binding.dtm
            previous = self.programmed.get(dtm)
            if dtm in self.running and previous == binding.signature:
                continue
            if previous is None:
                # Once per DTM: neutralize all old trace/trigger settings.
                dtm.dtm_reset_wps(preserve_config=False)
                dtm.pmu_set_counters([0], width=64)
            if previous != binding.signature:
                dtm.dtm_wp_set(binding.slot, binding.physical)
            # stop() disables local counting; enable the selected input again.
            dtm.pmu_configure_local([binding.slot], width=64)
            self.programmed[dtm] = binding.signature
        self.active = active
        # Both roles start counting with tag generation off. run_probe() turns
        # tags on only at the source, and only for the tagged sample window.
        self.tagging(self.active, False)

    def tagging(self, taggers, enabled):
        """Enable counting on these bindings and choose whether they set tags.

        Disabling tag generation leaves counters running, so observer baselines
        and tagged samples can use the same configuration and counter stream.
        """
        for binding in taggers:
            dtm = binding.dtm
            if dtm in self.running and (dtm in self.tagged) == enabled:
                continue
            dtm.dtm_update_control(control=self.states[dtm].control,
                                   enable=True, tag=enabled, sample=False)
            self.running.add(dtm)
            if enabled:
                self.tagged.add(dtm)
            else:
                self.tagged.discard(dtm)

    def sample(self, duration):
        """Return DTM -> {count, seconds, rate} for the current active bindings.

        Reads can be slow, so each DTM's rate uses its own actual read interval.
        Counters run across sample windows; deltas account for rollover without
        resetting them. One binding per DTM makes each count unambiguous.
        """
        before = {}
        for binding in self.active:
            value = binding.dtm.pmu_counters(width=64)[0]
            before[binding.dtm] = (value, self.clock())
        self.sleep(duration)
        result = {}
        for binding in self.active:
            value = binding.dtm.pmu_counters(width=64)[0]
            end = self.clock()
            initial, start = before[binding.dtm]
            elapsed = end - start
            if elapsed <= 0:
                raise OSError("measurement clock did not advance")
            count = (value - initial) & COUNTER_MASK
            result[binding.dtm] = {"count": count, "seconds": elapsed,
                                   "rate": float(count) / elapsed}
        return result

    def close(self, suppress_errors=False):
        """Restore saved programming while attempting cleanup of every block.

        Restore matches and counters only on DTMs we successfully stopped;
        restore DTC controls before resuming the old DTM control settings.
        Failed restorations remain marked for retry. During exception handling,
        report cleanup failures without hiding the original failure.
        """
        errors = []
        ready = []
        # Stop all tag generation before restoring any old watchpoint matches.
        for dtm in self.dtms:
            if dtm not in self.changed_dtms:
                continue
            try:
                self.stop(dtm)
                ready.append(dtm)
            except BaseException as error:
                errors.append("%s: stop: %s" % (dtm, error))
        restored = []
        for dtm in ready:
            try:
                dtm.dtm_restore(self.states[dtm], restore_control=False)
                self.programmed.pop(dtm, None)
                restored.append(dtm)
            except BaseException as error:
                errors.append("%s: restore registers: %s" % (dtm, error))
        for saved in reversed(self.dtc_saved):
            dtc, state, changed = saved
            if not changed:
                continue
            try:
                dtc.dtc_restore(state)
                saved[2] = False
            except BaseException as error:
                errors.append("%s: restore: %s" % (dtc, error))
        for dtm in restored:
            try:
                dtm.dtm_restore_control(self.states[dtm])
                self.changed_dtms.remove(dtm)
            except BaseException as error:
                errors.append("%s: restore control: %s" % (dtm, error))
        if errors:
            message = "could not restore CMN state: %s" % "; ".join(errors)
            if suppress_errors:
                print(message, file=sys.stderr)
            else:
                raise OSError(message)


def empty_counts(ports):
    """Create one repetition's accumulators, keyed by (mesh number, port base ID).

    Multiple VCs and source batches contribute to the same observer port.
    on_count and baseline_count record actual sampled matches; a reused
    baseline is counted once. excess_rate sums the baseline-subtracted rates,
    while excess_matches weights each excess rate by its tagged sample's
    duration. Thus excess_matches is an estimate, not on_count - baseline_count.
    """
    return dict((port_key(port), {"endpoint": port_description(port), "on_count": 0,
                                 "baseline_count": 0, "excess_rate": 0.0,
                                 "excess_matches": 0.0}) for port in ports)


def rank_observers(counts):
    return sorted(counts.values(), key=lambda item: (-item['excess_rate'],
                  item['endpoint']['mseq'], item['endpoint']['id']))


def classify(rounds, min_count=10, ratio=5.0):
    """Choose a peer from a list of repetitions, each a port-keyed count mapping.

    Rank ports by their mean excess rate. The winner must exceed the runner-up
    by ratio in every repetition as well as overall: a strong mean alone could
    conceal a changing peak. min_count applies to its accumulated excess
    matches, preventing a tiny signal from winning just because rivals are zero.
    """
    if not rounds or not rounds[0]:
        raise ValueError("need at least one observation in each repetition")
    if min_count < 1 or positive_number(ratio) <= 1:
        raise ValueError("min-count must be positive and ratio must exceed 1")
    if any(set(counts) != set(rounds[0]) for counts in rounds):
        raise ValueError("repetitions must cover the same observer ports")
    total = copy.deepcopy(rounds[0])
    for counts in rounds[1:]:
        for key in counts:
            for field in ['on_count', 'baseline_count', 'excess_rate', 'excess_matches']:
                total[key][field] += counts[key][field]
    # Retain negative differences until after summing repetitions, so downward
    # background fluctuations can cancel upward ones rather than bias the score.
    for item in total.values():
        item['excess_rate'] = max(0.0, item['excess_rate'] / len(rounds))
    ranked = rank_observers(total)
    first = ranked[0]
    second = ranked[1]['excess_rate'] if len(ranked) > 1 else 0.0
    peak = first['excess_rate']
    winner = (first['endpoint']['mseq'], first['endpoint']['id'])
    stable = True
    for counts in rounds:
        ranking = rank_observers(counts)
        round_peak = counts[winner]['excess_rate']
        runner_up = max(0.0, ranking[1]['excess_rate']) if len(ranking) > 1 else 0.0
        if (ranking[0]['endpoint'] != first['endpoint'] or round_peak <= 0 or
                round_peak < ratio * runner_up):
            stable = False
    status = 'detected'
    if peak <= 0:
        status = 'no-signal'
    elif first['excess_matches'] < min_count:
        status = 'low-traffic'
    elif not stable or peak < ratio * max(0.0, second) or peak == second:
        status = 'ambiguous'
    return {"status": status, "peer": first['endpoint'] if status == 'detected' else None,
            "peak_ratio": peak / second if second > 0 else None,
            "repeatable": stable, "observations": ranked}


def run_probe(plan, hardware, duration, settle, repeats, min_count, ratio, progress=None):
    """Execute one target CCG's plan and return its observations and inferred peer.

    Within each repetition, keep one observer batch configured while measuring
    its baseline and all target-filter/tagger batches. This ordering reuses
    observer programming and baseline sampling across the source batches. It
    assumes reasonably steady background traffic during that block; each new
    observer batch and repetition gets a fresh baseline.

    Hardware samples are keyed by DTM; bindings map those samples back to ports
    for accumulation. rounds retains one complete port mapping per repetition
    so classify() can check that the peak stays at the same remote endpoint.
    """
    rounds = []
    tag_matches = 0
    started = hardware.clock()
    baselines, tagged = plan.sample_counts(repeats)
    completed = 0
    for repeat in range(repeats):
        counts = empty_counts(plan.observers)
        for observers in plan.observer_batches:
            if progress is not None:
                progress('baseline', repeat + 1, completed, baselines + tagged)
            hardware.configure([], observers)
            hardware.sleep(settle)      # Let previous tagged transactions drain.
            background = hardware.sample(duration)
            completed += 1
            for binding in observers:
                counts[port_key(binding.port)]['baseline_count'] += background[binding.dtm]['count']
            for tgtid, tag_batches in plan.tag_batches:
                for taggers in tag_batches:
                    if progress is not None:
                        progress('tagged traffic', repeat + 1, completed, baselines + tagged)
                    hardware.configure(taggers, observers)
                    try:
                        hardware.tagging(taggers, True)
                        hardware.sleep(settle)
                        active = hardware.sample(duration)
                    finally:
                        hardware.tagging(taggers, False)
                    completed += 1
                    # Source matches distinguish an idle target from a failure
                    # to observe tags remotely; they are not a unique packet tally.
                    tag_matches += sum(active[b.dtm]['count'] for b in taggers)
                    for binding in observers:
                        on, off = active[binding.dtm], background[binding.dtm]
                        item = counts[port_key(binding.port)]
                        item['on_count'] += on['count']
                        # Subtract rates, since read intervals can differ and
                        # this baseline serves several tagged windows. Scale by
                        # the on-window duration for the excess-match threshold.
                        excess = on['rate'] - off['rate']
                        item['excess_rate'] += excess
                        item['excess_matches'] += excess * on['seconds']
        rounds.append(counts)
    if progress is not None:
        progress('complete', repeats, completed, baselines + tagged)
    result = classify(rounds, min_count=min_count, ratio=ratio)
    result.update({"source": port_description(plan.target), "target_ids": plan.target_ids,
                   "tag_matches": tag_matches,
                   "sample_counts": {"baseline": baselines, "tagged": tagged},
                   "elapsed_seconds": hardware.clock() - started,
                   "rounds": [rank_observers(counts) for counts in rounds]})
    if not tag_matches:
        result['status'] = 'no-target-traffic'
        result['peer'] = None
    return result


class ProbeProgress(object):
    """Report repetition/sample progress periodically, including on non-TTY consoles."""
    def __init__(self, clock=monotonic):
        self.clock = clock
        self.started = clock()
        self.last_time = self.started
        self.last_repeat = None

    def __call__(self, phase, repeat, completed, total):
        now = self.clock()
        if repeat != self.last_repeat or completed == total or now - self.last_time >= 5.0:
            print('  repetition %u: %u/%u samples done; %s; %.1fs elapsed' % (
                repeat, completed, total, phase, now - self.started))
            sys.stdout.flush()
            self.last_time = now
            self.last_repeat = repeat


def detected_links(results):
    """Convert accepted directional probes to consistent, undirected links.

    pairs maps a sorted pair of port keys to its report endpoints, merging
    A -> B and B -> A. neighbours records all peers claimed for each endpoint.
    A port must have exactly one peer: if A -> B and B -> C both passed the
    individual probe checks, omit both pairs rather than choose between them.
    """
    pairs = {}
    neighbours = {}
    for result in results:
        if result['peer'] is None:
            continue
        endpoints = [result['source'], result['peer']]
        keys = sorted((e['mseq'], e['id']) for e in endpoints)
        pair = tuple(keys)
        pairs[pair] = [{"mseq": key[0], "id": key[1]} for key in keys]
        for a, b in [keys, list(reversed(keys))]:
            neighbours.setdefault(a, set()).add(b)
    links = []
    conflicts = []
    for pair in sorted(pairs):
        if any(len(neighbours[key]) != 1 for key in pair):
            conflicts.append(pairs[pair])
            continue
        links.append({"id": "c2c-m%u-%x-m%u-%x" % (pair[0] + pair[1]),
                      "endpoints": pairs[pair]})
    return links, conflicts


def cached_mesh_map(system, cmns):
    """Match live meshes to the cache by physical address, never list order."""
    meshes = {}
    for cmn in cmns:
        matches = [c for c in system.CMNs
                   if cmn.periphbase is not None and c.periphbase == cmn.periphbase]
        if len(matches) != 1 or matches[0] in meshes.values():
            raise ValueError('cannot uniquely match live mesh %u to cached topology; run cmn_discover' % cmn.cmn_seq)
        cached = matches[0]
        if cached.product_config.product_id != cmn.product_config.product_id:
            raise ValueError('product mismatch for live mesh %u in cached topology' % cmn.cmn_seq)
        # These ports are already discovered by plan_probes(); this lookup
        # only checks the offline description and adds no register accesses.
        for port in cmn.ports(cmn_enum.CMN_PROP_CCG):
            cp = cached.port_at_id(port.base_id())
            if (cp is None or cp.base_id() != port.base_id() or
                    not cp.has_properties(cmn_enum.CMN_PROP_CCG)):
                raise ValueError('cached topology is missing %s; run cmn_discover' % port_label(port))
        meshes[cmn.cmn_seq] = cached
    return meshes


def merge_cached_links(description, cmns, links):
    """Merge accepted port pairs, retaining unrelated topology and annotations.

    A probe cannot resolve individual gateway devices or physical interfaces.
    Compare existing links at port granularity: retain matching records in full,
    replace records assigning a different peer to a detected port, and leave
    unobserved/unresolved ports alone. Validate the result through the object
    model while retaining the original JSON's other fields verbatim.
    """
    system = cmn_json.system_from_json(description)
    meshes = cached_mesh_map(system, cmns)
    pairs = set()
    for link in links:
        pairs.add(tuple(sorted((meshes[e['mseq']].cmn_seq, e['id'])
                               for e in link['endpoints'])))
    touched = set(key for pair in pairs for key in pair)
    retained = []
    known = set()
    for jl, link in zip(description.get('c2c_links', []), system.c2c_links):
        pair = tuple(sorted(port_key(e.device.port) for e in link.endpoints))
        if pair in pairs or not touched.intersection(pair):
            retained.append(jl)
            known.add(pair)
    ids = set(link['id'] for link in retained)
    for pair in sorted(pairs - known):
        name = 'c2c-m%u-%x-m%u-%x' % (pair[0] + pair[1])
        link_id = name
        suffix = 1
        while link_id in ids:
            link_id = '%s-%u' % (name, suffix)
            suffix += 1
        ids.add(link_id)
        retained.append({'id': link_id,
                         'endpoints': [{'mseq': seq, 'id': nid} for seq, nid in pair]})
    updated = dict(description)
    if retained:
        updated['c2c_links'] = retained
    cmn_json.system_from_json(updated)
    return updated


def update_cached_links(path, cmns, links):
    """Re-read the cache after measurement, then atomically save accepted links."""
    with open(path) as f:
        metadata = os.fstat(f.fileno())
        description = json.load(f)
    updated = merge_cached_links(description, cmns, links)
    if updated != description:
        write_json(path, updated, metadata=metadata)
        print('Updated C2C links in %s' % path)


def write_json(path, value, metadata=None):
    """Write JSON atomically, preserving existing cache ownership and permissions."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp = tempfile.mkstemp(prefix='.cmn-c2c-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as f:
            fd = None
            json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
            f.write('\n')
        if metadata is not None:
            current = os.stat(temp)
            if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                os.chown(temp, metadata.st_uid, metadata.st_gid)
            os.chmod(temp, stat.S_IMODE(metadata.st_mode))
        os.rename(temp, path)
    finally:
        if fd is not None:
            os.close(fd)
        if os.path.exists(temp):
            os.unlink(temp)


def print_result(result, verbose=False):
    source = result['source']
    text = "m%u:CCG@0x%x: %s" % (source['mseq'], source['id'], result['status'])
    if result['peer'] is not None:
        peer = result['peer']
        text += " -> m%u:CCG@0x%x" % (peer['mseq'], peer['id'])
    first = result['observations'][0]
    text += " (peak %.1f excess matches/s, %u tagger matches; %.1fs)" % (
        first['excess_rate'], result['tag_matches'], result['elapsed_seconds'])
    print(text)
    if verbose or result['peer'] is None:
        for item in result['observations']:
            endpoint = item['endpoint']
            print("  m%u:CCG@0x%x: on=%u baseline=%u excess=%.1f/s" % (
                endpoint['mseq'], endpoint['id'], item['on_count'],
                item['baseline_count'], item['excess_rate']))
    sys.stdout.flush()


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.epilog = ('--cmn-instance is an alias for --source-mesh. Discovery needs '
                     'exclusive use of CMN debug/PMU blocks and an active C2C workload.')
    parser.add_argument('--source-mesh', type=int, action='append', help='mesh to tag; repeatable (default: each mesh)')
    parser.add_argument('--tgtid', type=parse_target_id, metavar='ID', help='probe only this exact CCG target ID (integer, e.g. 0x24); requires one source mesh')
    parser.add_argument('--tag-node', type=cmn_select.CMNSelect, help='source upload port selector (default: all source ports)')
    parser.add_argument('--tag-channel', choices=['req', 'rsp', 'dat'], default='req', help='channel carrying the target ID (default: req)')
    parser.add_argument('--monitor-channel', choices=CHANNELS, default='req', help='upload channel to count at remote CCGs (default: req)')
    parser.add_argument('--time', type=positive_number, default=0.5, help='seconds per baseline/tagged sample (default: 0.5)')
    parser.add_argument('--settle', type=positive_number, default=0.05, help='seconds to settle before each sample (default: 0.05)')
    parser.add_argument('--repeats', type=int, default=3, help='repeat each probe (default: 3)')
    parser.add_argument('--min-count', type=int, default=10, help='minimum excess matches at the peak (default: 10)')
    parser.add_argument('--ratio', type=positive_number, default=5.0, help='minimum peak/runner-up ratio (default: 5)')
    parser.add_argument('--output', help='write observations and detected c2c_links as JSON')
    parser.add_argument('--json', help='cached system description to update (default: standard CMN cache)')
    parser.add_argument('--no-update', action='store_true', help='do not update cached C2C links')
    parser.add_argument('--dry-run', action='store_true', help='discover and show probe plan without programming watchpoints')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='show all observer counts')
    return parser


def main(argv=None):
    parser = argument_parser()
    opts = parser.parse_args(argv)
    if opts.repeats < 1 or opts.min_count < 1 or opts.ratio <= 1:
        parser.error('repeats/min-count must be positive and ratio must exceed 1')
    if opts.cmn_instance is not None:
        # Keep remote meshes in discovery when the common instance selector is used.
        opts.source_mesh = (opts.source_mesh or []) + [opts.cmn_instance]
        opts.cmn_instance = None
    if opts.source_mesh is not None and any(seq < 0 for seq in opts.source_mesh):
        parser.error('source mesh numbers must be nonnegative')
    if opts.tgtid is not None and len(set(opts.source_mesh or [])) != 1:
        parser.error('--tgtid requires exactly one --source-mesh (or --cmn-instance)')
    try:
        cmns = cmn_devmem.cmn_from_opts(opts)
        plans = plan_probes(cmns, opts.source_mesh, opts.tag_node,
                            opts.tag_channel, opts.monitor_channel, tgtid=opts.tgtid)
        results = []
        for plan in plans:
            baselines, tagged = plan.sample_counts(opts.repeats)
            print("%s: target IDs %s, %u baseline + %u tagged samples (~%.1fs plus register access)" % (
                port_label(plan.target), ', '.join('0x%x' % nid for nid in plan.target_ids),
                baselines, tagged, (baselines + tagged) * (opts.time + opts.settle)))
        if opts.dry_run:
            return 0
        cache_path = None
        if not opts.no_update:
            cache_path = cmn_json.cmn_config_default(opts.json)
            if opts.output and os.path.realpath(opts.output) == os.path.realpath(cache_path):
                raise ValueError('--output report must differ from the cached system description')
            cached = cmn_json.system_from_json_file(cache_path, missing_ok=True)
            if cached is None:
                raise ValueError('%s: cached topology not found; run cmn_discover first, '
                                 'or use --no-update for report-only discovery' % cache_path)
            cached_mesh_map(cached, cmns)
        print('Run traffic exercising the C2C links; stop other CMN perf/trace sessions during discovery.')
        sys.stdout.flush()
        # One hardware session spans all plans, preserving reusable programming
        # between targets and restoring the original state on leaving the block.
        with DirectProbe(plans) as hardware:
            for plan in plans:
                print('Probing %s...' % port_label(plan.target))
                sys.stdout.flush()
                result = run_probe(plan, hardware, opts.time, opts.settle,
                                   opts.repeats, opts.min_count, opts.ratio,
                                   progress=ProbeProgress(clock=hardware.clock))
                results.append(result)
                print_result(result, verbose=opts.verbose)
        links, conflicts = detected_links(results)
        report = {"version": 1, "generator": "cmn_detect_c2c.py", "probes": results,
                  "meshes": [{"mseq": cmn.cmn_seq, "periphbase": cmn.periphbase,
                              "product": str(cmn.product_config)} for cmn in cmns],
                  "c2c_links": links, "conflicts": conflicts,
                  "tag_channel": opts.tag_channel, "monitor_channel": opts.monitor_channel,
                  "time": opts.time, "settle": opts.settle, "repeats": opts.repeats,
                  "min_count": opts.min_count, "ratio": opts.ratio,
                  "baseline_scope": "observer batch per repetition"}
        if opts.output:
            write_json(opts.output, report)
        if cache_path is not None and links:
            update_cached_links(cache_path, cmns, links)
        print('%u inferred links; %u conflicting pairs omitted' % (len(links), len(conflicts)))
        return 0 if links and not conflicts and all(r['peer'] is not None for r in results) else 2
    except KeyboardInterrupt:
        print('C2C discovery interrupted; hardware restoration attempted.', file=sys.stderr)
        return 130
    except (TypeError, ValueError, IOError, OSError, cmn_devmem_find.CMNNotFound) as error:
        print('cmn_detect_c2c: %s' % error, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
