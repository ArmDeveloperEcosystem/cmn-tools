#!/usr/bin/python

"""
Manage details of CMN PMU events, and load details from a CSV file.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN nodes, as well as XPs, can export events for counting in DTM and DTC.
Each node can typically export 4 events at a time.
There are thus four event selectors in the node.

In addition, some events have a filter field. This is also set in the
event selector register but applies to all the node's current events.
E.g. CMN-600 HN-F, event 0xf (POCQ occupancy), uses the filter.
"""

from __future__ import print_function

import os
import sys

from cmn_enum import *


o_verbose = 0


class Event:
    """
    A single CMN PMU event that can be monitored on a CMN node.
    """
    def __init__(self, parent, node_type=None, pmu_index=0, event_number=None, pmu_event_name=None, filter=None, description=None):
        assert event_number > 0, "all CMN events have non-zero event number"
        self.node_type = node_type
        self.pmu_index = pmu_index            # Handle CCLA_RNI and HN-P which have two PMUs
        self.event_number = event_number
        self.filter = filter
        self.pmu_event_name = pmu_event_name
        self.description = description

    def name(self):
        if self.pmu_event_name:
            return self.pmu_event_name
        return str(self)

    def __str__(self):
        s = "0x%x(%s)" % (self.node_type, cmn_node_type_str(self.node_type))
        if self.pmu_index != 0:
            s += "[%u]" % self.pmu_index
        s += ":0x%x" % self.event_number
        if self.filter is not None:
            s += ":0x%x" % (self.filter)
        if self.pmu_event_name:
            s += "(%s)" % self.pmu_event_name
        return s


class Events:
    """
    A database of CMN PMU events, for a given CMN product.

    Note that this might be:

     - the set of events for some specific instance of the product, e.g. the
       current host

     - the set of events supported across all possible configurations of the
       product

    E.g. a given CMN-700 instance will support HN-F events, or HN-S events,
    but not both.
    """
    def __init__(self):
        self.events_by_node_ix = {}           # (nodetype, ix[, filter]) -> Event
        self.node_type_events_by_ix = {}      # nodetype -> (ix[, filter]) -> Event
        self.events_by_pmu_event_name = {}    # PMU mnemonic -> Event(s)

    def __str__(self):
        s = "{CMN PMU events: %u events, node types: %u}" % (len(list(self.events_by_node_ix.keys())), len(list(self.node_types())))
        return s

    def add(self, node_type=None, pmu_index=0, event_number=None, pmu_event_name=None, filter=None, description=None, add_name=True, allow_duplicates=True):
        if filter is not None:
            k = (node_type, pmu_index, event_number, filter)
        else:
            k = (node_type, pmu_index, event_number)
        if k in self.events_by_node_ix:
            e = self.events_by_node_ix[k]
            if not allow_duplicates:
                assert False, "duplicate %s and %s" % (e, pmu_event_name)
        else:
            e = Event(self, node_type=node_type, pmu_index=pmu_index,
                      event_number=event_number, pmu_event_name=pmu_event_name, filter=filter,
                      description=None)
            self.events_by_node_ix[k] = e
            if node_type not in self.node_type_events_by_ix:
                self.node_type_events_by_ix[node_type] = {}
            nk = (pmu_index, event_number, filter)
            self.node_type_events_by_ix[node_type][nk] = e
        if add_name and pmu_event_name is not None:
            # A name might map to multiple (node type, event_number) pairs,
            # as long as the node types are distinct.
            if pmu_event_name not in self.events_by_pmu_event_name:
                self.events_by_pmu_event_name[pmu_event_name] = []
            if e not in self.events_by_pmu_event_name[pmu_event_name]:
                self.events_by_pmu_event_name[pmu_event_name].append(e)
        return e

    def get_event(self, node_type, event_number, pmu_index=0, filter=None):
        """
        Get an event by node type, event number and filter value.
        The caller may specify the filter value (e.g. if read from pmu_sel)
        and it will be ignored if not relevant to this event type.

        Return None if we don't know about the event.
        """
        k = (node_type, pmu_index, event_number)
        if k in self.events_by_node_ix:
            return self.events_by_node_ix[k]
        if filter is not None:
            k = (node_type, pmu_index, event_number, filter)
            if k in self.events_by_node_ix:
                return self.events_by_node_ix[k]
        return None

    def events(self, node_type=None):
        """
        Yield events ordered by (node_type, event_number [, filter])
        Optionally, filter by node type.
        """
        for k in sorted(self.events_by_node_ix.keys()):
            if node_type is None or node_type == k[0]:
                yield self.events_by_node_ix[k]

    def node_types(self):
        """
        Return the sorted list of node types we know about.
        """
        return sorted(self.node_type_events_by_ix.keys())

    def print(self, file=None):
        """
        Print events in the usual traversal order
        """
        for e in self.events():
            print("%s" % (e))

    def load(self, fn):
        """
        Load an event set from a CSV file.
        """
        n_added = 0
        with open(fn) as f:
            for ln in f:
                x = ln.strip().split(',')
                nt = int(x[0], 16)        # node type
                pi = int(x[1])            # PMU index (usually zero)
                en = int(x[2], 16)        # event number
                fi = int(x[3], 16) if x[3] else None   # sub-field value
                mn = x[4] if x[4] else None      # mnemonic
                de = x[5] if x[5] else None
                e = self.add(node_type=nt, pmu_index=pi, event_number=en, filter=fi, pmu_event_name=mn, description=de, allow_duplicates=False)
                assert e == self.get_event(nt, en, pmu_index=pi, filter=fi), "bad load %s" % e
                n_added += 1
        if o_verbose:
            print("cmn_events: %u events added from %s" % (n_added, fn),
                  file=sys.stderr)
        return self

    def dump_f(self, f):
        """
        Dump the event set to a CSV file (takes file object).
        """
        n_written = 0
        for e in self.events():
            flds = [hex(e.node_type), str(e.pmu_index), hex(e.event_number)]
            flds.append(hex(e.filter) if e.filter is not None else "")
            flds.append(e.pmu_event_name if e.pmu_event_name is not None else "")
            flds.append(e.description if e.description is not None else "")
            print(','.join(flds), file=f)
            n_written += 1
        return n_written

    def dump(self, fn):
        """
        Dump the event set to a CSv file. Handles "-" meaning stdout.
        (There doesn't seem to be a nice pattern for this.)
        """
        if fn == "-":
            n_written = self.dump_f(sys.stdout)
            fn = "stdout"
        else:
            with open(fn, "w") as f:
                n_written = self.dump_f(f)
        if o_verbose:
            print("cmn_events: %u events written to %s" % (n_written, fn),
                  file=sys.stderr)


def load_events(fn):
    """
    Create a new event set, loaded from a file.
    """
    return Events().load(fn)


def _sysfs_events_iter():
    dir = "/sys/bus/event_source/devices/arm_cmn_0/events"
    for e in os.listdir(dir):
        with open(os.path.join(dir, e)) as f:
            m = {}
            for s in f.read().strip().split(','):
                (fld, val) = s.split('=')
                m[fld] = val
        yield (e, m)


def _add_sysfs_events(E):
    """
    Read the events currently exported by the OS,
    and add them to the event set.
    """
    n_added = 0
    for (e, m) in _sysfs_events_iter():
        if e in ["watchpoint_down", "watchpoint_up"]:
            continue
        type = int(m["type"], 16)
        if "eventid" not in m:
            # possibly dtc_cycles
            #print("%30s  %s" % (e, m))
            continue
        en = int(m["eventid"], 16)
        if len(m.keys()) > 2:
            if len(m.keys()) > 3:
                # we can cope with one subfield, but not more
                print("unexpected subfields: %s, %s" % (e, m))
                continue
            del m["type"]
            del m["eventid"]
            fi = int(list(m.values())[0], 16)
        else:
            fi = None
        pmu_index = 0
        if type in [CMN_NODE_HNP, CMN_NODE_CCLA]:
            pmu_index = 1
        ev = E.add(node_type=type, pmu_index=pmu_index, event_number=en, pmu_event_name=e, filter=fi)
        if type == CMN_NODE_RNI:
            # The Linux driver doesn't distinguish RN-I and RN-D events.
            # As named events, they work for both types.
            E.add(node_type=CMN_NODE_RND, event_number=en, pmu_event_name=e, filter=fi, add_name=False)
        elif type == CMN_NODE_HNI:
            # HN-I events are also valid on HN-P, using the first event selector
            E.add(node_type=CMN_NODE_HNP, event_number=en, pmu_event_name=e, filter=fi, add_name=False)
        elif type == CMN_NODE_CCLA:
            # CCLA events are also valid on CCLA_RNI, using the second event selector
            E.add(node_type=CMN_NODE_CCLA_RNI, pmu_index=1, event_number=en, pmu_event_name=e, filter=fi, add_name=False)
        n_added += 1
    if o_verbose:
        print("cmn_events: %u events added from sysfs" % n_added,
              file=sys.stderr)
    return E


def load_sysfs_events():
    return _add_sysfs_events(Events())


def event_file_name(product_id):
    """
    Generate the canonical CSV file name for a given CMN product id, e.g. 0434 for CMN-600.
    This should be located in the same directory as this module.
    """
    fn = "cmn-events-%04x.csv" % (product_id)
    return os.path.join(os.path.dirname(__file__), fn)


hns_events = {
    "hnf_slc_sf_cache_access": "hns_slc_sf_cache_access_all",
    "hnf_cache_miss": "hns_cache_miss_all",
    "hnf_sf_hit": "hns_sf_hit_all",
    "hnf_mc_reqs": "hns_mc_reqs_local_all",
    "hnf_mc_retries": "hns_mc_retries_local",
    "hnf_pocq_reqs_recvd": "hns_pocq_reqs_recvd_all",
    "hnf_pocq_retry": "hns_pocq_retry_all",
    "hnf_qos_pocq_occupancy_all": "hns_qos_pocq_occupancy_all",
    "hnf_qos_pocq_occupancy_read": "hns_qos_pocq_occupancy_read",
    "hnf_qos_pocq_occupancy_write": "hns_qos_pocq_occupancy_write",
    "hnf_qos_pocq_occupancy_atomic": "hns_qos_pocq_occupancy_atomic",
}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str, help="input CSV file")
    parser.add_argument("--add-sysfs", action="store_true", help="add events from sysfs")
    parser.add_argument("--list", action="store_true", help="list all events")
    parser.add_argument("-o", "--output", type=str, help="output CSV file")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    E = Events()
    if opts.input:
        E.load(opts.input)
    if opts.add_sysfs or not opts.input:
        _add_sysfs_events(E)
    if opts.verbose or not (opts.list or opts.output):
        print("cmn_events: %u events, %u node types" %
              (len(list(E.events())), len(list(E.node_types()))), file=sys.stderr)
        print("cmn_events: node types: %s" % str(E.node_types()), file=sys.stderr)
    if opts.output:
        E.dump(opts.output)    # Dump to CSV file
    if opts.list:
        E.print()
