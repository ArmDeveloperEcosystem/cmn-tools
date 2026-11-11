#!/usr/bin/python

"""
Manage CMN PMU events, including selector decoding and event data files.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN nodes, as well as XPs, can export events for counting in DTM and DTC.
Each node can typically export 4 events at a time.
There are thus four event selectors in the node.

In addition, some events have one or more filter fields. These are also set
in the event selector register but apply to all the node's current events.
E.g. CMN-600 HN-F, event 0xf (POCQ occupancy), uses the filter.

Typically, pmu_event_sel has several filter fields, of which only one or two
would be used for a given event type. In the Linux PMU, the applicable
filter values are encoded generically, i.e. in perf_event_attr there are
specific places for 'filter' and 'filter2' - the kernel driver then looks up
the event and puts the filter values in the correct fields in pmu_event_sel.
One consequence of this is that the actual pmu_event_sel fields are not
directly discoverable from sysfs, so it's not helpful in programming or
decoding direct register values.
"""

from __future__ import print_function


import os
import sys
import json
import re

import cmn_config


from cmn_enum import *


try:
    basestring
except NameError:
    basestring = str


o_verbose = 0


class Event:
    """
    A single CMN PMU event that can be monitored on a CMN node.
    """
    def __init__(self, parent, node_type=None, pmu_index=0, event_number=None, pmu_event_name=None, filter=None, description=None):
        cmn_config.check_integer(event_number, "event number")
        self.node_type = node_type
        self.pmu_index = pmu_index            # Handle CCLA_RNI and HN-P which have two PMUs
        self.event_number = event_number      # Event number within this node type's event space
        self.filter = filter
        self.pmu_event_name = pmu_event_name  # Name is globally unique (includes node type)
        self.description = description
        self.filter2 = None                  # Second Linux perf filter argument
        self.filter_fields = ()              # Hardware fields used by this event
        self.filters = {}                    # Unshifted hardware field values
        self.filter_labels = {}              # Display labels for hardware values
        self.no_count = False
        self.is_alias = False

    def name(self):
        if self.pmu_event_name:
            s = self.pmu_event_name
            if self.filter_fields and not self.is_alias:
                values = []
                for field in self.filter_fields:
                    value = self.filter_labels.get(field)
                    if value is None:
                        value = "0x%x" % self.filters[field] if field in self.filters else "?"
                    values.append("%s=%s" % (field, value))
                s += " [%s]" % ", ".join(values)
            if self.no_count:
                s += " [no_count]"
            return s
        return str(self)

    def __str__(self):
        s = "0x%x(%s)" % (self.node_type, cmn_node_type_str(self.node_type))
        if self.pmu_index != 0:
            s += "[%u]" % self.pmu_index
        s += ":0x%x" % self.event_number
        if self.filter is not None:
            s += ":0x%x" % (self.filter)
        if self.filter2 is not None:
            s += ":0x%x" % self.filter2
        if self.pmu_event_name:
            s += "(%s)" % self.name()
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
        self.node_aliases = {}               # Reported type -> canonical type
        self.event_masks = {}                # (node type, PMU index) -> event ID mask
        self.filter_positions = {}           # (node type, PMU, field) -> (position, width)
        self.filter_values = {}              # (node type, field, value) -> label
        self.event_no_counts = set()         # (node type, PMU, code, field, value)
        self.event_aliases = {}              # (node type, PMU, raw ID, hardware values) -> Event
        self.hardware_events = set()         # Keys loaded from E records

    def __str__(self):
        s = "{CMN PMU events: %u events, node types: %u}" % (len(list(self.events())), len(list(self.node_types())))
        return s

    def add(self, node_type=None, pmu_index=0, event_number=None, pmu_event_name=None, filter=None, description=None, add_name=True, allow_duplicates=True):
        if filter is not None:
            k = (node_type, pmu_index, event_number, filter)
        else:
            k = (node_type, pmu_index, event_number)
        if k in self.events_by_node_ix:
            e = self.events_by_node_ix[k]
            if not allow_duplicates:
                raise ValueError("duplicate %s and %s" % (e, pmu_event_name))
        else:
            e = Event(self, node_type=node_type, pmu_index=pmu_index,
                      event_number=event_number, pmu_event_name=pmu_event_name, filter=filter,
                      description=description)
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

    def get_event(self, node_type, event_number, pmu_index=0, filter=None, filters=None, filter_order=None):
        """
        Get an event by node type, event number and filter value.
        For .events data, filters maps hardware field names to unshifted
        values. Extra fields are ignored; missing fields remain unspecified.
        filter_order can supply field names in ascending register bit order.
        The singular filter argument is retained for legacy CSV/sysfs data.
        It must not be interpreted as a hardware field in the new format.

        Return None if we don't know about the event.
        """
        cmn_config.check_integer(event_number, "event number")
        if filters is not None and not isinstance(filters, dict):
            raise TypeError("hardware filters must be a dictionary")
        node_type = self.canonical_node_type(node_type)
        code = event_number & self.event_masks.get((node_type, pmu_index), event_number)
        k = (node_type, pmu_index, code)
        if k in self.hardware_events:
            base = self.events_by_node_ix[k]
            if filters is None:
                filters = {}
            values = dict((field, cmn_config.check_integer(filters[field], field))
                          for field in base.filter_fields if field in filters)
            alias_key = (node_type, pmu_index, event_number, tuple(sorted(values.items())))
            if len(values) == len(base.filter_fields) and alias_key in self.event_aliases:
                return self.event_aliases[alias_key]
            if not values and filter_order is None:
                return base
            e = Event(self, node_type=node_type, pmu_index=pmu_index, event_number=event_number,
                      pmu_event_name=base.pmu_event_name)
            order = list(filter_order or ())
            e.filter_fields = tuple([field for field in order if field in base.filter_fields] +
                                    [field for field in base.filter_fields if field not in order])
            e.filters = values
            e.filter_labels = dict((field, self.filter_values[(node_type, field, value)])
                                   for field, value in values.items() if (node_type, field, value) in self.filter_values)
            e.no_count = any(k + (field, value) in self.event_no_counts for field, value in values.items())
            return e
        if k in self.events_by_node_ix:
            return self.events_by_node_ix[k]
        if filter is not None:
            k = (node_type, pmu_index, event_number, filter)
            if k in self.events_by_node_ix:
                return self.events_by_node_ix[k]
        return None

    def canonical_node_type(self, node_type):
        """
        Normalize reported node types, including chained N records.
        """
        seen = set()
        while node_type in self.node_aliases:
            if node_type in seen:
                raise ValueError("cycle in node type aliases at 0x%x" % node_type)
            seen.add(node_type)
            node_type = self.node_aliases[node_type]
        return node_type

    def event_lookup_error(self, node_type, event_number, pmu_index=0):
        """
        Explain a failed lookup without reading registers or changing its key.
        Distinguish absent node/PMU tables, unknown event IDs, and unmatched
        legacy filters. Include other PMU indices to expose indexing mistakes.
        Call this only after get_event() or decode_selector() returns None.
        """
        cmn_config.check_integer(event_number, "event number")
        canonical_type = self.canonical_node_type(node_type)
        context = "node type 0x%x, PMU %u" % (node_type, pmu_index)
        if canonical_type != node_type:
            context += " (canonical type 0x%x)" % canonical_type
        entries = self.node_type_events_by_ix.get(canonical_type, {})
        if not entries:
            return "no known events for %s" % context
        indices = sorted(set(key[0] for key in entries))
        if pmu_index not in indices:
            return "no known events for %s (known PMUs: %s)" % (context, ", ".join(str(i) for i in indices))
        code = event_number & self.event_masks.get((canonical_type, pmu_index), event_number)
        if not any(key[0] == pmu_index and key[1] == code for key in entries):
            return "unknown event 0x%x for %s" % (event_number, context)
        return "no matching event/filter combination for event 0x%x, %s" % (event_number, context)

    def selector_fields(self, node_type, pmu_index=0):
        """
        Return hardware filter positions loaded from F records for this PMU.
        """
        node_type = self.canonical_node_type(node_type)
        return dict((field, layout) for (nt, pi, field), layout in self.filter_positions.items()
                    if (nt, pi) == (node_type, pmu_index))

    def decode_selector(self, node_type, event_number, selector, fields=None, pmu_index=0):
        """
        Decode a full, already-read pmu_event_sel without device access.
        Use filter positions loaded from the event database's F records.
        Optional fields maps hardware names to (bit position, width) and
        overrides that layout. Unknown automatic fields display as '?'; an
        incomplete explicit layout raises KeyError. Legacy CSV/sysfs data
        retains its historical single filter byte at bits [39:32].
        """
        cmn_config.check_integer(selector, "PMU event selector", maximum=(1 << 64) - 1)
        cmn_config.check_integer(event_number, "event number")
        canonical_type = self.canonical_node_type(node_type)
        code = event_number & self.event_masks.get((canonical_type, pmu_index), event_number)
        if (canonical_type, pmu_index, code) not in self.hardware_events:
            return self.get_event(node_type, event_number, pmu_index=pmu_index, filter=(selector >> 32) & 0xff)
        e = self.get_event(node_type, event_number, pmu_index=pmu_index)
        if e is None:
            return None
        explicit_fields = fields is not None
        if fields is None:
            fields = self.selector_fields(node_type, pmu_index=pmu_index)
        values = {}
        for field in e.filter_fields:
            if field not in fields and not explicit_fields:
                continue
            pos, width = fields[field]
            cmn_config.check_integer(pos, "filter position", maximum=63)
            cmn_config.check_integer(width, "filter width", minimum=1, maximum=64-pos)
            values[field] = (selector >> pos) & ((1 << width) - 1)
        order = sorted(values, key=lambda field: fields[field][0])
        return self.get_event(node_type, event_number, pmu_index=pmu_index, filters=values, filter_order=order)

    def to_json(self):
        j = []
        pk = None
        tj = None
        for e in self.events():
            tk = (e.node_type, e.pmu_index)
            if tk != pk:
                tj = []
                tjm = {
                    "NodeType": ("0x%x" % e.node_type),
                    "PMUIndex": e.pmu_index,
                    "Events": tj
                }
                j.append(tjm)       # reference: tj will be updated while referred to
                pk = tk
            ej = {
                "EventName": e.pmu_event_name,
                "EventCode": ("0x%x" % e.event_number),
            }
            if e.description:
                ej["BriefDescription"] = e.description
            if e.filter_fields:
                ej["FilterFields"] = list(e.filter_fields)
            if e.filters:
                ej["Filters"] = e.filters
            if e.filter is not None:
                ej["Filter"] = e.filter
            if e.filter2 is not None:
                ej["Filter2"] = e.filter2
            tj.append(ej)
        return j

    def events(self, node_type=None):
        """
        Yield events ordered by (node_type, event_number [, filter])
        Optionally, filter by node type.
        """
        if node_type is not None:
            node_type = self.canonical_node_type(node_type)
        events = list(self.events_by_node_ix.values()) + list(self.event_aliases.values())
        for e in sorted(events, key=lambda e: (e.node_type, e.pmu_index, e.event_number,
                                              tuple(sorted(e.filters.items())),
                                              -1 if e.filter is None else e.filter,
                                              e.pmu_event_name or "")):
            if node_type is None or node_type == e.node_type:
                yield e

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
            print("%s" % (e), end="")
            if e.description:
                print(" - %s" % e.description, end="")
            print()

    def load(self, fn):
        """
        Load .events records or a legacy CSV event file.
        """
        if not str(fn).endswith(".csv"):
            return self.load_records(fn)
        n_added = 0
        with open(fn) as f:
            for ln in f:
                lns = ln.strip()
                if not lns or lns.startswith('#'):
                    continue
                x = lns.split(',', 5)
                nt = int(x[0], 16)        # node type
                pi = int(x[1])            # PMU index (usually zero)
                en = int(x[2], 16)        # event number
                fi = int(x[3], 16) if x[3] else None   # sub-field (filter) value
                mn = x[4] if x[4] else None      # mnemonic
                de = x[5] if x[5] else None      # descriptive text
                e = self.add(node_type=nt, pmu_index=pi, event_number=en, filter=fi, pmu_event_name=mn, description=de, allow_duplicates=False)
                n_added += 1
        if o_verbose:
            print("cmn_events: %u events added from %s" % (n_added, fn),
                  file=sys.stderr)
        return self

    def load_records(self, fn):
        """
        Load the order-independent record format documented in data/events/README.md.
        Validate references after collecting the complete file. Hardware selectors
        and exact software aliases are indexed separately, since several aliases
        can share a code and Linux filters do not identify hardware fields.
        """
        records = []
        with open(fn) as f:
            for lineno, line in enumerate(f, 1):
                tokens = line.split()
                if not tokens or tokens[0].startswith('#'):
                    continue
                records.append((lineno, tokens))

        def number(s):
            n = int(s, 16 if s.lower().startswith("0x") else 10)
            return cmn_config.check_integer(n, "event data value")

        def put(table, key, value):
            if key in table:
                raise ValueError("duplicate record for %s" % (key,))
            table[key] = value

        uses = {}
        aliases = []
        new_events = []
        sizes = {"N": 3, "M": 4, "F": 6, "E": 5, "U": 5, "V": 5, "X": 7}
        for lineno, t in records:
            try:
                kind = t[0]
                if kind == "A":
                    if len(t) < 7:
                        raise ValueError("incomplete A record")
                    aliases.append((lineno, t))
                    continue
                if kind not in sizes or len(t) != sizes[kind]:
                    raise ValueError("unknown record or wrong field count: %s" % kind)
                nt = number(t[1])
                if kind == "N":
                    put(self.node_aliases, nt, number(t[2]))
                elif kind == "V":
                    put(self.filter_values, (nt, t[2], number(t[3])), t[4])
                elif kind == "F":
                    pi, field = number(t[2]), t[3]
                    pos = cmn_config.check_integer(number(t[4]), "filter position", maximum=63)
                    width = cmn_config.check_integer(number(t[5]), "filter width", minimum=1, maximum=64-pos)
                    for (other_nt, other_pi, other_field), (other_pos, other_width) in self.filter_positions.items():
                        if (nt, pi) == (other_nt, other_pi) and field != other_field:
                            if pos < other_pos + other_width and other_pos < pos + width:
                                raise ValueError("overlapping filter fields: %s and %s" % (field, other_field))
                    put(self.filter_positions, (nt, pi, field), (pos, width))
                else:
                    pi, code = number(t[2]), number(t[3])
                    k = (nt, pi, code)
                    if kind == "M":
                        put(self.event_masks, (nt, pi), code)
                    elif kind == "E":
                        e = self.add(node_type=nt, pmu_index=pi, event_number=code,
                                     pmu_event_name=t[4], add_name=False, allow_duplicates=False)
                        self.hardware_events.add(k)
                        new_events.append((lineno, k, e))
                    elif kind == "U":
                        if k not in uses:
                            uses[k] = {}
                        put(uses[k], t[4], lineno)
                    elif kind == "X":
                        if t[6] != "no_count":
                            raise ValueError("unsupported X effect: %s" % t[6])
                        xkey = k + (t[4], number(t[5]))
                        if xkey in self.event_no_counts:
                            raise ValueError("duplicate X record")
                        self.event_no_counts.add(xkey)
            except (ValueError, TypeError) as ex:
                raise ValueError("%s:%u: %s" % (fn, lineno, ex))
        try:
            for nt in self.node_aliases:
                self.canonical_node_type(nt)
            for nt, pi, field in self.filter_positions:
                if self.canonical_node_type(nt) != nt:
                    raise ValueError("F node type must be canonical")
            for k in uses:
                if k not in self.hardware_events:
                    raise ValueError("U references unknown event %s" % (k,))
            for nt, pi, code, field, value in self.event_no_counts:
                if field not in uses.get((nt, pi, code), {}):
                    raise ValueError("X references unused filter %s" % field)
                if (nt, pi, field) in self.filter_positions:
                    width = self.filter_positions[(nt, pi, field)][1]
                    cmn_config.check_integer(value, "X filter value", maximum=(1 << width) - 1)
            for lineno, k, e in new_events:
                positions = self.selector_fields(e.node_type, pmu_index=e.pmu_index)
                e.filter_fields = tuple(sorted(uses.get(k, {}), key=lambda field: (positions.get(field, (64, 0))[0], field)))
                if not e.filter_fields and e.event_number != 0:
                    self.events_by_pmu_event_name.setdefault(e.pmu_event_name, []).append(e)
        except ValueError as ex:
            raise ValueError("%s: %s" % (fn, ex))
        names = set()
        for lineno, t in aliases:
            try:
                nt, pi, raw_id = number(t[1]), number(t[2]), number(t[3])
                if self.canonical_node_type(nt) != nt:
                    raise ValueError("A node type must be canonical")
                code = raw_id & self.event_masks.get((nt, pi), raw_id)
                base = self.events_by_node_ix.get((nt, pi, code))
                if base is None:
                    raise ValueError("A references unknown event")
                values = {}
                for token in t[7:]:
                    field, value = token.split("=")
                    put(values, field, number(value))
                if set(values) != set(base.filter_fields):
                    raise ValueError("A must specify each used hardware filter exactly once")
                for field, value in values.items():
                    if (nt, pi, field) in self.filter_positions:
                        width = self.filter_positions[(nt, pi, field)][1]
                        cmn_config.check_integer(value, "A filter value", maximum=(1 << width) - 1)
                name = t[4]
                if name in names:
                    raise ValueError("duplicate software name: %s" % name)
                names.add(name)
                e = Event(self, node_type=nt, pmu_index=pi, event_number=raw_id,
                          pmu_event_name=name, filter=None if t[5] == "-" else number(t[5]))
                e.filter2 = None if t[6] == "-" else number(t[6])
                e.filter_fields = base.filter_fields
                e.filters = values
                e.is_alias = True
                e.no_count = any((nt, pi, code, field, value) in self.event_no_counts for field, value in values.items())
                put(self.event_aliases, (nt, pi, raw_id, tuple(sorted(values.items()))), e)
                # An unfiltered A replaces the E default for name-to-perf lookup.
                if not base.filter_fields and base.pmu_event_name in self.events_by_pmu_event_name:
                    defaults = self.events_by_pmu_event_name[base.pmu_event_name]
                    if base in defaults:
                        defaults.remove(base)
                    if not defaults:
                        del self.events_by_pmu_event_name[base.pmu_event_name]
                existing = self.events_by_pmu_event_name.get(name, [])
                if existing:
                    raise ValueError("duplicate software name: %s" % name)
                self.events_by_pmu_event_name[name] = [e]
            except (ValueError, TypeError) as ex:
                raise ValueError("%s:%u: %s" % (fn, lineno, ex))
        if o_verbose:
            print("cmn_events: %u selectors and %u aliases added from %s" %
                  (len(new_events), len(aliases), fn), file=sys.stderr)
        return self

    def dump_f(self, f):
        """
        Export software event mappings as legacy CSV (takes file object).
        Hardware field definitions and decoding labels require .events data.
        """
        n_written = 0
        overridden = set((e.node_type, e.pmu_index,
                          e.event_number & self.event_masks.get((e.node_type, e.pmu_index), e.event_number))
                         for e in self.event_aliases.values())
        for e in self.events():
            k = (e.node_type, e.pmu_index, e.event_number)
            if k in self.hardware_events and not e.is_alias:
                if e.filter_fields or k in overridden:
                    continue
            flds = [hex(e.node_type), str(e.pmu_index), hex(e.event_number)]
            if e.filter is None and e.filter2 is not None:
                raise ValueError("legacy CSV cannot represent filter2 without filter")
            fi = filters_to_str([e.filter, e.filter2]) if e.filter2 is not None else e.filter
            flds.append(hex(fi) if fi is not None else "")
            flds.append(e.pmu_event_name if e.pmu_event_name is not None else "")
            flds.append(e.description if e.description is not None else "")
            print(','.join(flds), file=f)
            n_written += 1
        return n_written

    def dump(self, fn):
        """
        Dump the event set to a CSV file. Handles "-" meaning stdout.
        (There doesn't seem to be a nice pattern for this.)
        """
        if fn == "-":
            n_written = self.dump_f(sys.stdout)
            fn = "stdout"
        else:
            with open(fn, "w") as f:
                if fn.endswith(".json"):
                    json.dump(self.to_json(), f, indent=4)
                    n_written = len(list(self.events()))
                else:
                    n_written = self.dump_f(f)
        if o_verbose:
            print("cmn_events: %u events written to %s" % (n_written, fn),
                  file=sys.stderr)


def load_events(fn):
    """
    Create a new event set, loaded from a file.
    """
    return Events().load(fn)


def filters_to_str(filters):
    """
    For historical reasons, filters are encoded in a single integer.
    """
    if not filters:
        return ""
    n_filters = len(filters)
    if n_filters > 2:
        raise ValueError("at most two perf filters are supported")
    n = cmn_config.check_integer(filters[0], "first perf filter", maximum=0x7ff if n_filters == 2 else None)
    if n_filters == 2:
        n |= (0x800) | (cmn_config.check_integer(filters[1], "second perf filter") << 12)
    return n


def _sysfs_events_iter():
    """
    Yield all the named events for arm_cmn on the current system.
    TBD: Currently, we pick arm_cmn_0 on the assumption that mesh configurations are the same.
    """
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
            # Watchpoints are handled specially, and have multiple sub-fields.
            continue
        type = int(m["type"], 16)
        if "eventid" not in m:
            # possibly dtc_cycles
            #print("%30s  %s" % (e, m))
            continue
        en = int(m["eventid"], 16)
        n_filters = len(m.keys()) - 2
        if n_filters >= 1:
            if n_filters >= 2:
                # maybe a 'filter2': we can cope with one subfield, but not more
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


def events_dir():
    """
    Events definitions are in the 'events' directory of this module's parent directory.
    """
    edir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data/events")
    if not os.path.isdir(edir):
        raise OSError("event definitions directory not found: %s" % edir)
    return edir


def print_event_catalogues():
    """
    List bundled event catalogues, event counts (including aliases) and node types.
    Read only local event data files; no target or Linux PMU access is needed.
    """
    directory = events_dir()
    print("%-32s %8s  %s" % ("Catalogue", "Events", "Node types"))
    for name in sorted(os.listdir(directory)):
        if not name.endswith((".events", ".csv")):
            continue
        fn = os.path.join(directory, name)
        if os.path.isfile(fn):
            events = load_events(fn)
            node_types = ", ".join(cmn_node_type_str(nt).lower().replace("-", "")
                                   for nt in events.node_types())
            print("%-32s %8u  %s" % (name, len(list(events.events())), node_types))


def event_file_name(product_id, revision=None):
    """
    Find the closest .events release for a product ID or CMNConfig.
    revision may be an rxpy string, (major, patch) pair, or peripheral revision
    code. Compare major releases first, then patches, preferring the older
    release in a tie. With no revision, choose the newest available file.
    Retain the legacy CSV path if this product has no .events files.
    """
    if isinstance(product_id, cmn_config.CMNConfig):
        cfg = product_id
        product_id = cfg.product_id
        if revision is None:
            if cfg.revision_override is not None:
                revision = cfg.revision_override
            elif cfg.revision_code is not None:
                cfg = cmn_config.CMNConfig(product_id=product_id, revision_code=cfg.clipped_revision_code)
                revision = cfg.product_name(revision=True).split()[-1]
    cmn_config.check_integer(product_id, "CMN product ID")
    if isinstance(revision, cmn_config.integer_types):
        return event_file_name(cmn_config.CMNConfig(product_id=product_id, revision_code=revision))
    if isinstance(revision, basestring):
        match = re.match(r"^r([0-9]+)(?:p([0-9]+))?$", revision.lower())
        if match is None:
            raise ValueError("invalid event release: %s" % revision)
        revision = (int(match.group(1)), int(match.group(2) or 0))
    if revision is not None:
        if not isinstance(revision, (tuple, list)) or len(revision) != 2:
            raise TypeError("event release must be rxpy, a pair, or a revision code")
        revision = tuple(cmn_config.check_integer(v, "event release") for v in revision)
    product = cmn_config.product_id_str(product_id).lower().replace("-", "").replace(" ", "")
    candidates = []
    for fn in os.listdir(events_dir()):
        match = re.match(r"^%s-r([0-9]+)(?:p([0-9]+)|-package)\.events$" % re.escape(product), fn)
        if match is not None:
            release = (int(match.group(1)), int(match.group(2) or 0))
            candidates.append((release, fn))
    if candidates:
        if revision is None:
            release, fn = max(candidates)
        else:
            release, fn = min(candidates, key=lambda item: (abs(item[0][0] - revision[0]),
                                                           abs(item[0][1] - revision[1]), item[0], item[1]))
        return os.path.join(events_dir(), fn)
    fn = "cmn-events-%04x.csv" % (product_id)
    return os.path.join(events_dir(), fn)


#
# The Linux PMU driver has different names for HN-F and HN-S events, following the product.
# Our perf recipes etc. use the HN-F events and we have a translation map here.
# Caller must find out if their mesh uses HN-S.
#
hns_events = {
    "hnf_slc_sf_cache_access": "hns_slc_sf_cache_access_all",
    "hnf_cache_miss": "hns_cache_miss_all",
    "hnf_sf_hit": "hns_sf_hit_all",
    "hnf_mc_reqs": "hns_mc_reqs_local_all",
    "hnf_mc_retries": "hns_mc_retries_local_all",
    "hnf_pocq_reqs_recvd": "hns_pocq_reqs_recvd_all",
    "hnf_pocq_retry": "hns_pocq_retry_all",
    "hnf_qos_pocq_occupancy_all": "hns_qos_pocq_occupancy_all",
    "hnf_qos_pocq_occupancy_read": "hns_qos_pocq_occupancy_read",
    "hnf_qos_pocq_occupancy_write": "hns_qos_pocq_occupancy_write",
    "hnf_qos_pocq_occupancy_atomic": "hns_qos_pocq_occupancy_atomic",
}


def main(argv):
    global o_verbose
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str, help="input .events or legacy CSV file")
    parser.add_argument("--cmn-product", type=(lambda x:int(x, 16)), help="CMN product id")
    parser.add_argument("--cmn-revision", help="CMN release, e.g. r2p0 (default: newest event file)")
    parser.add_argument("--add-sysfs", action="store_true", help="add events from the local Linux host's sysfs (only when requested)")
    parser.add_argument("--list", action="store_true", help="list events from the selected source, or bundled catalogues with event counts and node types if no source is selected")
    parser.add_argument("-o", "--output", type=str, help="output CSV file")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    if opts.cmn_revision and not opts.cmn_product:
        parser.error("--cmn-revision requires --cmn-product")
    o_verbose = opts.verbose
    if not (opts.input or opts.cmn_product or opts.add_sysfs):
        if opts.list:
            print_event_catalogues()
        else:
            parser.print_help()
        return
    E = Events()
    if opts.input:
        E.load(opts.input)
    if opts.cmn_product:
        fn = event_file_name(opts.cmn_product, opts.cmn_revision)
        E.load(fn)
    if opts.add_sysfs:
        _add_sysfs_events(E)
    if opts.verbose or not (opts.list or opts.output):
        print("cmn_events: %u events, %u node types" %
              (len(list(E.events())), len(list(E.node_types()))), file=sys.stderr)
        print("cmn_events: node types: %s" % str(E.node_types()), file=sys.stderr)
    if opts.output:
        E.dump(opts.output)    # Dump to CSV file
    if opts.list:
        E.print()


if __name__ == "__main__":
    main(sys.argv[1:])
