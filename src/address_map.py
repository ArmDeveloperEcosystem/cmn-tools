#!/usr/bin/python

"""
Map non-overlapping inclusive address ranges to caller-provided data.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import bisect


def ranges_overlap(start1, end1, start2, end2):
    """Return whether two inclusive ranges overlap."""
    return start1 <= end2 and start2 <= end1


class AddressRange(object):
    """One inclusive address range and its associated data."""

    def __init__(self, start, end, data):
        if start > end:
            raise ValueError(
                "address range starts after it ends: 0x%x-0x%x" %
                (start, end))
        self._start = start
        self._end = end
        self.data = data

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        return self._end

    def contains(self, addr):
        return self.start <= addr and addr <= self.end

    def overlaps(self, start, end):
        return ranges_overlap(self.start, self.end, start, end)

    def __iter__(self):
        # Allow convenient tuple unpacking while retaining named attributes.
        return iter((self.start, self.end, self.data))

    def __repr__(self):
        return "AddressRange(0x%x, 0x%x, %r)" % (
            self.start, self.end, self.data)


class AddressMap(object):
    """
    Map non-overlapping inclusive address ranges to data.

    Ranges are kept in start-address order. Address lookup is O(log n);
    adding a range is O(n) because it may require inserting into the lists.
    """

    def __init__(self):
        self._ranges = []
        self._starts = []

    def __len__(self):
        return len(self._ranges)

    def __iter__(self):
        """Iterate over AddressRange objects in ascending address order."""
        return iter(self._ranges)

    def ranges(self):
        """Iterate over AddressRange objects in ascending address order."""
        return iter(self._ranges)

    def items(self):
        """Iterate over (start, end, data) tuples in address order."""
        for r in self._ranges:
            yield (r.start, r.end, r.data)

    def add(self, start, end, data):
        """
        Add an inclusive address range and return its AddressRange object.

        Raise ValueError if the range is invalid or overlaps an existing range.
        Adjacent ranges are allowed.
        """
        r = AddressRange(start, end, data)
        ix = bisect.bisect_left(self._starts, start)
        if ix > 0 and self._ranges[ix - 1].end >= start:
            raise ValueError(
                "address range 0x%x-0x%x overlaps 0x%x-0x%x" %
                (start, end, self._ranges[ix - 1].start,
                 self._ranges[ix - 1].end))
        if ix < len(self._ranges) and self._ranges[ix].start <= end:
            raise ValueError(
                "address range 0x%x-0x%x overlaps 0x%x-0x%x" %
                (start, end, self._ranges[ix].start,
                 self._ranges[ix].end))
        self._starts.insert(ix, start)
        self._ranges.insert(ix, r)
        return r

    def find(self, addr):
        """Return the AddressRange containing addr, or None."""
        ix = bisect.bisect_right(self._starts, addr) - 1
        if ix >= 0 and self._ranges[ix].contains(addr):
            return self._ranges[ix]
        return None

    def lookup(self, addr, default=None):
        """Return the data associated with addr, or default."""
        r = self.find(addr)
        if r is None:
            return default
        return r.data

    def __getitem__(self, addr):
        """Return data associated with addr, raising KeyError if unmapped."""
        r = self.find(addr)
        if r is None:
            raise KeyError(addr)
        return r.data
