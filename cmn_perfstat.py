#!/usr/bin/python3

"""
Collect perf values for a set of CMN events (or events in general).

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN events will generally need sysctl kernel.perf_event_paranoid=0.
"""

from __future__ import print_function

import subprocess

o_verbose = 0

o_chunk_size = 1000

o_time = 0.1


class Reading:
    """
    A performance event reading from the Linux perf subsystem.
    Includes the estimated true value, adjusted for scheduling fraction.
    Also includes details of scheduling.
    If a time is provided, the value is also presented a rate (i.e. occurrences per second).
    """
    def __init__(self, scaled_value=None, raw_value=None, time_running_ns=None, fraction_running=None, event=None, time=None, name=None):
        self.name = name
        self.scaled_value = scaled_value
        self.raw_value = raw_value
        self.time_running_ns = time_running_ns
        self.fraction_running = fraction_running
        self.event = event
        if self.scaled_value is not None:
            self.value = self.scaled_value
        elif self.fraction_running == 0.0:
            self.value = None
        else:
            self.value = int(raw_value / fraction_running)
        if time is not None:
            # Calculate the rate of occurrence of the event, e.g. N transactions per second.
            self.rate = self.value / time
        else:
            self.rate = None

    def __str__(self):
        if self.raw_value is not None:
            s = str(self.raw_value)
            if self.fraction_running < 1.0:
                s += " (%.2f%%)" % (self.fraction_running*100.0)
        else:
            s = str(self.value)
        return s


def perf_raw(events, time=None, command=None):
    """
    Given a list of PMU event specifiers (e.g. "arm_cmn/hnf_cache_miss/")
    return a list of Reading objects.
    The event list can be arbitrarily long and we rely on the kernel perf subsystem
    to rotate counters.

    The default perf subprocess is "sleep" so will generally be unscheduled during
    the measurement period - reading CPU events will not return sensible values.
    """
    if time is None:
        time = o_time
    sep = '|'
    cmd = ["perf", "stat", "-x"+sep]
    for event in events:
        cmd += ["-e", event]
    cmd += ["--"]
    if command is None:
        cmd += ["sleep", str(time)]
    else:
        cmd += command.split()
    if o_verbose:
        print(">> %s" % (' '.join(cmd)))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    rc = p.returncode
    if rc != 0 or o_verbose:
        if out:
            print("== out: %s" % out)
        print("== err:\n%s" % err.decode())
    counts = []
    n_invalid = 0
    n_uncounted = 0
    n_valid = 0
    for ln in err.decode().split('\n'):
        if not ln:
            continue
        toks = ln.split(sep)
        if toks[0] == "<not supported>":
            # Invalid specifier, or privilege issue (we can't distinguish)
            n_invalid += 1
            counts.append(None)
        elif toks[0] == "<not counted>":
            # Valid specifier, but we were (presumably) not able to schedule it
            n_uncounted += 1
            counts.append(None)
        else:
            # perf stat has already scaled the value to account for partial scheduling.
            scaled_value = float(toks[0])
            r = Reading(scaled_value=scaled_value, time_running_ns=toks[3], fraction_running=float(toks[4])/100.0, event=toks[2], time=time)
            n_valid += 1
            counts.append(r)
    # The returned list is always one-for-one with the input event list, but may contain None's
    assert len(counts) == len(events), "unexpected: %u events but %u counts" % (len(events), len(counts))
    return counts


def perf_raw_chunked(events, time=None, chunk_size=-2):
    """
    Given a list of PMU event specifiers, return a list of Reading objects.
    The list can optionally be broken into chunks. We only need to do this if
    we suspect the kernel cannot cope with huge lists of events.

    chunk_size = 1     means do every event individually
    chunk_size = None  means don't use chunks
    chunk_size = -2    means use the default in o_chunk_size
    """
    if time is None:
        time = o_time
    n_events = len(events)
    if n_events == 0:
        return []
    if chunk_size == -2:
        chunk_size = o_chunk_size
    if chunk_size is None:
        return perf_raw(events, time=time)
    n_chunks = (n_events + chunk_size - 1) // chunk_size
    assert n_chunks >= 1
    time = time / n_chunks
    if n_chunks > 1 and o_verbose:
        print("split %u events into %u chunks" % (n_events, n_chunks))
    counts = []
    for i in range(n_chunks):
        chunk = events[(i*chunk_size):((i+1)*chunk_size)]
        counts += perf_raw(chunk, time=time)
    assert len(counts) == len(events), "unexpected: %u events but %u counts" % (len(events), len(counts))
    # Each measurement was taken over a shorter duration, so scale them back up
    for c in counts:
        if c is not None:
            c.value *= n_chunks
    return counts


def perf_stat(events, time=None):
    readings = perf_raw_chunked(events, time=time)
    return [(r.value if r is not None else None) for r in readings]


def perf_rate(events, time=None):
    readings = perf_raw_chunked(events, time=time)
    return [(r.rate if r is not None else None) for r in readings]


def _perf_rate1(event, time=None):
    reading = perf_raw([event], time=time)[0]
    return reading.rate if reading is not None else None


def cmn_frequency(time=None):
    """
    Get the CMN frequency, in Hz. This relies on DTC counting continuously
    during the measurement period, which generally requires DTC clock-gating
    to be disabled. The kernel does this automatically from 6.12 onwards.
    """
    return _perf_rate1("arm_cmn/dtc_cycles/")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="get PMU events")
    parser.add_argument("--time", type=float, default=1.0, help="time to wait")
    parser.add_argument("--frequency", action="store_true", help="show CMN frequency")
    parser.add_argument("-e", "--event", type=str, action="append", default=[], help="events to count")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    if opts.frequency:
        print("CMN frequency: %s" % cmn_frequency(time=opts.time))
    print(perf_stat(opts.event, time=opts.time))
