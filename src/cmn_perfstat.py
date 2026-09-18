#!/usr/bin/python3

"""
Collect perf values for a set of CMN events (or events in general).

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN events will need the arm-cmn module to be built or installed
into the kernel, and also generally need
  sysctl kernel.perf_event_paranoid=0.
"""

from __future__ import print_function

import re
import errno
import math
import operator
import sys
import time as modtime

import cmn_perfcheck


try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)


class PerfNotAvailable(OSError):
    def __init__(self, event_name=None):
        self.event_name = event_name

    def __str__(self):
        s = "Perf events not available"
        if self.event_name is not None:
            s += " (event='%s')" % self.event_name
        s += " - run cmn_perfcheck.py"
        return s


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
        if time is not None and self.value is not None:
            # Calculate the rate of occurrence of the event, e.g. N transactions per second.
            self.rate = self.value / _duration(time)
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


def _duration(time):
    """
    Require a positive, finite measurement duration.
    """
    time = float(0.1 if time is None else time)
    if math.isnan(time) or math.isinf(time) or time <= 0:
        raise ValueError("measurement time must be positive and finite")
    return time


def _event_list(events):
    """
    Materialize event arguments without splitting commas or perf event groups.
    """
    if isinstance(events, string_types):
        raise TypeError("events must be a sequence of event specifiers")
    events = list(events)
    for event in events:
        if not isinstance(event, string_types):
            raise TypeError("event specifiers must be strings")
        if not event.strip() or "\0" in event:
            raise ValueError("event specifiers must be nonempty and contain no NUL")
    return events


def _reading(fields, time):
    """
    Parse count, unit, event, runtime and scheduling fraction from perf stat -x.
    See perf-stat(1), CSV FORMAT:
    https://man7.org/linux/man-pages/man1/perf-stat.1.html#CSV_FORMAT
    Extra metric columns do not affect the counter reading.
    """
    if len(fields) < 5 or not fields[2]:
        raise ValueError("incomplete perf counter record: %s" % repr(fields))
    count, unit, event, running, fraction = fields[:5]
    if count == "<not supported>":
        raise PerfNotAvailable(event)
    if count == "<not counted>":
        return None
    try:
        count = float(count)
        runtime = float(running)
        fraction = float(fraction) / 100.0
    except ValueError:
        raise ValueError("invalid numeric field in perf record: %s" % repr(fields))
    for value in [count, runtime, fraction]:
        if math.isnan(value) or math.isinf(value) or value < 0:
            raise ValueError("invalid numeric field in perf record: %s" % repr(fields))
    if fraction > 1.0:
        raise ValueError("perf scheduling fraction exceeds 100 percent")
    return Reading(scaled_value=count, time_running_ns=running,
                   fraction_running=fraction, event=event, time=time)


def _counter_lines(output):
    """
    Ignore blank lines, comments and metric-only continuation records.
    """
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [field.strip() for field in line.split("|")]
        # perf-stat(1) specifies empty counter fields for additional metrics.
        if len(fields) >= 5 and not any(fields[:5]):
            continue
        yield fields


def _parse_aggregate(output, events, time):
    """
    Return one Reading (or None for an uncounted event) per event argument.
    """
    counts = [_reading(fields, time) for fields in _counter_lines(output)]
    if len(counts) != len(events):
        raise ValueError("perf returned %u counts for %u events" % (len(counts), len(events)))
    return counts


def _node_index(node_name):
    m = re.match(r'^(?:N(?:ODE)?)?([0-9]+)$', node_name, re.I)
    if m is None:
        raise ValueError("invalid NUMA node in perf output: %s" % node_name)
    return int(m.group(1))


def _parse_per_node(output, events, time):
    """
    Return a list indexed by NUMA node. Missing nodes have None for each event.
    Present nodes must report exactly one record per event, in event order.
    No reported nodes gives an empty list.
    """
    node_counts = {}
    for fields in _counter_lines(output):
        if len(fields) < 6:
            raise ValueError("incomplete per-node perf record: %s" % repr(fields))
        node_ix = _node_index(fields[0])
        # The node prefix may include the number of aggregated CPUs.
        # With no CPU-count column, fields[2] is the unit, not the counter.
        offset = 1
        try:
            float(fields[2])
            offset = 2
        except ValueError:
            if fields[2] in ["<not supported>", "<not counted>"]:
                offset = 2
        if offset == 2:
            try:
                n_cpus = int(fields[1])
            except ValueError:
                raise ValueError("invalid CPU count in perf record: %s" % repr(fields))
            if n_cpus < 0:
                raise ValueError("negative CPU count in perf record")
        reading = _reading(fields[offset:], time)
        if node_ix not in node_counts:
            node_counts[node_ix] = []
        node_counts[node_ix].append(reading)
    if not node_counts:
        return []
    for node_ix, readings in node_counts.items():
        if len(readings) != len(events):
            raise ValueError("perf node %u returned %u counts for %u events" %
                             (node_ix, len(readings), len(events)))
    return [node_counts.get(node_ix, [None] * len(events))
            for node_ix in range(max(node_counts) + 1)]


def _plan_chunks(events, time, chunk_size, verbose):
    """
    Divide the total measurement duration equally among event-list chunks.
    Event arguments, including any perf groups, are kept intact.
    chunk_size=None disables chunking.
    """
    events = _event_list(events)
    time = _duration(time)
    if chunk_size is not None:
        chunk_size = operator.index(chunk_size)
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive or None")
    if not events:
        return [], time
    if chunk_size is None:
        chunk_size = len(events)
    chunks = [events[i:i+chunk_size] for i in range(0, len(events), chunk_size)]
    if len(chunks) > 1 and verbose:
        print("split %u events into %u chunks" % (len(events), len(chunks)))
    return chunks, time / len(chunks)


def _scale_chunk(readings, n_chunks):
    """
    Extrapolate each value to the total requested duration, leaving its rate
    and original scheduling-scaled count unchanged.
    """
    for reading in readings:
        if reading is not None:
            reading.value *= n_chunks


class Perf(object):
    """
    One configured perf executable, shared by measurements and availability checks.
    Construction only stores settings; it does not launch processes or probe PMUs.
    The executable is trusted configuration, never shell text. Events, duration,
    workload and chunk size belong to each measurement, not to this object.
    """
    def __init__(self, perf_bin="perf", verbose=0):
        self.perf_bin = perf_bin
        self.verbose = verbose

    def run_stat(self, events, command, system_wide=True, per_node=False, separator="|"):
        """
        Execute perf stat and return stdout, stderr, return code and elapsed time.
        Callers interpret the output: measurements need full counter records,
        availability checks only need a count, and traffic has generator output.
        """
        cmd = [self.perf_bin, "stat"]
        if per_node:
            cmd += ["--per-node"]
        cmd += ["-x" + separator]
        if system_wide:
            cmd += ["-a"]
        for event in _event_list(events):
            cmd += ["-e", event]
        cmd += ["--"] + cmn_perfcheck.command_arguments(command)
        return cmn_perfcheck.run_command(cmd, verbose=self.verbose)

    def _collect(self, events, time, command, system_wide, per_node):
        """
        Sleep measurements use the requested duration; workloads use elapsed time.
        """
        if command is None:
            time = _duration(time)
            workload = ["sleep", str(time)]
        else:
            workload = command
        out, err, rc, elapsed = self.run_stat(events, workload, system_wide=system_wide, per_node=per_node)
        if rc != 0:
            raise PerfNotAvailable
        if command is not None:
            time = _duration(elapsed)
            if self.verbose:
                print("measured time %.2f" % time)
        return err.decode(), time

    def raw(self, events, time=None, command=None, system_wide=True):
        """
        Return aggregate Reading objects, counting system-wide by default.
        command may be an argument list or a quoted string; no shell is invoked.
        With no command, measure during sleep for time seconds (default 0.1).
        CPU events need a workload rather than sleep for meaningful measurements.
        """
        events = _event_list(events)
        if not events:
            return []
        output, time = self._collect(events, time, command, system_wide, False)
        return _parse_aggregate(output, events, time)

    def raw_per_node(self, events, time=None, command=None):
        """
        Return per-node CPU PMU readings, with one list per NUMA node index.
        Missing nodes have None for each event; no reported nodes gives [].
        """
        events = _event_list(events)
        if not events:
            return []
        output, time = self._collect(events, time, command, True, True)
        return _parse_per_node(output, events, time)

    def raw_chunked(self, events, time=None, chunk_size=1000):
        """
        Return aggregate readings, optionally splitting events into chunks.
        chunk_size=1 measures individually; None disables chunking.
        """
        chunks, time = _plan_chunks(events, time, chunk_size, self.verbose)
        counts = []
        for chunk in chunks:
            readings = self.raw(chunk, time=time)
            _scale_chunk(readings, len(chunks))
            counts.extend(readings)
        return counts

    def raw_per_node_chunked(self, events, time=None, chunk_size=1000):
        """
        Return per-node readings for chunked measurements.
        A node absent from any chunk has None entries for that chunk's events.
        """
        chunks, time = _plan_chunks(events, time, chunk_size, self.verbose)
        counts = []
        n_previous = 0
        for chunk in chunks:
            chunk_counts = self.raw_per_node(chunk, time=time)
            while len(counts) < len(chunk_counts):
                counts.append([None] * n_previous)
            for node_ix, readings in enumerate(counts):
                new_readings = (chunk_counts[node_ix] if node_ix < len(chunk_counts)
                                else [None] * len(chunk))
                _scale_chunk(new_readings, len(chunks))
                readings.extend(new_readings)
            n_previous += len(chunk)
        return counts

    def stat(self, events, time=None, chunk_size=1000):
        """
        Return counts extrapolated to the total measurement duration.
        """
        readings = self.raw_chunked(events, time=time, chunk_size=chunk_size)
        return [(r.value if r is not None else None) for r in readings]

    def rate(self, events, time=None, chunk_size=1000):
        """
        Return event counts per second, or None for uncounted events.
        """
        readings = self.raw_chunked(events, time=time, chunk_size=chunk_size)
        return [(r.rate if r is not None else None) for r in readings]

    def rate_per_node(self, events, time=None, chunk_size=1000):
        """
        Return event rates in lists indexed by NUMA node, then by event.
        """
        readings = self.raw_per_node_chunked(events, time=time, chunk_size=chunk_size)
        return [[(r.rate if r is not None else None) for r in row] for row in readings]

    def _rate1(self, event, time=None, system_wide=True, command=None):
        reading = self.raw([event], time=time, system_wide=system_wide, command=command)[0]
        return reading.rate if reading is not None else None

    def cmn_frequency(self, instance=0, time=None):
        """
        Get one mesh's CMN frequency in Hz, using its DTC cycle counter.
        DTC must count continuously, generally requiring disabled clock-gating
        (the kernel does this automatically from 6.12 onwards).
        The kernel counts one cycle regardless of the number of DTCs in a mesh.
        Select a mesh explicitly: arm_cmn/dtc_cycles/ would add counts across
        meshes, which may also be running at different frequencies.
        """
        cmn_perfcheck.check_cmn_pmu_installed()
        return self._rate1("arm_cmn_%u/dtc_cycles/" % instance, time=time)

    def cpu_frequency(self, time=0.1):
        """
        Get a random CPU's frequency in Hz while running a spin loop.
        On Arm, cpu-cycles does not count during WFx waits, so sleep is unsuitable.
        Use the generic cpu-cycles event rather than the Arm-specific cpu_cycles.
        """
        cmd = [sys.executable, __file__, "--xx-spin"]
        if time is not None:
            cmd += ["--time=%f" % _duration(time)]
        return self._rate1("cpu-cycles", time=time, system_wide=False, command=cmd)

    def _check_event_timed(self, event, time):
        """
        Probe an event: True means a nonzero count, False means zero or an
        unparseable count, and None means perf returned an error.
        A missing executable (including a broken perf wrapper) raises CMNNoPerfCommand.
        Note that there are assumptions elsewhere that we can do "check_event(hnf_...)"
        on an HN-S based system and this will return False and not throw.
        """
        try:
            out, err, rc, elapsed = self.run_stat([event], ["sleep", "%f" % _duration(time)], separator=",")
        except OSError as error:
            if error.errno == errno.ENOENT:
                raise cmn_perfcheck.CMNNoPerfCommand(self.perf_bin)
            raise
        if rc != 0:
            if err.decode().startswith("WARNING: perf not found"):
                raise cmn_perfcheck.CMNNoPerfCommand(self.perf_bin)
            return None
        try:
            n, _ = err.decode().split(',', 1)
            if self.verbose >= 2:
                print("%s => %s" % (event, n), file=sys.stderr)
            n = int(n)
        except ValueError:
            return False
        return n > 0

    def check_event(self, event):
        """
        Probe an event, retrying at longer intervals if no nonzero count is seen.
        """
        t = 0.001
        while t < 0.11:
            n = self._check_event_timed(event, t)
            if n is None or n > 0:
                break
            t *= 10.0
        return n

    def is_installed(self):
        """
        Check whether this perf executable can be invoked.
        """
        try:
            self.check_event("dummy")
            return True
        except cmn_perfcheck.CMNNoPerfCommand:
            return False
        except Exception as error:
            if self.verbose:
                print("error when running 'perf': %s" % error, file=sys.stderr)
            return False

    def check_cmn_events(self, file=None, check_rsp_dat=True):
        """
        Check CMN event availability and report driver or permission problems.
        """
        return cmn_perfcheck.check_cmn_pmu_events(file=file, check_rsp_dat=check_rsp_dat, perf=self)

    def check_cpu_events(self, file=None):
        """
        Check CPU event availability and report permission problems.
        """
        return cmn_perfcheck.check_cpu_pmu_events(file=file, perf=self)


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="get PMU events")
    parser.add_argument("--time", type=float, default=1.0, help="time to wait")
    parser.add_argument("--frequency", action="store_true", help="show CMN frequency")
    parser.add_argument("--cmn-instance", type=int, default=0, help="CMN instance for frequency")
    parser.add_argument("-e", "--event", type=str, action="append", default=[], help="events to count")
    parser.add_argument("--perf-bin", type=str, default="perf", help="perf command")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("--xx-spin", action="store_true", help=argparse.SUPPRESS)
    opts = parser.parse_args(argv)
    perf = Perf(perf_bin=opts.perf_bin, verbose=opts.verbose)
    if opts.xx_spin:
        # only used when we invoke ourselves recursively
        t_end = modtime.time() + opts.time
        while modtime.time() < t_end:
            pass
        sys.exit()
    done = False
    if opts.frequency:
        print("CPU frequency: %s" % perf.cpu_frequency(time=opts.time))
        print("CMN frequency: %s" % perf.cmn_frequency(time=opts.time, instance=opts.cmn_instance))
        done = True
    if opts.event:
        print(perf.stat(opts.event, time=opts.time))
        done = True
    if not done:
        print("Use --event or --frequency")


if __name__ == "__main__":
    main(sys.argv[1:])
