#!/usr/bin/python3

"""
Summarize system configuration, as described in
"System Discovery Requirements" in the CMN performance methodology.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Note: some figures reported are per mesh instance, not system-wide.
"""

from __future__ import print_function

import cmn_json
import cmn_perfstat
from cmn_enum import *
import multiprocessing
from dmi import DMI

import sys

if sys.version_info[0] == 2:
    PermissionError = OSError
    FileNotFoundError = IOError


o_verbose = 0


S = cmn_json.system_from_json_file()
C = S.CMNs[0]


def memsize_str(n):
    for u in range(4, 0, -1):
        if n >= (1 << (u*10)):
            return "%.3g%sb" % ((float(n) / (1 << (u*10))), "BKMGT"[u])
    return str(n)


assert memsize_str(1024*1024) == "1Mb"


def cpu_prop(s, cpu=0):
    return open("/sys/devices/system/cpu/cpu%u/%s" % (cpu, s)).read()


def cpu_identification():
    midr = int(cpu_prop("regs/identification/midr_el1"), 16)
    return midr


def n_cpus():
    return multiprocessing.cpu_count()


def popcount(x):
    return bin(x).count('1')


def slc_size():
    """
    Get the system cache size by looking at a CPU's last-level cache
    as described in the topology description - generally from ACPI PPTT.
    """
    max_level = 0
    max_index = None
    for i in range(0, 9):
        try:
            level = int(cpu_prop("cache/index%u/level" % i))
        except FileNotFoundError as e:
            if o_verbose >= 2:
                print("file not found: %s" % (e), file=sys.stderr)
            break
        if level > max_level:
            max_index = i
            max_level = level
    slc = "cache/index%u/" % max_index
    n_ways = int(cpu_prop(slc + "ways_of_associativity"))
    line   = int(cpu_prop(slc + "coherency_line_size"))
    sets   = int(cpu_prop(slc + "number_of_sets"))
    return line * sets * n_ways


def n_sockets():
    core0_package_cpus = int(cpu_prop("topology/package_cpus").replace(',',''), 16)
    n_cpus_per_package = popcount(core0_package_cpus)
    return n_cpus() // n_cpus_per_package


def cpu_frequency():
    return cmn_perfstat.cpu_frequency()


def cmn_frequency():
    try:
        return (C.frequency, "cached")
    except AttributeError:
        return (cmn_perfstat.cmn_frequency(), "measured")


class MemoryProperties:
    """
    Get system memory properties by decoding DMI table.
    Will generally require root privilege.
    """
    def __init__(self):
        self.speed = None          # MT/s
        self.n_channels = None
        self.data_width = None
        try:
            for d in DMI().memory():
                self.speed = d.c_speed_mts
                self.data_width = d.d_width
                # DDR5 (DMI mem_type >= 0x20) physically have 2 32-bit channels,
                # but in DMI reporting, they are reported as 64-bit.
                # So we treat it as 1x64 rather than 2x32.
                if self.n_channels is None:
                    self.n_channels = 0
                self.n_channels += 1
        except FileNotFoundError:
            if o_verbose:
                print("Can't get memory properties from DMI", file=sys.stderr)
            pass

    def total_bandwidth(self):
        if self.data_width is None:
            return None
        n_bytes = self.data_width // 8
        return n_bytes * self.n_channels * (self.speed * 1000000)


g_mem = None


def mem_props():
    global g_mem
    if g_mem is None:
        g_mem = MemoryProperties()
    return g_mem


def mem_speed():
    m = mem_props()
    return m.speed if m is not None else None


def mem_channels():
    m = mem_props()
    return m.n_channels if m is not None else None


def mem_bandwidth():
    m = mem_props()
    return m.total_bandwidth() if m is not None else None


group_CMN = [
    ("CMN version",           lambda: S.cmn_version().product_name(revision=True)),
    ("CHI",                   lambda: S.cmn_version().chi_version_str()),
    ("CMN frequency",         lambda: ("%.0f (%s)" % cmn_frequency())),
    ("Mesh X/Y config",       lambda: ("%u x %u" % (C.dimX, C.dimY))),
    ("HN-F/S count",          lambda: len(list(C.home_nodes()))),
    ("SN count",              lambda: len(list(C.sn_ids()))),
    ("SLC capacity per HN",   lambda: memsize_str((slc_size() // len(list(C.home_nodes()))))),
    ("CCG count",             lambda: len(list(C.nodes(CMN_PROP_CCG)))),
]


group_Memory = [
    ("Memory channels",       lambda: mem_channels()),
    ("DDR speed",             lambda: mem_speed()),
    ("Total bandwidth",       lambda: ("%s / s" % memsize_str(mem_bandwidth()))),
]


group_CPU = [
    ("CPU core version",      lambda: ("0x%08x" % cpu_identification())),
    ("CPU frequency",         lambda: cpu_frequency()),
    ("CPU sockets in system", lambda: n_sockets()),
    ("CPU cores in system",   lambda: n_cpus()),
]


group_IO = [
]


groups = [
    ("CMN",    group_CMN),
    ("Memory", group_Memory),
    ("CPU",    group_CPU),
    ("IO",     group_IO),
]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Show major system parameters")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    for (gname, group) in groups:
        gname_printed = False
        for (pname, par) in group:
            if not gname_printed:
                print("%s:" % gname)
                gname_printed = True
            if callable(par):
                try:
                    par = par()
                except PermissionError:
                    par = "<no permission - rerun as sudo>"
                except Exception as e:
                    par = None
                    if o_verbose:
                        if o_verbose >= 2:
                            par = "<exception (%s): %s>" % (type(e).__name__, str(e))
                        else:
                            par = "<exception in script: %s>" % (type(e).__name__)
            if par is None:
                par = "<not available>"
            print("  %30s: %s" % (pname, par))
