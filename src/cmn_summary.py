#!/usr/bin/python

"""
Summarize system configuration, as described in
"System Discovery Requirements" in the CMN performance methodology.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Note: some figures reported are per mesh instance, not system-wide.
"""

from __future__ import print_function

import os
import sys
import json


import cmn_json
import cmn_perfstat
from cmn_enum import *
from dmi import DMI
from memsize_str import memsize_str
import app_data


if sys.version_info[0] == 2:
    PermissionError = IOError
    FileNotFoundError = IOError


o_verbose = 0


def cpu_prop(s, cpu=0):
    return open("/sys/devices/system/cpu/cpu%u/%s" % (cpu, s)).read()


def cpu_identification():
    midr = int(cpu_prop("regs/identification/midr_el1"), 16)
    return midr


def n_cpus():
    """
    Return the number of CPUs, including offline CPUs.
    (multiprocessing.cpu_count() only returns online CPUs.)
    """
    return os.sysconf(os.sysconf_names["SC_NPROCESSORS_CONF"])


def popcount(x):
    return bin(x).count('1')


def slc_size():
    """
    Get the system cache size by looking at a CPU's last-level cache
    as described in the topology description - generally from ACPI PPTT.
    We ignore L1 and L2.

    TBD: this is not a reliable way of establishing CMN SLC size either
    overall or per node. CMN SLC might or might not be declared to the
    system as a LLC. A relatively small CMN SLC might be seen as essentially
    a victim cache for CPU L2 or cluster L3, rather than a true next level
    in the cache hierarchy.
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
        if level >= 3 and level > max_level:
            max_index = i
            max_level = level
    if max_index is None:
        return None
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
    """
    Return estimated current CPU frequency (for some typical CPU) in Hz.
    This assumes a homogeneous system.
    """
    return (cmn_perfstat.cpu_frequency(), "measured")


def cmn_frequency(C):
    if C.frequency is not None:
        return (C.frequency, "cached")
    else:
        return (cmn_perfstat.cmn_frequency(instance=C.cmn_seq), "measured")


def cmn_label(C):
    return "CMN#%u" % C.cmn_seq


def per_mesh_name(name, n_meshes):
    return (name + " per mesh") if n_meshes > 1 else name


class MemoryProperties:
    """
    Get system memory properties by decoding DMI table.
    Will generally require root privilege.
    """
    def __init__(self):
        self.speed = None          # MT/s
        self.n_channels = None
        self.data_width_bits = None
        self.size = 0
        self.discover()

    def is_valid(self):
        return self.speed is not None

    def discover(self):
        try:
            for d in DMI().memory():
                self.size += d.size
                self.speed = d.c_speed_mts
                self.data_width_bits = d.d_width
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
        if self.data_width_bits is None:
            return None
        n_bytes = self.data_width_bits // 8
        return n_bytes * self.n_channels * (self.speed * 1000000)


g_mem = None


class NoMemProperties(OSError):
    pass


def mem_props():
    global g_mem
    if g_mem is None:
        g_mem = MemoryProperties()
    if not g_mem.is_valid():
        raise NoMemProperties
    return g_mem


def mem_size():
    m = mem_props()
    return m.size if m is not None else None


def mem_speed():
    m = mem_props()
    return m.speed if m is not None else None


def mem_channels():
    m = mem_props()
    return m.n_channels if m is not None else None


def mem_width():
    m = mem_props()
    return m.data_width_bits if m is not None else None


def mem_bandwidth():
    m = mem_props()
    return m.total_bandwidth() if m is not None else None


def freq_str(fp):
    (n, how) = fp
    s = "%.2f GHz" % (n / 1e9)
    if how is not None:
        s += " (%s)" % how
    return s


def summary_groups(S):
    groups = []
    C = S.CMNs[0] if S is not None and S.CMNs else None

    if C is not None:
        n_meshes = len(S.CMNs)
        group_CMN = [
            ("CMN meshes in system",   None,         lambda: len(S.CMNs)),
            ("CMN version",           None,         lambda: S.cmn_version().product_name(revision=True)),
            ("CHI",                   None,         lambda: S.cmn_version().chi_version_str()),
            (per_mesh_name("Mesh X/Y config", n_meshes),       None,         lambda: ("%u x %u" % (C.dimX, C.dimY))),
            (per_mesh_name("HN-F/S count", n_meshes),          None,         lambda: len(list(C.home_nodes()))),
            (per_mesh_name("SN count", n_meshes),              None,         lambda: len(list(C.sn_ids()))),
            (per_mesh_name("SLC capacity per HN", n_meshes),   memsize_str,  lambda: ((slc_size() // len(list(C.home_nodes()))))),
            (per_mesh_name("CCG count", n_meshes),             None,         lambda: len(list(C.nodes(CMN_PROP_CCG)))),
        ]
        if n_meshes == 1:
            group_CMN.append(("CMN frequency", freq_str, lambda: cmn_frequency(C)))
        else:
            for mesh in S.CMNs:
                group_CMN.append(("%s frequency" % cmn_label(mesh), freq_str, lambda mesh=mesh: cmn_frequency(mesh)))
        groups.append(("CMN", group_CMN))

    group_Memory = [
        ("Size",                  memsize_str,  mem_size),
        ("Memory channels",       None,         mem_channels),
        ("DDR width",             "bits",       mem_width),
        ("DDR speed",             "MT/s",       mem_speed),
        ("Total DDR bandwidth",   None,         lambda: ("%s / s" % memsize_str(mem_bandwidth()))),
    ]

    group_CPU = [
        ("CPU core version",      None,         lambda: ("0x%08x" % cpu_identification())),
        ("CPU frequency",         freq_str,     cpu_frequency),
        ("CPU sockets in system", None,         n_sockets),
        ("CPU cores in system",   None,         n_cpus),
    ]

    group_IO = [
    ]

    groups.extend([
        ("Memory", group_Memory),
        ("CPU",    group_CPU),
        ("IO",     group_IO),
    ])
    return groups


def json_chr(c):
    return c.lower() if c.lower() in "abcdefghijklmnopqrstuvwxyz0123456789" else "_"


def json_str(s):
    return ''.join([json_chr(c) for c in s])


assert json_str("Mesh X/Y config") == "mesh_x_y_config"


def apply_render(s, render):
    return s if render is None else render(s) if callable(render) else str(s) + " " + render


def main(argv):
    global o_verbose
    import argparse
    parser = argparse.ArgumentParser(description="Show major system parameters")
    parser.add_argument("-o", "--output", type=str, help="JSON output")
    parser.add_argument("--perf-bin", type=str, help="override 'perf' command")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    if opts.perf_bin is not None:
        cmn_perfstat.o_perf_bin = opts.perf_bin
    S = cmn_json.system_from_json_file(exit_if_not_found=False)
    if S is None and o_verbose:
        print("CMN descriptor not available: showing local system information only", file=sys.stderr)
    groups = summary_groups(S)
    j = {}
    for (gname, group) in groups:
        gj = {}
        j[json_str(gname)] = gj
        gname_printed = False
        for (pname, render, par) in group:
            if not gname_printed and not opts.output:
                print("%s:" % gname)
                gname_printed = True
            par_err = None
            if callable(par):
                try:
                    par = par()
                except PermissionError:
                    par = None
                    par_err = "<no permission - rerun as sudo>"
                except Exception as e:
                    par = None
                    if o_verbose:
                        if o_verbose >= 2:
                            par_err = "<exception (%s): %s>" % (type(e).__name__, str(e))
                        else:
                            par_err = "<exception in script: %s>" % (type(e).__name__)
            if par is None and par_err is None:
                par_err = "<not available>"
            if not opts.output:
                if par is not None:
                    par = apply_render(par, render)
                else:
                    par = par_err
                print("  %30s: %s" % (pname, par))
            else:
                if par is not None:
                    gj[json_str(pname)] = par
                    if render is not None:
                        gj[json_str(pname) + "_str"] = apply_render(par, render)
                else:
                    print("%s not available: %s" % (pname, par_err), file=sys.stderr)
    if opts.output:
        if opts.output == "-":
            json.dump(j, sys.stdout, indent=4)
            print()
        else:
            with open(opts.output, "w") as f:
                json.dump(j, f, indent=4)
            app_data.change_to_real_user_if_sudo(opts.output)


if __name__ == "__main__":
    main(sys.argv[1:])
