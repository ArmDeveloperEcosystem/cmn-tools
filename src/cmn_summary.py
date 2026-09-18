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


def cpu_frequency(perf):
    """
    Return estimated current CPU frequency (for some typical CPU) in Hz.
    This assumes a homogeneous system.
    """
    return (perf.cpu_frequency(), "measured")


def cmn_frequency(C, perf):
    """
    Use the cached mesh frequency when available, otherwise measure it with perf.
    """
    if C.frequency is not None:
        return (C.frequency, "cached")
    else:
        return (perf.cmn_frequency(instance=C.cmn_seq), "measured")


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
                self.speed = d.c_speed_mts or d.p_speed_mts
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


def summary_groups(S, perf):
    """
    Build summary entries, retaining perf for frequency measurements when evaluated.
    """
    groups = []
    if S is not None and S.CMNs:
        meshes = list(S.CMNs)
        n_meshes = len(meshes)
        # Count each mesh once; use the same counts for grouping, totals and rows.
        counts = [(len(list(mesh.home_nodes())), len(list(mesh.sn_ids())),
                   len(list(mesh.nodes(CMN_PROP_CCG)))) for mesh in meshes]
        disabled_counts = [(sum(n.is_disabled() for n in mesh.home_nodes()),
                            sum(n.is_disabled() for n in mesh.nodes()) +
                            sum(xp.is_disabled() for xp in mesh.XPs())) for mesh in meshes]
        first = meshes[0]
        same_meshes = all(
            mesh.product_config == first.product_config and
            (mesh.dimX, mesh.dimY, mesh.home_node_type()) ==
            (first.dimX, first.dimY, first.home_node_type()) and count == counts[0]
            for mesh, count in zip(meshes, counts)) and all(
                count == disabled_counts[0] for count in disabled_counts)
        group_CMN = [("CMN meshes in system", None, n_meshes)]
        groups.append(("CMN", group_CMN))
        if n_meshes > 1:
            group_CMN.extend([
                ("HN-F/S count in system", None, sum(h for h, s, c in counts)),
                ("SN count in system", None, sum(s for h, s, c in counts)),
                ("CCG count in system", None, sum(c for h, s, c in counts)),
            ])
        if n_meshes > 1 and any(total for home, total in disabled_counts):
            group_CMN.extend([
                ("Disabled HN-F/S count in system", None, sum(h for h, t in disabled_counts)),
                ("Disabled node count in system", None, sum(t for h, t in disabled_counts)),
            ])
        for mesh, (n_home, n_sn, n_ccg), (disabled_home, disabled_total) in zip(meshes, counts, disabled_counts):
            if mesh.product_config is None:
                entries = [("CMN version", None, "unknown configuration")]
            else:
                entries = [(name, None, value) for name, value in mesh.product_config.summary_fields()]
            shared_meshes = n_meshes if same_meshes else 1
            entries.extend([
                (per_mesh_name("Mesh X/Y config", shared_meshes), None, "%u x %u" % (mesh.dimX, mesh.dimY)),
                ("Home-node type", None, cmn_json.home_node_type(mesh)),
                (per_mesh_name("HN-F/S count", shared_meshes), None, n_home),
                (per_mesh_name("SN count", shared_meshes), None, n_sn),
                # The topology does not record cache capacity per home node.
                (per_mesh_name("SLC capacity per HN", shared_meshes), memsize_str, None),
                (per_mesh_name("CCG count", shared_meshes), None, n_ccg),
            ])
            if disabled_total:
                entries.extend([
                    (per_mesh_name("Disabled HN-F/S count", shared_meshes), None, disabled_home),
                    (per_mesh_name("Disabled node count", shared_meshes), None, disabled_total),
                ])
            if same_meshes:
                group_CMN.extend(entries)
                break
            groups.append((cmn_label(mesh), [("CMN instance", None, mesh.cmn_seq)] + entries))
        for mesh in meshes:
            name = "CMN frequency" if n_meshes == 1 else "%s frequency" % cmn_label(mesh)
            group_CMN.append((name, freq_str, lambda mesh=mesh: cmn_frequency(mesh, perf)))

    group_Memory = [
        ("Size",                  memsize_str,  mem_size),
        ("Memory channels",       None,         mem_channels),
        ("DDR width",             "bits",       mem_width),
        ("DDR speed",             "MT/s",       mem_speed),
        ("Total DDR bandwidth",   None,         lambda: ("%s / s" % memsize_str(mem_bandwidth(), decimal=True))),
    ]

    group_CPU = [
        ("CPU core version",      None,         lambda: ("0x%08x" % cpu_identification())),
        ("CPU last level cache",  memsize_str,  slc_size),
        ("CPU frequency",         freq_str,     lambda: cpu_frequency(perf)),
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
    parser.add_argument("--perf-bin", type=str, default="perf", help="override 'perf' command")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    perf = cmn_perfstat.Perf(perf_bin=opts.perf_bin)
    S = cmn_json.load_system_for_cli(missing_ok=True)
    if S is None and o_verbose:
        print("CMN descriptor not available: showing local system information only", file=sys.stderr)
    groups = summary_groups(S, perf)
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
