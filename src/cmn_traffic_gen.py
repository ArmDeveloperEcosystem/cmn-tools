#!/usr/bin/python3

"""
Generate traffic from a CPU

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys
import os
import subprocess
import tempfile
import atexit

import cmn_perfcheck


o_verbose = 0

o_lmbench = None
o_perf_bin = "perf"


# Traffic generation. We need to generate a rapid stream of traffic to the
# interconnect, which can then be detected by measurement.
# The easiest way to generate traffic is to read a large memory buffer.
# We either use a small C program, or (if provided), lmbench bw_mem.
# The user can supply an approximate run time for each measurement.
# (1 second is usually enough). The time doesn't need to be accurate,
# so we haven't bothered setting up a calibration phase - the factors
# in the loop counts below should give reasonable results.

_gen_c = """
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    long N = atol(argv[1]);
    long size_M = atol(argv[2]);
    size_t sz = size_M << 20;
    long i;
    int x = 0;
    int volatile *m = (int *)malloc(sz);
    memset((void *)m, 0xcc, sz);      /* avoid sharing a zero page */
    fprintf(stderr, "generating load %luMB\\n", size_M);  /* match lmbench */
    for (i = 0; i < N*12; ++i) {
        long j;
        for (j = 0; j < size_M*1024*1024/sizeof(int); j += 4) {
            &ACCESS;
        }
    }
    return x;
}
"""


ACCESSOR_READ = "x += m[j]"
ACCESSOR_ATOMIC = "x += __atomic_xor_fetch(m+j, 1, __ATOMIC_RELAXED)"


g_generator_exe_acc = None


def _gen_generator():
    """
    Compile a traffic generator from a fragment of C.
    """
    o_atomic = False
    accessor = ACCESSOR_ATOMIC if o_atomic else ACCESSOR_READ
    global g_generator_exe_acc
    if g_generator_exe_acc is not None and g_generator_exe_acc[1] == accessor:
        # Previously compiled by this process, reuse it.
        return g_generator_exe_acc[0]
    src = _gen_c.replace("&ACCESS", accessor)
    if o_verbose >= 3:
        print()
        print(src)
        print()
    (fd, g_generator_exe) = tempfile.mkstemp(suffix=".exe")
    os.close(fd)
    g_generator_exe_acc = (g_generator_exe, accessor)
    atexit.register(os.remove, g_generator_exe)
    cmd = "cc -O2 -Wall -Werror -xc - -o %s" % (g_generator_exe)
    if o_verbose:
        print(">>> %s" % cmd, file=sys.stderr)
    p = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(src.encode())
    (out, err) = p.communicate()
    if p.returncode != 0:
        print("compiler out: %s" % out)
        print("compiler err: %s" % err)
        sys.exit(1)
    if o_verbose >= 3:
        os.system("objdump -d %s" % g_generator_exe)
    return g_generator_exe


def cpu_gen_traffic(cpu, events=["instructions"], time=0.1, size_M=16, perf_bin=None):
    """
    Generate traffic, and return performance events
    """
    if perf_bin is None:
        perf_bin = o_perf_bin
    if o_lmbench is not None:
        cmd = "%s/bw_mem -N %u %uM rd" % (o_lmbench, int(time*100), size_M)
    else:
        exe = _gen_generator()
        cmd = "%s %u %u" % (exe, int(time*100), size_M)
    if cpu is not None:
        cmd = "taskset -c %u %s" % (cpu, cmd)
    if events:
        elist = ",".join(events)
        cmd = "%s stat -x, -e %s -- %s" % (perf_bin, elist, cmd)
    if o_verbose >= 2:
        print(">>> %s" % cmd, file=sys.stderr)
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    if o_verbose >= 2:
        print("out: %s" % out, file=sys.stderr)
        print("err: %s" % err, file=sys.stderr)
    if p.returncode != 0:
        if cmn_perfcheck.check_cmn_pmu_events():
            # CMN PMU events appear to be available, so what happened?
            errs = err.decode()
            print("%s" % errs, file=sys.stderr)
        sys.exit(1)
    if not events:
        return []
    elines = err.decode().split('\n')
    ecounts = []
    for e in elines[1:]:    # first line is lmbench output, skip it
        if not e:
            continue
        f = e.split(',')
        if f[0] == "<not supported>":
            # We cannot get any further. Either the CMN events are not present
            # or we don't have permission to use them.
            print("CMN hardware events are not accessible: ", file=sys.stderr, end="")
            check_cmn_pmu_events()
            sys.exit(1)
        r = int(f[0])
        ecounts.append(r)
    if o_verbose >= 2:
        print("counts: %s" % (ecounts))
    return ecounts


if __name__ == "__main__":
    import argparse
    def cpu_list(s):
        ls = []
        for x in s.split(','):
            if '-' in x:
                (lo, hi) = x.split('-')
                ls += list(range(int(lo), int(hi)+1))
            else:
                ls += int(x)
        return ls
    parser = argparse.ArgumentParser(description="generate traffic from CPU")
    parser.add_argument("-c", "--cpu-list", type=cpu_list, default=[None], help="pin generator to CPU")
    parser.add_argument("--time", type=float, default=1.0, help="approximate run time")
    parser.add_argument("--size", type=int, default=16, help="workload size in MB")
    parser.add_argument("--perf-bin", type=str, default="perf", help="path to perf bin")
    parser.add_argument("--lmbench-bin", type=str, default=None, help="path to lmbench bin")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    o_lmbench = opts.lmbench_bin
    for cpu in opts.cpu_list:
        cpu_gen_traffic(cpu, time=opts.time, size_M=opts.size, perf_bin=opts.perf_bin)
