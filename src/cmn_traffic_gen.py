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


o_verbose = 0

o_lmbench = None


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
    fprintf(stderr, "generating load %luMb\\n", size_M);  /* match lmbench */
    for (i = 0; i < N*12; ++i) {
        long j;
        for (j = 0; j < size_M*1024*1024/sizeof(int); j += 4) {
            x += m[j];
        }
    }
    return x;
}
"""

g_generator_exe = None


def _gen_generator():
    global g_generator_exe
    if g_generator_exe is not None:
        return g_generator_exe
    (fd, g_generator_exe) = tempfile.mkstemp(suffix=".exe")
    os.close(fd)
    atexit.register(os.remove, g_generator_exe)
    cmd = "cc -O2 -Wall -Werror -xc - -o %s" % (g_generator_exe)
    if o_verbose:
        print(">>> %s" % cmd, file=sys.stderr)
    p = subprocess.Popen(cmd.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(_gen_c.encode())
    (out, err) = p.communicate()
    if p.returncode != 0:
        print("compiler out: %s" % out)
        print("compiler err: %s" % err)
        sys.exit(1)
    return g_generator_exe


def check_cmn_pmu_events():
    """
    Check that CMN PMU events are available, and report any problems to stderr.
    We could do this pre-emptively or after a problem.
    perf's error reporting on trying to use CMN events is inconsistent:
      - with perf_event_paranoid=2, it succeeds, but events are "<not supported>"
      - with perf_event_paranoid=1, it fails with a message about privilege
      - with perf_event_paranoid=0, it runs successfully
    """
    if not os.path.exists("/sys/bus/event_source/devices/arm_cmn_0"):
        print("CMN PMU driver not loaded - load driver or reconfigure kernel", file=sys.stderr)
        return False
    p = int(open("/proc/sys/kernel/perf_event_paranoid").read())
    if p > 0:
        # Driver is there but we don't have permissions? Check perf_event_paranoid
        # on the assumption we're an unprivileged user. If we're sudo then this
        # should have worked regardless.
        print("CMN PMU driver loaded, but you might not have permission to read hardware events", file=sys.stderr)
        print("kernel.perf_event_paranoid=%d - use sysctl to set it lower" % p, file=sys.stderr)
        return False
    return True


def cpu_gen_traffic(cpu, events=["instructions"], time=0.1, size_M=16):
    """
    Generate traffic, and return performance events
    """
    if o_lmbench is not None:
        cmd = "%s/bw_mem -N %u %uM rd" % (o_lmbench, int(time*100), size_M)
    else:
        exe = _gen_generator()
        cmd = "%s %u %u" % (exe, int(time*100), size_M)
    if cpu is not None:
        cmd = "taskset -c %u %s" % (cpu, cmd)
    if events:
        elist = ",".join(events)
        cmd = "perf stat -x, -e %s -- %s" % (elist, cmd)
    if o_verbose >= 2:
        print(">>> %s" % cmd, file=sys.stderr)
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    if o_verbose >= 2:
        print("out: %s" % out, file=sys.stderr)
        print("err: %s" % err, file=sys.stderr)
    if p.returncode != 0:
        if check_cmn_pmu_events():
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
    parser = argparse.ArgumentParser(description="generate traffic from CPU")
    parser.add_argument("--cpu", type=int, help="pin generator to CPU")
    parser.add_argument("--time", type=float, default=1.0, help="approximate run time")
    parser.add_argument("--size", type=int, default=16, help="workload size in Mb")
    parser.add_argument("--lmbench-bin", type=str, default=None, help="path to lmbench bin")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    o_lmbench = opts.lmbench_bin
    cpu_gen_traffic(opts.cpu, time=opts.time, size_M=opts.size)
