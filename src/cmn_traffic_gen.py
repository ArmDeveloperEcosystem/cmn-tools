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
o_atomic_line_size = 64
o_atomic_page_size = 4096
o_keep_exe = False


# Traffic generation. We need to generate a rapid stream of traffic to the
# interconnect, which can then be detected by measurement.
# The easiest way to generate traffic is to read a large memory buffer.
# We either use a small C program, or (if provided), lmbench bw_mem.
# The user can supply an approximate run time for each measurement.
# (1 second is usually enough). The time doesn't need to be accurate,
# so we haven't bothered setting up a calibration phase - the factors
# in the loop counts below should give reasonable results.

_gen_read_c = """
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


_gen_atomic_store_eor_c = """
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>

#if !defined(__aarch64__)
#error "Atomic tagged traffic generation requires AArch64"
#endif

struct worker_args {
    volatile uint8_t *target;
    volatile uint32_t *line_word;
    volatile int *go;
    long loops;
    int cpu;
    uint32_t seed;
};

static void atomic_store_eor_u8(volatile uint8_t *p, uint32_t value)
{
    asm volatile("steorb %w[val], [%[ptr]]"
                 :
                 : [ptr] "r" (p), [val] "r" (value)
                 : "memory");
}

static int pin_to_cpu(int cpu)
{
    cpu_set_t set;
    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        return EINVAL;
    }
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

static void *issuer_thread(void *argp)
{
    struct worker_args *a = (struct worker_args *)argp;
    uint32_t v = a->seed;
    long i;
    if (pin_to_cpu(a->cpu) != 0) {
        return (void *)1;
    }
    while (!*a->go) { }
    for (i = 0; i < a->loops; ++i) {
        atomic_store_eor_u8(a->target, v);
        v = (v << 1) | (v >> 31);
    }
    return 0;
}

static void *contender_thread(void *argp)
{
    struct worker_args *a = (struct worker_args *)argp;
    uint32_t v = a->seed;
    long i;
    if (pin_to_cpu(a->cpu) != 0) {
        return (void *)1;
    }
    while (!*a->go) { }
    for (i = 0; i < a->loops; ++i) {
        *a->line_word = v;
        v = (v << 5) ^ (v >> 2) ^ 0x9e3779b9u;
    }
    return 0;
}

int main(int argc, char **argv)
{
    long N = atol(argv[1]);
    long loops = N * 100000;
    size_t page_size = 4096;
    size_t line_size = 64;
    size_t sz = page_size;
    int n_entries = argc - 2;
    int max_threads = 0;
    void *base = NULL;
    pthread_t *threads = NULL;
    struct worker_args *args = NULL;
    int thread_count = 0;
    volatile int go = 0;
    int ei;
    for (ei = 0; ei < n_entries; ++ei) {
        const char *spec = argv[ei + 2];
        const char *last_colon = strrchr(spec, ':');
        max_threads += 1;     /* issuer */
        if (last_colon != NULL && strcmp(last_colon + 1, "-") != 0) {
            max_threads += 1; /* first contender */
            while (*last_colon) {
                if (*last_colon == '.') {
                    ++max_threads;
                }
                ++last_colon;
            }
        }
    }
    if (posix_memalign(&base, page_size, sz) != 0 || base == NULL) {
        fprintf(stderr, "failed to allocate page-aligned atomic buffer\\n");
        return 2;
    }
    memset(base, 0, sz);
    threads = (pthread_t *)calloc(max_threads, sizeof(*threads));
    args = (struct worker_args *)calloc(max_threads, sizeof(*args));
    if (threads == NULL || args == NULL) {
        fprintf(stderr, "failed to allocate thread state\\n");
        return 2;
    }
    fprintf(stderr, "generating batched AtomicStoreEOR traffic\\n");
    for (ei = 0; ei < n_entries; ++ei) {
        char *spec = strdup(argv[ei + 2]);
        char *saveptr = NULL;
        char *saveptr_cont = NULL;
        char *contenders;
        char *tok;
        unsigned long issuer_cpu;
        unsigned long line_index;
        unsigned long byte_offset;
        size_t line_off;
        size_t store_word_off;
        volatile uint8_t *target;
        volatile uint32_t *line_word;
        if (spec == NULL) {
            fprintf(stderr, "failed to duplicate entry spec\\n");
            return 2;
        }
        tok = strtok_r(spec, ":", &saveptr);
        if (tok == NULL) {
            fprintf(stderr, "bad entry spec\\n");
            free(spec);
            return 2;
        }
        issuer_cpu = strtoul(tok, NULL, 0);
        tok = strtok_r(NULL, ":", &saveptr);
        if (tok == NULL) {
            fprintf(stderr, "bad entry spec\\n");
            free(spec);
            return 2;
        }
        line_index = strtoul(tok, NULL, 0);
        tok = strtok_r(NULL, ":", &saveptr);
        if (tok == NULL) {
            fprintf(stderr, "bad entry spec\\n");
            free(spec);
            return 2;
        }
        byte_offset = strtoul(tok, NULL, 0);
        contenders = strtok_r(NULL, ":", &saveptr);
        line_off = (line_index * line_size);
        if ((line_off + byte_offset + sizeof(uint8_t)) > sz) {
            fprintf(stderr, "entry spec exceeds page: %s\\n", argv[ei + 2]);
            free(spec);
            return 2;
        }
        store_word_off = (byte_offset < sizeof(uint32_t)) ? sizeof(uint32_t) : 0;
        if ((line_off + store_word_off + sizeof(uint32_t)) > sz) {
            fprintf(stderr, "line word exceeds page: %s\\n", argv[ei + 2]);
            free(spec);
            return 2;
        }
        target = (volatile uint8_t *)((char *)base + line_off + byte_offset);
        line_word = (volatile uint32_t *)((char *)base + line_off + store_word_off);
        args[thread_count].target = target;
        args[thread_count].line_word = line_word;
        args[thread_count].go = &go;
        args[thread_count].loops = loops;
        args[thread_count].cpu = (int)issuer_cpu;
        args[thread_count].seed = (uint32_t)(0x10001u + issuer_cpu);
        if (pthread_create(&threads[thread_count], NULL, issuer_thread, &args[thread_count]) != 0) {
            fprintf(stderr, "failed to create issuer thread\\n");
            return 2;
        }
        ++thread_count;
        if (contenders != NULL && strcmp(contenders, "-") != 0) {
            char *cont = strtok_r(contenders, ".", &saveptr_cont);
            while (cont != NULL) {
                unsigned long contender_cpu = strtoul(cont, NULL, 0);
                args[thread_count].target = target;
                args[thread_count].line_word = line_word;
                args[thread_count].go = &go;
                args[thread_count].loops = loops;
                args[thread_count].cpu = (int)contender_cpu;
                args[thread_count].seed = (uint32_t)(0x20001u + contender_cpu + issuer_cpu);
                if (pthread_create(&threads[thread_count], NULL, contender_thread, &args[thread_count]) != 0) {
                    fprintf(stderr, "failed to create contender thread\\n");
                    free(spec);
                    return 2;
                }
                ++thread_count;
                cont = strtok_r(NULL, ".", &saveptr_cont);
            }
        }
        free(spec);
    }
    go = 1;
    for (ei = 0; ei < thread_count; ++ei) {
        void *status = 0;
        pthread_join(threads[ei], &status);
        if (status != 0) {
            fprintf(stderr, "worker thread failed to pin to a CPU\\n");
            return 2;
        }
    }
    free(args);
    free(threads);
    free(base);
    return 0;
}
"""

GEN_READ = "read"
GEN_ATOMIC_STORE_EOR = "atomic-store-eor"


g_generator_exes = {}


class TrafficMeasurementInconclusive(RuntimeError):
    pass


class TrafficMeasurementError(RuntimeError):
    pass


def atomic_entry(cpu, line_index=0, byte_offset=1, contenders=None):
    if contenders is None:
        contenders = []
    return {
        "cpu": cpu,
        "line_index": line_index,
        "byte_offset": byte_offset,
        "contenders": list(contenders),
    }


def atomic_entry_spec(entry):
    contenders = ".".join([str(c) for c in entry.get("contenders", [])]) or "-"
    return "%u:%u:%u:%s" % (entry["cpu"], entry["line_index"], entry["byte_offset"], contenders)


def _gen_generator(mode=GEN_READ):
    """
    Compile a traffic generator from a fragment of C.
    """
    if mode in g_generator_exes:
        return g_generator_exes[mode]
    if mode == GEN_READ:
        src = _gen_read_c.replace("&ACCESS", "x += m[j]")
        cmd = ["cc", "-O2", "-g", "-Wall", "-Werror", "-xc", "-", "-o"]
    elif mode == GEN_ATOMIC_STORE_EOR:
        src = _gen_atomic_store_eor_c
        cmd = ["cc", "-O2", "-g", "-Wall", "-Werror", "-pthread", "-march=armv8.1-a+lse", "-xc", "-", "-o"]
    else:
        raise ValueError("unknown traffic generator mode: %s" % mode)
    if o_verbose >= 3:
        print()
        print(src)
        print()
    (fd, g_generator_exe) = tempfile.mkstemp(suffix=".exe")
    os.close(fd)
    g_generator_exes[mode] = g_generator_exe
    if not o_keep_exe:
        atexit.register(os.remove, g_generator_exe)
    if o_verbose >= 2:
        print(">>> %s %s" % (" ".join(cmd), g_generator_exe), file=sys.stderr)
    p = subprocess.Popen(cmd + [g_generator_exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(src.encode())
    (out, err) = p.communicate()
    if p.returncode != 0:
        print("compiler out: %s" % out)
        print("compiler err: %s" % err)
        sys.exit(1)
    if o_verbose >= 3:
        os.system("objdump -d %s" % g_generator_exe)
    return g_generator_exe


def _run_traffic_command(cmd, events=None, perf_bin=None):
    if perf_bin is None:
        perf_bin = o_perf_bin
    if o_verbose >= 1:
        print("counting %u events" % len(events or []), file=sys.stderr)
    if events:
        elist = ",".join(events)
        cmd = "%s stat -x, -e %s -- %s" % (perf_bin, elist, cmd)
    if o_verbose >= 3:
        print(">>> %s" % cmd, file=sys.stderr)
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    if o_verbose >= 3:
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
    for e in elines[1:]:    # first line is generator output, skip it
        if not e:
            continue
        f = e.split(',')
        count = f[0].strip()
        if count == "<not supported>":
            # We cannot get any further. Either the CMN events are not present
            # or we don't have permission to use them.
            print("CMN hardware events are not accessible: ", file=sys.stderr, end="")
            cmn_perfcheck.check_cmn_pmu_events()
            sys.exit(1)
        if count in ["<not counted>", "<not counted", "<not supported"]:
            raise TrafficMeasurementInconclusive("perf did not count all requested events: %s" % e)
        try:
            r = int(count)
        except ValueError:
            raise TrafficMeasurementError("unexpected perf count field (%s) in line: %s" % (count, e))
        ecounts.append(r)
    if len(ecounts) != len(events):
        raise TrafficMeasurementInconclusive("perf returned %u counts for %u events" % (len(ecounts), len(events)))
    if o_verbose >= 2:
        print("counts: %s" % (ecounts))
    return ecounts


def cpu_gen_traffic(cpu, events=["instructions"], time=0.1, size_M=16, perf_bin=None):
    """
    Generate traffic, and return performance events
    """
    if o_lmbench is not None:
        cmd = "%s/bw_mem -N %u %uM rd" % (o_lmbench, int(time*100), size_M)
    else:
        exe = _gen_generator(mode=GEN_READ)
        cmd = "%s %u %u" % (exe, int(time*100), size_M)
    if cpu is not None:
        cmd = "taskset -c %u %s" % (cpu, cmd)
    if o_verbose >= 2:
        print("generator: %s" % cmd, file=sys.stderr)
    return _run_traffic_command(cmd, events=events, perf_bin=perf_bin)


def cpus_gen_atomic_traffic(entries, events=["instructions"], time=0.1, perf_bin=None):
    """
    Generate tagged atomic traffic for one or more CPUs. Each entry uses one
    cache line in a shared page, and contender threads can keep ownership of
    that line moving between CPUs.
    """
    exe = _gen_generator(mode=GEN_ATOMIC_STORE_EOR)
    specs = [atomic_entry_spec(e) for e in entries]
    cmd = " ".join([exe, str(int(time*100))] + specs)
    if o_verbose >= 2:
        print("generator: %s" % cmd, file=sys.stderr)
    return _run_traffic_command(cmd, events=events, perf_bin=perf_bin)


def cpu_gen_atomic_traffic(cpu, events=["instructions"], time=0.1, perf_bin=None, line_index=0, byte_offset=1, contenders=None):
    entry = atomic_entry(cpu, line_index=line_index, byte_offset=byte_offset, contenders=contenders)
    return cpus_gen_atomic_traffic([entry], events=events, time=time, perf_bin=perf_bin)


def main(argv):
    global o_keep_exe, o_lmbench, o_verbose
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
    parser.add_argument("--keep-exe", action="store_true", help="keep the generated traffic helper executable")
    parser.add_argument("--atomic", action="store_true", help="generate tagged AtomicStoreEOR traffic")
    parser.add_argument("--line-index", type=int, default=0, help="cache line index within the shared page")
    parser.add_argument("--byte-offset", type=int, default=1, help="byte offset within the selected cache line")
    parser.add_argument("--contenders", type=cpu_list, default=[], help="contender CPUs for the selected cache line")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    o_lmbench = opts.lmbench_bin
    o_keep_exe = opts.keep_exe
    for cpu in opts.cpu_list:
        if opts.atomic:
            cpu_gen_atomic_traffic(cpu, time=opts.time, perf_bin=opts.perf_bin,
                                   line_index=opts.line_index, byte_offset=opts.byte_offset,
                                   contenders=opts.contenders)
        else:
            cpu_gen_traffic(cpu, time=opts.time, size_M=opts.size, perf_bin=opts.perf_bin)


if __name__ == "__main__":
    main(sys.argv[1:])
