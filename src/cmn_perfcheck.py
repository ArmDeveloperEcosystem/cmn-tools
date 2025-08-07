#!/usr/bin/python3

"""
Check that CMN perf driver is installed and available.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN events will need the arm-cmn module to be built or installed
into the kernel, and also generally need
  sysctl kernel.perf_event_paranoid=0.

This module doesn't check that the "perf" command is installed and working.
"""

from __future__ import print_function

import os
import sys
import subprocess


o_perf_bin = "perf"

o_verbose = 0


try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError    # Python2


class CMNNoPerf(OSError):
    """
    Raise this exception if the CMN PMU driver isn't installed.
    """
    def __str__(self):
        return "CMN PMU driver is not installed"


def is_cmn_pmu_installed():
    """
    Return true if the arm-cmn driver has loaded and registered.
    """
    return os.path.exists("/sys/bus/event_source/devices/arm_cmn_0")


def check_cmn_pmu_installed():
    """
    Check that the arm-cmn driver is loaded, else throw CMNNoPerf.
    """
    if not is_cmn_pmu_installed():
        raise CMNNoPerf


def _uname_r():
    try:
        return os.uname().release
    except AttributeError:
        return os.uname()[2]      # Python2


def linux_lib_modules():
    return "/lib/modules/" + _uname_r()


def perf_event_paranoid():
    """
    Return the current setting of kernel.perf_event_paranoid
    """
    return int(open("/proc/sys/kernel/perf_event_paranoid").read())


def _check_perf_timed(e, t):
    """
    Check that an event can be obtained from perf, by trying to measure it.
    Several possible outcomes:
      perf command not found
      perf command gives unexpected output
      perf reports event "unsupported" etc.
      perf counts 0
      perf counts non-zero
    """
    cmd = "%s stat -a -x, -e %s -- sleep %f" % (o_perf_bin, e, t)
    if o_verbose >= 2:
        print(">>> %s" % cmd, file=sys.stderr)
    p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = p.communicate()
    rc = p.returncode
    if rc != 0:
        print("err: %s" % err.decode(), file=sys.stderr)
        return None
    try:
        (n, _) = err.decode().split(',', 1)
        if o_verbose:
            print("%s => %s" % (e, n), file=sys.stderr)
        n = int(n)
    except ValueError:
        return False
    return n > 0


def _check_perf(e):
    """
    Check that an event can be obtained from perf, by measuring it.
    We start with a small interval and increase it if we read zero.
    """
    t = 0.001
    while t < 0.11:
        n = _check_perf_timed(e, t)
        if n is None or n > 0:
            break
        t *= 10.0
    return n


def check_perf():
    """
    Check that the "perf" command is installed.
    """
    try:
        _check_perf("dummy")
        return True
    except FileNotFoundError as e:
        # "perf" command not installed
        if o_verbose:
            print(e, file=sys.stderr)
        return False
    except Exception as e:
        if o_verbose:
            print("error when running 'perf': %s" % e, file=sys.stderr)
        return False


def check_cmn_perf():
    """
    Check that perf can access CMN PMU events.
    """
    return _check_perf("arm_cmn/hnf_pocq_reqs_recvd/") or _check_perf("arm_cmn/hns_pocq_reqs_recvd_all/")


def check_watchpoints(chn=0):
    """
    Check if CMN watchpoints generally work, by setting up an open watchpoint on a given channel.
    """
    wp = "watchpoint_up,wp_chn_sel=%u,wp_dev_sel=0,wp_grp=0,wp_val=0,wp_mask=0xffffffffffffffff" % chn
    return _check_perf("arm_cmn/%s/" % wp)


def check_rsp_dat_dvm_watchpoints():
    """
    Check if security settings allow watchpoints to observe RSP/DAT/DVM.
    See README-cmn.md "Security and Observability".
    """
    return check_watchpoints(chn=1)


def linux_kernel_version(s):
    try:
        (kmaj, kmin, _) = s.split('.', 2)
        kmaj = int(kmaj)
        kmin = int(kmin)
        return (kmaj, kmin)
    except Exception:
        return (None, None)


assert linux_kernel_version("5.11.0-46") == (5, 11)


def check_hw_pmu_events(file=None):
    """
    Check permissions for hardware events generally.
    """
    if file is None:
        file = sys.stderr
    p = perf_event_paranoid()
    if p > 0:
        # Driver is there but we don't have permissions? Check perf_event_paranoid
        # on the assumption we're an unprivileged user. If we're sudo then this
        # should have worked regardless.
        print("** You might not have permission to read hardware events",
              file=file)
        print("**   kernel.perf_event_paranoid=%d - use sysctl to set it lower" % p,
              file=file)
        return False
    else:
        if o_verbose:
            print("  kernel.perf_event_paranoid=%d - hardware PMU events can be accessed non-root." % p,
                file=file)
    if not check_perf():
        print("** perf command is not installed", file=file)
        return False
    return True


def check_cmn_pmu_events(file=None, check_rsp_dat=True):
    """
    Check that CMN PMU events are available, and report any problems.
    We could do this pre-emptively or after a problem.
    perf's error reporting on trying to use CMN events is inconsistent:
      - with perf_event_paranoid=2, it succeeds, but events are "<not supported>"
      - with perf_event_paranoid=1, it fails with a message about privilege
      - with perf_event_paranoid=0, it runs successfully
    """
    if file is None:
        file = sys.stderr
    if o_verbose:
        print("CMN perf check:", file=file)
    if not is_cmn_pmu_installed():
        # Check for very old kernels (e.g. Ubuntu 20.04 with 5.8)
        kname = _uname_r()
        (kmaj, kmin) = linux_kernel_version(kname)
        if kmaj is not None and (kmaj < 5 or (kmaj == 5 and kmin < 10)):
            print("** CMN PMU driver is not installed - this kernel (%s) is too old" % kname,
                  file=file)
            return False
        print("** CMN PMU driver is not installed - load driver or reconfigure kernel",
              file=file)
        mods = linux_lib_modules()
        if not os.path.isdir(mods):
            print("** %s not found:" % mods, file=file)
            print("** install linux-modules-extra-%s" % kname, file=file)
        fn = mods + "/kernel/drivers/perf/arm-cmn.ko"
        if not os.path.isfile(fn) and not os.path.isfile(fn + ".zst"):
            print("** %s not found:" % fn, file=file)
            print("** reconfigure kernel or install linux-modules-extra-%s" % _uname_r(), file=file)
        else:
            print("** Try 'sudo modprobe arm_cmn'", file=file)
        return False
    else:
        if o_verbose:
            print("  CMN PMU driver is installed.", file=file)
    if not check_hw_pmu_events(file=file):
        return False
    if not check_cmn_perf():
        print("**  perf cannot access CMN events", file=file)
        return False
    else:
        if o_verbose:
            print("  perf can access CMN events", file=file)
    if not check_watchpoints():
        # This is unexpected - if events are working, REQ watchpoints should be
        print("** CMN watchpoints are not working", file=file)
    if check_rsp_dat and not check_rsp_dat_dvm_watchpoints():
        print("** CMN watchpoints cannot be set on RSP/DAT/DVM packets - see README-cmn.md for background",
              file=file)
    else:
         if o_verbose:
             print("    CMN watchpoints can monitor all channels (REQ, RSP, SNP, DAT).", file=file)
    return True


def check_cpu_pmu_events(file=None):
    return check_hw_pmu_events(file=file)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="check if CMN PMU driver is installed")
    parser.add_argument("--perf-bin", type=str, default="perf", help="path to perf binary")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_perf_bin = opts.perf_bin
    o_verbose = opts.verbose
    is_installed = is_cmn_pmu_installed()
    print("CMN PMU driver is installed: %s" % is_installed)
    pep = perf_event_paranoid()
    print("perf_event_paranoid: %u" % pep)
    print("Checking for CMN PMU events:")
    check_cmn_pmu_events()
    print("Checking for CPU hardware PMU events:")
    check_cpu_pmu_events()
