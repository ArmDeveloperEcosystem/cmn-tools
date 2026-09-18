#!/usr/bin/python3

"""
Check that CMN perf driver is installed and available.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN events will need the arm-cmn module to be built or installed
into the kernel, and also generally need
  sysctl kernel.perf_event_paranoid=0.

Also provides argument handling and subprocess execution shared by perf clients.
"""

from __future__ import print_function

import os
import sys
import subprocess
import shlex
import time as modtime


# Defaults for callers which do not supply explicit settings.
o_perf_bin = "perf"

o_verbose = 0


try:
    string_types = (basestring,)
    text_type = unicode
except NameError:
    string_types = (str,)
    text_type = str


class CMNNoPerf(OSError):
    pass


class CMNNoPerfKernelDriver(CMNNoPerf):
    """
    Exception: CMN PMU driver isn't installed.
    """
    def __str__(self):
        return "CMN PMU driver is not installed"


class CMNNoPerfCommand(CMNNoPerf):
    """
    Exception: perf userspace command isn't installed (or is non-functional wrapper).
    """
    def __init__(self, cmd):
        self.cmd = cmd

    def __str__(self):
        return "perf command is not installed: %s" % self.cmd


def command_arguments(command):
    """
    Copy an argument list, or split a command string while respecting quotes.
    This does not invoke a shell or perform shell expansion.
    """
    if isinstance(command, string_types):
        if sys.version_info[0] < 3 and isinstance(command, text_type):
            # Python 2 shlex uses a byte stream; return Unicode arguments again.
            command = [arg.decode("utf-8") for arg in shlex.split(command.encode("utf-8"))]
        else:
            command = shlex.split(command)
    elif isinstance(command, (list, tuple)):
        command = list(command)
    else:
        raise TypeError("command must be a string or an argument list")
    if not command or not command[0]:
        raise ValueError("command must name an executable")
    for arg in command:
        if not isinstance(arg, string_types):
            raise TypeError("command arguments must be strings")
        if "\0" in arg:
            raise ValueError("command arguments must not contain NUL")
    return command


def run_command(command, verbose=0, input_data=None):
    """
    Execute an argument list and return stdout, stderr, return code and elapsed time.
    An explicitly selected executable is trusted configuration; arguments are
    never interpreted as shell text.
    On an exception, stop and reap the child without replacing the original error.
    """
    cmd = command_arguments(command)
    if verbose:
        print(">> %s" % repr(cmd))
    t0 = modtime.time()
    p = subprocess.Popen(cmd, stdin=(subprocess.PIPE if input_data is not None else None),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    completed = False
    try:
        if input_data is None:
            out, err = p.communicate()
        else:
            out, err = p.communicate(input_data)
        completed = True
    finally:
        if not completed:
            # finally preserves the pending exception even when cleanup fails
            # on Python 2. Bare except also covers Java exceptions in Jython.
            try:
                p.kill()
            except:
                pass
            try:
                p.communicate()
            except:
                pass
    elapsed = modtime.time() - t0
    if (p.returncode != 0 and verbose) or verbose >= 2:
        if out:
            print("== out: %s" % out.decode())
        if err:
            print("== err:\n%s" % err.decode())
    return out, err, p.returncode, elapsed


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
        raise CMNNoPerfKernelDriver


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


def _default_perf():
    """
    Construct a perf instance for callers using this module's defaults.
    Import locally because cmn_perfstat uses this module's execution and
    CMN diagnostics. Neither module constructs or probes Perf at import time.
    """
    from cmn_perfstat import Perf
    return Perf(perf_bin=o_perf_bin, verbose=o_verbose)


def is_perf_command_installed(perf=None):
    """
    Check that the "perf" command is installed.
    Use o_perf_bin as the default when no executable is supplied.
    """
    if perf is None:
        perf = _default_perf()
    return perf.is_installed()


def check_cmn_perf(perf=None):
    """
    Check that perf can access CMN PMU events and get non-zero counts.
    We try the HN POCQ reqs event as that's sure to be counting.
    On systems with HN-S, perf tools may still accept "hnf_" events
    (configured from JSON) which will then not be supported by the kernel.
    Or they may support only the kernel published events. Error-handling
    in Perf.check_event() handles both cases.
    """
    if perf is None:
        perf = _default_perf()
    return (perf.check_event("arm_cmn/hnf_pocq_reqs_recvd/") or
            perf.check_event("arm_cmn/hns_pocq_reqs_recvd_all/") or
            perf.check_event("arm_cmn/hns_slc_sf_cache_access_all/"))


def check_watchpoints(chn=0, perf=None):
    """
    Check if CMN watchpoints generally work, by setting up an open watchpoint on a given channel.
    """
    if perf is None:
        perf = _default_perf()
    wp = "watchpoint_up,wp_chn_sel=%u,wp_dev_sel=0,wp_grp=0,wp_val=0,wp_mask=0xffffffffffffffff" % chn
    return perf.check_event("arm_cmn/%s/" % wp)


def check_rsp_dat_dvm_watchpoints(perf=None):
    """
    Check if security settings allow watchpoints to observe RSP/DAT/DVM.
    See README-cmn.md "Security and Observability".
    """
    return check_watchpoints(chn=1, perf=perf)


def linux_kernel_version(s):
    try:
        (kmaj, kmin, _) = s.split('.', 2)
        kmaj = int(kmaj)
        kmin = int(kmin)
        return (kmaj, kmin)
    except Exception:
        return (None, None)


assert linux_kernel_version("5.11.0-46") == (5, 11)


def check_hw_pmu_events(file=None, perf=None):
    """
    Check permissions for hardware events generally.
    """
    if perf is None:
        perf = _default_perf()
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
        if perf.verbose:
            print("  kernel.perf_event_paranoid=%d - hardware PMU events can be accessed non-root." % p,
                file=file)
    if not perf.is_installed():
        print("** perf command is not installed", file=file)
        return False
    return True


def check_cmn_pmu_events(file=None, check_rsp_dat=True, perf=None):
    """
    Check that CMN PMU events are available, and report any problems.
    We could do this pre-emptively or after a problem.
    perf's error reporting on trying to use CMN events is inconsistent:
      - with perf_event_paranoid=2, it succeeds, but events are "<not supported>"
      - with perf_event_paranoid=1, it fails with a message about privilege
      - with perf_event_paranoid=0, it runs successfully
    """
    if perf is None:
        perf = _default_perf()
    if file is None:
        file = sys.stderr
    if perf.verbose:
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
        if perf.verbose:
            print("  CMN PMU driver is installed.", file=file)
    if not check_hw_pmu_events(file=file, perf=perf):
        return False
    if not check_cmn_perf(perf=perf):
        print("** perf cannot access CMN events", file=file)
        return False
    else:
        if perf.verbose:
            print("  perf can access CMN events", file=file)
    if not check_watchpoints(perf=perf):
        # This is unexpected - if events are working, REQ watchpoints should be
        print("** CMN watchpoints are not working", file=file)
    if check_rsp_dat and not check_rsp_dat_dvm_watchpoints(perf=perf):
        print("** CMN watchpoints cannot be set on RSP/DAT/DVM packets - see README-cmn.md for background",
              file=file)
    else:
         if perf.verbose:
             print("    CMN watchpoints can monitor all channels (REQ, RSP, SNP, DAT).", file=file)
    return True


def check_cpu_pmu_events(file=None, perf=None):
    return check_hw_pmu_events(file=file, perf=perf)


def main(argv):
    import argparse
    from cmn_perfstat import Perf
    parser = argparse.ArgumentParser(description="check if CMN PMU driver is installed")
    parser.add_argument("--perf-bin", type=str, default="perf", help="path to perf binary")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="increase verbosity")
    opts = parser.parse_args(argv)
    perf = Perf(perf_bin=opts.perf_bin, verbose=opts.verbose)
    is_driver_installed = is_cmn_pmu_installed()
    print("CMN PMU driver is installed: %s" % is_driver_installed)
    print("perf command is installed: %s" % perf.is_installed())
    pep = perf_event_paranoid()
    print("perf_event_paranoid: %u" % pep)
    print("Checking for CMN PMU events:")
    perf.check_cmn_events()
    print("Checking for CPU hardware PMU events:")
    perf.check_cpu_events()


if __name__ == "__main__":
    main(sys.argv[1:])
