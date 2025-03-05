#!/usr/bin/python3

"""
Check that CMN perf driver is installed and available.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN events will need the arm-cmn module to be built or installed
into the kernel, and also generally need
  sysctl kernel.perf_event_paranoid=0.
"""

from __future__ import print_function

import os
import sys


class CMNNoPerf(OSError):
    """
    Raise this exception if the CMN PMU driver isn't installed.
    """
    def __str__(self):
        return "CMN PMU driver is not installed"


def is_cmn_pmu_installed():
    """
    Check if the arm-cmn driver has loaded and registered.
    """
    return os.path.exists("/sys/bus/event_source/devices/arm_cmn_0")


def perf_event_paranoid():
    """
    Return the current setting of kernel.perf_event_paranoid
    """
    return int(open("/proc/sys/kernel/perf_event_paranoid").read())


def check_cmn_pmu_events():
    """
    Check that CMN PMU events are available, and report any problems to stderr.
    We could do this pre-emptively or after a problem.
    perf's error reporting on trying to use CMN events is inconsistent:
      - with perf_event_paranoid=2, it succeeds, but events are "<not supported>"
      - with perf_event_paranoid=1, it fails with a message about privilege
      - with perf_event_paranoid=0, it runs successfully
    """
    if not is_cmn_pmu_installed():
        print("CMN PMU driver is not installed - load driver or reconfigure kernel",
              file=sys.stderr)
        return False
    p = perf_event_paranoid()
    if p > 0:
        # Driver is there but we don't have permissions? Check perf_event_paranoid
        # on the assumption we're an unprivileged user. If we're sudo then this
        # should have worked regardless.
        print("CMN PMU driver is installed, but you might not have permission to read hardware events",
              file=sys.stderr)
        print("kernel.perf_event_paranoid=%d - use sysctl to set it lower" % p,
              file=sys.stderr)
        return False
    return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="check if CMN PMU driver is installed")
    opts = parser.parse_args()
    is_installed = is_cmn_pmu_installed()
    print("CMN PMU driver is installed: %s" % is_installed)
    pep = perf_event_paranoid()
    print("perf_event_paranoid: %u" % pep)
    check_cmn_pmu_events()
