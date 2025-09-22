#!/usr/bin/python

"""
Map device memory, using whatever is appropriate for the target platform.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import os

RUNNING_IN_ARM_DEBUGGER = False

if "CMN_DUMP" in os.environ:
    from devmem_dump import DumpMemFactory as DevMem
else:
    try:
        from arm_ds.debugger_v1 import Debugger
        from devmem_ds import DSMemFactory as DevMem
        RUNNING_IN_ARM_DEBUGGER = True
    except ImportError:
        from devmem_os import DevMemFactory as DevMem
