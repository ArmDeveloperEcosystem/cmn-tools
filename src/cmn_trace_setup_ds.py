"""
CMN flit capture tool (ATB trace capture with Arm Debugger)

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This script wraps cmn_capture.py for capturing CMN trace to the CoreSight
ATB bus. It's intended to be run from within an Arm Debugger target connection.

For usage details, see README-capture-ATB.md.
"""

from __future__ import print_function

import cmn_capture
import cmn_devmem

TS_PERIODS = [0, 0, 0, 8192, 16384, 32768, 65536]

def configure_dtcs_for_atb(opts, trace_session, dtsl_cmn_trace_controller):
    tracectl = 0x9 # alignment sync after 512B of trace
    if opts.ts:
        tss = TS_PERIODS.index(opts.ts)
        tracectl |= (tss << 5)
    if opts.cc:
        tracectl |= cmn_devmem.CMN_DTC_TRACECTRL_CC_ENABLE
    # apply the unique ATB IDs set from DTSL
    sourcesForMesh = dtsl_cmn_trace_controller.getMeshDTCTraceSources()[trace_session.C.D.cmn_mesh_name]
    assert len(sourcesForMesh) >= 1
    for dtsl_dtc_trace_source in sourcesForMesh:
        dtc = trace_session.C.debug_nodes[dtsl_dtc_trace_source.getDTCDomainNumber()]
        dtc.write64(cmn_devmem.CMN_DTC_TRACECTRL, tracectl)
        dtc.set_atb_traceid(dtsl_dtc_trace_source.getStreamID())
        if opts.verbose:
            print("For " + str(dtc) + " using ATB ID: " + str(dtsl_dtc_trace_source.getStreamID()))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser("setup CMN for trace capture on the ATB using Arm Debugger")
    cmn_capture.add_trace_arguments(parser)
    parser.add_argument("--ts", type=int, choices=set(TS_PERIODS), help="timestamp period, in cycles")
    opts = parser.parse_args()
    trace_session = cmn_capture.TraceSession(opts, atb=True)

    from arm_ds.debugger_v1 import Debugger
    from com.arm.debug.dtsl import ConnectionManager
    debugger = Debugger()
    dtslConnectionConfigurationKey = debugger.getConnectionConfigurationKey()
    dtslConnection = ConnectionManager.openConnection(dtslConnectionConfigurationKey)
    dtslCfg = dtslConnection.getConfiguration()
    dtsl_cmn_trace_controller = dtslCfg.cmn_trace_controller

    dtsl_cmn_trace_controller.setTraceSession(trace_session, trace_session.C.D.cmn_mesh_name)
    configure_dtcs_for_atb(opts, trace_session, dtsl_cmn_trace_controller)
