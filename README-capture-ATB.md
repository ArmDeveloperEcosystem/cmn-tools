CMN trace capture onto the CoreSight ATB bus
============================================

README-capture.md explains how to run the cmn_capture.py script to
capture CMN trace into a buffer within the CMN mesh. For capturing
larger amounts of trace, it's instead necessary to send the trace out
of the CMN mesh, and onto the CoreSight ATB bus. This can be done by
running cmn_trace_setup_ds.py within an Arm Debugger connection.

cmn_trace_setup_ds.py is a wrapper around cmn_capture.py. It has the
same command line options, with the addition of a timestamp (--ts) flag.

For cmn_trace_setup_ds.py to work it needs some integration with the Arm
Debugger target config. This is outlined briefly below, for a full
explanation see the CMN section of the Arm DS user guide
(https://developer.arm.com/documentation/101470/latest/).

 - The CMN mesh and CMN DTC(s) need to have been added to the .sdf file of
the target config

 - The cmn_config and cmn_trace_controller fields need to have been added
to the dtsl_config_script.py file of the target config

 - An example of this can be seen with the N1SDP target config (see
sw/debugger/configdb/Boards/Arm Development Boards/Neoverse_N1/ within
an Arm Debugger install)

When cmn_trace_setup_ds.py is run, it will pass a reference of the
cmn_capture.TraceSession object to the target config's
cmn_trace_controller. It will use the ATB ID's determined by Arm Debugger
to use for programming up each of the CMN DTCs. Arm Debugger will handle
programming the devices along the ATB path from the CNM DTC trace source(s)
to the CoreSight trace sink.

As a user, the flow is to initially run cmn_trace_setup_ds.py - this
will setup the CMN mesh ready for trace capture, but it will not start
trace capture. The commands to start/stop trace capture are to be
initiated from the Arm Debugger session (i.e. using the trace start/stop
commands, or the Trace Start/Stop buttons in the Trace Control panel of
the Arm DS GUI).

The captured trace may then be dumped to local disk (using the Arm
Debugger 'trace dump' command), and the cmn_decode_trace.py script can
be run (using your OS's Python) to decode the dumped trace.


Offline latency from trace files
--------------------------------
If you have a CoreSight trace file (e.g. captured via `cmn_capture.py` or ATB),
you can report request/response latency from the trace stream:

    ./cmn_trace_latency.py --cmn-version=0x600 --input trace.bin --tagged-only

By default, the tool matches REQ to RSP/DAT using txnid and source/target IDs
when available; use `--match` to adjust, and `--req-channel`/`--rsp-channels`
to focus on a specific path.

For end-to-end reads where RN-F requests are serviced by SN-F data directly back
to the requester, use the DAT response path:

    ./cmn_trace_latency.py --cmn-version=0x43e --input trace.bin --end-to-end

Or equivalently:

    ./cmn_trace_latency.py --cmn-version=0x43e --input trace.bin --rsp-channels=DAT --match=txnid-reqsrc

If you see occasional very large latencies due to missing responses or trace loss,
cap matches with (default is 5000 cycles):

    ./cmn_trace_latency.py --cmn-version=0x43e --input trace.bin --end-to-end --max-latency=5000

In other cases it may be possible to use filtering on the original tag-setting
watchpoint, as in the first example where --tgtid was used to filter requests
to a single HN-F rather than requests to all HN-Fs. This will reduce the number of
tagged packets in the system.
