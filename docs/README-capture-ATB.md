CMN trace capture onto the CoreSight ATB bus
============================================

README-capture.md explains how to run the cmn_capture.py script to
capture CMN trace into a buffer within the CMN mesh. For capturing
larger amounts of trace, it's instead necessary to send the trace out
of the CMN mesh, and onto the CoreSight ATB bus. This can be done by
running cmn_trace_setup_ds.py within an Arm Debugger connection.

cmn_trace_setup_ds.py is a wrapper around cmn_capture.py. It has the
same command line options, with the addition of a timestamp (--ts) flag.
See "Timestamps and cycle counts" for details of timestamping.

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


Timestamps and cycle counts
---------------------------
There are two kinds of timing information in CMN traces.

The CMN has a 16-bit cycle counter that increments at CMN cycle frequency
(typically this is near, but not identical to, CPU frequency). The value
of this counter can be attached to each packet. Because it rolls over
frequently (50us might be typical) it is not suitable for long-range
time correlation. Cycle counting in trace is on by default but can be
turned off with "--no-cc", resulting in a very modest space saving.
Note that in multi-mesh systems the cycle counter is not synchronized
between meshes. In fact the meshes may be running at different frequency.

Secondly, the global timestamp can be inserted into the trace stream.
This runs at a constant frequency (a nominal 1GHz although the actual
granularity of updates may be lower) and should be the same across all
trace sources in the system, including across multiple sockets.
It is used for ETE, CoreSight STM and other trace sources and may be
used to correlate CMN trace with other events.

Timestamps are not attached to every CMN packet. Instead they are
periodically inserted into the trace stream. Current CMN implementations
do this regardless of whether there is any data to be output. Leaving
trace enabled can result in a trace buffer being filled up with
timestamps. Because of this, the capture scripts only enable timestamps
when requested, using the --ts=<period> option. The timestamp period
should be specified as 8192, 16384, 32768 or 65536.


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

Packets in a trace file are emitted in formatter order, not necessarily in exact
capture-time order. If small inversions in cycle count are causing poor readability
or request/response matching, both `cmn_decode_trace.py` and `cmn_trace_latency.py`
support `--reorder-cc-window=<cycles>`. This uses packet start position in the
formatted trace to fix cross-stream skew, and uses the cycle counter only for
small same-stream inversions within the given window. Values around `64` may now
be sufficient. This remains heuristic: the CMN cycle counter is only 16 bits and
is not synchronized across meshes.

In other cases it may be possible to use filtering on the original tag-setting
watchpoint, as in the first example where --tgtid was used to filter requests
to a single HN-F rather than requests to all HN-Fs. This will reduce the number of
tagged packets in the system.
