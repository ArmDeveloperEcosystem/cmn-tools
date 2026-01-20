CMN flit capture
================

The CMN interconnect can capture packet headers of CHI transactions
in the interconnect. Capture happens at individual crosspoints (XPs)
in the mesh. The XPs capture the headers of "flits", the individual
message units that make up CHI transactions.

The cmn_capture.py tool demonstrates how to capture flit headers.
It can be used to give a more detailed picture of interconnect
traffic than can be obtained by PMU events or counting. For example,
the actual addresses and attributes of memory transactions can be
captured.


CHI basics
----------
CHI is the AMBA Coherent Hub Interface. It is the protocol used in
the CMN interconnect. The full CHI specification is complex, but a
basic understanding of CHI request types and transaction flows can
greatly help understand what is happening in a system. No detailed
knowledge of CHI is needed to use cmn_capture.py - in fact, the tool
may be useful when gaining an understanding of CHI.

For an introduction to CHI, see the "Learn the architecture -
Introducing AMBA CHI" document at
https://developer.arm.com/documentation/102407/0100


Setting up watchpoints to capture CHI flits
-------------------------------------------
Flit capture uses the same watchpoints that are used for counting,
as in the "watchpoint_up" and "watchpoint_down" perf events.

As with watchpoint perf events, a watchpoint must select the
port number on the crosspoint, and the CHI channel (REQ, RSP,
SNP or DAT). It can also match selected CHI fields.

A watchpoint match causes the CHI flit header to be captured into
a small FIFO in the XP. The --format option selects one of several
different levels of detail that the FIFO can be programmed to capture.
Depending on the level of detail, a different number of FIFO entries
are available.

Format 0: transaction id x 18

Format 1: (opcode, transaction id) x 9

Format 2: (srcid, tgtid, opcode, transaction id) x 4

Format 4: (various CHI header fields) x 1

Format 4 is the default, and provides the most insights into what
types of transactions and responses are occurring in the interconnect.
This is the default format for cmn_capture.py.

Note that the capture format only affects the selection of fields
captured from the CHI header. Matches against CHI fields happen
regardless of capture format.


Flit sampling and histograms
----------------------------
cmn_capture.py offers two modes: sampling, and setup/inspect.

In the sampling mode, cmn_capture.py sets up watchpoints and
then polls the FIFOs to check for captured data. If data is
present, it is displayed either as a trace or (with --histogram)
in histogram form.

In setup/inspect mode, the tool is run first to set up watchpoints,
then separately to check for captured data. This is described
in more detail under "Setup/inspect mode" below.

REQ, RSP, SNP and DAT traffic can be selected using the --vc option
with values of 0 to 3 respectively. Additional command-line options
can filter on CHI fields, such as opcode, as for cmnwatch.py.

In the default sampling mode, the tool will set up watchpoints to
capture flits at each crosspoint, and print out the captured flits.
It will take up to 10 samples per crosspoint.

With the --histogram option, the tool summarizes the samples
for each combination of source and destination type and opcode,
and also prints a representative flit for each combination.
Again the default is 10 samples per crosspoint.

An example histogram of REQ traffic is shown below:

      37  HN-F  SN-F   ReadNoSnp             024(HN-F)->060(SN-F):RNSp:00 e 04:ReadNoSnp            lpid=00 ret=020:02   0x00816c087900  64 nSWBA
      30  RN-F  HN-F   ReadNotSharedDirty    020(RN-F)->044(HN-F):RNSD:01 e 26:ReadNotSharedDirty   lpid=00 ret=000:00   0x00810ea5e340  64 SWBA eca
      22  HN-F  SN-F   WriteNoSnpFull        024(HN-F)->060(SN-F):WNSF:80 e 1d:WriteNoSnpFull       lpid=00 ret=000:00   0x00816a8f6e00  64 nSWBA
      17  RN-F  HN-D   ReadNoSnp             020(RN-F)->068(HN-D):RNSp:02 e 04:ReadNoSnp            lpid=00 ret=000:00            <CMN>   8 dev-nRnE eca
      10  RN-F  HN-F   ReadUnique            04c(RN-F)->024(HN-F):RUnq:81 e 07:ReadUnique           lpid=00 ret=000:00   0x0083fdf5ec40  64 SWBA eca
       7  RN-F  HN-F   WriteEvictFull        020(RN-F)->024(HN-F):WEFu:81 e 15:WriteEvictFull       lpid=00 ret=000:00   0x0000f1aeb7c0  64 SWBA
       6  RN-F  HN-F   WriteBackFull         020(RN-F)->024(HN-F):WBFu:80 e 1b:WriteBackFull        lpid=00 ret=000:00   0x00810d87ab00  64 SWBA
       1  HN-F  SN-F   WriteNoSnpPtl         044(HN-F)->060(SN-F):WNSP:00 e 1c:WriteNoSnpPtl        lpid=00 ret=000:00   0x0000f1acad40  64 nSWBnA

This shows that 37 sampled flits were ReadNoSnp requests from HN-F
home nodes to SN-F memory controller nodes. A representative flit
is shown indicating a request to a specific physical address.
Note also the "ret=" field in the request directing the memory
controller node to send the data directly to node 0x20 -
likely the original requesting CPU for this data.


Setup/inspect mode
------------------
In setup/inspect mode, cmn_capture.py is run first to set up
watchpoints, then can be run again to check for captured data:

    cmn_capture.py --setup ...
    ... do something to generate traffic ...
    cmn_capture.py --inspect
    ... do something else
    cmn_capture.py --inspect

This mode may be particularly useful when debugging access to
I/O devices.


Data capture
------------
In addition to showing header details from REQ, RSP, SNP and DAT
packets, cmn_capture.py offers limited support for capturing data
payloads from DAT packets, i.e. the actual data being transported
across the interconnect.

To use this feature, it is necessary to know something about how
data payloads are carried in CMN.

Each DAT packet carries up to 32 bytes of data. The 'active' data
is naturally aligned within the payload, e.g. for a 4-byte write to
address 0x8018, the value will be at offset 0x18. CMN can capture
either the low 16 bytes or the high 16 bytes. So to capture data
for a transaction to a known address, bit 4 of the address should
be examined to see whether the low or high 16 bytes should be
captured.

On top of this, 64-byte transfers (e.g. full cache lines) are
carried in two DAT packets, distinguished by the DataId field
being 0 or 2. So a single REQ for a 64-byte transfer, will be
associated with two DAT packets, distinguished by DataId.

In cmn_capture.py, the --data option specifies which data fragment
to capture:

    0: dataid=0, header + low 16 bytes
    1: dataid=0, header + high 16 bytes
    2: dataid=2, header + low 16 bytes
    3: dataid=2, header + high 16 bytes

In each case, the DAT packet header (with source, destination and
opcode etc.) is also captured.

This feature is not supported in CMN-600.


Flit capture and security
-------------------------
Depending on the security configuration of the interconnect, it may
be possible to capture either of:

 - REQ, RSP, SNP and DAT flits, including DVM messages and Secure flits

 - Non-Secure REQ and SNP flits only, and no Secure flits or DVM

"Secure" and "Non-Secure" refer here to the security attributes of
the traffic. "Secure" traffic is generally specific to I/O or secure
firmware. Traffic originating from operating system or user applications
will be "Non-Secure".

If the capture tool appears to be only able to capture REQ and SNP
traffic, the cause is likely to be security configuration.
In some cases it may be possible to change the security configuration,
via firmware or an external debugger.


cmn_capture.py requirements
---------------------------
cmn_capture.py can run on any Linux system with CMN accessible
via /dev/mem - the same requirements as cmn_devmem.py.

cmn_capture.py accesses the CMN directly, bypassing the Linux kernel
CMN PMU drivers. It generally needs root privilege to run, as well
as access to physical memory space via /dev/mem. It aims to leave
the CMN in a state that is compatible with the kernel drivers,
but using both at the same time may cause unexpected results,
especially if watchpoint PMU events are being used.
