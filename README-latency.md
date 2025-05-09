CMN latency measurement using TraceTag
======================================

It is possible to measure latency directly in CMN, for example:

 - the latency between a packet being uploaded at one port and downloaded at another

 - the latency between a request and its response

The cmn_capture.py tool uses CHI tagging features in CMN to report on latency.
Before explaining how to use the tool, we cover the basic operation of CHI tagging.


CHI TraceTag basics
-------------------
All packets in the CHI interconnect protocol have a TraceTag bit which can be used
to count and collect related transactions. TraceTag is used as follows:

 - an agent causes TraceTag to be set on a packet; this agent could be a watchpoint
   match in CMN, or some other agent like Statistical Profiling (SPE) in a CPU

 - the TraceTag is not only carried along with the packet, but the CHI architecture
   requires it to be propagated into related packets, e.g. from a request to its
   response and data packets

 - these packets with TraceTag set can be collected or counted.

A specific use case is for the tag-setting agent to record the time (or cycle count)
that it set TraceTag, and then when we see the same packet elsewhere, or related
packets, we can record a time or cycle count delta.


Using the cmn_latency tool
--------------------------
cmn_latency programs the CMN interconnect performance features directly (bypassing
the kernel CMN PMU driver if installed). It must be run as root.

cmn_latency operates as follows:

    sudo ./cmn_latency.py <options> <chi fields> <request> <watchers...>

The <request> option specifies where to set the tag. It must be set at an upload
port somewhere in CMN. Currently the tool supports setting the tag at exactly one
upload port. You should use the CMN mesh diagram to identify a suitable port.
<request> is a string that specifies the crosspoint (XP), port, and CHI channel.
It is made up of components separated by ':'. Components can be:

 - a device identifier e.g. "0x6c"

 - a port number e.g. "P2"

 - a CMN instance number e.g. "C1" - only needed when the system has more than one CMN

 - a CHI channel ("REQ"/"RSP"/"SNP"/"DAT")

 - a CPU number as known to the OS, e.g. "cpu#1": this relies on CPU discovery (see README-discovery.md)

Collectively these specify an upload port and channel. For example:

    0x84:snp     a device at 0x84 (perhaps an HN-F); packets on SNP are tagged

    0x80:p1:snp  another way of specifying the same thing (assuming P1 is 0x84)

    cpu#0        REQs originating at CPU#0's port. (Note: CMN cannot distinguish between multiple CPUs on a CAL.)

In addition, packet contents can be filtered using CHI fields such as "--opcode=ReadNoSnp"
or "--memattr=0bxx1x".

The tag watcher locations are specified in a similar way to the tag-setting location,
except that they can be on upload or download ports (or both) and there can be multiple watchers.
The specification supports additional components:

 - a direction "up" or "down"

 - a port class e.g. "RN-F", "HN-F", "CCG"

The watcher location defaults to the tag setter location. If no watcher location is specified,
the tool will set watchers on RSP and DAT channels.

Note that tag watchers (unlike tag setters) catch any packet with TraceTag set - there is no filtering on packet contents.


Operation
---------
Having programmed the tag-setting watchpoint and the tag-catching watchpoints, the tool then
polls to see if it has captured data. If the watchpoints have captured data, it prints the
tag-setting packet followed by the tag-matching packets in latency order, e.g.

      00001cbc @0x048 DEV=1 WP=1  ...
    12  00001cc8 @0x020 DEV=1 WP=0  ...
    15  00001ccb @0x048 DEV=1 WP=2  ...
    41  00001ce5 @0x048 DEV=1 WP=0  ...
    44  00001ce8 @0x020 DEV=1 WP=2  ...

Each capture is a "one-shot", i.e. the data is extracted and the watchpoints are reset in
between each capture. For high-frequency streams of traffic the tool will only pick up a
small sample - but hopefully this is enough to show typical latencies.

The total number of captures (defaulting to 1) can be controlled with:

  --capture=<n>

It may be that nothing is captured - a timeout for the command can be set with:

  --wait=<seconds>

The polling interval is set to a reasonable default but can be adjusted with:

  --poll-time=<seconds>


Using the tool with other tag-setting agents
--------------------------------------------
cmn_latency.py can also capture tagged packets where the tag has been set by other
tag-setting agents such as CPU statistical profiling (SPE).
In this case the tag-setting watchpoint specifier should be set as "none".

In this example, a "perf record" session is being run to capture SPE data for a user process,
while concurrently capturing tagged packets in CMN, either uploaded to a RN-F (CPU) port,
or downloaded to an HN-F.

    $ perf record -e arm_spe//u ... &
    $ sudo ./cmn_latency.py none req:rn-f:up req:hn-f:down

Note: currently in order to activate SPE, "perf record" must be used to capture SPE
samples into an output perf.data file.


Examples
--------
Show latency between a CPU uploading a request to the HN-F at 0x48, and the HN-F downloading it:

    sudo ./cmn_latency.py --tgtid=0x48 cpu#1 0x48:req:down

      00002e38 @0x048 DEV=1 WP=0  0000101007f400085d02e1c000020026048e  REQ 04c->048:RUnq:80 e 07:ReadUnique           lpid=02 ret=000:00    0x0080803fa000  64 SWBA eca
     6  00002e3e @0x048 DEV=0 WP=2  0000101007f400185d02e1c000020026048e  REQ 04c->048:RUnq:80 e 07:ReadUnique           lpid=02 ret=000:00    0x0080803fa000  64 SWBA eca TAG

We see that the REQ was uploaded from the RN-F at 0x2e38 and downloaded to the HN-F at 0x2e3e, i.e. 6 cycles later.

Show latency between a CPU uploading a WriteCleanFull request, and downloading the response:

    sudo ./cmn_latency.py --opcode=WriteCleanFull cpu#1 rsp

      000000be @0x048 DEV=1 WP=0  0000107fbeda58005502e5c000021426048e  REQ 04c->048:WCFu:85 e 17:WriteCleanFull       lpid=02 ret=000:00    0x0083fdf6d2c0  64 SWBnA
     4  000000c2 @0x048 DEV=1 WP=2  0000000000000000000004004016142404ce  RSP 048->04c:CDBR:85 e 05:CompDBIDResp         resp=0/0 dbid=0x01 TAG

Here we can see that the response arrived back 4 cycles after the request was uploaded.
In this case, the response is simply allocating a data buffer and does not complete the transaction.
The tool does not guarantee to capture all packets involved in a transaction.

We can see more detail by adding further tag-catching watchpoints. Here the source of the
request is at 0x4c, and we filter the request to ensure we only match requests to the home
node at 0x24.

    sudo ./cmn_latency.py --opcode=WriteCleanFull --tgtid=0x24 cpu#1 rsp dat:up 0x24:rsp:up 0x24:dat:down

      00001cbc @0x048 DEV=1 WP=1  0000107fbf1cf0005502e5c000020026024e  REQ 04c->024:WCFu:80 e 17:WriteCleanFull       lpid=02 ret=000:00    0x0083fdf8e780  64 SWBnA
    12  00001cc8 @0x020 DEV=1 WP=0  0000000000000000000004000016001204ce  RSP 024->04c:CDBR:80 e 05:CompDBIDResp         resp=0/0 dbid=0x00 TAG
    15  00001ccb @0x048 DEV=1 WP=2  0000000000000000000004000016001204ce  RSP 024->04c:CDBR:80 e 05:CompDBIDResp         resp=0/0 dbid=0x00 TAG
    41  00001ce5 @0x048 DEV=1 WP=0  00000000000000000610001840000026024e  DAT 04c->024:CBWD:00.0 e 02:CopyBackWrData       resp=UD_PD dbid=0x00 TAG
    44  00001ce8 @0x020 DEV=1 WP=2  00000000000000000610001840000026024e  DAT 04c->024:CBWD:00.0 e 02:CopyBackWrData       resp=UD_PD dbid=0x00 TAG

Here we can see the CPU notifying the home node that it has data to write, but it needs to wait for the
home node to respond with a write buffer ID (DBID). Once the CPU receives the DBID it can send the data.
Note how both the home node and the CPU propagate TraceTag from one packet to the next.


Unexpected tag matches
----------------------
Because of the way CMN watchpoints are designed, the tool may appear to capture more
packets than expected. This section explains why.

Here we are attempting to see latency from a CPU to whichever HN-F it happens to be targeting,
so we set tag watchers at all HN-Fs:

    sudo ./cmn_latency.py --opcode=WriteCleanFull cpu#1 hn-f:req:down

      0000cd07 @0x048 DEV=1 WP=0  0000001e3595a8005502e5c000020426044e  REQ 04c->044:WCFu:81 e 17:WriteCleanFull       lpid=02 ret=000:00    0x0000f1acad40  64 SWBnA
     2  0000cd09 @0x040 DEV=1 WP=2  0000001e3595a8105502e5c000020426044e  REQ 04c->044:WCFu:81 e 17:WriteCleanFull       lpid=02 ret=000:00    0x0000f1acad40  64 SWBnA TAG
    84  0000cd5b @0x028 DEV=0 WP=2  0000001e359308105502e5c000022426028e  REQ 04c->028:WCFu:89 e 17:WriteCleanFull       lpid=02 ret=000:00    0x0000f1ac9840  64 SWBnA TAG
   311  0000ce3e @0x020 DEV=1 WP=2  0000107fbf1cf0105502e5c000022026024e  REQ 04c->024:WCFu:88 e 17:WriteCleanFull       lpid=02 ret=000:00    0x0083fdf8e780  64 SWBnA TAG

Why do we see multiple tagged packets, some with higher than expected latencies?

The explanation is due to the behavior of CMN watchpoints.
The tag-setting watchpoint will *capture* the first matching packet, but set the
trace tag on *all* matching packets. Each tag-matching watchpoint then catches the first
tagged packet it sees. The result is that if a requester A sends a packet to B,
and then another unrelated packet to C, the initial pair may be caught at A and B,
while C may catch the later packet. (Similar considerations apply if the catcher
watchpoints are watching for related packets, e.g. a RSP corresponding to a REQ.)

Currently there is no guaranteed way to avoid this. Any time we have tag-matching
watchpoints that are not guaranteed to be involved in all tag-setting transctions,
they might pick up a packet from a later transaction and not the first one.

A related problem occurs when responses are reordered. For example, suppose a
HN-F home node sends two REQs to a SN-F memory controller, and the SN-F sends
the responses in the opposite order, i.e. responds first to the second request.
If we have a tag-setting watchpoint on the REQ and a tag-catching watchpoint on
the RSP, we might capture the first request and the second response.

In some cases it may be possible to inspect the captured data and use CHI fields
such as TGTID or TXNID to match the initial packet with the correct tagged packets,
although in more complex CHI tag propagation scenarios, these fields may have other values.

In other cases it may be possible to use filtering on the original tag-setting
watchpoint, as in the first example where --tgtid was used to filter requests
to a single HN-F rather than requests to all HN-Fs. This will reduce the number of
tagged packets in the system.


Known limitations
-----------------
Unexpected tagged packets might be matched as described above.
This is the likely cause of higher than expected latencies.

There are a limited number of physical watchpoints in each mesh crosspoint,
and it may not be possible to watch tags in all places. In particular, crosspoints
with more than two ports cannot generally watch all ports. If possible, avoid
setting multiple watchpoints on the same crosspoint: for example, when analyzing
traffic between a CPU and a home node, it may be best to ensure they are on different
crosspoints.

The tool assumes it has full control over CMN performance features. Using it concurrently with
the Linux PMU driver may give unexpected results. It is expected to leave CMN in a clean state.

The tool assumes that CMN - i.e. the tag-setting watchpoint it programs into CMN - is the only
tag-setting agent in the system. Using the tool concurrently with CPU SPE may give unexpected
results, although in future the tool may be able to make use of SPE and provide additional
insights into sampled memory operations.

Some systems are configured to provide no visibility of RSP and DAT traffic.
This significantly limits the usefulness of this tool in measuring response latencies.

Although watchpoints can be set in multiple CMN interconnects (e.g. on multiple sockets),
and CHI will propagate TraceTag across chip-to-chip interfaces, the cycle counter
is not synchronized across interconnects, either in terms of baseline or frequency.
Results from the latency tool (sorted by cycle offset from the request packet) may be
misleading when packets are captured in multiple interconnects.
