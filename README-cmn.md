CMN background
==============

The CMN interconnect is a rectangular grid comprised of
"crosspoints" (XPs). Nodes of various types are attached to
crosspoints. Some systems may have more than one CMN
interconnect - for instance a multi-socket system would
have at least one CMN mesh per socket.

Important CMN node types include:

 - requesters (RN-F): CPUs are attached to these

 - memory home nodes (HN-F): these handle all memory requests
   from the CPU and also contain slices of system cache

 - subordinate nodes (SN-F): these interface to memory
   controllers, which manage DDR modules

 - chip-to-chip gateways (CCG): these act as bidirectional
   interfaces to other CMN interconnects.

Full details of CMN can be found in Arm's product documentation.


CHI protocol
------------

The CMN interconnect implements the CHI protocol, which defines
request and response types. The full CHI protocol is complex,
and is fully defined in Arm's CHI Architecture Specification,
but some basic knowledge may be useful when looking at CMN
traffic samples and traffic metrics.

### CHI channels

CHI defines interfaces between components. An interface is
comprised of channels of four types:

 - requests (REQ)
 - responses (RSP)
 - snoops (SNP)
 - data (DAT)

Each channel is undirectional, though a given interface may have
channels in both directions.

Specifically, the interface between a CPU and the interconnect
will typically have the following channels:

 - TXREQ: CPU transmits requests to the interconnect
 - RXRSP: CPU receives responses from the interconnect
 - TXDAT: CPU transmits data to the interconnect
 - RXDAT: CPU receives data from the interconnect
 - RXSNP: CPU receives snoops from the interconnect
 - TXRSP: CPU transmits responses to the interconnect

Note that there is no TXSNP, and no RXREQ. The CPU does not
issue snoops directly (snoops are issued by Home Nodes, see
below); conversely, any requests a CPU receives are of very
specific kinds, e.g. snoops, stashes and distributed cache
management, and are carried over the RXSNP channel.

Other external devices such as memory controllers and I/O
devices are also connected to CMN using CHI, with a suitable
combination of channels.

Although home nodes are integrated into CMN, their connections
can also be regarded as CHI interfaces, and CMN watchpoints
on CHI channels can be used to observe traffic.


### Transactions

A transaction will involve packets (flits) being passed across
one or more channels. Different transaction types will use
different combinations of channels. A transaction generally
starts with a request (or a snoop). The completion of a request
might be indicated in a response packet, or in a data packet.

For example, a CPU reads data:

 - CPU sends a read request on TXREQ
 - interconnect responds with data on RXDAT, also indicating
   cache line status and completing the request.

A CPU writes data:

 - CPU sends a write request on TXREQ
 - interconnect responds on RXRSP with a write buffer identifier
 - CPU sends data on TXDAT
 - interconnect responds with completion indication.

Interconnect snoops data from a CPU:

 - interconnect sends snoop request on RXSNP
 - CPU sends data on TXDAT

These examples are for illustration only.


### Security and Observability

CMN has security controls that may prevent Secure packets
being observed using watchpoint counts and packet tracing.
Observation of Secure packets is controlled by a SPNIDEN
(Secure Non-Invasive Debug Enable) input to the CMN, which is
typically managed at boot-time by on-chip firmware.

For REQ and SNP packets, the Security status is indicated by a bit
in the packet. However, RSP and DAT packets are always considered
as Secure. As a result, these packets might not be directly
observable in some systems where SPNIDEN=0.

DVM messages (see below) are also always considered as Secure,
so again these are not observable when SPNIDEN=0.


CPU interface: cache, CAL and DSU
---------------------------------

### CPU cache

Internally, the CPU contains a cache - all CPUs found in Neoverse
systems contain split L1 instruction and data caches (typically
64K each) and a unified L2 cache. The CPU only needs to request
data from the interconnect if it is not already in cache.

The CPU may operate on data in cache and modify it. At this point
the data becomes "dirty".

In order to make room to bring data into cache, the CPU may need
to evict other data, i.e. remove it from the CPU cache. If this
data is dirty, i.e. updated compared to memory, the updates must
not be lost. Typically, the dirty data is written to the system
cache in the CMN, so that this CPU or another CPU can easily
retrieve it when needed again. The CMN system cache may itself
evict data, and in the case of dirty data it will need to write
a copy back to DRAM.

Clean data (i.e. where cached data has not been modified with
respect to memory) can be discarded, or it can be written to
system cache if not already present. This is one of a number
of places where the system (CPU and interconnect) have a choice
of behaviors and may choose one or the other depending on
configuration options, ongoing profiling, or other heuristics.

It is important that data does not exist in multiple places in
inconsistent states (e.g. two CPUs each with a different, dirty
copy of the same line), and a significant amount of the complexity
of CHI is devoted to maintaining consistency. This is termed
"coherency".

Separately, the CPU may also access memory-mapped devices,
that are not cached; and in some cases it may access certain
system memory areas (e.g. I/O buffers, or frame buffers) that
have non-standard access arrangements. We will defer these topics
till later. For now we will cover CPU access to data and
instruction working sets - i.e. the data being operated on
and produced by CPU workloads, or comprising CPU code itself.


### CAL: Component Aggregation Layer

Two (or occasionally more) CPUs may be connected to the a single
CMN interconnect port via a CAL component. This effectively
creates two ports for the price of one. Each CPU interface can
be considered separately, and each CPU has its own CHI addressing
id, but the fact that they are multiplexed on to a single CMN
port has some impact on the ability of CMN watchpoints and
counters to distinguish traffic from the two CPUs.

Similarly, two CMN home nodes (each with a cache slice) may be
multiplexed on to a single port.


### DSU: DynamIQ Shared Unit

In mobile systems, a DSU is a small high-performance interconnect
that clusters multiple CPUs, often of different types, as well as
incorporating a Level 3 cache.

DSUs are not typically seen in Neoverse/CMN systems, which instead
will "direct connect" the CPUs to a CMN interconnect port or a CAL.
However, some Neoverse/CMN systems do feature a DSU. This DSU might
or might not contain a cache, depending on configuration.

For instance, the Arm N1 Software Development Platform (N1SDP)
comprises a CMN interconnect and four Neoverse N1 CPUs. The CPUs
are grouped in pairs each in a DSU with a DSU L3 cache. This then
means that the CMN system cache is a Level 4 cache. However, this
configuration is atypical. In the majority of systems, there is
no DSU cache and the CMN system cache is at level 3.


Home nodes
----------

In the CMN, each physical memory address is associated with a
"home node" (HN) in the CMN. In smaller CMN systems, the
mapping is system-wide, i.e. all CPUs agree on which home node
a given address belongs to. Very large (multi-socket) CMN
systems can be partitioned so that CPUs have local home nodes,
but this is an advanced topic which we will leave for now.

The allocation of addresses to home nodes is configured into
the system address map (SAM) which all requesters have a copy of.
Specifically, when a CPU (RN) needs to read data, it looks up the
address in its copy of the SAM (RN-SAM) and finds out which home
node to send the request to. That home node will then deal with
the request, e.g. supply the data from its system cache slice,
or retrieve it from a memory controller or snoop it from another
CPU's cache.

The mapping of addresses to home nodes is fixed for a given
system, but is not typically something that application developers
should normally be concerned with. The mapping is configured in
such a way that data is evenly split between the home nodes
comprising the system.

Note that when the CPU reads cacheable data, it has no knowledge
of whether that data needs to come from the home node's system
cache slice, or from a memory controller, or from another CPU's
cache. It always sends the request to the home node, and the
home node is responsible for dealing with it.

This also explains why CPUs have no outbound snoop channel
(TXSNP) - a CPU never snoops data directly. Snoops are issued
from the home node when necessary.


### Request optimizations

We said above that the CPU always sends its request to the
correct home node for that data, as determined by the SAM.
The home node might contain a copy of the data in its system cache
However, the data might reside elsewhere. CHI (and CMN)
provide for two optimizations in this case:

 - if the data resides in DRAM, Direct Memory Transfer (DMT)
   allows the memory controller to send data directly back to the
   requesting CPU

 - if the data resides in another CPU's cache, Direct Cache
   Transfer (DCT) allows that CPU to send data directly to the
   requesting CPU

In each case, the home node is aware of the transaction and can
update its own internal state, but latency is reduced because
returned data does not have to go via the home node.

DMT and DCT explain some of the traffic flows typically seen
when using the CMN tools.


Distributed Virtual Memory (DVM)
--------------------------------

In some cases it may be necessary to coordinate the management of
virtual memory across the system. This involves passing specific
message types (DVM) between CPUs.

DVM messages are carried in two ways:

 - a DVM message sent by a CPU is carried partly in a REQ packet
   (in the address field) and partly in the payload of DAT packet.

 - a DVM message received by a CPU is carried in the address field
   of two SNP packets.

When using CMN tracing and watchpoints, several points need to be
kept in mind:

 - it is not generally possible to observe DAT data payloads.
   Thus the second half of outgoing DVM requests is not observable.

 - special arrangements must be made to observe both SNP packets
   involved in an incoming DVM request

 - in terms of standard CHI fields, DVM messages are marked as
   Secure, with the actual security status being indicated inside
   the DVM payload; this has the unfortunate consequence that
   DVM transactions are not observable when SPNIDEN=0 (see
   "Security and Observability" above).


