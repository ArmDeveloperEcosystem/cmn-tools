Self-hosted CMN trace capture over CoreSight ATB
================================================

The ``cmn_trace_atb.py`` script captures CMN trace through a platform's
CoreSight ATB network into on-chip trace buffers or system RAM through an ETR.
It programs the selected CMN watchpoints and DTCs, configures the components between each
DTC and its capture sink, collects the buffers, and decodes the trace.

This is an alternative to capturing short samples in the CMN's own DTM
FIFOs with ``cmn_capture.py``. For trace capture controlled by Arm Debugger,
see [README-capture-ATB.md](README-capture-ATB.md).


Before capturing
----------------

The normal CMN topology must have been discovered using the other CMN tools.
You must also have the CoreSight ATB topology file supplied for your platform.
Put that file at the default location:

    ~/.cache/arm/cmn-coresight-atb.json

Alternatively, pass its location to ``cmn_trace_atb.py``:

    --atb-topology /path/to/platform/cmn-coresight-atb.json

Live capture normally requires ``sudo`` because it accesses physical device
memory. Only use an ATB topology supplied for the exact platform. See the
later sections for validation and more information about the file.


Capturing and viewing trace
---------------------------

The watchpoint syntax and most capture options are shared with
``cmn_capture.py`` and are described in
[README-capture.md](README-capture.md). For example, using the default ATB
topology file:

    sudo python src/cmn_trace_atb.py rn-f/up:req

To use a topology at another location:

    sudo python src/cmn_trace_atb.py \
        --atb-topology /path/to/platform/cmn-coresight-atb.json \
        rn-f/up:req

The script assigns an ATB trace ID to each selected DTC, enables the required
funnel inputs and trace buffers, captures for the requested interval, and
decodes each collected sink buffer.

ETF and ETR capture sinks default to stop-on-full software FIFO mode. They
retain the first buffer of trace and stop accepting data when full, applying
backpressure upstream. Intermediate ETFs continue to forward in hardware
FIFO mode. Use ``--circular`` to keep capturing and overwrite the oldest data,
retaining the most recent buffer instead.

Full is not the TMC Stopped state: ``TMCReady`` can remain low while a software
FIFO is full. At the end of the capture interval, the tool requests a flush,
keeps forwarding paths enabled, and drains the sink until ``TMCReady`` confirms
flush completion. It retains at most the first buffer's worth of trace;
additional data is drained and discarded to make room for the flush tail.
It then disables upstream hardware FIFOs and closes the routes. The hardware
behavior is described in the [TMC TRM, sections 2.2.1 and 2.2.2](https://documentation-service.arm.com/static/5f1060dd0daa596235e7ab7a).

By default, decoded packets are printed to standard output after capture.
Use the decode options below to control the amount of detail shown.

Useful ATB-specific options include:

* ``--atb-capture NAME`` selects a named capture option from the topology.
  Without it, top-level ``captures`` is used if present; otherwise the first
  entry in ``capture_options`` is used.
* ``--atid`` selects the first ATB trace ID. Further DTCs use consecutive IDs;
  the complete allocation must fit within 1-111 (0x01-0x6f).
* ``--ts`` inserts global timestamps at the selected period.
* ``--circular`` overwrites old trace when the capture sink fills, instead of
  the default software FIFO behavior that retains the earliest trace.
* ``--unformatted`` disables CoreSight frame formatting in capture sinks.
  It requires ``--circular`` because software FIFO mode requires formatting.
  Intermediate ETFs retain the formatting required for hardware FIFO mode.
  It cannot be used when multiple DTC streams share a sink.
* ``--etr-buffer-size BYTES`` sets the RAM buffer size for each ETR sink
  (default 1048576). Decimal and ``0x`` hexadecimal values are accepted.
  Software FIFO mode requires at least 512 bytes; smaller buffers require
  ``--circular``.
* ``--trace-out`` writes a captured buffer to a file. It should currently be
  used only when the selected topology has one capture sink.
* ``--decode-raw`` and ``--decode-verbose`` provide additional decode detail.
* ``--atb-reset-only`` discards existing trace, disables the selected ATB
  paths and recovers their ETFs, then exits without starting a capture.
* ``--atb-diagnostics`` reports failed ETF waits, actions attempted and observed
  status, including six status/control registers read on the failing ETF.
* ``--atb-open-all-ports`` helps debug connectivity by opening every hardware
  funnel input and both replicator outputs on the selected paths. It reads
  each funnel's input count once and reports any discrepancy with
  ``input_ports`` in the JSON. Additional trace streams may reach the sink,
  and an opened replicator branch may stall trace if its destination cannot
  accept data. Ports are closed during normal cleanup.

For example, to investigate a suspected port-selection error:

    sudo python src/cmn_trace_atb.py --atb-open-all-ports -vv rn-f/up:req

With ``-v``, the tool reports major setup and capture stages to stderr and
flushes each message before continuing. For ETR capture, these include the
initial device probe, RAM allocation and locking, virtual and physical
addresses, contiguity verification, cache helper compilation and loading,
cache maintenance, ETR programming and enable, and CMN trace start. The last
message helps locate an access that stalls the system.

With ``-vv``, path setup also reports the selected funnel inputs and replicator
outputs, and reports each ETF/ETR's hardware FIFO, software FIFO or circular
buffer mode. CMN discovery, watchpoint and DTM detail
also starts at this level. ``-vvv`` adds buffer and device status dumps.

At shutdown, the forwarding paths remain open while each capture sink waits
for flush completion, draining software FIFOs during the wait. Each sink's
status is polled at most 100 times, with 10ms pauses between polls. Each software
FIFO poll drains at most one buffer's worth of data, so a source that keeps
sending cannot make shutdown loop indefinitely. A timeout reports an incomplete
capture, preserves the trace already retrieved, and proceeds with forced
upstream disable for recovery. If circular ETF
flushing fails, cleanup clears the sink's
``CTL.TraceCaptEn`` and waits for ``STS.TMCReady`` again to force it into
Disabled state. Cleanup still attempts to close all paths and reports the
original error. Unflushed circular ETF trace is discarded and cannot be collected.
ETR flush timeouts instead attempt best-effort RAM readback before final
disable, as described below.

Startup also closes the selected paths and attempts to force their ETFs into
Disabled state before programming them. To run this recovery without starting
another capture:

    sudo python src/cmn_trace_atb.py \
        --atb-topology /path/to/platform/cmn-coresight-atb.json \
        --atb-reset-only

Recovery uses the same polling limit. If an ETF remains busy after forced
disable, or rejects its formatter configuration, the command exits with an
error; a platform CoreSight reset may be required.

Use ``python src/cmn_trace_atb.py --help`` for the complete set of CMN
selection, watchpoint and capture options.


Capturing into system RAM with an ETR
-------------------------------------

Use ``tmc-etr`` for the capture sink's device type in the topology, and select
it in ``captures`` or a named capture option. Intermediate ETFs still run in
hardware FIFO mode. For example, a sink entry is:

    {"id": "cmn-etr", "type": "tmc-etr", "address": "0x400050000"}

Omit the optional ``buffer`` field: the capture tool allocates its own RAM;
reserved buffers are not supported. To select an ETR capture option and
request a 2 MiB stop-on-full buffer:

    sudo python src/cmn_trace_atb.py --atb-capture memory \
        --etr-buffer-size 0x200000 rn-f/up:req

ETR capture requires local AArch64 Linux, ``cc``, permission to lock the
allocation, and permission to read physical frame numbers from
``/proc/self/pagemap`` (normally ``CAP_SYS_ADMIN``). It builds the cache helper
on first capture. The ETR must address the same physical RAM as Linux,
without an SMMU or other address translation that changes those addresses.
The platform's Point of Coherency must make cache maintenance effective for
the ETR's RAM accesses. Remote debugger access remains supported for ETF
capture; allocating ETR RAM through this tool is local only.

Before unlocking or programming an ETR, the tool reads its CoreSight
identification, ``DEVID`` and ``STS``. This probe precedes RAM allocation and
cache helper compilation. Use ``-v`` to see messages before the identification
and status accesses, and their completion.

The allocator first tries the default huge page pool, then requests transparent
huge pages. It populates and checks every page before capture and rejects
the allocation unless the entire block is physically contiguous. Huge pages
must already be configured to use the pool; the tool does not change system
huge page settings. Larger buffers can span several huge pages, which are
checked for adjacency too. If allocation is not contiguous, reserve suitable
huge pages or try a smaller buffer. The rounded allocation can exceed the
requested trace capacity, especially when using the huge page pool.

ETR software FIFO capture uses SoC-600 Software FIFO mode 2 (SWF2) to read
RAM directly and acknowledge consumed bytes through ``RURP``, allowing pending
trace and the flush tail to enter the buffer. This mode is enabled for the
SoC-600 TMC-ETR (part ``0x9e8``); other ETR implementations require ``--circular``.
See the [SoC-600 TRM, sections 4.8.5 and 9.15.2](https://documentation-service.arm.com/static/5f609dae235b3560a01ec366).

The tool cleans and invalidates caches before capture. At readback, it
reports the number of bytes indicated by the write pointer and
Full/Empty flags, checks the page mappings again, invalidates cached contents,
and reads the RAM. Software FIFO captures return the first buffer of trace;
circular captures return the oldest retained bytes first across a wrap.
An AXI memory error, invalid write pointer, or observed address change causes
the capture to fail. Address-change diagnostics identify affected virtual
pages and their old and new physical addresses.

If a circular ETR flush times out, the tool reports the timeout and attempts RAM
readback anyway. Before accessing RAM, it prints the estimated byte count,
write pointer and status. The ETR remains enabled until after readback so
that forced disable does not disturb this evidence. The snapshot can be
incomplete or changing, and the byte count is only an estimate: the circular
buffer write pointer is not guaranteed readable until TMCReady is set
([TMC TRM, section 3.3.5](https://documentation-service.arm.com/static/5f1060dd0daa596235e7ab7a)).
Pointer bounds and physical-address checks still apply. A forwarding FIFO
timeout also allows collection from ETR RAM and software FIFO ETFs; circular
ETF readback is skipped in that case. Use ``--trace-out FILE`` to retain the
recovered bytes before decoding or final cleanup. Cleanup still attempts to disable the ETR and returns an
error if it cannot confirm disable, even if the trace file was written.

``mlock`` keeps pages resident but does not pin their physical addresses.
The final checks are diagnostic: they can miss migration away and back, and
cannot undo writes to obsolete physical addresses. The ETR is disabled and
confirmed ready before RAM is released. If disable fails, the tool retains
its buffer until process exit; a platform reset may still be needed.
``--atb-reset-only`` recovers the ETR without allocating a new buffer or
building the cache helper.


Diagnosing an ETF timeout
-------------------------

Add ``--atb-diagnostics`` to the failing command, including when using
``--atb-reset-only``. Reports go to standard error. For example:

    sudo python src/cmn_trace_atb.py \
        --atb-topology /path/to/platform/cmn-coresight-atb.json \
        --atb-diagnostics rn-f/up:req

Manual flush sets ``FFCR.FlushMan``. The ETF requests an upstream flush using
AFVALID; sources and links send pending trace downstream and return AFREADY.
Merging links must wait for participating inputs. The ETF then finishes its
formatter and memory writes. With ``StopOnFl=1``, the expected result is
``CTL.TraceCaptEn=1, STS.TMCReady=1``. This is separate from SYNCREQ, which
requests synchronization information in the trace stream. An ATB flush cannot
be cancelled once issued; forced disable does not guarantee recovery from a
pending flush. See [AMBA ATB IHI 0032B, sections 4.2 and 4.4](https://documentation-service.arm.com/static/5fb7ec16d77dd807b9a80cb6).

Normal shutdown requests CMN DTC and DTM disable before flushing the ETF.
Upstream components must still complete the ATB flush handshake.

Each timeout adds one read of ``ITCTRL`` (0xf00), ``CTL`` (0x020), ``STS``
(0x00c), ``MODE`` (0x028), ``FFSR`` (0x300) and ``FFCR`` (0x304), on that ETF
only. The report distinguishes these observations:

* ``CTL=0, TMCReady=0`` means disabling has not completed.
* ``FlushMan=1`` means manual flush has not completed. ``FlInProg=1`` can
  describe either an input-side flush or internal pipeline activity; it cannot
  identify a missing upstream acknowledgement.
* Normal status interpretation requires ``ITCTRL.IME=0``. With capture
  disabled, some fields can read UNKNOWN; FFSR can retain an earlier value.

See the [SoC-600 TRM, sections 4.8.1, 4.8.4 and ETF FFSR/FFCR descriptions](https://documentation-service.arm.com/static/5f609dae235b3560a01ec366).

Each readiness timeout produces a post-mortem report before further cleanup writes:

* The ETF's recent actions, in order: flush requests, CTL clears and their
  existing readback check results, and preceding waits that succeeded or failed.
  Up to 32 entries are retained for that ETF in this process.
* The failed wait's first and last STS values, number of polls and elapsed time.
  ``TMCReady=0 throughout`` means no readiness response was observed in polling.
* The six-register snapshot and its interpretation, distinguishing an
  uncompleted manual flush from an uncompleted forced disable.
* Upstream control writes already attempted, their return/check results, and
  the relevant JSON connections. No future capture plans are shown.

For example, a startup recovery failure can report that both replicator filters
were written to ``0xff`` to block trace, then the ETF's CTL clear passed its
readback check, but 100 STS polls still found TMCReady clear. That establishes
that the ETF did not report completing disable, despite the CTL clear being
accepted. It does not establish whether an upstream acknowledgement was missing.

The report explicitly marks the upstream ATB response as ``NOT OBSERVED``.
Replicator writes have no readback check; funnel readback results are from the
write time. Neither establishes receipt of AFREADY. No per-port handshake or
source-clock samples are taken, so missing upstream acknowledgement and
incomplete internal draining cannot be distinguished with this evidence.

Startup isolation writes change forwarding controls before ETF recovery;
the preceding port state is not captured. After a flush timeout, cleanup can
produce another report if forced disable also times out. Each report describes
its own failed wait, with prior ETF actions retained for context. Ambiguous
input wiring is flagged, and no upstream device reads are added.


The ATB topology file
---------------------

The ATB file supplements the normal CMN topology; it does not replace it.
The CMN topology identifies CMN instances, XPs, nodes and DTC domains. The
platform-specific ATB file describes how each DTC is connected to a trace
sink, including any funnels or intermediate FIFOs, and gives the physical
addresses of those CoreSight components.

The platform ATB JSON should be supplied by the platform provider or system
integrator. Its schema is
``data/schemas/cmn-coresight-atb-schema.json``.

An incorrect device address can access the wrong hardware and may make the
system unstable. Validate the file before live capture.


Installing or selecting the topology file
-----------------------------------------

For example, a supplied platform file can be installed in the default cache
location with:

    mkdir -p ~/.cache/arm
    cp /path/to/platform/cmn-coresight-atb.json ~/.cache/arm/cmn-coresight-atb.json

It is not necessary to copy the file. Both the capture and validation tools
accept an explicit path with ``--atb-topology``.


Validating and inspecting the topology
--------------------------------------

``coresight_atb.py`` loads and semantically validates the JSON without
accessing device memory. It also prints a compact list of devices and capture
paths:

    python src/coresight_atb.py \
        --atb-topology /path/to/platform/cmn-coresight-atb.json

Omit ``--atb-topology`` to validate the default cached file. A valid file is
shown in a form similar to:

    System: Example system
    File: /path/to/platform/cmn-coresight-atb.json
    Devices:
      cmn-etf: tmc-etf at 0x400020000 (part 0x961)
      cmn-funnel: funnel at 0x400090000 (part 0x908)
    Capture paths:
      CMN0 DTC0 (cmn0-dtc0): cmn0-dtc0 -> cmn-funnel:1; cmn-funnel:0 -> cmn-etf:0 (capture sink)

The number after a device name is its ATB port for that link. Validation
checks the JSON structure, identifiers, addresses, declared port ranges, DTC
bindings, capture sink references, and that each capture has one unambiguous
path. Every named capture option is validated, including unselected options.
It does not probe the listed physical addresses or verify the wiring.

When named capture options are present, inspection lists their names and the
selected option. Use the same selector to inspect a different capture:

    python src/coresight_atb.py \
        --atb-topology /path/to/platform/cmn-coresight-atb.json \
        --atb-capture downstream

Files can additionally be checked directly against the JSON schema:

    python src/validate_json.py \
        --schema data/schemas/cmn-coresight-atb-schema.json \
        /path/to/platform/cmn-coresight-atb.json


ATB topology format
-------------------

The top-level JSON properties are:

* ``version``: format version, currently ``1``.
* ``system``: optional platform name and description for diagnostics.
* ``sources``: CMN DTC sources, bound by ``cmn_instance`` and ``dtc_domain``.
  An optional ``cmn_base`` can guard against selecting the wrong CMN instance.
* ``devices``: addressable CoreSight components, with unique IDs, types and
  hexadecimal physical addresses. An optional ``part_number`` is checked
  against the discovered component before programming.
* ``links``: directed ATB connections. Ports are zero-based and may be omitted
  on single-port interfaces, where they default to zero. Funnel inputs and
  replicator outputs require explicit ports, as do interfaces declared to
  have multiple ports. ETF inputs and outputs, replicator inputs and funnel
  outputs do not need a port specification. A funnel input port can also be
  omitted if the device declares ``input_ports: 1``.
* ``captures``: the default trace sink selected for each source.
* ``capture_options``: optional named capture specifications, each containing
  a unique ``name``, a ``captures`` list and an optional ``description``.
  At least one of ``captures`` and ``capture_options`` must be present.

A topology with a funnel, a pass-through TMC-ETF and a TMC-ETF capture sink
looks like this:

    {
        "version": 1,
        "system": {"name": "Example system"},
        "sources": [
            {"id": "cmn0-dtc0", "cmn_instance": 0, "dtc_domain": 0}
        ],
        "devices": [
            {"id": "cmn-funnel", "type": "funnel",
             "address": "0x400090000", "part_number": "0x908"},
            {"id": "cmn-fifo", "type": "tmc-etf",
             "address": "0x400030000", "part_number": "0x961"},
            {"id": "cmn-etf", "type": "tmc-etf",
             "address": "0x400020000", "part_number": "0x961"}
        ],
        "links": [
            {"from": {"source": "cmn0-dtc0"},
             "to": {"device": "cmn-funnel", "port": 1}},
            {"from": {"device": "cmn-funnel"},
             "to": {"device": "cmn-fifo"}},
            {"from": {"device": "cmn-fifo"},
             "to": {"device": "cmn-etf"}}
        ],
        "captures": [
            {"source": "cmn0-dtc0", "sink": "cmn-etf"}
        ]
    }

Both ETFs have type ``tmc-etf``. The ``links`` connect the pass-through ETF's
input and output on port zero, and ``captures[].sink`` selects the final
ETF. The script configures ``cmn-fifo`` in hardware FIFO mode and
``cmn-etf`` as the capture sink, using software FIFO mode by default or
circular mode with ``--circular``, and collects trace only from ``cmn-etf``.
No separate mode property is needed. More FIFOs can be chained by adding
devices and links in the same way. Topology inspection labels intermediate
ETFs as ``hardware FIFO`` and the selected ETF as ``capture sink``.

An ETF may be shared by several selected source paths, but it cannot be a
capture sink and an intermediate FIFO in the same capture session.

The devices and links can describe several possible capture arrangements.
For example, replace the top-level ``captures`` in the example above with:

    "capture_options": [
        {
            "name": "local",
            "description": "Capture in the first ETF",
            "captures": [
                {"source": "cmn0-dtc0", "sink": "cmn-fifo"}
            ]
        },
        {
            "name": "downstream",
            "description": "Forward trace to the downstream ETF",
            "captures": [
                {"source": "cmn0-dtc0", "sink": "cmn-etf"}
            ]
        }
    ]

Select the downstream sink with:

    sudo python src/cmn_trace_atb.py \
        --atb-topology /path/to/platform/cmn-coresight-atb.json \
        --atb-capture downstream rn-f/up:req

With ``local``, only the path as far as ``cmn-fifo`` is configured, and that
ETF becomes the capture sink. With ``downstream``, the same ETF
forwards trace in hardware FIFO mode to ``cmn-etf``. Capture options may map
several sources to a shared sink. Only paths used by the selected option
and the selected CMN DTCs are configured. An unknown option name is rejected
before CMN discovery and the error lists the available names.

Without ``--atb-capture``, this example selects ``local`` because it is the
first option. Existing files containing only top-level ``captures`` continue
to work. If both properties are present, top-level ``captures`` provides the
default and ``--atb-capture`` selects a named alternative. The selector also
applies when using ``--atb-reset-only``.

Programmable Arm ATB replicators use type ``replicator``, with input port
zero and output ports zero and one. For example, a device entry is:

    {"id": "cmn-replicator", "type": "replicator",
     "address": "0x400040000", "output_ports": 2}

Connect its input using a link whose ``to`` endpoint names
``cmn-replicator``. A link from output port one to the capture
sink is:

    {"from": {"device": "cmn-replicator", "port": 1},
     "to": {"device": "cmn-etf"}}

The script enables only the replicator outputs used by the selected capture
paths. Each enabled output passes all trace IDs; other outputs block all IDs.
If several selected paths share a replicator, their required outputs are
enabled together. Both outputs are blocked when capture ends. Previous filter
settings are not restored. The current implementation supports two output
ports. ``output_ports`` can be omitted; output port limits are still checked.

The schema reserves device types for a wider range of CoreSight topologies.
The capture script currently programs funnels, programmable Arm ATB
replicators, TMC-ETF devices and TMC-ETR capture sinks. A TMC-ETF can be an
intermediate hardware FIFO or a capture sink. It rejects a selected path
containing an unsupported component before attempting to configure the
CoreSight devices.
