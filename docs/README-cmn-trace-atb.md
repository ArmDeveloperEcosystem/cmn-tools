Self-hosted CMN trace capture over CoreSight ATB
================================================

The ``cmn_trace_atb.py`` script captures CMN trace through a platform's
CoreSight ATB network into on-chip trace buffers. It programs the selected
CMN watchpoints and DTCs, configures the CoreSight components between each
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

By default, decoded packets are printed to standard output after capture.
Use the decode options below to control the amount of detail shown.

Useful ATB-specific options include:

* ``--atid`` selects the first ATB trace ID. Further DTCs use consecutive IDs.
* ``--ts`` inserts global timestamps at the selected period.
* ``--unformatted`` disables CoreSight frame formatting. It cannot be used
  when multiple DTC streams share a sink.
* ``--trace-out`` writes a captured buffer to a file. It should currently be
  used only when the selected topology has one capture sink.
* ``--decode-raw`` and ``--decode-verbose`` provide additional decode detail.

Use ``python src/cmn_trace_atb.py --help`` for the complete set of CMN
selection, watchpoint and capture options.


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
      CMN0 DTC0 (cmn0-dtc0): cmn0-dtc0 -> cmn-funnel:1; cmn-funnel:0 -> cmn-etf:0

The number after a device name is its ATB port for that link. Validation
checks the JSON structure, identifiers, addresses, declared port ranges, DTC
bindings, capture sink references, and that each capture has one unambiguous
path. It does not probe the listed physical addresses or verify the wiring.

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
* ``links``: directed ATB connections. Device endpoints include their
  zero-based input or output port.
* ``captures``: the trace sink selected for each source.

A minimal topology with a funnel and TMC-ETF sink looks like this:

    {
        "version": 1,
        "system": {"name": "Example system"},
        "sources": [
            {"id": "cmn0-dtc0", "cmn_instance": 0, "dtc_domain": 0}
        ],
        "devices": [
            {"id": "cmn-funnel", "type": "funnel",
             "address": "0x400090000", "part_number": "0x908"},
            {"id": "cmn-etf", "type": "tmc-etf",
             "address": "0x400020000", "part_number": "0x961"}
        ],
        "links": [
            {"from": {"source": "cmn0-dtc0"},
             "to": {"device": "cmn-funnel", "port": 1}},
            {"from": {"device": "cmn-funnel", "port": 0},
             "to": {"device": "cmn-etf", "port": 0}}
        ],
        "captures": [
            {"source": "cmn0-dtc0", "sink": "cmn-etf"}
        ]
    }

The schema reserves device types for a wider range of CoreSight topologies.
The capture script currently programs funnels and TMC-ETF devices, with a
TMC-ETF usable either as an intermediate hardware FIFO or as a circular
capture sink. It rejects a selected path containing an unsupported component
before attempting to configure the CoreSight devices.
