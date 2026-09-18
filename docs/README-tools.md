CMN tool overview
=================

This document summarizes the scripts in src/ that are intended to be
used directly. It is a starting point for choosing the right tool; use
each script's --help option for the full command line.

Some Python files in src/ are primarily modules used by these tools.
Those are listed separately at the end.


Discovery and topology
----------------------

cmn_discover.py
  Discover CMN instances and write a JSON topology description.

  Use this first on a new system, before running tools that need the
  cached topology file.

      sudo python src/cmn_discover.py

cmn_detect_cpu.py
  Discover where Linux CPUs sit in the CMN topology, updating the JSON
  system description with CPU mappings.

  Use this after cmn_discover.py if you want later tools to accept
  selectors such as cpu#0.

      python src/cmn_detect_cpu.py --update

  See [README-cpu-discovery.md](README-cpu-discovery.md) for the discovery
  approach, command-line workflows, and implementation.

cmn_detect_c2c.py
  Infer chip-to-chip connections by tagging traffic to each source CCG and
  comparing tagged download counts at CCG ports on the other meshes.

  Run a workload exercising the links, with other CMN PMU/trace users stopped.
  Weak or conflicting peaks are reported as unresolved.

      sudo python src/cmn_detect_c2c.py --source-mesh 0 --dry-run
      sudo python src/cmn_detect_c2c.py --source-mesh 0 -v --output c2c.json

  See [README-c2c-discovery.md](README-c2c-discovery.md) for selectors,
  measurement settings, result interpretation and the JSON report.

cmn_diagram.py
  Print a text diagram of a discovered CMN mesh.

  Use this to get a quick visual map of XPs, ports, node ids and CPU
  locations.

      python src/cmn_diagram.py

cmn_json.py
  Inspect a CMN JSON topology file.

  Use this for simple offline queries such as listing nodes, ports,
  XPs, CPU mappings or recorded chip-to-chip links without accessing device memory.

      python src/cmn_json.py --summary
      python src/cmn_json.py --nodes
      python src/cmn_json.py -i topology.json --c2c-links
      python src/cmn_json.py -i topology.json --c2c-links --cmn-instance 1

  `--summary` lists meshes separately when their configurations, dimensions,
  or home-node types differ. Missing configuration is labelled explicitly.

  The C2C listing shows each connection once, with both mesh/device IDs,
  optional node types and interface numbers, and recorded protocol and
  description. Selecting a CMN instance includes links with either endpoint
  in that mesh. An unresolved node selector is marked in the output.
  "No C2C links recorded" means the file has no matching connection records;
  it does not establish that the hardware has no links. Connections must be
  supplied in the topology description; this option does not discover them.
  See [C2C links in the object model](README-object-model.md#chip-to-chip-links)
  for the JSON format and how to add links.

cmn_list.py
  Inspect CMN topology and configuration by reading CMN device memory.

  Use this when you want a live list of nodes, ports, credited slices,
  routing information, or address map information.

      sudo python src/cmn_list.py --list
      sudo python src/cmn_list.py --node-type hn-f

cmn_address_map.py
  Map physical address ranges to CMN home nodes and inspect hashing/striping
  peers and downstream SN targets. Save I/O mappings for offline lookups.

      sudo python src/cmn_address_map.py --by-node
      sudo python src/cmn_address_map.py --hashed-groups
      sudo python src/cmn_address_map.py --update

  See [README-address-map.md](README-address-map.md) for address lookups,
  node selectors, output interpretation, access requirements and caching.

cmn_debugmap.py
  Generate a Linux-driver-style CMN debug map from the JSON topology.

  Use this when comparing the tools' topology model with the kernel
  driver's debugfs map.

      python src/cmn_debugmap.py --diff

cmn_traceroute.py
  Calculate route distances between selected endpoints in the JSON
  topology.

  Use this to compare expected path lengths, for example between CPU
  request ports and home or memory nodes.

      python src/cmn_traceroute.py rn-f hn-f


Register and low-level inspection
---------------------------------

cmn_regdump.py
  Dump CMN configuration registers using register definition files.

  Use this for detailed register inspection, or with --aggregate to find
  differences between nodes of the same type.

      sudo python src/cmn_regdump.py --node xp --reg device_port_connect_info
      sudo python src/cmn_regdump.py --aggregate --no-common --node hn-f

  See README-regdump.md.

cmn_devmem.py
  Live CMN device driver, with a small low-level diagnostic command line.

  Use --diagram or --sketch to check the discovered mesh, and --dump to
  create an offline CMN register dump. Other tools use its register-access
  and discovery APIs. The diagrams use the shared cmn_diagram renderer,
  showing topology without live status or PMU counters. --no-color and --force-color
  control colour output. Use cmn_pmuvis.py for PMU visualization, or
  cmn_diagram.py for offline topology diagrams.

      sudo python src/cmn_devmem.py --diagram
      sudo python src/cmn_devmem.py --sketch --no-color
      sudo python src/cmn_devmem.py --dump > cmn.dump

cmn_pmuvis.py
  Display live PMU counter changes on a CMN diagram, sample DTM counters,
  or trigger a DTC PMU snapshot. This uses device memory, not perf.

  The former cmn_devmem.py --watch, --pmu-enable, --pmu-sample and
  --pmu-snapshot options now belong to this tool. Its --diagram and --sketch
  options add counter annotations and enabled-DTC highlighting to the shared
  mesh diagram.
  With no action option it displays a diagram without programming events.
  --watch programs the two SLC events selected by --e0 and --e1 (hexadecimal,
  defaults 1 and 3), then updates the diagram at --watch-interval seconds.
  --pmu-sample prints the legacy four 16-bit counter deltas over 10 ms.

  --watch and --pmu-enable overwrite PMU configuration and leave it in
  place on exit. --pmu-snapshot disables the DTC PMU afterwards, restoring
  the previous DTC debug enable state. Do not use these control options
  concurrently with perf or another tool using the PMU.

      sudo python src/cmn_pmuvis.py --diagram
      sudo python src/cmn_pmuvis.py --watch --cmn-instance 0
      sudo python src/cmn_pmuvis.py --pmu-sample
      sudo python src/cmn_pmuvis.py --pmu-snapshot --dtc 0

cmn_frequency.py
  Estimate CMN clock frequency from the CMN cycle counter.

  Use this when checking whether the CMN frequency is known or stable.

      sudo python src/cmn_frequency.py
      sudo python src/cmn_frequency.py --watch 1

cmn_errstat.py
  Report CMN error status registers for nodes that implement error
  reporting.

  Use this during low-level debug or RAS investigation, especially when
  Secure register access is available.

      sudo python src/cmn_errstat.py --secure-access

cmn_dtstat.py
  Inspect and control CMN debug/trace components, including DTCs and
  DTMs.

  Use this when debugging trace setup, checking FIFO state, or resetting
  DTM programming. This tool changes debug/trace state when control
  options are used.

      sudo python src/cmn_dtstat.py --dtms
      sudo python src/cmn_dtstat.py --dtc-sources
      sudo python src/cmn_dtstat.py --dtc 0 --dtc-sources

  `--dtc-sources` groups DTM exports under each DTC's counters `#0` through
  `#7`. Each entry identifies the XP, DTM instance, local counter, and input
  selector, followed by its programming: watchpoint parameters, an XP event,
  or a device PMU event and its name when available. Counters with no known
  exporters are listed too. `--dtc` selects the domain; `--xp` and `--if-tag`
  restrict the contributing DTMs included in the report.

  Disabled DTM/PMU programming is marked as such. Combined local counters
  identify their shared event input and carry relationship; combined DTC
  counter pairs are also marked. DTMs whose domain cannot be determined
  (for example, CMN-600 with multiple DTCs) appear separately under `DTC?`.
  An isolated device cannot be decoded, but its DTM input selector is retained.

  This is a read-only view of current hardware programming, using the same
  configuration access paths as `--dtms`. It does not stop counters or request
  a PMU snapshot. Registers are read sequentially, so a running perf session
  can change the programming during the scan, especially when multiplexing.

cmn_unlock.py
  Set or clear CMN security override bits.

  Use this from a debug environment when normally-Secure CMN registers
  need to be inspected. This is a bring-up/debug tool and should be used
  with care.

      python src/cmn_unlock.py --unlock


PMU and perf tools
------------------

cmn_perfcheck.py
  Check whether the Linux CMN PMU driver and basic perf access are
  available.

  Use this before trying perf-based CMN tools on a new system.

      python src/cmn_perfcheck.py

cmn_perfstat.py
  Collect one or more perf events and report counts or rates.

  Use this as a lightweight wrapper around perf when experimenting with
  CMN PMU event strings.

      python src/cmn_perfstat.py -e arm_cmn_0/cycles/

cmnwatch.py
  Construct CMN watchpoint perf event strings for matching CHI flits.

  Use this when perf needs to count traffic matching CHI fields such as
  channel, opcode, address bits or memory attributes.

      perf stat -e `python src/cmnwatch.py up:req:opcode=ReadNoSnp` -- sleep 1

cmn_perfdecode.py
  Decode CMN watchpoint perf event strings into readable CHI field
  matches.

  Use this as a filter when a perf event string already exists and you
  need to understand which watchpoint it programs. With CMN topology
  JSON, it can also resolve nodeid/wp_dev_sel to the XP, port type,
  device slot and explicit node type.

      python src/cmn_perfdecode.py --cmn-version=cmn-700 \
          'arm_cmn/watchpoint_up,wp_chn_sel=0,wp_val=0x80000000,wp_mask=0xfffffff01fffffff,wp_grp=0/'

cmn_topdown.py
  Run top-down CMN traffic analysis using PMU events and recipes.

  Use this for whole-system traffic characterization: dominant
  requesters, local/remote traffic, and cache hit/miss style breakdowns
  where supported.

      python src/cmn_topdown.py --all

cmn_events.py
  Inspect or generate CMN PMU event definition data.

  Use this when working on event CSV files or checking event names
  available from the event database.

      python src/cmn_events.py --list


Trace and capture
-----------------

cmn_capture.py
  Program CMN watchpoints and capture CHI flit headers from DTM FIFOs.

  Use this when you need packet-level evidence of traffic type,
  direction, source, target or address.

      sudo python src/cmn_capture.py --node rn-f --vc 0 --histogram

  See README-capture.md.

cmn_latency.py
  Measure transaction latency using CHI TraceTag and CMN capture.

  Use this when you want cycle-count deltas between a tagged request and
  packets observed elsewhere in the mesh.

      sudo python src/cmn_latency.py cpu#0 hn-f

  See README-latency.md.

cmn_trace_atb.py
  Capture CMN trace through a platform's CoreSight ATB network into
  on-chip trace buffers, then collect and decode it.

  Use this for self-hosted ATB capture when a platform-specific
  ``cmn-coresight-atb.json`` topology file is available.

      sudo python src/cmn_trace_atb.py rn-f/up:req

  Validate and inspect the ATB topology without accessing hardware using
  ``python src/coresight_atb.py``. See README-cmn-trace-atb.md.

cmn_trace_setup_ds.py
  Set up CMN trace capture onto CoreSight ATB from an Arm Debugger
  session.

  Use this when CMN trace should be captured through an ETF, ETR or
  external debug probe rather than only from on-mesh FIFOs.

  See README-capture-ATB.md.

cmn_decode_trace.py
  Decode a binary CMN ATB trace file.

  Use this after collecting CMN trace through CoreSight.

      python src/cmn_decode_trace.py --cmn-version 700 trace.bin

  Trace widths can be supplied with ``--pa-width``, ``--req-pa-width``
  and ``--rsvdc-width``. When omitted, the decoder retains its historical
  product defaults. The same options are available for
  ``cmn_trace_latency.py``.

cmn_trace_latency.py
  Report transaction latency from an offline CMN trace file.

  Use this when latency should be calculated from trace already captured
  through CoreSight.

      python src/cmn_trace_latency.py --cmn-version 700 trace.bin


System and support utilities
----------------------------

cmn_summary.py
  Print major system properties used by CMN performance methodology.

  Use this to collect a short system summary including CPU, memory and
  CMN-related properties.

      python src/cmn_summary.py
      python src/cmn_summary.py --output summary.json

  JSON groups shared properties under `cmn` and differing meshes under `cmn_N`,
  with `cmn_instance` identifying each mesh. Multi-mesh summaries include system
  node totals and individual frequencies. Unattributed per-HN SLC capacity is
  unavailable.

cmn_config.py
  Look up CMN product version names and known revisions.

  Use this when translating between product numbers and names used by
  other tools.

      python src/cmn_config.py --list

cmn_cpu.py
  Print the discovered CMN location for one Linux CPU.

  Use this as a quick check after CPU discovery.

      python src/cmn_cpu.py 0

cmn_traffic_gen.py
  Generate CPU traffic for discovery or experiments.

  This is mainly a support tool for CPU discovery and controlled traffic
  generation. It may build and run a helper program locally.

      python src/cmn_traffic_gen.py --cpu-list 0 --time 1


Primarily module-oriented scripts
---------------------------------

The following files are primarily library modules used by the tools
above. Some have a small main program for testing, conversion or
development use, but they are not the main user-facing commands:

 - acpi.py
 - app_data.py
 - chi_spec.py
 - cmn_base.py
 - cmn_devmem_find.py
 - cmn_devmem_regs.py
 - cmn_enum.py
 - cmn_flits.py
 - cmn_routing.py
 - cmn_sam.py
 - cmn_select.py
 - cmn_topdown_recipes.py
 - coresight_atb.py
 - cs_decode.py
 - cs_decode_cmn.py
 - devmem.py
 - devmem_base.py
 - devmem_ds.py
 - devmem_dump.py
 - devmem_os.py
 - dmi.py
 - iommap.py
 - memsize_str.py
 - regview.py
 - textdiagram.py
 - validate_json.py
