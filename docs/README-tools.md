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

      sudo python cmn_discover.py

cmn_detect_cpu.py
  Discover where Linux CPUs sit in the CMN topology, updating the JSON
  system description with CPU mappings.

  Use this after cmn_discover.py if you want later tools to accept
  selectors such as cpu#0.

      python cmn_detect_cpu.py --update

cmn_diagram.py
  Print a text diagram of a discovered CMN mesh.

  Use this to get a quick visual map of XPs, ports, node ids and CPU
  locations.

      python cmn_diagram.py

cmn_json.py
  Inspect a CMN JSON topology file.

  Use this for simple offline queries such as listing nodes, ports,
  XPs or CPU mappings without accessing device memory.

      python cmn_json.py --summary
      python cmn_json.py --nodes

cmn_list.py
  Inspect CMN topology and configuration by reading CMN device memory.

  Use this when you want a live list of nodes, ports, credited slices,
  routing information, or address map information.

      sudo python cmn_list.py --list
      sudo python cmn_list.py --node-type hn-f

cmn_debugmap.py
  Generate a Linux-driver-style CMN debug map from the JSON topology.

  Use this when comparing the tools' topology model with the kernel
  driver's debugfs map.

      python cmn_debugmap.py --diff

cmn_traceroute.py
  Calculate route distances between selected endpoints in the JSON
  topology.

  Use this to compare expected path lengths, for example between CPU
  request ports and home or memory nodes.

      python cmn_traceroute.py rn-f hn-f


Register and low-level inspection
---------------------------------

cmn_regdump.py
  Dump CMN configuration registers using register definition files.

  Use this for detailed register inspection, or with --aggregate to find
  differences between nodes of the same type.

      sudo python cmn_regdump.py --node xp --reg device_port_connect_info
      sudo python cmn_regdump.py --aggregate --no-common --node hn-f

  See README-regdump.md.

cmn_devmem.py
  Low-level CMN device-memory explorer.

  Use this for diagnostics, diagrams, PMU sampling experiments, and for
  creating offline CMN dump files with --dump. Most users should prefer
  the more specific tools where possible.

      sudo python cmn_devmem.py --diagram
      sudo python cmn_devmem.py --dump > cmn.dump

cmn_frequency.py
  Estimate CMN clock frequency from the CMN cycle counter.

  Use this when checking whether the CMN frequency is known or stable.

      sudo python cmn_frequency.py
      sudo python cmn_frequency.py --watch 1

cmn_errstat.py
  Report CMN error status registers for nodes that implement error
  reporting.

  Use this during low-level debug or RAS investigation, especially when
  Secure register access is available.

      sudo python cmn_errstat.py --secure-access

cmn_dtstat.py
  Inspect and control CMN debug/trace components, including DTCs and
  DTMs.

  Use this when debugging trace setup, checking FIFO state, or resetting
  DTM programming. This tool changes debug/trace state when control
  options are used.

      sudo python cmn_dtstat.py --dtms

cmn_unlock.py
  Set or clear CMN security override bits.

  Use this from a debug environment when normally-Secure CMN registers
  need to be inspected. This is a bring-up/debug tool and should be used
  with care.

      python cmn_unlock.py --unlock --root


PMU and perf tools
------------------

cmn_perfcheck.py
  Check whether the Linux CMN PMU driver and basic perf access are
  available.

  Use this before trying perf-based CMN tools on a new system.

      python cmn_perfcheck.py

cmn_perfstat.py
  Collect one or more perf events and report counts or rates.

  Use this as a lightweight wrapper around perf when experimenting with
  CMN PMU event strings.

      python cmn_perfstat.py -e arm_cmn_0/cycles/

cmnwatch.py
  Construct CMN watchpoint perf event strings for matching CHI flits.

  Use this when perf needs to count traffic matching CHI fields such as
  channel, opcode, address bits or memory attributes.

      perf stat -e `python cmnwatch.py up:req:opcode=ReadNoSnp` -- sleep 1

cmn_perfdecode.py
  Decode CMN watchpoint perf event strings into readable CHI field
  matches.

  Use this as a filter when a perf event string already exists and you
  need to understand which watchpoint it programs. With CMN topology
  JSON, it can also resolve nodeid/wp_dev_sel to the XP, port type,
  device slot and explicit node type.

      python cmn_perfdecode.py --cmn-version=cmn-700 \
          'arm_cmn/watchpoint_up,wp_chn_sel=0,wp_val=0x80000000,wp_mask=0xfffffff01fffffff,wp_grp=0/'

cmn_topdown.py
  Run top-down CMN traffic analysis using PMU events and recipes.

  Use this for whole-system traffic characterization: dominant
  requesters, local/remote traffic, and cache hit/miss style breakdowns
  where supported.

      python cmn_topdown.py --all

cmn_events.py
  Inspect or generate CMN PMU event definition data.

  Use this when working on event CSV files or checking event names
  available from the event database.

      python cmn_events.py --list


Trace and capture
-----------------

cmn_capture.py
  Program CMN watchpoints and capture CHI flit headers from DTM FIFOs.

  Use this when you need packet-level evidence of traffic type,
  direction, source, target or address.

      sudo python cmn_capture.py --node rn-f --vc 0 --histogram

  See README-capture.md.

cmn_latency.py
  Measure transaction latency using CHI TraceTag and CMN capture.

  Use this when you want cycle-count deltas between a tagged request and
  packets observed elsewhere in the mesh.

      sudo python cmn_latency.py cpu#0 hn-f

  See README-latency.md.

cmn_trace_setup_ds.py
  Set up CMN trace capture onto CoreSight ATB from an Arm Debugger
  session.

  Use this when CMN trace should be captured through an ETF, ETR or
  external debug probe rather than only from on-mesh FIFOs.

  See README-capture-ATB.md.

cmn_decode_trace.py
  Decode a binary CMN ATB trace file.

  Use this after collecting CMN trace through CoreSight.

      python cmn_decode_trace.py --cmn-version 700 trace.bin

cmn_trace_latency.py
  Report transaction latency from an offline CMN trace file.

  Use this when latency should be calculated from trace already captured
  through CoreSight.

      python cmn_trace_latency.py --cmn-version 700 trace.bin


System and support utilities
----------------------------

cmn_summary.py
  Print major system properties used by CMN performance methodology.

  Use this to collect a short system summary including CPU, memory and
  CMN-related properties.

      python cmn_summary.py

cmn_config.py
  Look up CMN product version names and known revisions.

  Use this when translating between product numbers and names used by
  other tools.

      python cmn_config.py --list

cmn_cpu.py
  Print the discovered CMN location for one Linux CPU.

  Use this as a quick check after CPU discovery.

      python cmn_cpu.py 0

cmn_traffic_gen.py
  Generate CPU traffic for discovery or experiments.

  This is mainly a support tool for CPU discovery and controlled traffic
  generation. It may build and run a helper program locally.

      python cmn_traffic_gen.py --cpu-list 0 --time 1


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
