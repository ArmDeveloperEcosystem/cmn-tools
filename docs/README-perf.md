CMN PMU and perf tools
======================

Some CMN tools use the Linux perf subsystem and the arm-cmn PMU driver
rather than reading CMN device memory directly. These tools are useful
when you want counts, rates or higher-level traffic summaries.

The main scripts are:

 - cmn_perfcheck.py: check that CMN perf events are available

 - cmn_perfstat.py: collect named perf events and report counts/rates

 - cmnwatch.py: construct CMN watchpoint event strings for perf

 - cmn_topdown.py: run higher-level traffic analysis using PMU recipes

 - cmn_events.py: inspect or generate CMN event definition data


Prerequisites
-------------

The kernel must have the arm-cmn PMU driver installed and enabled. A
typical system exposes CMN PMUs under:

    /sys/bus/event_source/devices/arm_cmn_0

The user must also have permission to open the relevant perf events.
On many systems this requires:

    sudo sysctl kernel.perf_event_paranoid=0

or equivalent local policy.

The perf command-line tool must be installed. Most scripts use "perf"
from PATH by default, but provide --perf-bin if a different binary is
needed.


Checking perf availability
--------------------------

Use cmn_perfcheck.py first on a new system:

    python cmn_perfcheck.py

With more verbose output:

    python cmn_perfcheck.py -v

This checks whether the arm-cmn PMU driver is visible and whether basic
CMN events can be opened through perf. If this fails, other perf-based
CMN tools are unlikely to work.


Simple event counting
---------------------

cmn_perfstat.py collects one or more perf events and prints counts.

Count one event for the default measurement time:

    python cmn_perfstat.py -e arm_cmn_0/cycles/

Count more than one event:

    python cmn_perfstat.py \
      -e arm_cmn_0/cycles/ \
      -e arm_cmn_0/hnf_cache_miss/

Select the measurement time:

    python cmn_perfstat.py --time 2.0 -e arm_cmn_0/cycles/

Show estimated CMN frequency from perf:

    python cmn_perfstat.py --frequency

cmn_perfstat.py adjusts readings for perf scheduling fraction where perf
reports it. This is useful when measuring many events, or on systems
where events cannot all be scheduled at once.


Constructing watchpoints
------------------------

cmnwatch.py generates CMN watchpoint event strings for perf. A
watchpoint matches CHI flits by channel and selected fields such as
opcode, address bits, memory attributes or source/target identifiers.

Generate event strings for ReadNoSnp requests:

    python cmnwatch.py up:req:opcode=ReadNoSnp

Use the generated strings directly with perf:

    perf stat -e `python cmnwatch.py up:req:opcode=ReadNoSnp` -- sleep 1

List supported CHI fields:

    python cmnwatch.py --list

Use explicit options instead of the short watchpoint form:

    python cmnwatch.py --upload --REQ --opcode ReadNoSnp

Match traffic at a CPU, using CPU mappings from the CMN JSON topology:

    python cmnwatch.py --at-cpu 0 --upload --REQ --opcode ReadNoSnp

Run perf stat directly from cmnwatch.py:

    python cmnwatch.py --stat --sleep 1 up:req:opcode=ReadNoSnp

Watchpoint construction requires the tool to know the CMN version. This
can come from a CMN JSON description, from system discovery, or from an
explicit --cmn-version option.


Decoding watchpoints
--------------------

cmn_perfdecode.py scans text for CMN watchpoint perf event strings and
adds a readable explanation. This is useful when a watchpoint starts out
as a perf event string and you want to understand the CHI channel,
direction and fields it matches.

Decode a single event string:

    python cmn_perfdecode.py --cmn-version=cmn-700 \
        'arm_cmn/watchpoint_up,wp_chn_sel=0,wp_val=0x80000000,wp_mask=0xfffffff01fffffff,wp_grp=0/'

Use it as a filter:

    perf stat -vv -e `python cmnwatch.py up:req:opcode=ReadNoSnp` -- sleep 1 2>&1 \
        | python cmn_perfdecode.py --cmn-version=cmn-700

If CMN topology JSON is available, cmn_perfdecode.py also uses the PMU
name (for example arm_cmn_0) and the event's nodeid/wp_dev_sel fields
to show the XP, port type, device slot and explicit node type where it
can. By default it uses the standard cached CMN JSON file. Pass
--cmn-json to decode against a specific topology file instead:

    python cmn_perfdecode.py --cmn-json systems/json/n1sdp-cmn.json \
        'arm_cmn_0/watchpoint_up,wp_chn_sel=0,nodeid=0x0,bynodeid=1,wp_dev_sel=0,wp_mask=0xffffffffffffffff/'


Top-down analysis
-----------------

cmn_topdown.py runs a set of PMU measurements intended to summarize
important traffic behavior.

Run all built-in top-down levels:

    python cmn_topdown.py --all

Run a specific level:

    python cmn_topdown.py --level 1

Use a fixed measurement interval:

    python cmn_topdown.py --all --time 2.0

Print request counts as bandwidth:

    python cmn_topdown.py --all --bandwidth

For multi-mesh systems, report mesh-scoped metrics per mesh:

    python cmn_topdown.py --all --per-mesh

Run a command while measuring:

    python cmn_topdown.py --all --cmd "sleep 2"

The --cmd process is started by cmn_topdown.py and killed when the
measurement ends. Use it for short controlled workloads, not for
long-running services.


Recipes
-------

Top-down measurements can be described by JSON recipes. Built-in recipes
are in:

    data/recipes/

Use an additional recipe:

    python cmn_topdown.py --recipe my-recipe.json

Add a directory to the recipe search path:

    python cmn_topdown.py --recipe-path /path/to/recipes --recipe my-recipe.json

Print the recipe selected by command-line options:

    python cmn_topdown.py --all --print-recipe

Recipes are useful when a system or investigation needs a repeatable set
of events and derived metrics.


Event definitions
-----------------

CMN PMU event definitions are held in CSV files under:

    data/events/

cmn_events.py can list or regenerate event data.

List events from a CSV file:

    python cmn_events.py -i data/events/cmn-events-0436.csv --list

Add events from sysfs, when the running kernel exposes them:

    python cmn_events.py --add-sysfs --list

Write an output CSV:

    python cmn_events.py -i input.csv -o output.csv

Most users do not need cmn_events.py directly. It is mainly useful when
maintaining event definition files or debugging event naming.


Common problems
---------------

No arm-cmn PMU appears in sysfs:

 - check that the kernel has the arm-cmn PMU driver

 - check that the system actually exposes CMN to Linux

 - check for /sys/bus/event_source/devices/arm_cmn_0

perf reports permission errors:

 - check kernel.perf_event_paranoid

 - try running as root if local policy allows it

Events report zero:

 - increase the measurement interval

 - verify that the selected traffic is expected to occur

 - for watchpoints, check channel direction and field selection

Too many events to schedule at once:

 - reduce the number of events

 - split the measurement into multiple runs

 - check perf scheduling percentages in the output

Unexpected watchpoint results:

 - verify upload vs. download direction

 - verify CHI channel: REQ, RSP, SNP or DAT

 - use cmn_diagram.py or cmn_json.py to check node ids and CPU mappings

 - use cmn_capture.py if packet-level evidence is needed
