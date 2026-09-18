Discovering chip-to-chip connections
===================================

`cmn_detect_c2c.py` infers which CCG ports on different CMN meshes are connected.
It tags traffic destined for each source CCG in turn and looks for a repeatable
peak in tagged upload traffic from the CCG ports into the other meshes.

Run a workload that exercises the links throughout discovery. The script does
not generate traffic. It needs direct CMN register access, normally root when
running on Linux, and does not require the Linux CMN PMU driver. Stop other CMN
PMU and trace users, including live sysview sampling, while running discovery:
the script temporarily owns the affected watchpoints and counters.

Getting started
---------------

Preview the probes and estimated measurement time:

    sudo python src/cmn_detect_c2c.py --source-mesh 0 --dry-run

This discovers the live topology but does not program watchpoints or counters.
The usual CMN location options, such as `--cmn-locations`, are available when
automatic location discovery is unsuitable.

Create the cached topology with `cmn_discover.py` first if it is absent.
Probe mesh 0, update its detected links in the cache, and save the observations:

    sudo python src/cmn_detect_c2c.py --source-mesh 0 -v --output c2c.json

Omit `--source-mesh` to probe every mesh in turn. Repeat the option to probe
several source meshes. `--cmn-instance` is an alias for `--source-mesh` here;
remote meshes remain visible for observation.

To find just one link, select a source mesh and an exact CCG target ID:

    sudo python src/cmn_detect_c2c.py --source-mesh 0 --tgtid 0x24 -v

`--tgtid` accepts Python-style integer notation, such as decimal `36` or
hexadecimal `0x24`. It must identify a known CCG device on the selected mesh, and requires exactly one `--source-mesh` (or
`--cmn-instance`), since target IDs are local to a mesh. Only that exact ID is
tagged, even if the CCG has another device ID. All remote CCG ports remain
observers. Add `--dry-run` to preview this single probe. The report records the
selected ID in `target_ids` and the CCG port base ID as the link endpoint.

By default, the script tags REQ uploads at all source-mesh ports, filtered by
the `tgtid` of the CCG being probed. Where the CCG's device IDs can be covered
exactly by one masked filter, they are tagged together. Other ID sets are
probed separately, so the filter never includes a neighbouring port. To limit
tagging to HN-S upload ports, for example:

    sudo python src/cmn_detect_c2c.py --source-mesh 0 --tag-node hn-s -v

`--tag-node` accepts the node selectors used by the other CMN tools, without
a watchpoint channel or field expression. A selected device selects its port;
an XP selector selects the ports on that XP.

Observers use `up:req:tracetag=1` at every CCG port on every other mesh.
After crossing the link, the request is uploaded from the receiving CCG into
its local mesh. Both tag setters and monitors therefore use upload watchpoints:
setters match the source CCG's `tgtid` and enable tag generation; monitors match
`tracetag=1`, leave tag generation disabled, and do not filter on `tgtid`.
`--tag-channel` can select `req`, `rsp` or `dat`; `--monitor-channel` can select
any CHI channel. Both default to `req`. Selecting a different monitoring
channel can help if the workload produces little tagged REQ upload traffic.

The script covers all replicated channel instances and handles multiple DTMs
per XP. Ports and channel instances sharing a DTM are measured in separate
batches. Each DTM combines its four local counters into one wide counter;
the probes do not consume DTC event counters. Larger meshes or more replicated
channels therefore take longer to scan. The estimate excludes register access
time, which can be significant through a debugger. Unchanged watchpoints
remain programmed between samples. Each probe prints periodic sample progress
and its measured elapsed time.

The plan lists baseline and tagged sample counts separately. A baseline is
measured once for each observer batch in each repetition, then reused for the
source batches measured against it. For example, two source batches and one
observer batch take nine samples over three repetitions: about 4.95 seconds
at the default timings, plus register access. The sample duration and repetition
count can be reduced explicitly, for example `--time 0.2`; this needs sufficient
traffic to continue meeting the detection thresholds.

Interpreting results
--------------------

Each probe reports its strongest observing port, if the evidence meets the
thresholds. `-v` lists every observer with:

- `on`: tagged matches counted while source tagging was enabled.
- `baseline`: tagged matches counted during the baseline samples, with source
  tagging disabled.
- `excess`: the difference in match rates between those two measurements.

Counts accumulate over all batches and repetitions. Rates are summed across
source batches, target-ID filters and observing channel instances, then averaged
over repetitions. Baselines cover fewer samples than the tagged counts, so
compare the baseline-adjusted `excess` rate rather than subtracting the two raw
counts. A baseline is refreshed for each observer batch and repetition; keep the
workload steady while its source batches are measured. The rates describe the
discovery signal, not link utilization or a simultaneous measurement of all
traffic. `tagger matches` counts matching
source uploads during the tagged measurement windows; it helps distinguish an
idle source from a failure to observe tags remotely.

By default, each measurement lasts 0.5 seconds, with a 0.05-second settling
period before both the baseline and tagged measurement. Each probe is repeated
three times. A result is `detected` only when the same observing port has a
positive peak in every repetition, exceeds every other observer by at least
five times in every repetition, and accumulates at least ten excess matches.
Nonzero counts at other ports are allowed.

Unresolved results show all observer counts even without `-v`:

- `no-target-traffic`: no matching source uploads were counted.
- `no-signal`: source uploads occurred but no positive excess was observed.
- `low-traffic`: the excess count was below the minimum.
- `ambiguous`: the peak was insufficiently distinct or did not repeat.

Increase `--time`, run a steadier workload, or change the source selector or
monitoring channel to investigate an unresolved result. `--settle`, `--repeats`,
`--ratio` and `--min-count` adjust the corresponding thresholds. A missing
signal does not establish that a link is absent. TraceTag can propagate to
associated transactions, which can also produce background or secondary peaks;
these thresholds are an inference heuristic, not proof of physical wiring.
The tagging and propagation behavior is described in section 6.2.2 of the
[Arm CMN S3 TRM](https://documentation-service.arm.com/static/67ac4cf66dbc975ccea92cd0).

When multiple source meshes are probed, reciprocal discoveries produce one
connection record. If accepted probes assign more than one peer to the same
CCG port, all pairs involving that conflict are omitted from the inferred link
list and reported separately. Port-level probing does not distinguish parallel
physical interfaces behind the same CCG port.

Saving results
--------------

Normal runs merge accepted `c2c_links` into the standard cached system
description (`~/.cache/arm/cmn-system.json` on Linux). Use `--json topology.json`
to update another system description, or `--no-update` to collect observations
without changing the cache. `--dry-run` does not load or update the cache.

    sudo python src/cmn_detect_c2c.py --json topology.json --output c2c.json
    python src/cmn_json.py -i topology.json --c2c-links

The cache must already contain the discovered meshes and CCG ports. Meshes are
matched by physical base address and checked for matching CMN products; endpoint
mesh numbers are translated into the cache's CMN-element order. Missing or
incompatible cached topology is reported before measurements begin. Refresh it
with `cmn_discover.py`, or use `--no-update` for a report-only run.

Accepted pairs replace cached links assigning a different peer to either of
those CCG ports. Other cached links are retained, including ports whose probes
were unresolved or conflicting. Matching links retain their IDs, descriptions,
protocols, node selectors and interface numbers, including recorded parallel
interfaces between the same ports. New records refer to port base IDs; no
protocol, node type or physical interface number is guessed. CPU mappings,
address maps and other topology fields are preserved. The complete result is
validated through the [object model](README-object-model.md#chip-to-chip-links)
and saved atomically, preserving cache ownership and permissions, after
measurement and hardware restoration finish. An unchanged cache is not rewritten.

`--output` additionally writes a JSON report containing the probe settings, mesh
identities, per-probe and per-repetition observer counts, sample counts and
elapsed times, inferred `c2c_links`, and conflicting pairs. `baseline_scope`
records that a baseline is reused within an observer batch and repetition.
Endpoint `mseq` values in this report are the live mesh numbers; `id` values are
CCG port base IDs. The report uses the object model's connection format, but
is a measurement report rather than a topology description. It must use a
different filename from the cache and is also replaced atomically after
hardware restoration.

Exit status is 0 when all requested probes resolve without conflicts, 2 when
any probe is unresolved or connections conflict, 1 for an error, and 130 for
Ctrl-C. Completed runs save accepted, non-conflicting links and write the
requested report even when other probes are unresolved. An interruption or
hardware restoration failure leaves the cache unchanged.
The script restores the DTM configuration and saved local counter values and
the DTC control registers it changed on completion, errors and Ctrl-C. A
restoration failure is reported explicitly. Measurements from another PMU user
cannot remain continuous during discovery.
