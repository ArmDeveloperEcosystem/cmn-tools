Investigating CMN address mappings
==================================

`cmn_address_map.py` builds a system-wide physical address map by reading
the RN-SAMs in every discovered CMN mesh.

Use this to identify the mesh and home node selected for each address
range, resolving inter-mesh gateway routes to the final home mesh.
On a local target, ranges are split and annotated using /proc/iomem
so memory-mapped devices can be associated with their CMN targets.
Differences between RN-SAM tables are reported as warnings. CSV output
is available for further processing.

    sudo python src/cmn_address_map.py
    sudo python src/cmn_address_map.py --csv > cmn-address-map.csv

Look up physical addresses
--------------------------

One or more physical addresses may be supplied for lookup. If the cached
JSON contains an I/O address map, it is used without accessing CMN device
registers. Otherwise the map is discovered by probing the SAMs. Addresses
use the same decimal or `0x`-prefixed hexadecimal syntax as
`proc_iomem.py`.

    python src/cmn_address_map.py 0x2a000000 0x40000000

`--cached` requires cached information and fails rather than probing
when it is unavailable. `--live` ignores cached address information
and probes the SAMs. `--json` selects an alternative system description.

    python src/cmn_address_map.py --cached 0x2a000000
    sudo python src/cmn_address_map.py --live 0x40000000

Find ranges and peers for a node
--------------------------------

Run node and SN queries on the live system. Use `--cached` for
physical-address lookups in the saved I/O map.

To ask which address ranges can reach a node, use `--by-node` or
`--node`. These reports include all targets in the decoded RN-SAM map,
including coherent home nodes and gateways. Each effective range shows
whether selection is direct or hashed/striped, its SAM table and group
index, and the other targets in that group. CAL, hierarchical hashing,
and CPA information is included where decoded. A node can have different
peers in different regions; direct overrides are removed from the
effective hashed ranges.

    sudo python src/cmn_address_map.py --by-node
    sudo python src/cmn_address_map.py --node m0:hn-f@0x20
    sudo python src/cmn_address_map.py --node hn-s

`--node` uses the common `cmn_select` expressions: hexadecimal CHI
IDs (`0x20` or `hn-f@20`), node types/properties (`hn` or `hn-f`),
logical IDs (`hn-f#0`), coordinates (`sn-f(0,_)`), and optional mesh
prefixes (`m0:`). Node types and properties are matched against topology
objects, including external attachments such as SN-Fs. For example,
`hn-f` also matches HN-S nodes, as in other tools.

    sudo python src/cmn_address_map.py --node 'm0:hn-f#0,sn-f(0,_)' --include-sn

Repeat `--node` or use comma-separated expressions to query several
targets. Peers remain visible even when the report is filtered to one node.
A SAM target ID missing from the topology can still be queried by ID;
type and coordinate selectors require a resolved device. Aggregation groups
without a node ID appear in the unfiltered report, but are not nodes that
can be selected with `--node`.

List hashed groups and find unreferenced nodes
---------------------------------------------

Use `--hashed-groups` to inspect groups, their targets in table order, and
which source SAMs route address ranges to them:

    sudo python src/cmn_address_map.py --hashed-groups
    sudo python src/cmn_address_map.py --hashed-groups --include-sn

The report identifies System Cache Groups (SCGs), Hashed Target Groups
(HTGs), and CML Port Aggregation Groups (CPAGs). CPAG entries list gateway
members, port type, and address or AXID hashing. Enabled CPAGs are listed
even if no address region selects them; references to disabled CPAGs are
marked. With `--include-sn`, the report also lists HN-SAM hashed groups
and default SN target groups. These names follow the
[CMN S3 TRM, sections 2.4.6 and 2.4.7](https://documentation-service.arm.com/static/678ac7553f2a9a07789e5224).

`--hashed-groups` reads additional RN-SAM CPA configuration registers on
CMN-700 r0-r3 and CMN S3 r0-r2. Access may require Secure/Root access or
a CMN security override. These reads are omitted for the ordinary
address-map report. `gateway membership unknown` or `CPA routing
incomplete` means the configuration could not be decoded; check the
accompanying warning. Unsupported revisions, inaccessible or inconsistent
tables, and HN-P CPA selection remain unknown.

When CAL mode is enabled, the target list expands each programmed HN
entry to its CAL members. CAL2 normally includes both even and odd node
IDs; where programmable CAL mappings are implemented, the list follows
those mappings.

Target and source lists show a count, node type, and hexadecimal node IDs,
for example `32 x HN-S at 0x0a0, 0x0a8, ...`. Target-table order is retained.
Each effective address range is followed by a one-line list of the traffic
sources associated with the RN-SAMs, for example
`from 2 x RN-F at 0x080, 0x081; 1 x RN-I at 0x084`. The source type comes
from the discovered device at the RN-SAM's ID, or its port attachment type
for external RN-Fs. Gateway agents retain their own types, such as CCG-HA.
If the attachment is unavailable, the list says `unknown source` and keeps
the RN-SAM's ID. Node IDs belong to the mesh named in the group heading.
Sources sharing a range are listed together; direct overrides are excluded.
Different programming at different sources remains visible, even when it
disagrees with the majority table used by the ordinary address-map report. A CPAG source
also identifies the selecting HTG or non-hashed memory region (NHMR).
An HN-SAM entry identifies the forwarding home and the traffic sources that
can reach it. Groups with no effective incoming range remain visible.

The final section lists discovered HN-F/HN-S nodes and request gateways
(CXRA/CCG-RA) outside the decoded groups, or with no effective route in the
scanned tables. A direct route is reported separately from an absent route;
disabled nodes are marked. A gateway whose membership could depend on an
unresolved CPAG is reported as unknown. CCG-HA nodes are not included in this
check of request destinations.

Use this list to find possible omissions in SAM programming. It does not
prove that a node is unreachable: the check covers decoded address regions
in the scanned meshes, and does not cover incoming remote-chip traffic,
snoop routing, or undecoded SAM features. Group membership describes
configured selection candidates, not measured traffic.

Follow routing to SN nodes
--------------------------

Add `--include-sn` to read HN-F/HN-S SAMs and explain downstream SN
targets. This also shows each home node's onward target sets. HN range
precedence is applied: direct regions, then hashed target groups, then
the default region. The result is intersected with the addresses that
can reach that home through the RN-SAM.

    sudo python src/cmn_address_map.py --by-node --include-sn
    sudo python src/cmn_address_map.py --node m0:sn-f@0x80 --include-sn

An SN entry identifies the forwarding HN and the SN peers for that HN's
group. It is conditional on the RN selecting that home and the home
forwarding the transaction, for example after a cache miss. These reports
describe configured target sets; they do not evaluate the hash to select
the exact target for an individual address. They do not establish that
each candidate path carries traffic, or that each peer receives an equal
share of traffic.

`--include-sn` requires access to HN registers, which may need
Secure/Root access or a CMN security override. Isolated, skipped, and
disabled nodes are excluded from the HN scan.
Undecoded HN configurations, including masked address comparisons, are
reported as unknown downstream routing. Aggregated SA targets, where
decoded, identify the gateway; its remote SN targets are not expanded.
When RN-SAMs disagree, the report uses the majority table and warns about
the differences.

For the HN routing stages, see the
[Arm CMN-700 TRM addendum, section 3.4.3](https://documentation-service.arm.com/static/647de4cb3071ab482ad1060e),
and [CMN S3 TRM, section 2.4.7](https://documentation-service.arm.com/static/67ca2fbcfdbd9d54ee9450f2).

Save I/O mappings for offline use
---------------------------------

With `--update`, non-hashed regions hosted by I/O home nodes are
captured in the top-level `io_address_map` section of the cached CMN
system JSON. Named subranges from `/proc/iomem` are retained as resource
annotations. Coherent home-node groups and downstream SN routing are
available only in live reports; they are not saved in the I/O map.

    sudo python src/cmn_address_map.py --update
    python src/cmn_address_map.py --cached 0x2a000000
