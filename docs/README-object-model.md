# CMN Object Model

This repository uses a shared object model in both `cmn_base.py` and
`cmn_devmem.py` to describe a CMN mesh in terms that match the CMN
topology.

`cmn_base.py` holds a persistent, topology-oriented model used by JSON and
offline tools.

`cmn_devmem.py` exposes the same topology concepts, but backs them with live
register discovery and access.

`cmn_pmuvis.py` is a client of that live driver. It owns PMU event setup
for visualization, counter sampling and the PMU-annotated diagram. DTM and
DTC register-access methods remain in `cmn_devmem.py`; the driver does not
import the visualizer. Its standalone `--diagram` and `--sketch` options
use `cmn_diagram.CMNDiagram`, importing the renderer only when requested.

`CMN.is_live()` distinguishes the two models: `False` for the offline topology
in `cmn_base`, and `True` for the register-access model in `cmn_devmem`.
The query itself does not discover devices or access registers. Clients that
accept either model must check it before investigating status; the offline
model does not provide status-query methods.

The shared renderer uses topology alone for port labels and colours in both
models; it does not investigate or display live status. `CMNDiagramPerf` in
`cmn_pmuvis.py` overrides `port_label_color()` to highlight ports containing
an enabled DTC, checking `is_live()` before investigating its state.


## Overview

The main containment hierarchy is:

`System -> CMN -> XP -> Port -> Device slot -> Device node`

This maps onto CMN concepts as follows:

- `System`: the whole machine, possibly containing multiple CMN meshes.
- `CMN`: one mesh interconnect instance, usually one per die.
- `XP`: a crosspoint in the mesh grid.
- `Port`: one device-facing XP port.
- `Device slot`: one CHI-addressable attachment point behind a port.
- `Device node`: an explicit CMN node discovered on that device slot, such as
  HN-F, HN-S, RN-SAM or DTC.

The important distinction is that a CHI device slot is not always backed by a
distinct CMN node object. External attachments such as RN-F and SN-F consume
CHI ids and therefore appear as device slots, but may have no explicit CMN
device node in the topology.


## Top-Level Objects

### `System`

A `System` groups all CMN instances and any discovered CPU and I/O address
mappings.

- `System.CMNs`: all meshes in the system.
- `System.ports()`, `System.XPs()`, `System.nodes()`: iterate across all
  meshes.
- `System.cpu_node`: map from OS CPU number to `CPU`.
- `System.c2c_links`: recorded direct chip-to-chip connections between meshes.
- `System.io_address_map`: optional capture of non-hashed physical-address
  regions hosted by I/O home nodes. Each home refers back to a mesh and CHI
  target ID; named `/proc/iomem` resources may annotate its regions.

Use `System` when a tool needs a whole-system view, especially on multi-mesh
systems where CHI ids must be interpreted together with a mesh instance.


### Chip-to-chip links

A `C2CLink` is one direct connection between gateway attachments on different
meshes. A `System` owns each link once, separately from the containment
hierarchy. Its two `C2CLinkEndpoint` objects reference existing device slots.
The endpoint order does not imply a source/destination direction. A link
records adjacency; routes through intermediate chips and aggregation groups
are separate concepts.

The system JSON has an optional top-level `c2c_links` array alongside
`elements`. For example, this fragment describes one connection (the mesh
numbers and device IDs are illustrative and must exist in `elements`):

```json
{
  "c2c_links": [
    {
      "id": "c2c0",
      "endpoints": [
        {"mseq": 0, "id": 256, "interface": 0},
        {"mseq": 1, "id": 264, "interface": 0}
      ],
      "protocol": "CHI-C2C",
      "description": "Connection between the two compute dies"
    }
  ]
}
```

Each link requires a nonempty string `id`, unique within the system, and
exactly two endpoints. `protocol` and `description` are optional strings;
protocol names are not restricted to a fixed list. Other link details can be
added as schema fields when needed.

Endpoint fields are:

| Field | Meaning |
| --- | --- |
| `mseq` | Required nonnegative CMN sequence number, assigned in CMN-element order within the descriptor. It is not a hardware chip ID. |
| `id` | Required CHI device slot ID within that mesh, in the range 0 through 65535. |
| `type` | Optional numeric node type at that slot, in the range 0 through 65535. This is a node type, not the XP port's connected type. |
| `interface` | Optional nonnegative interface number within the gateway attachment. This is independent of XP port numbering and need not match the peer's interface number. |

Omitting `type` refers to the device slot as a whole, without choosing one of
its explicit nodes. This supports composite gateways and attachments without
captured nodes. No particular CCG type or gateway family is required. When
`type` is supplied but the node is absent, the selector is preserved and the
node remains unresolved; JSON loading can collect a warning and the CLI marks
it in the listing. The mesh and device slot themselves must exist.

Omitting `interface` means unspecified, not zero. Parallel connections using
the same slot require distinct explicit interface numbers. Reusing an
interface is rejected even if the node-type annotations differ. A slot with
an unspecified interface cannot acquire another link until its existing
interface is identified. Duplicate link IDs, conflicting endpoints and
connections within one mesh are rejected before registering the new link.

Absent and empty `c2c_links` both mean no connections were recorded; neither
claims that the topology capture is complete. Writers omit an empty array.
This is an optional addition to descriptor version 1: existing files load
unchanged, but older strict schemas reject the field and older readers may
discard it on rewriting. The current writer preserves recorded links and
writes their mesh references in output CMN-element order, including when
live mesh numbers are sparse or the mesh list has been reordered.

[`cmn_detect_c2c.py`](README-c2c-discovery.md#saving-results) updates these links
in the cached description by default after successful measurement and hardware
restoration. It translates live mesh numbers by matching physical base addresses,
retains annotations on matching links, and preserves unrelated cached topology.
Use `--json` to select a different cache or `--no-update` to save only a report.

`C2CLink` and `C2CLinkEndpoint` are shared classes in `cmn_base` and can bind to
either model's device slots. To add a link to an existing system description:

```python
import cmn_base
import cmn_json

system = cmn_json.system_from_json_file("topology.json")
a = cmn_base.C2CLinkEndpoint(system, 0, 256, interface=0)
b = cmn_base.C2CLinkEndpoint(system, 1, 264, interface=0)
link = system.create_c2c_link("c2c0", [a, b], protocol="CHI-C2C")
cmn_json.json_dump_file_from_system(system, "topology-with-links.json")
```

Supply `node_type=...` to `C2CLinkEndpoint` when selecting an explicit node.
The constructor binds to a device slot using the mesh's current `cmn_seq`.
It can materialize an offline slot already represented by a port, but never
performs live child discovery or register reads.

Navigation is available in both models:

- `system.c2c_links`: the list of system-owned links.
- `cmn.c2c_links()`: iterate links with an endpoint on this mesh.
- `device.c2c_endpoints()`: iterate endpoints attached to this device slot.
- `link.endpoints`: the two endpoints, stored as a tuple.
- `link.other_endpoint(endpoint)`: obtain the endpoint's peer.
- `endpoint.link`, `endpoint.device`: navigate to the link and attachment.
- `endpoint.node_type`, `endpoint.interface`: optional selectors.
- `endpoint.node`: the selected node if captured or already discovered;
  otherwise `None`. It is also `None` when no node type was selected.

A node reaches its attachment through `node.device_object`; an endpoint
reaches its mesh through `endpoint.device.CMN()`. The mesh and device
iterators return the same objects owned by the system. The common
`device.cached_node_by_type()` lookup used by endpoints never discovers
children. In the live model, a later independent discovery may make
`endpoint.node` resolvable without changing the link.

To list recorded links without device access:

```sh
python src/cmn_json.py -i topology-with-links.json --c2c-links
python src/cmn_json.py -i topology-with-links.json --c2c-links --cmn-instance 1
```


### I/O address-map capture

`IOAddressMap` is optional whole-system discovery data. It contains
`IOAddressHome` objects identified by a CMN sequence number, CHI target ID
and descriptive node type. Each home contains its non-hashed
`IOAddressRegion` objects. Region bounds are inclusive.

An `IOAddressRegion` may contain `IOAddressResource` annotations derived
from named `/proc/iomem` entries. These names describe kernel resources; they
do not assert a more specific operating-system device identity.


### `CMN`

A `CMN` object represents one rectangular CMN mesh.

`CMN.home_node_type()` returns the recorded home-node type code, or `None`.
It does not discover nodes or access registers. Each mesh has one home-node type;
different meshes can have different types.

- In `cmn_base`, it is a topology container populated from discovery data or
  JSON.
- In `cmn_devmem`, it is also the live access point for register-backed
  discovery and control.

Each mesh's `product_config` records synthesis-time properties needed by
other tools, including the CHI version, MTE and MPAM enablement, MPAM PARTID
width, and physical-address, REQ-address and REQ-RSVDC widths. Unknown optional
values are omitted from topology JSON.

FIFO capture, latency capture and ATB decoding convert these settings through
`cmn_flits.trace_config_from_cmn_config()`. The conversion preserves the
product id, major revision, CHI version, MPAM enablement and flit-field widths.
Unspecified CHI versions and widths retain the decoder's defaults. Standalone
decoders can still construct `CMNTraceConfig` directly without a CMN model.

Key responsibilities:

- hold mesh dimensions and XP lookup tables
- translate between coordinates and node ids
- iterate XPs, ports, nodes and device slots
- resolve a CHI id to its owning port or device slot

Important iteration methods:

- `XPs()`: crosspoints only
- `ports()`: ports only
- `nodes()`: explicit CMN nodes only
- `devices()`: CHI-addressable device slots, including external attachments

`nodes()` and `devices()` are intentionally different. If a tool cares about
CHI ids seen on the fabric, it usually wants `devices()`. If it cares about
explicit CMN components, it usually wants `nodes()`.

In both object models, `CMN.nodes()` yields explicit device nodes only. For
live access, `CMN.register_nodes()` additionally yields the root configuration
node and XPs for tools which operate directly on every register-backed node.


## XP, Port and Device Slot

### `CMNNodeXP`

An XP is a crosspoint in the mesh, identified by `(X, Y)` coordinates and an
XP node id.

An XP owns:

- zero or more device-facing `CMNPort` objects
- mesh-link information
- in `cmn_devmem`, one or more DTMs and the logic to discover child nodes

The XP is the anchor point for interpreting the low bits of CHI node ids into
port number and device number.

In the live model, `xp.DTMs()` yields the XP's `CMNDTM` objects. Each DTM's
`ports()` method yields its associated `CMNPort` objects, and `port.dtm`
identifies the DTM for a port. These are the same port objects returned by
`xp.ports()`, retaining their XP-wide `port_number` values rather than
DTM-local numbers. Iterating `dtm.ports()` does not discover child nodes or
read registers.

`dtm.unit_info` returns the live DTM's unit-info register value, read on first
access and then cached. `dtm.dtc_domain()` returns that DTM's domain; there is
no live XP-wide `dtc_domain()` method. On CMN-600, `unit_info` is `None` and
the domain is known only when the mesh has a single DTC.

Both models provide `xp.dtc_domains()`, returning a list of domain values.
The live model returns one entry per DTM, in DTM-index order, using the DTM
unit-info caches. The offline model returns one entry containing the saved
XP domain. An unknown domain is represented by `None`.

The JSON XP `dtc` field records the common DTC domain of its DTMs. JSON
generation uses `xp.dtc_domains()` to check that all domains agree and reports
an unsupported configuration if they differ. The offline model's singular
`xp.dtc_domain()` still returns the saved value, not a live status query.


### Live DTM/DTC programming

Use-case scripts select watchpoints, sequence measurements and interpret the
counts. Register offsets, bit-field layouts and exact state restoration belong
in `cmn_devmem`. These operations are specific to the live model; the cached
`cmn_base` topology does not emulate hardware programming.

`dtm.dtm_save()` returns a `DTMState` containing control, PMU configuration,
live local counter values, and all four watchpoints. It reads those registers
once, without stopping the DTM or accessing its FIFO. The saved object belongs
to that DTM and is not a serialized topology record. Counter values are those
observed while saving; saving/restoring cannot maintain another user's running
measurement. The caller must own the affected debug/PMU blocks throughout.

`dtm.dtm_update_control(enable=..., tag=..., sample=..., atb=...)` preserves
unspecified controls. `False` clears a feature; `None` leaves it unchanged.
Supplying `control=saved.control` uses that saved word instead of reading the
current register. The existing `dtm_set_control()` retains its original behavior
of starting from the supplied word and OR-ing in requested features.

Once the DTM is disabled:

- `dtm.dtm_reset_wps(preserve_config=False)` clears all watchpoint configurations
  and sets matches to match nothing, without reading their old settings. Its
  default still preserves the configuration needed to interpret existing FIFO
  entries. Neither mode clears FIFO contents.
- `dtm.dtm_wp_set(slot, watchpoint)` programs a `DTMWatchpoint` as before.
- `dtm.pmu_configure_local(inputs, width=16)` selects local counter inputs with
  no export to DTC event counters. Supply four selectors for 16-bit counters,
  two for 32-bit counters, or one for a 64-bit counter. Input selectors 0–3
  count watchpoint matches; XP/device selectors use the hardware's event-input
  encoding. This configures and enables the local PMU; DTM and DTC enables
  are managed separately.
- `dtm.pmu_set_counters(values, width=16)` sets all live local counters with
  one write. `dtm.pmu_counters(width=16)` reads them with one access and is
  also usable while counting. Both use the same width choices; the caller
  supplies the programmed width to avoid repeated configuration reads.
- `dtm.pmu_disable(config=saved.pmu_config)` disables local counting using
  the supplied configuration, without reading it again.

`dtm.dtm_restore(saved)` restores watchpoints, counters and configuration, then
the original control word. Disable the DTM first. Restoration preserves the
exact saved configuration words, including bits not decoded by the Python
watchpoint model. For coordinated restoration across several DTMs, call
`dtm_restore(saved, restore_control=False)` on each disabled DTM, restore the
DTC controls, then call `dtm_restore_control(saved)` on each DTM. This lets a
caller stop all tagging before restoring any previous watchpoint configuration.

`dtc.dtc_save()` returns a `DTCState` containing the DTC control and PMU control
words. `dtc.dtc_enable(pmu=True, wait=False, state=saved)` enables immediate
counting, clearing wait-for-trigger while preserving unrelated settings. The
saved state avoids control-register rereads. `dtc.dtc_restore(saved)` restores
these controls exactly. It does not restore event counters, trace settings or
FIFO contents. The existing enable API remains usable without a saved state.


### `CMNPort`

A `CMNPort` is not itself a CMN node. It represents one device-facing port on
an XP.

Each port has:

- a `connected_type`: the kind of device attached to the port
  (`RN-F`, `HN-F`, `SN-F`, etc.)
- a `base_id()`: the CHI base id for the port
- zero or more device numbers behind that port

The canonical port attributes are `port_number` and `connected_type`.
`port` and `device_type()` are compatibility aliases and should not be used by
new code.

If the port has a CAL, the port can expose multiple device numbers and
therefore multiple CHI ids.

The port is the place where port-level attachment type lives. This is why
properties such as "this is an RN-F attachment" can be known even when there is
no explicit CMN device node object.

Use `port.has_properties(props)` or `ports(properties=props)` to select ports.
HCAL3 RN-F ports match both RN-F and HN-I, but do not match HN-F or RN-I merely
because they contain those two roles. Each role is tested separately against
the complete requested property mask. Ports do not expose a `properties()`
method: a combined mask can mix bits from different roles and give false
matches, even when formatting descriptive labels. For example, RN-F
contributes `CMN_PROP_F`, while HN-I contributes `CMN_PROP_HN`. Their combined
mask therefore contains all the bits of `CMN_PROP_HNF = CMN_PROP_HN | CMN_PROP_F`,
even though neither attachment role is HN-F. `has_properties(CMN_PROP_HNF)`
tests each role separately and correctly returns `False` for this port.

To describe a port's roles, test each named role with `has_properties()`.
Individual nodes still expose `properties()`, since they have a single role.

The live model uses port information already cached during XP creation for
this selection, without discovering child nodes or adding register reads.

`device_numbers()` returns sorted, distinct slot numbers. The live model
uses the device cache populated during XP creation, including slots with no
child nodes or whose nodes were skipped during discovery. The offline model
combines CAL-implied slots (or D0 without a CAL) with its stored device objects,
since those objects need not exist for every slot. Neither implementation
discovers child nodes. `ids()` adds each slot number to the port's recorded
`base_id()`.

`port.devices(properties=...)` filters device objects in slot-number order.
In the offline model it only visits existing objects; it does not create
CAL-implied slots. `cmn_base.port_devices(port, create=True)` includes those
implied slots, materializing offline objects as needed. Live slot objects
are created during XP initialization, never by these iterators. Unfiltered
live port iteration needs no child discovery or register reads. Property
filtering can discover children if it falls back to explicit node properties;
merely constructing the iterator does not start discovery.


### `CMNDevice`

A `CMNDevice` is a device slot, not a device node.

It represents:

- one CHI node id
- one `device_number` behind a port
- zero, one, or several explicit CMN device nodes associated with that slot

Examples:

- An RN-F attachment usually appears as a `CMNDevice` with no RN-F node object.
- An HN-F attachment usually appears as a `CMNDevice` with one or more
  associated device nodes.
- A CAL-attached port may expose several `CMNDevice` objects, one per device
  number.

This object is the best abstraction for anything keyed by CHI SRCID or TGTID.

Use `device.port`, `device.XP()` and `device.CMN()` to navigate to its owners;
`device.PD()` returns `(port_number, device_number)` in both models.
`device.has_properties()` first tests the port's attachment roles, then falls
back to explicit nodes on that slot. In the live model, only that fallback
needs child discovery.

To select device slots, use `cmn_select.CMNSelect.match_device(device)`.
Use `match_device_id(cmn, node_id)` when you have a CHI ID instead of a
device object. If the slot is absent from the topology, only mesh/ID-only
expressions or `ALL` can match; a `None` ID never matches. Matching a live
device can discover its child nodes.


## Device Nodes

### `CMNNodeBase`

`CMNNodeBase` is the base class for explicit CMN nodes.

Common concepts on nodes:

- `type()` / `type_str()`: CMN node type
- `node_id()`: CHI node id for non-root nodes
- `logical_id()`: logical identifier programmed for that node type
- `disabled` / `is_disabled()`: recorded disabled state, defaulting to `False`
- `properties()`: classification bits used by selectors
- `XY()` / `coords()`: physical location within the mesh
- `CMN()` / `XP()`: navigate back to owning mesh or crosspoint

In `cmn_base`, this is a pure topology object.

In `cmn_devmem`, it additionally owns the mapped register space for that node
and methods for reading or writing registers.

A node known to be disabled can be marked with `node.disabled = True`, or
created with `disabled=True`. Both models expose `is_disabled()` as a query
that uses only this recorded flag. The flag does not discover hardware state
or control hardware access. Automatic detection of disabled nodes is not yet
implemented; `False` means the node has not been marked disabled, rather than
confirming that it is operational.

The JSON description accepts `"disabled": true` on an XP or on a device node
in a port's `devices` array. Missing flags and explicit `false` load as `False`.
Serialization writes the field only when it is true. The flag belongs to each
node: it does not propagate from an XP to its children or between nodes that
share a device slot. Disabled nodes retain their IDs and topology connections,
and remain included in node iteration and topology counts.

`cmn_json.py --nodes` and `--xps` label disabled nodes with `(disabled)`.
Summary output reports disabled counts separately; these are subsets of the
reported topology counts. `cmn_diagram.py` marks disabled nodes with `!` and
marks a port with `!` when it contains any disabled node. Use `--large` to see
which individual nodes are marked. The diagram includes a legend and uses
red for affected XP and port labels when color is enabled.

`CMNPort.nodes(discover=False)` queries previously discovered nodes without
initiating child discovery or register reads, so displaying recorded state
does not probe inaccessible devices. The default remains `discover=True`.


### `CMNNodeDev`

`CMNNodeDev` is any non-XP, non-root CMN node attached to a port.

Examples include:

- HN-F / HN-S
- RN-SAM
- DTC
- other internal CMN node types discovered under an XP

A device node belongs to exactly one port and one device slot. Several device
nodes may share the same device slot and therefore the same CHI node id.


### Root/config node

Only `cmn_devmem` models the root configuration node explicitly. It is useful
for discovery, but it is not part of the shared topology abstraction used by
most tools.


## CPU Objects

### `Requester` and `CPU`

`Requester` is a generic object representing a requester behind a device slot,
identified by CHI id and LPID.

`CPU` is the concrete subclass used in this repository.

A `CPU` maps:

- OS CPU number
- CHI SRCID
- LPID
- the `CMNDevice` through which the CPU enters the fabric

When a CPU's LPID has not been discovered, the object uses `None` and the
optional `lpid` field is omitted from its JSON description. An LPID of zero
is represented explicitly and is distinct from an unknown LPID.

This is why CPU mappings hang off device slots rather than device nodes:
requesters are identified by CHI ids, and those ids belong to device slots.


## Identity and Coordinates

Several identifiers coexist:

- mesh instance: `cmn_seq`
- XP coordinates: `(X, Y)`
- port number: `P`
- device number: `D`
- CHI node id: encoded from XP coordinates plus `P` and `D`
- logical id: per-node-type identifier programmed by the mesh configurator

For non-XP nodes, `coords()` returns `(X, Y, P, D)`.

For XP nodes, `coords()` returns `(X, Y, 0, 0)`.

Ports record their base ids explicitly. Callers should prefer helper methods
such as `port_at_id()`, `device_at_id()`, `base_id()`, `ids()` and `coords()`
instead of deriving a port's base id by shifting its port number.

Missing mesh lookups use `None`: `CMN.XP()`, `CMN.port_at_id()` and
`CMN.device_at_id()` do not assert merely because an id is absent.
`XP.device_at_id()` also returns `None` for an absent slot object. Offline
callers can use `create=True` to materialize a slot represented by a port;
otherwise lookups do not create objects. Live port, XP and mesh device lookups
use the slot cache without discovering children. A port-scoped
`device_at_id()` validates against `device_numbers()` and rejects ids outside
that port with `IndexError`, including under optimized Python.
`XP.id_port_device()` requires an existing slot object and raises `KeyError`
if it is absent.

JSON loading and offline model construction reject malformed types, invalid
ranges and duplicate topology identities with `TypeError` or `ValueError`,
also when Python runs with `-O`. `CMNBadStructure` remains available for
structural conflicts and is a subclass of `ValueError`. A rejected duplicate
does not replace the object already registered under that identity.

Port base IDs must belong to their XP; they are not required to follow a fixed
port-number shift. An explicit device's ID must equal the port base ID plus
its device number. Legacy descriptions without a recorded base ID remain
supported, including sparse `pdevices` lists that omit D0. Descriptions whose
port base IDs belong to another XP are rejected rather than silently relocated.


## Common Usage Patterns

- Use `CMN.nodes()` when you want explicit CMN components.
- Use `CMN.devices()` when you want all CHI-visible endpoints, including
  external ones.
- Use `device.device_nodes` to move from a CHI id to explicit CMN nodes, if
  any exist.
- Use `node.device_object` to move from a device node to its owning device
  slot.
- Use `port.connected_type` when the distinction is about what is attached to a
  port, not about which explicit CMN node types were discovered.
- Use `node.CMN()` to navigate to a mesh. `owning_cmn()` is a compatibility
  alias in the persistent model.
- Use the `properties=` keyword for filtered iteration. `props=` is retained
  only for compatibility.


## `cmn_base` vs `cmn_devmem`

The shared model is deliberately close, but the two modules have different
roles:

- `cmn_base`: stable topology model for serialization, offline analysis and
  tests.
- `cmn_devmem`: live-discovery model with register access, lazy child
  discovery, node-isolation handling, DTM/DTC control, and other hardware
  behavior.

When adding features, prefer to preserve this split:

- topology concepts belong in the shared model
- live register behavior belongs in `cmn_devmem`
- code that works in terms of `CMN`, `XP`, `Port`, `Device`, and node objects
  should work against either implementation where possible

Small functions in `cmn_base` share attachment/slot classification, slot
number ordering, port-relative id arithmetic, filtered slot iteration and
mesh-to-XP device lookup. The model methods supply stored or discovered
topology and retain ownership of object creation, register reads, caching
and child-discovery timing; the shared functions do not decode registers.


## Register-access mappings

The live model uses `devmem_base.DevMap` for 32-bit and 64-bit register
accesses. Its public read/write methods own the access contract; OS,
debugger and dump backends implement the width-specific private methods.

Mappings require a positive size and a range within the unsigned 64-bit
address space. Each access must fit completely within the requested logical
mapping, even if the OS maps additional page padding. Offsets and write values
must be integers, physical accesses must be naturally aligned, and written
values must fit the selected width. Native mappings also reject sizes and
offset ranges that cannot be represented safely by the underlying C API.

Out-of-range accesses raise `DevMemOutOfBounds`, also an `IndexError`.
Invalid values and alignment raise `ValueError`; unsupported input types
raise `TypeError`. Writes require a writeable mapping; callers must explicitly
use `ensure_writeable()` to upgrade one. Set/clear operations validate the
write request before their initial read. Validation itself performs no device
reads.

Write readback uses the call's `check` setting, then the mapping's setting,
then the factory's setting, falling back only when a setting is `None`.
`check=False` suppresses readback. A mismatch raises `DevMemWriteFailed`.
Factory `n_read` and `n_write` counters count logical backend attempts,
including failed backend operations and requested readback, but excluding
requests rejected before backend dispatch by validation or mapping write
protection.
