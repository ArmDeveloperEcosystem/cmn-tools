# CMN Object Model

This repository uses a shared object model in both `cmn_base.py` and
`cmn_devmem.py` to describe a CMN mesh in terms that match the CMN
topology.

`cmn_base.py` holds a persistent, topology-oriented model used by JSON and
offline tools.

`cmn_devmem.py` exposes the same topology concepts, but backs them with live
register discovery and access.


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

A `System` groups all CMN instances and any discovered CPU mappings.

- `System.CMNs`: all meshes in the system.
- `System.ports()`, `System.XPs()`, `System.nodes()`: iterate across all
  meshes.
- `System.cpu_node`: map from OS CPU number to `CPU`.

Use `System` when a tool needs a whole-system view, especially on multi-mesh
systems where CHI ids must be interpreted together with a mesh instance.


### `CMN`

A `CMN` object represents one rectangular CMN mesh.

- In `cmn_base`, it is a topology container populated from discovery data or
  JSON.
- In `cmn_devmem`, it is also the live access point for register-backed
  discovery and control.

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


### `CMNPort`

A `CMNPort` is not itself a CMN node. It represents one device-facing port on
an XP.

Each port has:

- a `connected_type`: the kind of device attached to the port
  (`RN-F`, `HN-F`, `SN-F`, etc.)
- a `base_id()`: the CHI base id for the port
- zero or more device numbers behind that port

If the port has a CAL, the port can expose multiple device numbers and
therefore multiple CHI ids.

The port is the place where port-level attachment type lives. This is why
properties such as "this is an RN-F attachment" can be known even when there is
no explicit CMN device node object.


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


## Device Nodes

### `CMNNodeBase`

`CMNNodeBase` is the base class for explicit CMN nodes.

Common concepts on nodes:

- `type()` / `type_str()`: CMN node type
- `node_id()`: CHI node id for non-root nodes
- `logical_id()`: logical identifier programmed for that node type
- `properties()`: classification bits used by selectors
- `XY()` / `coords()`: physical location within the mesh
- `CMN()` / `XP()`: navigate back to owning mesh or crosspoint

In `cmn_base`, this is a pure topology object.

In `cmn_devmem`, it additionally owns the mapped register space for that node
and methods for reading or writing registers.


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

The split between port bits and device bits depends on the XP's number of
device ports, so callers should prefer helper methods such as `port_at_id()`,
`device_at_id()`, `base_id()`, `ids()` and `coords()` instead of re-decoding
ids manually.


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
