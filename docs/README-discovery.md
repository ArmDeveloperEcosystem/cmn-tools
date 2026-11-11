CMN mesh discovery
==================

The other tools in this collection depend on knowing the CMN
interconnect topology. The CMN tools include a script to discover
the topology and save it in a JSON file for future reference.

It is expected that this discovery procedure only needs to be
run once per system type.


What this script does
---------------------
For background on CMN topology, see README-cmn.md.

This script first tries to discover the number and location
of CMN interconnects in the system memory space.

It then accesses each CMN memory space to discover properties
of the interconnect:

 - the specific interconnect version (e.g. CMN-600, CMN-700)

 - the X/Y dimensions of the rectangular mesh; there are
   X*Y crosspoints (XPs), one at each connection point

 - the number of device ports on each XP; generally this is
   0, 1 or 2

 - the type of device attached to each device port, e.g.
   RN-F, HN-F, RN-I etc.

For FlatID meshes, discovery counts the device slots reported by each XP's
ports and chooses the device-ID field width from the largest XP population.
It assigns slot IDs before scanning XP child nodes and saves the width in the
topology JSON when it differs from three bits.

On a mesh where the CFG node exposes only part of the original XP grid,
the saved X/Y dimensions still describe the node-ID encoding grid. Discovery
uses the wrapped dimensions in `por_info_global_2` and the visible XP IDs;
the number of CFG child pointers need not equal X times Y. Coordinates with
no exposed XP are absent from the saved topology.

The script does not discover where CPUs are located in the
interconnect; this is done by a separate script. See
[CPU location discovery](README-cpu-discovery.md).


Prerequisites for running CMN mesh discovery
--------------------------------------------

- The system must use Arm's CMN family interconnect.

- The system must have CMN in the memory map. This generally
  implies a bare-metal server or "metal" instance.
  If "perf list" shows the CMN events, the CMN is visible.

- The kernel must be built with CONFIG_DEVMEM, so that
  ``/dev/mem`` is visible in the file system

- The user must have sufficient privilege to open ``/dev/mem``.
  Generally this requires root privilege.


Running the CMN mesh discovery script
-------------------------------------

The script can be run as follows:

    python src/cmn_discover.py

This will create a file ``cmn-system.json`` with details of the
CMN mesh topology. By default, this is saved in

    ~/.cache/arm/cmn-system.json

It will print summary details of the CMN mesh.


Skipping inaccessible nodes
---------------------------

When an XP or device node cannot safely be accessed, supply its register-space
offset from `PERIPHBASE` or its absolute address in the `skiplist` of a CMN
locations JSON file. For example:

```json
{"elements": [{"product": "CMN", "base": "0x50000000",
               "skiplist": ["0x100000", "0x50200000"]}]}
```

Pass the file with `python src/cmn_discover.py --cmn-locations locations.json`.
If the CMN base address is found automatically, keep the skiplist in a separate
JSON file instead:

```json
{"skiplist": ["0x100000", "0x200000"]}
```

Pass it with `python src/cmn_discover.py --cmn-skiplist skiplist.json`.
The offsets are relative to `PERIPHBASE`; absolute addresses also work. Select
one CMN with `--cmn-instance` if more than one location is found.
The config node's child pointers identify XP entries; each discovered XP's
child pointers identify device entries. An address that matches both kinds of
node, or matches no child pointer, is rejected. Skipping an XP also omits its
devices from discovery; do not separately list its devices, since their child
pointers cannot be checked. Only list nodes whose addresses are known to be
unsafe to access.


Discovering the CPU locations
-----------------------------
This step is optional, but allows tools to refer to CPUs under
their Linux identities rather than physical request ports.

After mesh discovery, discover or refresh the CPU mappings with:

    python src/cmn_detect_cpu.py --update

This uses the topology JSON as input and counts generated traffic through
the Linux CMN PMU driver. It adds CPU locations without repeating mesh
register discovery.

See [README-cpu-discovery.md](README-cpu-discovery.md) for prerequisites,
RN-F/SRCID/LPID discovery, atomic and interval methods, verification and
update workflows, checkpoints, and limitations.
