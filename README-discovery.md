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

The script does not discover where CPUs are located in the
interconnect; this is done by a separate script. (See README.md.)


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

    python cmn_discover.py

This will create a file ``cmn-system.json`` with details of the
CMN mesh topology. By default, this is saved in

    ~/.cache/arm/cmn-system.json

It will print summary details of the CMN mesh.


Discovering the CPU locations
-----------------------------
This step is optional, but allows tools to refer to CPUs under
their Linux identities rather than physical request ports.

This step takes the topology description JSON file as input and
generates traffic to discover CPU locations. The goal is to
detect which request port (RN-F) the CPU is attached to, and also
the logical id (LPID) by which it is identified in requests.

The system must be reasonably free of other load. If successful,
the discovery script will update the cached JSON file.

Depending on system design, the mapping of CPUs to interconnect
locations may be universal across instances, or it may vary from
instance to instance (i.e. from chip to chip).

To discover the CPU locations, run:

    python cmn_detect_cpu.py

Depending on the interconnect design, there are three possible
outcomes, which impact on later analysis:

 - at most one CPU per request port

 - several CPUs per request port, distinguished by LPID

 - several CPUs per request port, not distinguished by LPID

In the last case, CPU-centric analysis may be more approximate,
as traffic can only be associated with a group of CPUs.
