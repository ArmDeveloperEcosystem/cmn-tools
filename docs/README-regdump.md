CMN register dump
=================

The cmn_regdump.py tool reads CMN configuration registers and prints
them using the register definitions in data/regdefs/.

It is intended for inspection and comparison of CMN register state. It
does not attempt to interpret every register in context; it prints
register names, values, and optionally field names from the register
definition files.


Prerequisites
-------------

cmn_regdump.py accesses CMN memory space directly. For normal self-hosted
use this means:

 - the system must expose CMN in the memory map

 - the user must have access to /dev/mem, generally requiring root
   privilege

 - CMN location discovery must work, or the CMN base address must be
   supplied explicitly

For CMN-600, the root configuration node is not always at offset zero
from the CMN base. In that case, pass --cmn-root-offset as well as
--cmn-base.

For example, on N1SDP:

    python cmn_regdump.py --cmn-base=0x50000000 --cmn-root-offset=0xd00000


Basic usage
-----------

Dump non-zero registers:

    python cmn_regdump.py

Include registers whose value is zero:

    python cmn_regdump.py --include-zero

Show field output:

    python cmn_regdump.py --fields

Show register and field descriptions:

    python cmn_regdump.py --descriptions

Descriptions can be long. Limit their printed length with:

    python cmn_regdump.py --descriptions --max-desc=40

Show the physical address of each register:

    python cmn_regdump.py --address

By default, read-only registers are included. To exclude them:

    python cmn_regdump.py --exclude-read-only

Volatile registers can be excluded:

    python cmn_regdump.py --exclude-volatile

If Secure registers are not accessible, cmn_regdump.py will skip them.
If the environment is known to allow Secure access, use:

    python cmn_regdump.py --secure-access


Selecting nodes
---------------

The --node option selects which CMN nodes to dump. It uses the common
CMN selector syntax used by other tools in this repository.

Dump all XPs:

    python cmn_regdump.py --node xp

Dump all HN-F nodes:

    python cmn_regdump.py --node hn-f

Dump one XP by coordinates:

    python cmn_regdump.py --node 'xp(0,0)'

Dump one node by node id:

    python cmn_regdump.py --node hn-f@0x24

Dump nodes in a particular mesh:

    python cmn_regdump.py --node m1:xp

More than one --node option may be supplied. The selections are combined.


Selecting registers
-------------------

The --reg option selects registers by a case-insensitive regular
expression matched against the register name.

Show only NODE_INFO registers:

    python cmn_regdump.py --reg node_info

Show only UNIT_INFO registers on XPs:

    python cmn_regdump.py --node xp --reg unit_info

The positional form reads a named register from every matching node:

    python cmn_regdump.py por_mxp_node_info

If a field name is supplied after a dot, only that field is printed:

    python cmn_regdump.py por_mxp_device_port_connect_info_p0.device_type_p0

If a value is supplied, cmn_regdump.py writes the register or field and
then reads it back:

    python cmn_regdump.py some_register=0x1

Use write forms with care. Some CMN registers control live interconnect
state.


Searching register definitions
------------------------------

The --search option searches the register definitions for the current
CMN product rather than reading the target:

    python cmn_regdump.py --search node_info

The --search-all option searches all register definition files:

    python cmn_regdump.py --search-all device_port_connect_info

These modes are useful when looking for the exact register or field name
to use with --reg or positional register access.


Output order
------------

The default node order is topology order: root configuration node first,
then each XP, followed by the device nodes under that XP.

This can be made explicit:

    python cmn_regdump.py --node-order topology

For comparison work it can be useful to visit nodes by type instead:

    python cmn_regdump.py --node-order type

Type order prints the configuration node, then all XPs, then all nodes
of each device-node type.


Aggregate mode
--------------

The --aggregate option groups selected nodes by node type and compares
register values within each group.

When all nodes of a type have the same value for a register, the value
is printed once:

    python cmn_regdump.py --aggregate --node xp --reg device_port_connect_info

When values differ, cmn_regdump.py prints the value for each node:

    python cmn_regdump.py --aggregate --node xp --reg device_port_connect_info --no-fields

To show only differences, suppress registers and fields whose values are
common across the group:

    python cmn_regdump.py --aggregate --no-common

This is useful for finding configuration differences between instances
of the same node type:

    python cmn_regdump.py --aggregate --no-common --node hn-f

With --fields, aggregate mode also compares fields. Fields whose values
differ are printed per node. Fields whose values are common are printed
once, unless --no-common is specified:

    python cmn_regdump.py --aggregate --fields --node xp --reg device_port_connect_info

    python cmn_regdump.py --aggregate --fields --no-common --node xp --reg device_port_connect_info

If there is only one selected node of a type, aggregate mode prints it
as a normal node dump. With --no-common, single-node type groups are
suppressed.


Flat output
-----------

The --flat option prints output in a simpler assignment-like form:

    python cmn_regdump.py --flat --node xp --reg node_info

This can be useful for simple scripts or for diffing output.


Using captured dumps
--------------------

cmn_regdump.py can operate on a previously captured CMN dump instead of
live device memory. Set the CMN_DUMP environment variable to the dump
file.

For example, using a dump captured from a CMN-600 system:

    CMN_DUMP=/path/to/cmn.dump \
    python src/cmn_regdump.py \
      --cmn-base=<cmn-base> \
      --cmn-root-offset=<root-offset> \
      --aggregate --fields --node xp --reg device_port_connect_info

The base address and root offset still need to match the captured system.
For CMN products where the root node is at offset zero, the
--cmn-root-offset option is not needed.


Register definition files
-------------------------

cmn_regdump.py chooses a register definition file based on the discovered
CMN product and revision. The files are in:

    data/regdefs/

If a different directory is needed when using CMNRegDumper from another
script, pass regdefs_dir to the CMNRegDumper constructor.


Examples
--------

Dump all non-zero HN-F registers, without field detail:

    python cmn_regdump.py --node hn-f --no-fields

Show all zero and non-zero XP device-port connection information:

    python cmn_regdump.py --node xp --reg device_port_connect_info --include-zero

Find differing XP device-port connection fields:

    python cmn_regdump.py --aggregate --no-common --fields --node xp --reg device_port_connect_info

Find differing UNIT_INFO values on RN-D nodes:

    python cmn_regdump.py --aggregate --no-common --no-fields --node rn-d --reg unit_info

Search all register definition files for registers containing "pmu":

    python cmn_regdump.py --search-all pmu
