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

    python src/cmn_regdump.py --cmn-base=0x50000000 --cmn-root-offset=0xd00000


Basic usage
-----------

Dump non-zero registers:

    python src/cmn_regdump.py

Include registers whose value is zero:

    python src/cmn_regdump.py --include-zero

Show field output:

    python src/cmn_regdump.py --fields

Descriptive register output includes its access and volatility code: `RW` for read/write
and non-volatile, `V` for read/write and volatile, or `RO`, `ROV`, `WO`, `WOV`.
Fields show a prefix only for properties that differ from their register:
`(RO)` or `(WO)` for different access, `(NV)` for a non-volatile field in a
volatile register, and `(RO,NV)` when both differ. For example:

```text
  0000  000000000000000f  CONTROL_STATUS (V)
    [0]                          (NV) enable = 1
    [1]                           (RO) ready = 1
    [2]                          (RO,NV) cfg = 1
    [3]                               active = 1
```

The same prefixes appear in aggregate output and definition searches.
When a field is requested by name, its parent properties are shown as
`(register V)`, for example. Flat output omits register and field property
annotations.
Write-one-to-clear registers and fields also show `W1C` in descriptive
output, combined with other annotations, for example `(V,W1C)` or
`(NV,W1C)`. Fields omit `W1C` when it is already shown on their register.

Show register and field descriptions:

    python src/cmn_regdump.py --descriptions

Descriptions can be long. Limit their printed length with:

    python src/cmn_regdump.py --descriptions --max-desc=40

Show the physical address of each register:

    python src/cmn_regdump.py --address

By default, read-only registers are included. To exclude them:

    python src/cmn_regdump.py --exclude-read-only

Volatile registers can be excluded:

    python src/cmn_regdump.py --exclude-volatile

If Secure registers are not accessible, cmn_regdump.py will skip them.
If the environment is known to allow Secure access, use:

    python src/cmn_regdump.py --secure-access


Selecting nodes
---------------

The --node option selects which CMN nodes to dump. It uses the common
CMN selector syntax used by other tools in this repository.

Dump all XPs:

    python src/cmn_regdump.py --node xp

Dump all HN-F nodes:

    python src/cmn_regdump.py --node hn-f

Dump one XP by coordinates:

    python src/cmn_regdump.py --node 'xp(0,0)'

Dump one node by node id:

    python src/cmn_regdump.py --node hn-f@0x24

Dump nodes in a particular mesh:

    python src/cmn_regdump.py --node m1:xp

More than one --node option may be supplied. The selections are combined.


Selecting registers
-------------------

The --reg option selects registers by a case-insensitive regular
expression matched against the register name.

Show only NODE_INFO registers:

    python src/cmn_regdump.py --reg node_info

Show only UNIT_INFO registers on XPs:

    python src/cmn_regdump.py --node xp --reg unit_info

The positional form reads a named register from every matching node:

    python src/cmn_regdump.py por_mxp_node_info

If a field name is supplied after a dot, only that field is printed:

    python src/cmn_regdump.py por_mxp_device_port_connect_info_p0.device_type_p0

If a value is supplied, cmn_regdump.py writes the register or field and
then reads it back:

    python src/cmn_regdump.py some_register=0x1

Use write forms with care. Some CMN registers control live interconnect
state.


Searching register definitions
------------------------------

The --search option searches the register definitions for the current
CMN product rather than reading the target:

    python src/cmn_regdump.py --search node_info

The --search-all option searches all register definition files:

    python src/cmn_regdump.py --search-all device_port_connect_info

These modes are useful when looking for the exact register or field name
to use with --reg or positional register access.


Output order
------------

The default node order is topology order: root configuration node first,
then each XP, followed by the device nodes under that XP.

This can be made explicit:

    python src/cmn_regdump.py --node-order topology

For comparison work it can be useful to visit nodes by type instead:

    python src/cmn_regdump.py --node-order type

Type order prints the configuration node, then all XPs, then all nodes
of each device-node type.


Aggregate mode
--------------

The --aggregate option groups selected nodes by node type and compares
register values within each group. It also applies to positional register
and field reads:

    python src/cmn_regdump.py por_mxp_node_info --aggregate

    python src/cmn_regdump.py por_mxp_device_port_connect_info_p0.device_type_p0 --aggregate

A positional name matches exactly and includes zero values. When a field
is named, only that field is compared, even if other fields in the register
differ. The --no-common option also applies to these reads. Positional
writes continue to report each node's before and readback values separately.

When all nodes of a type have the same value for a register, the value
is printed once:

    python src/cmn_regdump.py --aggregate --node xp --reg device_port_connect_info

When values differ, cmn_regdump.py prints the value for each node:

    python src/cmn_regdump.py --aggregate --node xp --reg device_port_connect_info --no-fields

To show only differences, suppress registers and fields whose values are
common across the group:

    python src/cmn_regdump.py --aggregate --no-common

This is useful for finding configuration differences between instances
of the same node type:

    python src/cmn_regdump.py --aggregate --no-common --node hn-f

With --fields, aggregate mode also compares fields. Fields whose values
differ are printed per node. Fields whose values are common are printed
once, unless --no-common is specified:

    python src/cmn_regdump.py --aggregate --fields --node xp --reg device_port_connect_info

    python src/cmn_regdump.py --aggregate --fields --no-common --node xp --reg device_port_connect_info

If there is only one selected node of a type, aggregate mode prints it
as a normal node dump. With --no-common, single-node type groups are
suppressed.


Flat output
-----------

The --flat option prints output in a simpler assignment-like form:

    python src/cmn_regdump.py --flat --node xp --reg node_info

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

In a `.regdefs` file, register lines use
`R <offset> <bits> <access> <security> <name> [W1C]`. Access codes combine software
access and volatility: `NV` (also accepted as `-`) means read/write and
non-volatile, `V` means read/write and volatile, and `RO`, `ROV`, `WO`, `WOV`
describe read-only or write-only access with the same optional `V` suffix.
Register lines retain the compact `-` spelling when written.

Field lines use `F <position> <width> <name> [<access>] [W1C]`. Omit the access token
to inherit both properties from the register. An explicit token specifies
both properties and is only written when they differ. Field overrides use
`NV` for read/write and non-volatile; the reader also accepts the legacy `-`
spelling with the same meaning. For example:

```text
R 0x0 32 V - CONTROL_STATUS
F 0 1 enable NV
F 1 1 ready ROV
F 2 6 count
```

Here `enable` is read/write and non-volatile, `ready` is read-only and
volatile, and `count` inherits read/write and volatile. A field cannot allow
access forbidden by its register or be volatile in a non-volatile register;
these combinations are rejected. Existing files remain valid and gain no
extra tokens when rewritten. Files containing field overrides require an
updated reader; older readers do not accept the optional token.

These inheritance rules are specific to regdefs. When converting another
format, its own defaults must first be applied to determine each field's
effective properties, then any differences from the register are written
as explicit overrides.

The optional `W1C` token marks a write-one-to-clear register or field.
On a field it can appear with or without an access override, and applies
to fields of any width:

```text
R 0x8 64 V - ERROR_STATUS
F 0 16 errors W1C
F 16 8 software_flags NV W1C
R 0x10 64 V - ERROR_CLEAR W1C
F 0 16 errors
```

Each written one clears its corresponding bit; written zeroes leave those
bits unchanged, as specified by IP-XACT `modifiedWriteValue=oneToClear`.
See [IEEE 1685-2014 clarification of modifiedWriteValue](https://www.accellera.org/images/downloads/standards/ip-xact/IPXACT-2014-issues-April_2020.pdf).
Fields inherit W1C from a register marked W1C, so the marker need not be
repeated on those fields. Otherwise, omitting the marker leaves the register
or field unmarked. A read-only register or field cannot be W1C.

The model exposes a boolean `is_w1c` flag on `Register` and `RegField`.
The readers translate IP-XACT `oneToClear` to this flag; other
`modifiedWriteValue` modes are unsupported and rejected during conversion.
The flag records write behavior; it does not change cmn_regdump.py's existing
read/modify/write operations.


Examples
--------

Dump all non-zero HN-F registers, without field detail:

    python src/cmn_regdump.py --node hn-f --no-fields

Show all zero and non-zero XP device-port connection information:

    python src/cmn_regdump.py --node xp --reg device_port_connect_info --include-zero

Find differing XP device-port connection fields:

    python src/cmn_regdump.py --aggregate --no-common --fields --node xp --reg device_port_connect_info

Find differing UNIT_INFO values on RN-D nodes:

    python src/cmn_regdump.py --aggregate --no-common --no-fields --node rn-d --reg unit_info

Search all register definition files for registers containing "pmu":

    python src/cmn_regdump.py --search-all pmu
