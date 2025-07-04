Using CMN scripts with the Arm DS debugger
==========================================

Some of the tools will run in the Arm DS debugger as an alternative
to running on the command line of the target.

Generally, tools that access CMN directly will run under DS,
while tools that use Linux PMU (perf) drivers will not.

The location of CMN interconnect(s) in memory must already
be known. This can be determined by running the tools self-hosted,
or from vendor information. The CMN location should be passed in
on the command line:

  ./cmn_xxx.py --cmn-base=<address>

For CMN-600, it is also typically necessary to pass in the offset
of the CMN root (configuration) node:

  ./cmn_xxx.py --cmn-base=<address> --cmn-root-offset=<offset>

(For later versions of CMN, this offset is always zero.)

By default, the tools assume that DS can access CMN memory space
in the "AXI" address space. It may be necessary to adjust this.
This can be done by setting the ARMDS_CMN_SPACE environment variable.


Scripts that are expected to work with DS
-----------------------------------------

cmn_devmem.py         - low-level access to CMN

cmn_discover.py       - generate JSON system description

cmn_diagram.py        - print JSON system description as a 2-D map

cmn_capture.py        - capture and decode CHI flits

cmn_latency.py        - use trace tagging to capture related flits


Scripts that will not work with DS
----------------------------------

cmn_detect_cpu.py     - detect where CPUs are in the mesh:
                        uses Linux PMU drivers

cmn_topdown.py        - simple top-down perf analysis:
                        uses Linux PMU drivers

cmn_summary.py        - system summary: uses BIOS information


Using CMN scripts with Arm development boards
---------------------------------------------

N1SDP:
  ./cmn_discover.py --cmn-base=0x50000000 --cmn-root-offset=0xd00000

Morello:
  ./cmn_discover.py --cmn-base=0x50000000 --cmn-root-offset=0x804000


The DS sripting environment
---------------------------

ArmDS implements Jython, the Java implementation of Python. This currently
implements Python 2.7. Many Python modules are available, but some are not.
Scripts in this repository are generally written to be bilingual - running
both as Python2.7 and as any current version of Python3.

Output to stderr is highlighted in red, and DS will print a warning message
(CMD656) indicating a possible script error. This is undesirable when
stderr is being used for informational and progress messages and minor
warnings. We could either ensure that this sort of message uses stdout
(when running under DS), or we could redirect stderr to stdout at some
point early in module loading. Currently the latter approach is taken,
in devmem_ds.py.

File references, or other OS references (e.g. querying the number of CPUs,
or the hardware architecture), will be to the machine locally running DS.
There is no built-in method of communicating with any OS running on the
target. It is also not possible to directly read ACPI/SMBIOS tables on
the target - indeed they may not yet have been created.
