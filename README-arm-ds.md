Using CMN scripts with the Arm DS debugger
==========================================

Some of the tools will run in the Arm DS debugger as an alternative
to running on the command line of the target. There are several
reasons to do this:

 - the system might not yet have booted to a state where it
   can run self-hosted scripts

 - the user might want to combine CMN access with other low-level
   techniques like halting and single-stepping CPUs

 - some CMN configuration information is normally only accessible
   to debug-level access

On the other hand, running scripts from DS has less visibility into
the software environment. It is also typically less performant to
access CMN via JTAG than self-hosted, especially when retrieving
large amounts of information.

Generally, tools that access CMN directly will run under DS
(as well as self-hosted), while tools that use Linux PMU (perf)
drivers will only run self-hosted.

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

cmn_unlock.py         - set/unset security override bit(s)


Scripts that will not work with DS
----------------------------------

cmn_detect_cpu.py     - detect where CPUs are in the mesh:
                        uses Linux PMU drivers

cmn_topdown.py        - simple top-down perf analysis:
                        uses Linux PMU drivers

cmn_summary.py        - system summary: uses BIOS information


Combining DS and self-hosted scripting
--------------------------------------

As mentioned above, one reason to run under DS is to access
additional configuration information. override flags in CMN that
allow more CMN can in some cases permit self-hosted scripts to access these
registers.

The "cmn_unlock.py" script is provided to set these flags from DS.
Once this is done, self-hosted scripts can access more details
of CMN configuration. So a typical use case might be:

From DS:
  ./cmn_unlock.py --unlock <CMN location>

Self-hosted:
  ./cmn_list.py --node-type=rn


Using CMN scripts with Arm development boards
---------------------------------------------

N1SDP:
  ./cmn_discover.py --cmn-base=0x50000000 --cmn-root-offset=0xd00000

Morello:
  ./cmn_discover.py --cmn-base=0x50000000 --cmn-root-offset=0x804000


The DS scripting environment
----------------------------

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


CMN trace capture over CoreSight ATB using DS
---------------------------------------------

The cmn_capture.py script will capture CMN trace into a buffer within the
CMN mesh. For capturing larger amounts of trace, it's instead necessary to
send the trace out of the CMN mesh, and onto the CoreSight ATB bus. The
trace can then be captured on-chip from a trace sink such as an ETF or ETR,
or sent off-chip via a TPIU or ETR to be captured by an external debug
probe (such as a DSTREAM-ST/-PT/-XT).

This can be done using the cmn_trace_setup_ds.py script. See
README-capture-ATB.md for more details.

For general information about trace capture using Arm DS, see the 'Arm
Development Studio Trace User Guide': https://developer.arm.com/documentation/109870/0100
Please contact Arm Support if any issues are encountered whilst using Arm DS.
