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


Scripts that will work with DS
------------------------------

cmn_devmem.py         - low-level access to CMN

cmn_discover.py       - generate JSON system description

cmn_diagram.py        - print JSON system description

cmn_capture.py        - capture and decode CHI flits


Scripts that will not work with DS
----------------------------------

cmn_detect_cpu.py     - detect where CPUs are in the mesh:
                        uses Linux PMU drivers

cmn_topdown.py        - simple top-down perf analysis:
                        uses Linux PMU drivers

cmn_summary.py        - system summary: uses BIOS information
