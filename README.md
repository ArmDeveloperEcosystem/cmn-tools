CMN System Investigation Tools
==============================

These tools help developers understand system performance on
systems based on Arm's CMN family interconnects (CMN-600, CMN-650,
CMN-700, CI-700 etc.).

The tools are aimed at developers of complex multithreaded
applications and middleware, and at system administrators and
others who need to understand whole-node performance.

The tools generally assume root privilege, and direct access
to a server or a "metal" instance.

Tools are provided to:

 - discover the CMN mesh topology and record it in a JSON file

 - discover the mapping of Linux CPUs to mesh nodes

 - visualize the mesh topology as a 2-D diagram

 - construct PMU event specifiers (including complex watchpoints)
   for use with "perf" tools

 - collect histograms and metrics to understand system traffic
   behaviors associated with common scenarios

The tools are mostly written in Python. Any recent version of
Python3 should be sufficient. Some tools may work with Python2.


Setup
=====

Some of the tools need a system topology description, to
identify the specific configuration, topology and CPU locations
for your system. This may already be available for your system.
If not, it can be created using the discovery tools (see below).

The default location for this file in your home directory is:

    ~/.cache/arm/cmn-system.json

Discovery scripts and other tools will create, update or use
this file as appropriate.


Creating the topology description file
--------------------------------------
This step should only need to be done once, but needs a
significant level of system privilege. See README-discovery.md.


Visualizing a CMN interconnect
------------------------------

The interconnect can be visualized as a text diagram. Run:

    python cmn_diagram.py

This will print a text diagram like this:

              0c:RN-D              2c:RN-D              4c:RN-F:#0,#1        6c:SN-F
             /                    /                    /                    /
            08(0,1)--------------28(1,1)--------------48(2,1)--------------68(3,1)
           /|                   /|                   /|                   /|
    08:RN-D |            28:HN-F |            48:HN-F |            68:HN-D |
            |                    |                    |                    |
            | 04:RN-D            | 24:HN-F            | 44:HN-F            | 64:SBSX
            |/                   |/                   |/                   |/
            00(0,0)--------------20(1,0)--------------40(2,0)--------------60(3,0)
           /                    /                    /                    /
    00:CXRH        20:RN-F:#2,#3              40:RN-D              60:SN-F


Recap - discovering the mesh topology
-------------------------------------

Let's recap the CMN discovery process:

    sudo python cmn_discover.py
    python cmn_detect_cpu.py
    python cmn_diagram_py

If this succeeds, you should have a cached CMN configuration file in
``~/.cache/arm/cmn-system.json``, and a diagram of the mesh will
appear on the console.

If problems occur see the "troubleshooting" section.


Top-down analysis
-----------------

Top-down performance analysis aims at finding the significant
contributors to system bandwidth.  It analyzes system usage, rather
than specific applications.

The ``cmn_topdown.py`` script provides several levels of top-down
performance analysis, using CMN PMU events.  Currently three
levels are featured:

 - Level 1 identifies which requesters are dominant (CPU vs. I/O)

 - Level 2, for multi-die or multi-socket systems, measures local
   versus remote access

 - Level 3 further characterizes memory accesses into system
   cache hits and misses.

The exact process of top-down analysis may vary across different
systems, depending on CMN version and configuration.

Top-down analysis is currently at an experimental stage and will
be significantly enhanced in upcoming releases of these tools.


Constructing CHI watchpoint strings
-----------------------------------

If the Linux CMN PMU driver is installed, CMN perf events are
available through the ``perf_event_open`` interface and the ``perf``
userspace tools. These should be sufficient for many purposes.

In some cases it may be useful to construct CMN watchpoints to
match and count certan types of interconnect traffic. This generally
requires some level of knowledge of the CHI architecture.
The ``cmnwatch.py`` script can be used to generate strings that
match CHI flits. The strings can be passed to the ``perf`` command.

    perf stat -e `python cmnwatch.py up:req:opcode=Evict` ...

will expand into one or more CMN ``watchpoint_up`` events,
that will count all flits (interconnect packets) matching the
selected fields.

Watchpoints can refer to a subset of CHI fields. Not all fields
can be matched.


Troubleshooting
===============

It is difficult to cover all possible problems that might be
encountered but we can cover some common issues:

 - the system might not be based on an Arm CMN interconnect.
   cmn_discover.py will report this.

 - the Linux CMN PMU driver might not be installed and enabled.
   Check for /sys/devices/arm_cmn_0. (A future version of this
   guide might explain how to enable the CMN PMU driver.)

 - insufficient privilege to see CMN PMU events. Try this:
   ``sysctl kernel.perf_event_paranoid=0``

 - due to security settings, some systems do not provide
   visibility of the RSP and DAT channels in the interconnect.
   Some use cases for advanced watchpoints will not be
   available.

Please also see TODO.md which lists some known limitations that
may be addressed in future releases.


License Information
===================

*Copyright (C) ARM Limited, 2024. All rights reserved.*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

