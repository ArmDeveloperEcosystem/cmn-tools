CMN background
--------------
The CMN interconnect is a rectangular grid comprised of
"crosspoints" (XPs). Nodes of various types are attached to
crosspoints. Some systems may have more than one CMN
interconnect - for instance a multi-socket system would
have at least one per socket.

Important CMN node types include:

 - requesters (RN-F): CPUs are attached to these

 - memory home nodes (HN-F): these handle all memory requests
   from the CPU and also contain slices of system cache

 - subordinate nodes (SN-F): these interface to memory
   controllers, which manage DDR modules

 - chip-to-chip gateways (CCG): these act as bidirectional
   interfaces to other CMN interconnects.

Full details of CMN can be found in Arm's product documentation.

