Known limitations and assumptions in the CMN tools
==================================================

This note describes some known limitations in the CMN toolkit
which may be addressed in future releases.

- The tools currently assume that the Linux PMUs "arm_cmn_<n>"
  are ordered according to CMN base physical address. In fact this
  is not guaranteed, and the PMU ordering can vary between reboots.
  The correspondence between PMUs and meshes (and their CPU maps)
  should be established at least once per reboot. This will likely
  need to be done empirically, similar to CPU discovery.


