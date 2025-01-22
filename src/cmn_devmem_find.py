#!/usr/bin/python3

"""
Locate CMN interconnect instances in memory.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

The goal is to return a set of CMNLocator objects, by reading /proc/iomem.
The descriptors should be returned with their physical addresses.

We don't do discovery of CMN mesh structure here.

There are various reasons why discovery might fail:

 - CMN does not appear in /proc/iomem:
   - because the system does not use CMN
   - because this is a guest instance, with no visible interconnect
   - because CMN is not described in the ACPI tables
 - CMN does appear but we aren't root and can't see the physical address

We should report absence of CMN in preference to not being root.
I.e. don't tell the user to run as root, if CMN isn't there anyway.
"""

from __future__ import print_function

import os, sys, json
import cmn_json

o_verbose = 0


def _cmn_location_cache():
    return cmn_json.cmn_config_cache("cmn-locations.json")


class IOmem_region:
    """
    A descriptor of an I/O region - basically a line from /proc/iomem
    """
    def __init__(self, addr, aend, name=None, level=0):
        self.addr = addr
        self.aend = aend     # last included address (..fff) or zero
        self.name = name
        self.level = level

    def size(self):
        return self.aend + 1 - self.addr

    def contains(self, addr):
        return self.addr <= addr and addr <= self.aend

    def contains_range(self, desc):
        return self.addr <= desc.addr and desc.aend <= self.aend

    def is_missing(self):
        return self.addr == 0 and self.aend == 0

    def __str__(self):
        s = "%x-%x : %s" % (self.addr, self.aend, self.name)
        s = ("  " * self.level) + s
        return s


def iomem_regions(iomem=None):
    """
    Scan over the list of I/O device regions in /proc/iomem,
    and yield IOmem_region objects.
    It is up to the caller to find the objects they are looking for.
    """
    if iomem is None:
        iomem = "/proc/iomem"
    with open(iomem) as f:
        for ln in f:
            level = (len(ln) - len(ln.lstrip())) // 2     # count leading "  "
            ln = ln.strip()
            toks = ln.split()
            (a, b) = toks[0].split('-')
            addr = int(a, 16)
            aend = int(b, 16)
            # At this point, don't fault zero-zero objects, because the caller
            # might still want to check if there are any objects matching the name.
            ntok = toks[2].split(':')
            name = ntok[0]
            yield IOmem_region(addr, aend, name, level)


# "ARMHC" prefix isn't enough, ARMHC502 is something different
cmn_acpi_names = ["ARMHC600", "ARMHC650", "ARMHC700"]

def cmn_iomem_regions(iomem=None):
    for r in iomem_regions(iomem=iomem):
        if r.name in cmn_acpi_names:
            if r.is_missing():
                print("CMN region(s) found: re-run as root to discover location", file=sys.stderr)
                sys.exit(1)
            yield r


class CMNLocator:
    """
    Specification of where CMN is. This has the base address (PERIPHBASE),
    root node address, and CMN product number (e.g. 700).
    We get it from /proc/iomem, ACPI tables, user override etc.
    """
    def __init__(self, periphbase=None, rootnode_offset=None, version=None):
        self.periphbase = periphbase
        self.rootnode_offset = rootnode_offset
        self.version = version

    def __str__(self):
        s = "CMN"
        if self.version is not None:
            s += "-%u" % self.version
        s += " at 0x%x" % self.periphbase
        if self.rootnode_offset:
            s += " (root +0x%x)" % self.rootnode_offset
        return s


def cmn_locators_from_iomem(iomem=None):
    """
    Yield all known CMN instances.
    """
    locs = []
    loc = None
    for ad in cmn_iomem_regions(iomem=iomem):
        if ad.level == 0:
            assert loc is None
            loc = CMNLocator(periphbase=ad.addr, version=int(ad.name[5:]))
            if loc.version >= 650:
                loc.rootnode_offset = 0
                yield loc
                locs.append(loc)
                loc = None
            else:
                # wait for the subordinate node to give the config address
                pass
        elif loc is not None:
            if loc.version == 600:
                loc.rootnode_offset = ad.addr - loc.periphbase
                yield loc
                locs.append(loc)
                loc = None
            else:
                assert False
        else:
            # subordinate node - ignore
            pass
    assert not loc
    if not locs:
        cpath = _cmn_location_cache()
        if os.path.exists(cpath):
            print("reading CMN locations from %s" % (cpath))
            with open(cpath) as f:
                jcmn = json.load(f)
            base = int(jcmn["base"], 16)
            offset = int(jcmn.get("root-offset", "0"), 16)
            version = jcmn.get("version", 600)
            yield CMNLocator(base, offset, version)
        else:
            #print("%s: no CMNs found, cache does not exist" % cpath, file=sys.stderr)
            pass


def cmn_locators(opts=None, single_instance=False):
    if o_verbose:
        print("CMN: locating with %s, single=%s" % (opts, single_instance))
    if opts is not None and opts.cmn_base is not None:
        loc = CMNLocator(opts.cmn_base, opts.cmn_root_offset)
        yield loc
    else:
        n_inst = 0
        for loc in cmn_locators_from_iomem(iomem=opts.cmn_iomem if opts is not None else None):
            if o_verbose:
                print("#%u: %s" % (n_inst, loc))
            if single_instance and (opts is None):
                # No user options overriding: return the first instance discovered
                yield loc
                return
            if opts is None or opts.cmn_instance is None or n_inst == opts.cmn_instance:
                yield loc
            n_inst += 1


def cmn_single_locator(opts=None):
    locs = list(cmn_locators(opts, single_instance=True))
    if locs:
        return locs[0]
    else:
        return None


def cmn_at(base_addr):
    for c in cmn_locators():
        if c.periphbase == base_addr:
            return c
    return None


def add_cmnloc_arguments(parser):
    """
    Add command-line arguments to an argparse.ArgumentParser
    object to allow the CMN address to be overridden
    """
    def inthex(s):
        return int(s, 16)
    parser.add_argument("--cmn-base", type=inthex, help="CMN base address")
    parser.add_argument("--cmn-root-offset", type=inthex, default=0, help="CMN root node offset")
    parser.add_argument("--cmn-instance", type=int, help="CMN instance e.g. 0, 1, ...")
    parser.add_argument("--cmn-version", type=int, help="CMN product number")
    parser.add_argument("--cmn-iomem", type=str, default="/proc/iomem", help="/proc/iomem file (for testing)")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="locate CMN interconnects")
    add_cmnloc_arguments(parser)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("--no-cache", action="store_true", help="don't cache results")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    o_use_cache = not opts.no_cache
    for c in cmn_locators(opts=opts):
        print(c)
