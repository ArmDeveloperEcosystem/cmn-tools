#!/usr/bin/python3

"""
Generate system description JSON file by discovering CMN in memory

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import os
import sys
import time

import cmn_devmem
import cmn_devmem_find
import cmn_base
import cmn_json
import dmi
import cmn_perfcheck


def system_is_remote(S):
    return S.CMNs and not S.CMNs[0].is_local


def system_description(verbose=1, opts=None, frequency=True):
    """
    Generate a complete system description, currently consisting only of the CMNs.

    We annotate the description with some identification strings
    scanned from the DMI table.
    """
    S = cmn_base.System()
    S.CMNs = [cmn_devmem.CMN(loc, verbose=verbose, defer_discovery=opts.cmn_defer) for loc in cmn_devmem_find.cmn_locators(opts=opts)]
    S.timestamp = time.time()
    # ensure all devices are discovered before we create the JSON
    for C in S.CMNs:
        C.discover_all_devices()
    if system_is_remote(S):
        # If accessing remotely, don't try to add local information
        print("Target is being accessed remotely, some information not discoverable",
              file=sys.stderr)
        return S
    if frequency:
        # Try to discover the CMN clock frequency
        if S.CMNs:
            if verbose:
                print("CMN: measuring CMN clock frequency...")
            for c in S.CMNs:
                c.frequency = c.estimate_frequency()
    try:
        D = dmi.DMI()
        dsys = D.system()
        # System identification strings aren't used consistently
        # (e.g. product name vs. product version), so concatenate various fields
        # or: sys_vendor + product_name + product_version
        S.system_type = "%s %s %s" % (dsys.mfr, dsys.product, dsys.version)
        # or: product_uuid (root only)
        S.system_uuid = D.system().uuid     # n.b. Python uuid.UUID object
        S.processor_type = D.processor()
    except Exception:
        print("Note: could not get system name from DMI", file=sys.stderr)
        S.system_type = "unknown"
    return S


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="generate system description JSON")
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument("-o", "--output", type=str, default=cmn_json.cmn_config_filename(), help="output JSON file")
    parser.add_argument("--overwrite", action="store_true", help="overwrite output file")
    parser.add_argument("--no-frequency", action="store_true", help="don't estimate CMN frequency")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    S = system_description(verbose=opts.verbose, opts=opts, frequency=(not opts.no_frequency))
    if not S.CMNs:
        # This toolkit is currently specific to CMN, and it's not useful to save
        # a system descriptor if the system doesn't have CMN.
        print("CMN interconnects not found (system = \"%s\")" % S.system_type, file=sys.stderr)
        guest_type = cmn_devmem_find.system_is_probably_guest()
        if guest_type:
            print("System appears to be running as a %s guest" % (guest_type), file=sys.stderr)
        sys.exit(1)
    for c in S.CMNs:
        print("Found %s" % c)
    ok = True
    if not opts.overwrite and os.path.exists(opts.output):
        print("File already exists (rerun with --overwrite): %s" % opts.output, file=sys.stderr)
        ok = False
    else:
        print("Writing system configuration to %s..." % opts.output)
        cmn_json.json_dump_file_from_system(S, opts.output)
    if not system_is_remote(S):
        if not cmn_perfcheck.check_cmn_pmu_events():
            ok = False
    if not ok:
        sys.exit(1)
