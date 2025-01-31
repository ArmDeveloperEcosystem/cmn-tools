#!/usr/bin/python3

"""
Generate system description JSON file by discovering CMN in memory

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import os, sys

import cmn_devmem, cmn_devmem_find
import cmn_base
import cmn_json
import dmi
import time


def system_description():
    """
    Generate a complete system description, currently consisting only of the CMNs.
    """
    S = cmn_base.System()
    S.CMNs = [cmn_devmem.CMN(loc) for loc in cmn_devmem_find.cmn_locators()]
    # Try to discover the CMN clock frequency
    for c in S.CMNs:
        c.frequency = c.estimate_frequency()
    try:
        S.system_type = dmi.DMI().processor()
    except Exception:
        print("Note: could not get system name from DMI", file=sys.stderr)
        S.system_type = "unknown"
    return S


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="generate system description JSON")
    parser.add_argument("-o", "--output", type=str, default=cmn_json.cmn_config_filename(), help="output JSON file")
    parser.add_argument("--overwrite", action="store_true", help="overwrite output file")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    o_verbose = opts.verbose
    S = system_description()
    if not S.CMNs:
        # This toolkit is currently specific to CMN, and it's not useful to save
        # a system descriptor if the system doesn't have CMN.
        print("CMN interconnects not found (system = \"%s\")" % S.system_type, file=sys.stderr)
        sys.exit(1)
    for c in S.CMNs:
        print("Found %s" % c)
    if not opts.overwrite and os.path.exists(opts.output):
        print("File already exists (rerun with --overwrite): %s" % opts.output, file=sys.stderr)
        sys.exit(1)
    print("Writing system configuration to %s..." % opts.output)
    cmn_json.json_dump_file_from_system(S, opts.output)
