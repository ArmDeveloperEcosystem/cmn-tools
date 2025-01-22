#!/usr/bin/python3

"""
Example of finding the CMN location for a CPU

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import cmn_json

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CPU location")
    parser.add_argument("cpu", type=int, help="CPU number")
    opts = parser.parse_args()
    S = cmn_json.system_from_json_file()
    c = S.cpu(opts.cpu)
    print(c)
