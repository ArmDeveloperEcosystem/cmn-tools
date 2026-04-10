#!/usr/bin/python3

"""
Example of finding the CMN location for a CPU

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import sys
import cmn_json

def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="CPU location")
    parser.add_argument("cpu", type=int, help="CPU number")
    opts = parser.parse_args(argv)
    S = cmn_json.system_from_json_file()
    c = S.cpu(opts.cpu)
    print(c)


if __name__ == "__main__":
    main(sys.argv[1:])
