#!/usr/bin/python

"""
Decode a binary CMN ATB trace file.

Copyright (C) ARM Ltd. 2018-2022.  All rights reserved.

SPDX-License-Identifer: Apache 2.0
"""

from __future__ import print_function


import sys


import cs_decode
import cs_decode_cmn
import cmn_flits


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="decode a binary CMN ATB trace file")
    parser.add_argument("-i", "--input", type=str, help="input trace binary")
    parser.add_argument("--cmn-version", type=(lambda x: int(x, 0)), help="CMN version", required=True)
    parser.add_argument("--mpam", action="store_true", help="CMN has MPAM enabled")
    parser.add_argument("--no-sync", action="store_true", help="don't look for sync sequence")
    parser.add_argument("--unformatted", action="store_true", help="trace file has no CoreSight framing")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("inputs", type=str, nargs="*", help="input trace binaries")
    opts = parser.parse_args()
    if opts.input is not None:
        opts.inputs.insert(0, opts.input)
    if not opts.inputs:
        print("%s: input files are required" % __file__, file=sys.stderr)
        sys.exit(1)
    cfg = cs_decode_cmn.CMNTraceConfig(opts.cmn_version, opts.mpam)
    decoder = cs_decode_cmn.CMNDecoder(cfg, verbose=opts.verbose)
    decoder_fn = decoder.decode(sync=(not opts.no_sync))
    if opts.unformatted:
        decode_map = {"unformatted": decoder_fn}
    else:
        decode_map = {"all": decoder_fn}
    for fn in opts.inputs:
        if opts.verbose:
            print("Decoding CMN trace in '%s'..." % fn, file=sys.stderr)
        with open(fn, "rb") as f:
            try:
                cs_decode.stream_decode(f, decode_map, verbose=opts.verbose)
            except cs_decode.TraceCorrupt as e:
                print("%s: trace error: %s" % (fn, str(e)), file=sys.stderr)
