#!/usr/bin/python

"""
Report CMN transaction latency from a trace file.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function

import argparse
import sys

import cs_decode
import cs_decode_cmn
import cmn_flits


CHI_CHANNELS = {
    "REQ": cmn_flits.REQ,
    "RSP": cmn_flits.RSP,
    "SNP": cmn_flits.SNP,
    "DAT": cmn_flits.DAT,
}


def sub16(a, b):
    """
    Subtract two numbers, modulo 2**16, for wrapping counters.
    """
    if a < b - 300:
        a += 0x10000
    return a - b


class LatencyStats:
    """
    Track counts and summary stats for request/response matching.
    """
    def __init__(self):
        self.n_req = 0
        self.n_rsp = 0
        self.n_match = 0
        self.n_rsp_unmatched = 0
        self.n_req_dropped = 0
        self.n_req_missing_cc = 0
        self.n_rsp_missing_cc = 0
        self.n_key_missing = 0
        self.lat_min = None
        self.lat_max = None
        self.lat_sum = 0

    def add_latency(self, lat):
        self.n_match += 1
        self.lat_sum += lat
        if self.lat_min is None or lat < self.lat_min:
            self.lat_min = lat
        if self.lat_max is None or lat > self.lat_max:
            self.lat_max = lat

    def mean(self):
        return float(self.lat_sum) / self.n_match if self.n_match else None


class RequestRecord:
    """
    Snapshot of a request flit and its capture context.
    """
    def __init__(self, flit, group, cc):
        self.flit = flit
        self.group = group
        self.cc = cc


class TransactionMatcher:
    """
    Collect requests, match responses, and emit latency results.
    """
    def __init__(self, opts, stats, out):
        self.opts = opts
        self.stats = stats
        self.out = out
        self.pending = {}

    def _auto_mode(self, flit):
        # Use the richest key we can, based on which fields are present.
        if flit.srcid is not None and flit.tgtid is not None:
            return "txnid-srcid-tgtid"
        if flit.srcid is not None:
            return "txnid-srcid"
        return "txnid"

    def _req_key(self, flit):
        mode = self._auto_mode(flit) if self.opts.match == "auto" else self.opts.match
        if mode == "txnid":
            return (mode, flit.txnid)
        if mode == "txnid-reqsrc":
            if flit.srcid is None:
                return None
            return (mode, flit.txnid, flit.srcid)
        if mode == "txnid-srcid":
            if flit.srcid is None:
                return None
            return (mode, flit.txnid, flit.srcid)
        if mode == "txnid-srcid-tgtid":
            if flit.srcid is None or flit.tgtid is None:
                return None
            return (mode, flit.txnid, flit.srcid, flit.tgtid)
        return None

    def _rsp_key(self, flit):
        mode = self._auto_mode(flit) if self.opts.match == "auto" else self.opts.match
        if mode == "txnid":
            return (mode, flit.txnid)
        if mode == "txnid-reqsrc":
            if flit.tgtid is None:
                return None
            return (mode, flit.txnid, flit.tgtid)
        if mode == "txnid-srcid":
            if flit.tgtid is None:
                return None
            return (mode, flit.txnid, flit.tgtid)
        if mode == "txnid-srcid-tgtid":
            if flit.srcid is None or flit.tgtid is None:
                return None
            return (mode, flit.txnid, flit.tgtid, flit.srcid)
        return None

    def _flit_desc(self, flit):
        parts = []
        ctx = flit.group.context_str()
        if ctx:
            parts.append(ctx)
        parts.append(cmn_flits.CHI_VC_strings[flit.group.VC])
        parts.append(flit.short_str())
        if flit.tracetag:
            parts.append("TAG")
        return " ".join(parts)

    def _format_key(self, key):
        mode = key[0]
        if mode == "txnid":
            return "txnid=0x%x" % key[1]
        if mode == "txnid-reqsrc":
            return "txnid=0x%x reqsrc=0x%x" % (key[1], key[2])
        if mode == "txnid-srcid":
            return "txnid=0x%x srcid=0x%x" % (key[1], key[2])
        if mode == "txnid-srcid-tgtid":
            return "txnid=0x%x srcid=0x%x tgtid=0x%x" % (key[1], key[2], key[3])
        return "key=%s" % (key,)

    def process_group(self, g):
        # Walk all flits in a decoded group and match requests/responses.
        for flit in g.flits:
            if g.cc is None:
                if g.VC == self.opts.req_channel:
                    self.stats.n_req_missing_cc += 1
                elif g.VC in self.opts.rsp_channels:
                    self.stats.n_rsp_missing_cc += 1
                continue
            if self.opts.tagged_only and not flit.tracetag:
                continue
            if g.VC == self.opts.req_channel:
                self.stats.n_req += 1
                key = self._req_key(flit)
                if key is None:
                    self.stats.n_key_missing += 1
                    continue
                self.pending.setdefault(key, []).append(RequestRecord(flit, g, g.cc))
            elif g.VC in self.opts.rsp_channels:
                self.stats.n_rsp += 1
                key = self._rsp_key(flit)
                if key is None:
                    self.stats.n_key_missing += 1
                    continue
                if key not in self.pending or not self.pending[key]:
                    self.stats.n_rsp_unmatched += 1
                    continue
                req = None
                lat = None
                while self.pending[key]:
                    candidate = self.pending[key][0]
                    lat = sub16(g.cc, candidate.cc)
                    if self.opts.max_latency is not None and lat > self.opts.max_latency:
                        # Drop stale requests until latency falls within the cap.
                        self.pending[key].pop(0)
                        self.stats.n_req_dropped += 1
                        continue
                    req = self.pending[key].pop(0)
                    break
                if req is None:
                    self.stats.n_rsp_unmatched += 1
                    continue
                self.stats.add_latency(lat)
                if self.opts.verbose:
                    req_desc = str(req.group)
                    rsp_desc = str(g)
                else:
                    req_desc = self._flit_desc(req.flit)
                    rsp_desc = self._flit_desc(flit)
                key_desc = self._format_key(key)
                print("%6u  req_cc=0x%04x rsp_cc=0x%04x  %s  ->  %s  (%s)" %
                      (lat, req.cc, g.cc, req_desc, rsp_desc, key_desc), file=self.out)

    def show_pending(self):
        if not self.pending:
            return
        print("Pending requests:", file=self.out)
        for (key, reqs) in sorted(self.pending.items()):
            for req in reqs:
                print("  req_cc=0x%04x %s (%s)" %
                      (req.cc, self._flit_desc(req.flit), self._format_key(key)),
                      file=self.out)


class LatencyDecoder(cs_decode_cmn.CMNDecoder):
    """
    CMN trace decoder that forwards decoded flit groups to the matcher.
    """
    def __init__(self, cfg, matcher, verbose=0, reorderer=None):
        super(LatencyDecoder, self).__init__(cfg, verbose=verbose, reorderer=reorderer)
        self.matcher = matcher

    def output_flits(self, g):
        self.matcher.process_group(g)


def parse_channel(name):
    key = name.strip().upper()
    if key not in CHI_CHANNELS:
        raise argparse.ArgumentTypeError("unknown channel '%s'" % name)
    return CHI_CHANNELS[key]


def parse_channel_list(text):
    items = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        items.append(parse_channel(part))
    if not items:
        raise argparse.ArgumentTypeError("no channels specified")
    return items


def add_trace_args(parser):
    parser.add_argument("-i", "--input", type=str, help="input trace binary")
    parser.add_argument("--cmn-version", type=(lambda x: int(x, 0)), help="CMN version", required=True)
    parser.add_argument("--cmn-revision", type=int, default=0, help="CMN revision")
    parser.add_argument("--mpam", action="store_true", help="CMN has MPAM enabled")
    parser.add_argument("--no-sync", action="store_true", help="don't look for sync sequence")
    parser.add_argument("--ignore", type=str, action="append", help="ignore trace stream(s)")
    parser.add_argument("--unformatted", action="store_true", help="trace file has no CoreSight framing")
    parser.add_argument("--reorder-cc-window", type=int, default=0, help="allow small same-stream CC reorder within this window; cross-stream order uses packet start position")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("inputs", type=str, nargs="*", help="input trace binaries")


def print_summary(stats, matcher, out):
    if stats.n_match:
        mean = stats.mean()
        print("Matches: %u  min=%u  max=%u  mean=%.1f" %
              (stats.n_match, stats.lat_min, stats.lat_max, mean), file=out)
    else:
        print("Matches: 0", file=out)
    if stats.n_req or stats.n_rsp:
        print("Requests: %u  Responses: %u  Unmatched responses: %u" %
              (stats.n_req, stats.n_rsp, stats.n_rsp_unmatched), file=out)
    if stats.n_req_dropped:
        print("Dropped requests (over max latency): %u" % stats.n_req_dropped, file=out)
    if stats.n_req_missing_cc or stats.n_rsp_missing_cc:
        print("Missing CC: req=%u rsp=%u" %
              (stats.n_req_missing_cc, stats.n_rsp_missing_cc), file=out)
    if stats.n_key_missing:
        print("Missing key fields: %u (adjust --match or capture format)" %
              stats.n_key_missing, file=out)
    if matcher.pending:
        print("Pending requests: %u" % sum(len(v) for v in matcher.pending.values()), file=out)


def run_for_file(fn, opts, out):
    # Build CMN trace decoders and feed the trace stream into the matcher.
    cfg = cs_decode_cmn.CMNTraceConfig(
        opts.cmn_version,
        cmn_product_revision=opts.cmn_revision,
        has_MPAM=opts.mpam,
    )
    stats = LatencyStats()
    matcher = TransactionMatcher(opts, stats, out)
    reorderer = cs_decode_cmn.CMNTraceCCReorderer(opts.reorder_cc_window) if opts.reorder_cc_window > 0 else None

    def new_decoder(id=None):
        decoder = LatencyDecoder(cfg, matcher, verbose=opts.verbose, reorderer=reorderer)
        return cs_decode_cmn.CMNDecoderPump(decoder, sync=(not opts.no_sync))

    if opts.unformatted:
        decode_map = {"unformatted": new_decoder()}
    else:
        decode_map = {"default": new_decoder}

    for ign_ids in (opts.ignore or []):
        for ign_id in ign_ids.split(","):
            decode_map[int(ign_id, 0)] = cs_decode.sink()

    with open(fn, "rb") as f:
        try:
            cs_decode.stream_decode(f, decode_map, verbose=opts.verbose)
            if reorderer is not None:
                reorderer.flush()
        except cs_decode.TraceCorrupt as e:
            print("%s: trace error: %s" % (fn, str(e)), file=sys.stderr)

    if opts.show_pending:
        matcher.show_pending()
    print_summary(stats, matcher, out)


def main(argv):
    parser = argparse.ArgumentParser(
        description="Report CMN transaction latency from a trace file"
    )
    add_trace_args(parser)
    parser.add_argument(
        "--req-channel",
        type=parse_channel,
        default=cmn_flits.REQ,
        help="request channel (default: REQ)",
    )
    parser.add_argument(
        "--rsp-channels",
        type=parse_channel_list,
        default=parse_channel_list("RSP,DAT"),
        help="response channels as comma-separated list (default: RSP,DAT)",
    )
    parser.add_argument(
        "--match",
        choices=["auto", "txnid", "txnid-reqsrc", "txnid-srcid", "txnid-srcid-tgtid"],
        default="auto",
        help="matching key for request/response correlation",
    )
    parser.add_argument(
        "--end-to-end",
        action="store_true",
        help="set match/rsp-channels for RN-F request to DAT response latency",
    )
    parser.add_argument(
        "--tagged-only",
        action="store_true",
        help="only consider flits with TraceTag set",
    )
    parser.add_argument(
        "--max-latency",
        type=int,
        default=5000,
        help="drop request/response matches above this cycle count (default: 5000)",
    )
    parser.add_argument(
        "--show-pending",
        action="store_true",
        help="print unmatched pending requests at end",
    )
    opts = parser.parse_args(argv)
    if opts.end_to_end:
        opts.match = "txnid-reqsrc"
        opts.rsp_channels = [cmn_flits.DAT]
    if opts.input is not None:
        opts.inputs.insert(0, opts.input)
    if not opts.inputs:
        print("%s: input files are required" % __file__, file=sys.stderr)
        return 1
    if len(opts.inputs) > 1:
        for fn in opts.inputs:
            print("File: %s" % fn)
            run_for_file(fn, opts, sys.stdout)
            print()
    else:
        run_for_file(opts.inputs[0], opts, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
