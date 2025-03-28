#!/usr/bin/python

"""
Decode CMN-xxx interconnect trace

Copyright (C) ARM Ltd. 2024-2025.  All rights reserved.

SPDX-License-Identifer: Apache 2.0
"""

from __future__ import print_function

import struct

from cs_decode import TraceCorrupt
from cmn_flits import CMNTraceConfig, CMNFlitGroup, CMNFlit


def BITS(x, p, n):
    return (x >> p) & ((1 << n)-1)


def BIT(x, p):
    return (x >> p) & 1


def bytes_hex(x):
    s = ""
    for b in x:
        s += ("%02x" % b)
    return s


class CMNDecoder:
    """
    Simple decoder for CMN trace stream.
    User will likely want to subclass this class to do something with the payload.
    """
    def __init__(self, cfg, verbose=0):
        self.verbose = verbose
        self.cfg = cfg
        if self.cfg._cmn_base_type == 0:
            self.sync_size = 16
        else:
            self.sync_size = 20
        if self.verbose:
            print("CMN decoder created (%s)" % (self.cfg))
        self.reset()

    def reset(self):
        self.n_sync = 0
        self.n_ts_bytes_valid = 0
        self.ts_last = 0
        self.n_timestamps = 0

    def __str__(self):
        s = "CMN{v=%s,n_sync=%u, ts=%s}" % (self.cfg, self.n_sync, self.ts_string())
        return s

    def decode(self, sync=True):
        self.n_ts_bytes_valid = 0
        if self.verbose:
            print("%s stream decode start, sync=%u" % (self, sync))
        if sync:
            # Caller requests that we scan for a sync sequence. Used if we are picking up
            # the decode in mid-stream.
            # Work around CMN-600 bug, it generates 12*0x00 0x80 3*0x00
            # rather than the correct 15*0x00 0x80. Note that this creates a possible
            # ambiguity since this sequence might be seen in the payload of a data packet.
            if self.verbose:
                print("CMN: scanning for sync sequence")
            seen_zeroes = 0
            n_discarded = 0
            while True:
                x = (yield)
                if x == 0x00:
                    seen_zeroes += 1
                    if seen_zeroes == self.sync_size-4:
                        x = (yield)
                        if x == 0x80 and (yield) == 0x00 and (yield) == 0x00 and (yield) == 0x00:
                            break
                        elif x == 0x00 and (yield) == 0x00 and (yield) == 0x00 and (yield) == 0x80:
                            break
                else:
                    seen_zeroes = 0
                    n_discarded += 1
            if self.verbose:
                print("CMN: sync sequence found, %u bytes discarded" % n_discarded)
            self.n_sync += 1
        else:
            # Caller is asserting that the stream begins on a packet boundary.
            pass
        while True:
            x = (yield)
            if self.verbose:
                print("CMN: packet header 0x%02x" % (x))
            if x == 0x00:
                # Alignment sync packet after seeing other packets; or possibly at the
                # start when we didn't request sync.
                for i in range(0, self.sync_size-5):
                    x = (yield)
                    if x != 0x00:
                        raise TraceCorrupt("invalid sync sequence (sync=%u, n_sync=%u)" % (sync, self.n_sync))
                x = (yield)
                if x == 0x00:
                    x = (yield)
                    x = (yield)
                    x = (yield)
                elif x == 0x80:
                    x = (yield)
                    x = (yield)
                    x = (yield)
                self.n_sync += 1
            elif (x & 0xc0) == 0x40:
                # Data packet. Note that the header for CMN-700 is different.
                CC = BIT(x, 4)     # not bit 1 as indicated in the CMN-600 TRM
                b1 = (yield)
                b2 = (yield)
                b3 = (yield)
                header = (b3 << 24) | (b2 << 16) | (b1 << 8) | x
                size = BITS(b2, 3, 5)
                payload = b''
                for i in range(0, size+1):
                    x = (yield)
                    payload += struct.pack("B", x)
                if CC:
                    # 2-byte cycle count follows the payload
                    c0 = (yield)
                    c1 = (yield)
                    cx = (c1 << 8) | c0
                else:
                    cx = None
                self.emit_data(header, payload, cc=cx)
            elif (x & 0xc0) == 0x80:
                # Timestamp packet - just the changed lower bytes
                CC = BIT(x, 4)
                TSn = BITS(x, 0, 3) + 1
                TS = 0
                for i in range(0, TSn):
                    x = (yield)
                    TS |= (x << (i*8))
                if CC:
                    c0 = (yield)
                    c1 = (yield)
                    cx = (c1 << 8) | c0
                else:
                    cx = None
                ts_new = (self.ts_last & ~((1 << (TSn*8)) - 1)) | TS
                self.n_ts_bytes_valid = max(self.n_ts_bytes_valid, TSn)
                self.emit_timestamp(ts_new, cc=cx)
            else:
                print("unknown CMN trace header byte 0x%02x" % x)
                raise TraceCorrupt("unknown header byte 0x%02x" % x)

    def output_cc(self, cc):
        if cc is not None:
            print(" %4x " % cc, end="")
        else:
            print("      ", end="")

    def emit_data(self, h, payload, cc=None):
        """
        Called when we've got a data packet.
        """
        # Header format changed incompatibly between CMN-600 and CMN-650
        lossy = BIT(h, 0)
        nodeid = BITS(h, 8, 11)
        if self.cfg._cmn_base_type == 0:
            type = BITS(h, 24, 3)
            WP = BITS(h, 27, 2)
            DEV = BIT(h, 29)
            VC = BITS(h, 30, 2)
        else:
            type = BITS(h, 1, 3)
            WP = BITS(h, 24, 2)
            DEV = 0
            VC = BITS(h, 28, 2)
        g = CMNFlitGroup(self.cfg, format=type, WP=WP, DEV=DEV, VC=VC, nodeid=nodeid, cc=cc, lossy=lossy)
        g.decode(payload)
        self.output_flits(g)

    def output_flits(self, g):
        self.output_cc(g.cc)
        # Print flit data to standard output. Decoder user might override this.
        print(g)

    def ts_string(self):
        n_digits = self.n_ts_bytes_valid * 2
        s = ("0x%%s%%0%ux" % n_digits) % ("."*(16-n_digits), self.ts_last)
        return s

    def output_ts(self):
        print("  TS: %s" % self.ts_string())

    def emit_timestamp(self, ts, cc=None):
        self.ts_last = ts
        self.n_timestamps += 1
        self.output_cc(cc)
        self.output_ts()
