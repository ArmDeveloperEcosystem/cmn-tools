#!/usr/bin/python

"""
CoreSight trace decoding.

Copyright (C) ARM Ltd. 2018-2025.  All rights reserved.

SPDX-License-Identifer: Apache 2.0

This module handles the overall processing of a combined CoreSight trace
stream which may interleave trace from multiple sources (e.g. ETMs, STMs etc.).
It doesn't handle the decode of actual stream formats, but hands off data
to decoders for these formats.  You call it something like this:

  import cs_decode, cs_decode_etm
  decoders = {1: cs_decode_etm.decode_etm()}
  cs_decode.stream_decode(stream, decoders)

In general the CoreSight trace decode pipeline consists of a
number of steps:

  - remove any 4-byte frame sync packets
  - synchronize to 16-byte frame boundaries (assumed already done)
  - find first trace stream identifier (indicated by LSB=1 in even bytes)
  - align to packet boundary for each stream (stream-specific sync packet)
    - for ETM/PFT this is A-sync
  - recover enough context to successfully decode stream (stream-specific)
    - for ETM/PFT this is I-sync, and possibly CONTEXTID

References:

[CSA] CoreSight Architecture Specification v2.0

In this module and elsewhere in the trace decoder, various techniques
are used for streams of data.

  - file-like objects (FLOs) which respond to read(n) requests

  - generators which yield bytes, packets, frames etc.

  - consumers which accept bytes or packets
"""

from __future__ import print_function

import sys
import io


class Finished(Exception):
    pass


class TraceDecodeException(Exception):
    """
    Any exception produced when decoding a single stream or sequence
    of formatted frames.
    """
    pass


class TraceUnimplemented(TraceDecodeException):
    """
    Trace decoder does not support a feature (e.g. speculation)
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "Unimplemented: %s" % self.msg


class TraceUnformatException(TraceDecodeException):
    def __init__(self, msg, frame):
        self.msg = msg
        self.frame = frame

    def __str__(self):
        return "Corrupt formatted trace frame: %s\n%s" % (self.msg, frame_hex(self.frame))


class TraceStreamException(TraceDecodeException):
    pass


"""
Trace stream decoder indicates that the trace stream is corrupt -
it's encountered packet data that doesn't match its configuration
(e.g. a reserved packet header, or a data-trace packet when data
trace is not enabled).  Further decode of this stream is likely
to be pointless, and any program addresses, timestamps etc. recovered
from the stream are likely to be invalid.
"""

class TraceCorrupt(TraceDecodeException):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


def frame_changes_id(fr):
    """
    Test a 16-byte CoreSight formatted frame to see it has a change
    of trace source id anywhere in it.  This test may be useful when skipping
    over sections of trace where the source id is unknown or unwanted.
    There may be several changes of id within a frame.
    """
    return ((fr[0] | fr[2] | fr[4] | fr[6] | fr[8] | fr[10] | fr[12] | fr[14]) & 1) != 0


def frame_is_zero(fr):
    return fr == b"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"


def frame_hex(fr):
    """
    Return a string summarizing the undecoded contents of the 16-byte frame.
    Byte 15 is the flags byte.
    """
    assert len(fr) == 16
    s = "["
    for i in range(0, 16, 2):
        s += "%s%02x %02x" % (" ."[fr[i] & 1], fr[i], fr[i+1])
    s += " ]" + " *"[frame_changes_id(fr)]
    #s = "[ %s ]" % ' '.join(["%02x" % b for b in fr])
    #if frame_changes_id(fr):
    #    s += " CHANGE"
    return s


def bin(b):
    s = ""
    for i in range(0, 8):
        s = ("%u" % ((b >> i) & 1)) + s
    return s


TRIGGER = 0x7d


def frame_demux(fr, id, fault_reserved_ids=True, discard_id0=True, check=True):
    """
    Given a 16-byte CoreSight formatted frame, yield its trace bytes, as a
    stream of (id, data) tuples.  The starting id should be passed in.
    An initial or returned id of None indicates that the id isn't yet known.
    If the id changes in byte 14, when there is no more data left to yield,
    finish by yielding (id, None).

    See chapter D4, "Trace Formatter" in [CSA].
    """
    assert len(fr) == 16, "expecting 16-byte CoreSight frame, got %u-byte frame" % (len(fr))
    flags = fr[15]
    if id is not None and not frame_changes_id(fr):
        # Fast-path for when the frame has 15 data bytes with no change of source id.
        if discard_id0 and id == 0:
            # Still in a null-source state, data associated with this source
            # must be ignored by debugger, until we see a source change.
            return
        for i in range(0, 7):
            Aux = (flags >> i) & 1
            b0 = fr[i*2]          # LSB will be unset
            b1 = fr[i*2+1]
            yield (id, b0 | Aux)
            yield (id, b1)
        yield (id, fr[14] | ((flags >> 7) & 1))
        return
    for i in range(0, 8):
        Aux = (flags >> i) & 1
        b0 = fr[i*2]    # either data byte, or new trace source id
        if i < 7:
            b1 = fr[i*2+1]
        else:
            # Byte 15: the flags byte
            b1 = None
        F = b0 & 1     # LSB of the even-numbered bytes
        if F != 0:
            # new ID - either applying to b1, or the next byte
            newid = b0 >> 1
            if Aux == 1:
                # next byte corresponds to old id
                if i == 7:
                    # if byte 14 is a new id, this bit is R, MBZ,
                    # must be ignored when decompressing the frame
                    raise TraceUnformatException("Unexpected Aux flag 0x%02x" % b0, fr)
                if discard_id0 and id == 0:
                    pass
                else:
                    yield (id, b1)
            id = newid
            if id == 0:
                # null trace source.  Any trace associated with this source ID
                # must be ignored by the debugger.
                # This may occur when there is insufficient data to complete
                # a formatter frame. We yield a None value so that the consumer
                # updates their stream id to zero.
                yield (id, None)
            elif id == 0x7f:
                # this is reserved for frame sync packets - which should
                # have been handled at an earlier stage in the decoding pipeline.
                if fault_reserved_ids:
                    raise TraceUnformatException("Frame sync id=0x7f", fr)
            elif id == 0x7d:
                # Indicates a trigger within the trace stream and is
                # accompanied by one byte of data for each trigger.
                # The value of each data byte indicates the ID of the trigger.
                # This is treated like any other stream id - each byte of
                # data is interpreted as a trigger id until the next ID change.
                pass
            elif id == 0x7b:
                # Indicates a flush response. Trace that is output with the
                # flush response ID signifies that all previous trace that
                # was generated previous to a flush request has been output.
                # Each byte of trace that is output with ID 0x7b constitutes
                # a separate flush response:
                #   0x00: all active trace sources have indicated a flush response
                #   0x01-0x6f: trace source with this ID value has indicated f.r.
                pass
            elif id == 0x7e or id == 0x7c or (id >= 0x70 and id <= 0x7a):
                if fault_reserved_ids:
                    raise TraceUnformatException("Reserved id=0x%02x" % id, fr)
            if i < 7:
                if not Aux:
                    if discard_id0 and id == 0:
                        pass
                    else:
                        yield (id, b1)
            else:
                # special case - change id after all the data
                yield (id, None)
        else:
            # data byte, not a new id
            # n.b. may be on trigger channel
            # Data associated with ID=0x00 should be ignored.
            if discard_id0 and id == 0x00:
                pass
            else:
                yield (id, b0 | Aux)
                if i < 7:
                    yield (id, b1)


def id_str(id):
    if id is None:
        s = "(??)"     # Still in starting state where we don't know the id
    elif id == 0x00 or id >= 0x70:
        s = "(*%02x*)" % id
    else:
        s = "(%02x)" % id
    return s


def frame_summary(fr, id):
    """
    Return a string indicating how the frame demultiplexes to stream bytes.
    This function is intended primarily for diagnostics.
    """
    s = id_str(id)       # Starting id
    previd = id
    for (id, b) in frame_demux(fr, id, fault_reserved_ids=False, discard_id0=False):
        # Note that it's not observable when id is changed to its previous value.
        if id != previd:
            s += " " + id_str(id)
            previd = id
        if b is not None:
            s += " %02x" % b
    return s


def frame_end_id(fr, id):
    """
    Return the stream id at the end of a frame.
    """
    for (id, b) in frame_demux(fr, id, fault_reserved_ids=False):
        pass
    return id


FRAME_SYNC = bytearray(b"\xff\xff\xff\x7f")


def stream_frames(stream, framesyncs_present=True):
    """
    Break a trace byte stream into 16-byte CoreSight frames,
    skipping over any 4-byte frame sync packets.
    Yield each frame.
    Signature: FLO -> generate(frames)
    """
    if isinstance(stream, bytes) or isinstance(stream, bytearray):
        stream = io.BytesIO(stream)
    while True:
        if framesyncs_present:
            while True:
                fr = bytearray(stream.read(4))
                #print("comparing against FRAME_SYNC: %02x%02x%02x%02x" % (fr[0],fr[1],fr[2],fr[3]))
                if fr != FRAME_SYNC:
                    break
            fr += bytearray(stream.read(12))
        else:
            fr = bytearray(stream.read(16))
        if len(fr) < 16:
            # end of file
            if len(fr) > 0:
                print("** unexpected data at end of stream")
            break
        #print("yield: %s" % frame_hex(fr))
        yield fr


def stream_demux(stream, id=None, trace_frames=False, fault_reserved_ids=True, stop_on_id0=False):
    """
    Given a CoreSight trace stream, demultiplex it and yield a stream of
    (id, data) tuples where each data is one byte.
    The starting id may be passed in, in case this is a continuation
    of a previous stream of formatted frames.
    The statting id may be None, if not already known.
    A trigger is reported as id 0x7b (TRIGGER).
    Signature: FLO -> generate((id, byte))
    """
    n_frames = 0
    for fr in stream_frames(stream):
        if trace_frames:
            # We print a frame sequence number, but this can only be converted
            # back into a byte offset if the buffer doesn't contain any frame-syncs.
            print(" %6x %s -> %s" % (n_frames*16, frame_hex(fr), frame_summary(fr, id)))
            n_frames += 1
        for (id, b) in frame_demux(fr, id, fault_reserved_ids=fault_reserved_ids):
            if b is not None:
                yield (id, b)
        if id == 0 and stop_on_id0:
            # Any trace associated with ID=0x00 must be ignored by the debugger.
            # The spec is not quite clear about whether, following ID=0x00,
            # all remaining data in the buffer must be ignored, or whether we
            # should continue scanning for a change to a different ID.
            # The intention is that we do scan for further ID changes, but some
            # trace generators may insert a zero frame as a terminator, leaving
            # the rest of the buffer undecodable.
            # We provide the 'stop_on_id0' flag to control behavior.
            break


def stream_extract(stream, id):
    """
    Given a CoreSight trace stream (a FLO responding to read()),
    extract the substream for a given id.
    Signature: FLO -> generate(byte)
    """
    for (sid, b) in stream_demux(stream):
        if sid == id:
            yield b


def stream_unformatted_decode(stream, decoder, trace=False):
    """
    Read an unformatted trace stream and send to a single decoder.
    """
    count = 0
    decoder.send(None)
    while True:
        b = stream.read(1)
        if len(b) == 0:
            break
        b = ord(b)
        if trace:
            print("0x%06x  0x%02x" % (count, b))
        decoder.send(b)
        count += 1
    return count


def string_decode(s, decoder):
    """
    Read a byte string and send to a single decoder.
    """
    decoder.send(None)
    count = 0
    for c in s:
        decoder.send(c)
        count += 1
    return count


def stream_decode(stream, decoders, verbose=0, name=None):
    """
    Unformat (demultiplex) a CoreSight formatted trace stream, and send to decoders.
    Input is a stream of 16-byte formatted frames as described in [CSA] D4.2.
    The caller should pass in a set of decoders, indexed by trace source id.
    Each decoder is a coroutine expecting to read a byte at time using (yield).
    This function then demultiplexes the trace streams and sends them byte by byte
    to the decoders.
    """
    if "unformatted" in decoders:
        assert len(decoders) == 1, "expected single decoder for unformatted stream: %s" % decoders
        return stream_unformatted_decode(stream, decoders["unformatted"], trace=(verbose >= 2))
    sname = ""
    if name is not None:
        sname = name + ": "
    id = None    # current trace source id
    nb = 0
    decoder = None
    count = {}
    unknown_warned = {}
    # start all the coroutines
    for d in decoders:
        decoders[d].send(None)   # Start each coroutine
    for (newid, b) in stream_demux(stream, id, trace_frames=verbose):
        if newid is None:
            continue
        if id is None or newid != id:
            # change of id
            if verbose:
                print()
                print("ID = %u" % newid)
            id = newid
            decoder = None
            if id == 0:
                # null trace source.  Any trace following this
                # ID change must be ignored by the debugger.
                if False:
                    print("** %strace id 0 seen - ignoring rest of trace" % sname)
                    break
            elif id == 0x7f:
                # this is reserved for frame sync packets - which should
                # have been handled at an earlier stage in the decoding pipeline.
                print("** %strace corrupt: id=0x7f" % sname)
            elif id == 0x7e:
                id = None   # reserved
            elif id in decoders:
                decoder = decoders[id]
            elif id == TRIGGER:
                # Indicates a trigger within the trace stream and is
                # accompanied by one byte of data for each trigger.
                # The value of each data byte indicates the ID of
                # the trigger.
                # The caller can cause triggers to be handled, by passing in
                # a decoder for the TRIGGER (0x7d) stream.
                print("** %strigger: %u" % (sname, b))
            elif id == 0x7b:
                # Flush response
                print("** %sflush response: %u" % (sname, b))
            elif "all" in decoders:
                decoder = decoders["all"]
            else:
                # no decoder registered for this id
                if id not in unknown_warned:
                    print("** %sunknown trace source id: %u (known ids are %s)" % (sname, id, str(list(decoders.keys()))))
                    unknown_warned[id] = True
                decoder = None
        if id is not None:
            if id not in count:
                count[id] = 0
            count[id] += 1
        if decoder is not None:
            if verbose >= 3:
                print(" %6u | %02x | %s | %02x |" % (nb, id, bin(b), b))
            try:
                assert b is not None
                decoder.send(b)
            except Finished:
                print("** %strace [%u] consumer finished" % (sname, id))
            except TraceCorrupt as e:
                print("** %strace [%u] corrupt: %s" % (sname, id, e.msg), file=sys.stderr)
                raise
        else:
            # stream id not known, or no decoder for this stream
            pass
        nb += 1

    if verbose:
        if count:
            print("%strace streams: %s" % (sname, count))
        else:
            print("** %sno trace streams found" % (sname))


def stream_decode_aux(f, decoders, verbose=0, name=None):
    ret = None
    try:
        ret = stream_decode(f, decoders, verbose=verbose, name=name)
    except Finished:
        pass
    except StopIteration:
        pass
    return ret


def file_decode(fn, decoders, verbose=0):
    if fn == "-":
        return stream_decode_aux(sys.stdin.buffer, decoders, verbose=verbose, name="stdin")
    else:
        with open(fn, "rb") as f:
            return stream_decode_aux(f, decoders, verbose=verbose, name=fn)


def buffer_decode(buf, decoders, verbose=0, fn=None):
    if fn is None:
        fn = "<buffer>"
    f = io.BytesIO(buf)
    ret = None
    try:
        ret = stream_decode(f, decoders, verbose=verbose, name=fn)
    except Finished:
        pass
    except StopIteration:
        pass
    f.close()
    return ret


def sink():
    """
    Trace stream sink.  Register this for a trace source id
    if you want to ignore all bytes from this stream.
    """
    while True:
        _ = (yield)


def dump():
    """
    Trace stream raw dump.  Register this for a trace source id
    if you want to print out raw hex values from the trace stream.
    (Doesn't look particularly good if the trace stream is mixed
    with others.)
    """
    n = 0
    while True:
        a = (yield)
        if (n % 16) == 0:
            print(("%06x: " % n), end=' ')
        print(("%02x" % a), end=' ')
        n += 1
        if (n % 16) == 0:
            print()


def stream_ids(stream, verbose=0):
    """
    Scan a trace stream and count the number of bytes for each trace source.
    Return a map: source -> counts
    """
    def idname(id):
        return str(id)
    count = {}
    thisid = 0
    previd = None
    for (id, b) in stream_demux(stream, fault_reserved_ids=False, trace_frames=(verbose >= 2)):
        if id is not previd and (thisid > 0):
            if verbose:
                # print a running commentary on the number of bytes we get for each stream
                print("%s: %u bytes" % (idname(previd), thisid))
            thisid = 0
        previd = id
        if id is not None:
            if id not in count:
                count[id] = 0
            count[id] += 1
        thisid += 1
    if verbose and thisid > 0:
        print("%s: %u bytes" % (idname(previd), thisid))
    return count


def inspect_stream(stream, verbose=0):
    print("total:", stream_ids(stream, verbose=verbose))


def inspect_trace(fn, verbose=0):
    if fn == "-":
        inspect_stream(sys.stdin.buffer, verbose=verbose)
    else:
        with open(fn, "rb") as stream:
            inspect_stream(stream, verbose=verbose)


def dump_stream(stream, verbose=0):
    """
    Dump the contents of a trace buffer.
    TBD: currently assumes formatted.
    """
    previd = None
    online = 0
    line = ""
    for (id, b) in stream_demux(stream, trace_frames=verbose):
        if id is not previd:
            if online > 0:
                if line:
                    print(line)
                    line = ""
                print("---")
                online = 0
            previd = id
        if online == 0:
            if id is not None:
                line = "%02x:" % id
            else:
                line = "??:"
        line += " %02x" % b
        online += 1
        if online == 16:
            print(line)
            line = ""
            online = 0
    if online > 0:
        print(line)


def dump_trace(fn, verbose=0):
    """
    Dump the contents of a trace file.
    """
    with open(fn, "rb") as stream:
        dump_stream(stream, verbose=verbose)


def inspect_frame(s):
    """
    Show each data byte in a formatted frame.
    """
    frame = s
    print("Data")
    for (id, b) in frame_demux(frame, id=None):
        if id is None:
            print("0x%02X, ID ?" % (b))
        elif id == TRIGGER:
            print("TRIGGER, ID=0x%02X" % (b))
        else:
            print("0x%02X, ID 0x%02X" % (b, id))


def self_test():
    # Try the example from CSA.  Note that the decode in CSA 1.0 Table 14-2 is incorrect,
    # it's fixed in CSA 2.0 Table D4-2.
    def test(frs):
        print()
        print("Testing frame: %s" % frame_hex(frs))
        inspect_frame(frs)
    test(b"\x07\xAA\xA6\xA7\x2B\xA8\x54\x52\x52\x54\x07\xCA\xC6\xC7\xC8\x1C")
    test(b"\x07\xAA\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    test(b"\x07\xAA\xfb\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    test(b"\x07\xAA\xfb\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CoreSight trace decoder")
    parser.add_argument("--test", action="store_true", help="run self-tests")
    parser.add_argument("--decode", action="store_true", help="decode trace")
    parser.add_argument("--dump", action="store_true", help="dump raw trace")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("trace", type=str, help="trace file to decode")
    opts = parser.parse_args()
    if opts.test:
        self_test()
    o_verbose = opts.verbose
    o_dump = opts.dump
    o_decode = opts.decode
    if opts.stream:
        o_decode = True
    decoders = {}
    arg = opts.trace
    if o_dump:
        # raw dump
        dump_trace(arg, verbose=o_verbose)
    elif o_decode:
        file_decode(arg, decoders, verbose=o_verbose)
    else:
        inspect_trace(arg, verbose=o_verbose)
