#!/usr/bin/python

"""
Demonstrate collecting CMN trace over CoreSight ATB, with self-hosted
trace retrieval.

This leverages the CMN DTM programming support in cmn_capture.py, but instead
of using FIFO, it redirects the trace to ATB, and also programs downstream
ATB and collects trace from a suitable sink.

The platform-specific CoreSight topology is read from JSON. By default, the
file is ~/.cache/arm/cmn-coresight-atb.json; coresight_atb_detect.py can install the
descriptor for a recognized platform.
"""

from __future__ import print_function


import sys
import os
import time


sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import cmn_capture
import cmn_devmem
from cmn_flits import CMNFlitGroup, trace_config_from_cmn_config


# CoreSight device management and decoding
import coresight_atb
import cs_decode
import cs_decode_cmn


TS_PERIODS = [0, 0, 0, 8192, 16384, 32768, 65536, 0]


class ATBTraceSession(cmn_capture.TraceSession):
    """
    Manage a trace session to CoreSight ATB

    Construction retains the validated plan and topology without accessing
    devices. activate() prepares CMN, configures the CoreSight paths and
    assigns DTC trace IDs. Retain the device manager before configuring it,
    so that the session owns it even if configuration fails partway through.

    trace_start() enables sinks before CMN trace generation. collect_from_sinks()
    stops the sinks and forwarding devices before reading their buffers.
    The caller must close the session in a finally block covering activation,
    capture, collection and decoding; main() demonstrates this. Cleanup leaves
    DTCs enabled, but does not restore prior CoreSight or watchpoint settings.
    """
    def __init__(self, plan, opts, topology):
        if plan.dtms_rotating:
            raise cmn_capture.NotEnoughWatchpoints("ATB capture cannot rotate watchpoints")
        cmn_capture.TraceSession.__init__(self, plan, opts, atb=True)
        self.topology = topology
        self.atb_devices = None
        self.dtc_to_sink = {}    # (cmn_seq, dtc#) -> sink
        self.dtc_map = {}        # DTC -> (sink, atid)
        self.sinks = []

    def activate(self, init=True):
        cmn_capture.TraceSession.activate(self, init=init)
        self._activated = False    # Not ready to start until the ATB path is ready.
        if self.opts.verbose:
            system_name = self.topology.system.get("name", "unspecified")
            print("ATB topology: %s (%s)" %
                  (self.topology.filename, system_name))
        self.configure_atb_sinks()
        self.configure_dtcs_for_atb()
        self._activated = True

    def _close_output(self):
        if self.atb_devices is not None:
            self.atb_devices.stop()

    def configure_atb_sinks(self):
        dtcs = list(self.DTCs())
        source_for_dtc = {}
        for dtc in dtcs:
            source_for_dtc[dtc] = self.topology.source_id_for_dtc(dtc)
        self.atb_devices = coresight_atb.ATBDeviceManager(
            self.topology, list(source_for_dtc.values()),
            formatting=(not self.opts.unformatted),
            verbose=self.opts.verbose, checking=True)
        self.atb_devices.configure()
        self.sinks = self.atb_devices.sinks
        for dtc in dtcs:
            sid = source_for_dtc[dtc]
            key = (dtc.CMN().cmn_seq, dtc.dtc_domain())
            self.dtc_to_sink[key] = self.atb_devices.sink_for_source[sid]

    def configure_dtcs_for_atb(self):
        """
        Arrange for the DTCs to have unique ATIDs. Right now we make
        assumptions elsewhere that we only have one trace source,
        but this demonstrates the general idea.
        """
        tracectl = 0x9    # alignment sync after 512B of trace
        if self.opts.ts:
            tss = TS_PERIODS.index(self.opts.ts)
            tracectl |= (tss << 5)
        if self.opts.cc:
            tracectl |= cmn_devmem.CMN_DTC_TRACECTRL_CC_ENABLE
        for (i, dtc) in enumerate(self.DTCs()):
            dtc.write64(cmn_devmem.CMN_DTC_TRACECTRL, tracectl)
            atid = self.opts.atid + i
            if self.opts.verbose:
                print("%s: ATID=0x%x" % (dtc, atid))
            dtc.dtc_disable()
            dtc.set_atb_traceid(atid)
            sink = self.dtc_to_sink[(dtc.CMN().cmn_seq, dtc.dtc_domain())]
            self.dtc_map[dtc] = (sink, atid)

    def trace_start(self):
        """
        Override base method, and ensure the trace sink is enabled.
        """
        self._require_active()
        self.atb_devices.enable()
        cmn_capture.TraceSession.trace_start(self)

    def collect_from_sinks(self):
        """
        Collect buffers from the ATB trace sinks, returning a (sink -> data) map.
        """
        self.atb_devices.stop()
        bufs = {}
        for s in self.sinks:
            buf = s.collect()
            if not buf:
                print("no trace captured", file=sys.stderr)
            else:
                print("%u bytes of trace captured" % (len(buf)))
            if True:
                if self.opts.verbose >= 2:
                    for (i, b) in enumerate(buf):
                        print(" %02x" % b, end="")
                        if i == 127:
                            break
                        if (i + 1) % 32 == 0:
                            print()
                    print()
            bufs[s] = buf
        return bufs


class CMNVis:
    """
    Print CMN trace in a human-readable form, one packet per line, minimizing clutter.
    """
    def __init__(self, cmns, opts):
        self.cmns = list(cmns)
        self.opts = opts
        self.id_map = cmn_capture.build_cached_cmn_id_map(self.cmns)
        if False:  # self.opts.animate:
            self.decoder = CMNAnimator(self.cmns[0])
        else:
            self.reorderer = cs_decode_cmn.CMNTraceCCReorderer(self.opts.reorder_cc_window) if self.opts.reorder_cc_window > 0 else None
        self.last_xp = None

    def new_decoder(self, C, atid):
        cfg = trace_config_from_cmn_config(C.product_config)

        def new_flit_group(cfg, **kwargs):
            return cmn_capture.CMNFlitGroupX(
                cfg, cmn_seq=C.cmn_seq, id_map=self.id_map,
                annotate_unknown=False, **kwargs)

        return cs_decode_cmn.CMNDecoder(
            cfg, id=atid, verbose=self.opts.decode_verbose,
            raw=self.opts.decode_raw, reorderer=self.reorderer,
            flit_group_factory=new_flit_group)

    def decode_atb(self, buf, atid=None, dtcs=None, dtc_atids=None):
        """
        Decode a single binary buffer containing streamed CMN trace.
        The buffer is assumed to be formatted (in the CoreSight sense).
        """
        decode_map = {}
        if dtc_atids is None:
            if dtcs is None:
                dtcs = []
                for C in self.cmns:
                    dtcs.extend(list(C.DTCs()))
            dtc_atids = []
            for (i, dtc) in enumerate(dtcs):
                stream_atid = atid if len(dtcs) == 1 else atid + i
                dtc_atids.append((dtc, stream_atid))
        decoders = []
        for (dtc, stream_atid) in dtc_atids:
            decoder = self.new_decoder(dtc.CMN(), stream_atid)
            decoders.append(decoder)
            decode_map[stream_atid] = decoder.decode(sync=(not self.opts.no_sync))
        if self.opts.decode_verbose:
            print("Decoding buffer (%u bytes, sync=%u):" % (len(buf), not self.opts.no_sync))
        cs_decode.stream_decode(buf, decode_map, verbose=self.opts.decode_verbose)
        if self.reorderer is not None:
            self.reorderer.flush()
        if decoders and all([decoder.n_sync == 0 for decoder in decoders]):
            print("warning: no alignment packets in trace stream")
            if not self.opts.no_sync:
                print(" - consider using --no-sync")
        if False and self.opts.ts:
            # Show interesting facts about the timestamp, based on what the decoder saw
            cmn_cycles_per_ts = self.opts.ts
            ts_per_second = int(self.decoder.n_timestamps / self.opts.sleep)
            print("%u timestamps seen in %g seconds, %u per second, last 0x%x" % (self.decoder.n_timestamps, self.opts.sleep, ts_per_second, self.decoder.ts_last))
            cmn_cycles_per_second = cmn_cycles_per_ts * ts_per_second
            print("CMN cycles per second: %u, i.e. %.2f MHz" % (cmn_cycles_per_second, cmn_cycles_per_second/1e6))


def report_missing_cached_atb_topology():
    print("No cached CoreSight ATB topology description is available.", file=sys.stderr)
    print("Provide one with --atb-topology FILE, or install it in the default cache.", file=sys.stderr)
    print("See docs/README-cmn-trace-atb.md for setup instructions.", file=sys.stderr)


def main(argv):
    import argparse
    parser = argparse.ArgumentParser("capture CMN trace to ATB")
    cmn_capture.add_trace_arguments(parser, cc_default=True)
    parser.set_defaults(samples=1, sleep=1.0)
    parser.add_argument("--ts", type=int, choices=set(TS_PERIODS), help="timestamp period, in cycles")
    parser.add_argument("--atid", type=int, default=32, help="ATB trace id base")
    parser.add_argument("--unformatted", action="store_true", help="don't use ATB formatting in trace buffer")
    parser.add_argument("--decode-raw", action="store_true", help="show raw packet contents")
    parser.add_argument("--reorder-cc-window", type=int, default=32, help="trace reorder window")
    default_atb_topology = coresight_atb.default_atb_topology_file()
    parser.add_argument("--atb-topology", type=str,
                        default=default_atb_topology,
                        help="CoreSight ATB topology JSON (default: %(default)s)")
    parser.add_argument("-o", "--trace-out", type=str, help="write trace buffer to file")
    parser.add_argument("-i", "--trace-in", type=str, help="read trace buffer from file")
    opts = parser.parse_args(argv)
    if opts.atb_topology == default_atb_topology and not os.path.exists(
            default_atb_topology):
        report_missing_cached_atb_topology()
        sys.exit(1)
    try:
        topology = coresight_atb.ATBTopology.from_file(opts.atb_topology)
        cmns = list(cmn_devmem.cmn_from_opts(opts))
        plan = cmn_capture.TracePlan.from_opts(cmns, opts, allow_rotation=False)
        ts = ATBTraceSession(plan, opts, topology)
    except (cmn_capture.CaptureSetupException,
            coresight_atb.ATBTopologyError) as e:
        print("%s" % e, file=sys.stderr)
        sys.exit(1)
    failed = True
    try:
        try:
            ts.activate()
        except (cmn_capture.CaptureSetupException,
                coresight_atb.ATBTopologyError) as e:
            print("%s" % e, file=sys.stderr)
            sys.exit(1)
        TV = CMNVis(ts.cmns, opts)
        if not opts.trace_in:
            ts.trace()
            time.sleep(0.1)
            bufs = ts.collect_from_sinks()
            if opts.verbose:
                print("Collected %u trace buffers" % len(bufs))
                print("  Buffer map:")
                for (dtc, (etf, dtc_atid)) in ts.dtc_map.items():
                    print("    %s: %s ATID 0x%02x" % (dtc, etf, dtc_atid))
            for (sink, buf) in bufs.items():
                if opts.verbose:
                    print("\nDecoding sink %s buffer %u bytes..." % (sink, len(buf)))
                dtc_atids = []
                for (dtc, (etf, dtc_atid)) in ts.dtc_map.items():
                    if etf == sink:
                        dtc_atids.append((dtc, dtc_atid))
                        if opts.verbose:
                            print("DTC %s has %s, ATID 0x%02x" %
                                  (dtc, etf, dtc_atid))
                if not dtc_atids:
                    if opts.verbose:
                        print("No ATID found for sink")
                    continue
                if opts.trace_out:
                    # TBD: what about multiple trace buffers?
                    with open(opts.trace_out, "wb") as f:
                        f.write(buf)
                else:
                    TV.decode_atb(buf, dtc_atids=dtc_atids)
        else:
            with open(opts.trace_in, "rb") as f:
                buf = f.read()
            TV.decode_atb(buf, opts.atid)
        failed = False
    finally:
        ts.close(suppress_errors=failed)


if __name__ == "__main__":
    main(sys.argv[1:])
