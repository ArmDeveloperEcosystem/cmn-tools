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
import copy


sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import cmn_capture
import cmn_devmem
from cmn_flits import CMNFlitGroup, trace_config_from_cmn_config


# CoreSight device management and decoding
import coresight_atb
import cs_decode
import cs_decode_cmn


TS_PERIODS = [0, 0, 0, 8192, 16384, 32768, 65536, 0]


def cmn_options(opts):
    """
    Reserve -v for progress, moving shared CMN discovery/programming detail to -vv.
    Keep the original command options unchanged for ATB progress and decoding.
    """
    detail_opts = copy.copy(opts)
    detail_opts.verbose = max(0, opts.verbose - 1)
    return detail_opts


def validate_atids(atid, n_dtcs):
    """
    Validate the complete consecutive allocation before programming any DTC.
    CoreSight trace IDs 0x00 and 0x70-0x7f are reserved (Arm CoreSight
    Architecture Specification, trace source identification).
    """
    if type(atid) not in coresight_atb.integer_types or not 1 <= atid <= 0x6f:
        raise cmn_capture.CaptureSetupException(
            "--atid must be an integer from 1 to 111 (0x01-0x6f)")
    if n_dtcs > 0x70 - atid:
        raise cmn_capture.CaptureSetupException(
            "--atid %u with %u DTCs exceeds trace ID 111 (0x6f)" %
            (atid, n_dtcs))


class ATBTraceSession(cmn_capture.TraceSession):
    """
    Manage a trace session to CoreSight ATB

    Construction retains the validated plan and topology without accessing
    devices. activate() prepares CMN, configures the CoreSight paths and
    assigns DTC trace IDs. Retain the device manager before configuring it,
    so that the session owns it even if configuration fails partway through.

    trace_start() enables sinks before CMN trace generation. collect_from_sinks()
    requests sink flushes, draining software FIFOs before stopping forwarding.
    Software FIFO sinks retain the first buffer and defer final disable to close().
    The caller must close the session in a finally block covering activation,
    capture, collection and decoding; main() demonstrates this. Cleanup leaves
    DTCs enabled, but does not restore prior CoreSight or watchpoint settings.
    """
    def __init__(self, plan, opts, topology):
        validate_atids(opts.atid, 0)
        if plan.dtms_rotating:
            raise cmn_capture.NotEnoughWatchpoints("ATB capture cannot rotate watchpoints")
        cmn_capture.TraceSession.__init__(self, plan, cmn_options(opts), atb=True)
        self.verbose = opts.verbose
        self.topology = topology
        self.atb_devices = None
        self.dtc_to_sink = {}    # (cmn_seq, dtc#) -> sink
        self.dtc_map = {}        # DTC -> (sink, atid)
        self.sinks = []
        self._dtcs = None
        self._atb_paths_enabled = False

    def DTCs(self):
        if self._dtcs is None:
            return cmn_capture.TraceSession.DTCs(self)
        return iter(self._dtcs)

    def activate(self, init=True):
        if self._closed or self._activation_started:
            raise RuntimeError("trace session is closed or already activated")
        # Reuse this discovery for path setup and ID programming; validating
        # the allocation does not require any additional device reads.
        self._dtcs = list(self.DTCs())
        validate_atids(self.opts.atid, len(self._dtcs))
        coresight_atb.progress(self.verbose, "Preparing CMN trace devices and watchpoints...")
        cmn_capture.TraceSession.activate(self, init=init)
        coresight_atb.progress(self.verbose, "CMN trace devices prepared")
        self._activated = False    # Not ready to start until the ATB path is ready.
        if self.verbose:
            system_name = self.topology.system.get("name", "unspecified")
            coresight_atb.progress(self.verbose, "ATB topology: %s (%s)" %
                                  (self.topology.filename, system_name))
            if self.topology.capture_name is not None:
                coresight_atb.progress(self.verbose, "ATB capture option: %s" % self.topology.capture_name)
        coresight_atb.progress(self.verbose, "Configuring ATB devices and trace sinks...")
        self.configure_atb_sinks()
        coresight_atb.progress(self.verbose, "ATB devices configured; assigning CMN trace IDs...")
        self.configure_dtcs_for_atb()
        self._activated = True
        coresight_atb.progress(self.verbose, "CMN/ATB capture setup complete")

    def _close_output(self):
        if self.atb_devices is not None:
            self.atb_devices.close()

    def configure_atb_sinks(self):
        dtcs = list(self.DTCs())
        source_for_dtc = {}
        for dtc in dtcs:
            source_for_dtc[dtc] = self.topology.source_id_for_dtc(dtc)
        self.atb_devices = coresight_atb.ATBDeviceManager(
            self.topology, list(source_for_dtc.values()),
            formatting=(not self.opts.unformatted),
            verbose=self.verbose, checking=True,
            open_all_ports=self.opts.atb_open_all_ports,
            diagnostics=self.opts.atb_diagnostics,
            etr_buffer_size=self.opts.etr_buffer_size,
            circular=self.opts.circular)
        self.atb_devices.configure()
        self.sinks = self.atb_devices.sinks
        for dtc in dtcs:
            sid = source_for_dtc[dtc]
            key = (dtc.CMN().cmn_seq, dtc.dtc_domain())
            self.dtc_to_sink[key] = self.atb_devices.sink_for_source[sid]

    def configure_dtcs_for_atb(self):
        """
        Assign consecutive, non-reserved ATIDs to all DTCs in this session.
        """
        dtcs = list(self.DTCs())
        validate_atids(self.opts.atid, len(dtcs))
        tracectl = 0x9    # alignment sync after 512B of trace
        if self.opts.ts:
            tss = TS_PERIODS.index(self.opts.ts)
            tracectl |= (tss << 5)
        if self.opts.cc:
            tracectl |= cmn_devmem.CMN_DTC_TRACECTRL_CC_ENABLE
        for (i, dtc) in enumerate(dtcs):
            dtc.write64(cmn_devmem.CMN_DTC_TRACECTRL, tracectl)
            atid = self.opts.atid + i
            if self.verbose >= 2:
                print("%s: ATID=0x%x" % (dtc, atid))
            dtc.dtc_disable()
            dtc.set_atb_traceid(atid)
            sink = self.dtc_to_sink[(dtc.CMN().cmn_seq, dtc.dtc_domain())]
            self.dtc_map[dtc] = (sink, atid)

    def trace_start(self, dtcs=None):
        """
        Override base method, and ensure the trace sink is enabled.
        """
        self._require_active()
        if not self._atb_paths_enabled:
            coresight_atb.progress(self.verbose, "Enabling ATB trace sinks and forwarding paths...")
            self.atb_devices.enable()
            self._atb_paths_enabled = True
        coresight_atb.progress(self.verbose, "ATB paths enabled; starting CMN trace...")
        cmn_capture.TraceSession.trace_start(self, dtcs=dtcs)
        coresight_atb.progress(self.verbose, "CMN trace started")

    def trace_stop(self, suppress_errors=False, dtcs=None):
        was_running = self.any_DTCs_running()
        if was_running:
            coresight_atb.progress(self.verbose, "Stopping CMN trace...")
        if was_running and self.opts.atb_diagnostics:
            print("CMN trace stop: requesting DTC disable, then DTM disable before "
                  "ETF flush. Upstream components must still complete the ATB "
                  "flush handshake; source clocks and handshake signals are not read.",
                  file=sys.stderr)
        cmn_capture.TraceSession.trace_stop(self, suppress_errors=suppress_errors, dtcs=dtcs)
        if was_running and not suppress_errors:
            coresight_atb.progress(self.verbose, "CMN trace stopped")

    def collect_from_sinks(self):
        """
        Collect buffers from the ATB trace sinks, returning a (sink -> data) map.
        """
        coresight_atb.progress(self.verbose, "Flushing and stopping ATB trace sinks...")
        stop_failed = False
        try:
            self.atb_devices.stop()
        except coresight_atb.ATBReadyTimeout as error:
            # A forwarding FIFO timeout must not hide trace already in a sink.
            # Circular ETF collection still requires a successful handshake.
            recoverable_sinks = [s for s in self.sinks if isinstance(s, coresight_atb.ETR) or
                                 (isinstance(s, coresight_atb.ETF) and
                                  s.mode == coresight_atb.TMC_MODE_SOFTWARE_FIFO and s._readback_pending)]
            if not recoverable_sinks:
                raise
            stop_failed = True
            coresight_atb.progress(1, "WARNING: %s; attempting buffer collection despite "
                                  "the ATB stop timeout" % error)
        finally:
            self._atb_paths_enabled = False
        coresight_atb.progress(self.verbose, "ATB stop attempts complete; collecting trace buffers...")
        bufs = {}
        for s in self.sinks:
            if stop_failed and s not in recoverable_sinks:
                coresight_atb.progress(1, "Skipping circular ETF readback after ATB stop timeout")
                continue
            buf = s.collect()
            if not buf:
                print("no trace captured", file=sys.stderr)
            else:
                print("%u bytes of trace captured" % (len(buf)))
            if True:
                if self.verbose >= 3:
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
    parser = argparse.ArgumentParser("capture CMN trace to ATB",
                                     epilog="-v reports major capture stages; -vv adds CMN/DTM and "
                                            "ATB path detail; -vvv adds buffer and status dumps.")
    cmn_capture.add_trace_arguments(parser, cc_default=True)
    parser.set_defaults(samples=1, sleep=1.0)
    parser.add_argument("--ts", type=int, choices=set(TS_PERIODS), help="timestamp period, in cycles")
    parser.add_argument("--atid", type=int, default=32,
                        help="ATB trace ID base (1-111); all consecutive DTC IDs must fit")
    parser.add_argument("--unformatted", action="store_true",
                        help="don't use ATB formatting in trace buffer (requires --circular)")
    parser.add_argument("--circular", action="store_true",
                        help="overwrite old trace when capture buffers fill; default: software FIFO "
                             "stops accepting data when full, retaining the earliest trace")
    parser.add_argument("--etr-buffer-size", type=lambda s: int(s, 0),
                        default=coresight_atb.DEFAULT_ETR_BUFFER_SIZE, metavar="BYTES",
                        help="RAM buffer bytes per ETR, decimal or 0x hex (default: %(default)s, "
                             "minimum 512 in software FIFO mode); "
                             "requires contiguous RAM, PFN access, AArch64 Linux and cc")
    parser.add_argument("--decode-raw", action="store_true", help="show raw packet contents")
    parser.add_argument("--reorder-cc-window", type=int, default=32, help="trace reorder window")
    default_atb_topology = coresight_atb.default_atb_topology_file()
    parser.add_argument("--atb-topology", type=str,
                        default=default_atb_topology,
                        help="CoreSight ATB topology JSON (default: %(default)s)")
    parser.add_argument("--atb-capture", metavar="NAME",
                        help="named capture option (default: captures, otherwise first option)")
    parser.add_argument("--atb-open-all-ports", action="store_true",
                        help="debug ATB connectivity by opening all funnel inputs and replicator "
                             "outputs on selected paths; may admit other trace streams or stall trace")
    parser.add_argument("--atb-reset-only", action="store_true",
                        help="discard existing trace and reset the selected CMN/ATB paths, "
                             "then exit without capturing")
    parser.add_argument("--atb-diagnostics", action="store_true",
                        help="explain ETF waits and report routes on timeout; additionally "
                             "read CTL, STS, MODE, FFSR, FFCR and ITCTRL once on the failing ETF")
    parser.add_argument("-o", "--trace-out", type=str, help="write trace buffer to file")
    parser.add_argument("-i", "--trace-in", type=str, help="read trace buffer from file")
    opts = parser.parse_args(argv)
    try:
        validate_atids(opts.atid, 0)
        coresight_atb.validate_etr_buffer_size(opts.etr_buffer_size, circular=opts.circular)
        if opts.unformatted and not opts.circular:
            raise ValueError("--unformatted requires --circular; software FIFO mode requires formatting")
    except (cmn_capture.CaptureSetupException, ValueError) as e:
        parser.error(str(e))
    if opts.atb_topology == default_atb_topology and not os.path.exists(
            default_atb_topology):
        report_missing_cached_atb_topology()
        sys.exit(1)
    try:
        coresight_atb.progress(opts.verbose, "Loading ATB topology: %s" % opts.atb_topology)
        topology = coresight_atb.ATBTopology.from_file(
            opts.atb_topology, capture=opts.atb_capture)
        detail_opts = cmn_options(opts)
        coresight_atb.progress(opts.verbose, "Discovering CMN devices...")
        cmns = list(cmn_devmem.cmn_from_opts(detail_opts))
        coresight_atb.progress(opts.verbose, "CMN discovery complete; planning trace capture...")
        plan = cmn_capture.TracePlan.from_opts(cmns, detail_opts, allow_rotation=False)
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
        if opts.atb_reset_only:
            print("Selected CMN/ATB paths reset and disabled.")
            failed = False
            return
        TV = CMNVis(ts.cmns, opts)
        if not opts.trace_in:
            ts.trace()
            time.sleep(0.1)
            bufs = ts.collect_from_sinks()
            coresight_atb.progress(opts.verbose, "Collected %u trace buffers" % len(bufs))
            if opts.verbose >= 2:
                print("  Buffer map:")
                for (dtc, (etf, dtc_atid)) in ts.dtc_map.items():
                    print("    %s: %s ATID 0x%02x" % (dtc, etf, dtc_atid))
            for (sink, buf) in bufs.items():
                if opts.verbose >= 2:
                    print("\nDecoding sink %s buffer %u bytes..." % (sink, len(buf)))
                dtc_atids = []
                for (dtc, (etf, dtc_atid)) in ts.dtc_map.items():
                    if etf == sink:
                        dtc_atids.append((dtc, dtc_atid))
                        if opts.verbose >= 2:
                            print("DTC %s has %s, ATID 0x%02x" %
                                  (dtc, etf, dtc_atid))
                if not dtc_atids:
                    if opts.verbose >= 2:
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
    except (coresight_atb.ATBDeviceError, OSError, ValueError) as e:
        print("%s" % e, file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            ts.close(suppress_errors=failed)
        except (coresight_atb.ATBDeviceError, OSError, ValueError) as e:
            print("ATB cleanup failed: %s" % e, file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
