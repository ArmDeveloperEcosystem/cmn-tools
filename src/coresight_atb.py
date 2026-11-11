#!/usr/bin/python

"""
CoreSight ATB topology loading and device management.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import print_function

import json
import os
import struct
import sys
import time

import app_data
import csscan
import csbuffer

TMC_MODE_CIRCULAR = 0
TMC_MODE_SOFTWARE_FIFO = 1
TMC_MODE_HARDWARE_FIFO = 2
TMC_MODE_SOFTWARE_FIFO_2 = 3
TMC_SOFTWARE_FIFO_MODES = (TMC_MODE_SOFTWARE_FIFO, TMC_MODE_SOFTWARE_FIFO_2)
DEFAULT_ETR_BUFFER_SIZE = 2 * 1024 * 1024

# Keep RAM referenced if an ETR cannot be confirmed disabled after an error.
# Releasing it while the device can still write would expose unrelated memory.
_active_etr_buffers = []


def progress(verbose, message):
    """
    Flush major events before operations which may stall on device access.
    Messages must use known values, without additional diagnostic device reads.
    """
    if verbose:
        print(message, file=sys.stderr)
        sys.stderr.flush()


try:
    string_types = (basestring,)
    integer_types = (int, long)
except NameError:
    string_types = (str,)
    integer_types = (int,)


def default_atb_topology_file():
    return os.path.join(app_data.home_dir(), ".cache", "arm", "cmn-coresight-atb.json")


class ATBTopologyError(ValueError):
    pass


class ATBDeviceError(RuntimeError):
    pass


class ATBReadyTimeout(ATBDeviceError):
    """
    A TMC status poll timed out; register access itself did not fail.
    """
    pass


def validate_etr_buffer_size(size, circular=True):
    """
    Check RSZ limits and formatter alignment before allocating or accessing devices.
    SoC-600 TRM (100806 r4p0), section 9.15.2, RSZ and DBALO.
    """
    if type(size) not in integer_types or size < 16 or size > (1 << 32) or size % 16:
        raise ValueError("ETR buffer size must be a multiple of 16 bytes from 16 to 4 GiB")
    if not circular and size < 512:
        raise ValueError("ETR software FIFO requires at least 512 bytes; use --circular for smaller buffers")


def _check_object(obj, required, optional, where):
    if not isinstance(obj, dict):
        raise ATBTopologyError("%s must be an object" % where)
    missing = set(required) - set(obj.keys())
    if missing:
        raise ATBTopologyError("%s is missing %s" %
                               (where, ", ".join(sorted(missing))))
    unexpected = set(obj.keys()) - set(required) - set(optional)
    if unexpected:
        raise ATBTopologyError("%s has unexpected properties: %s" %
                               (where, ", ".join(sorted(unexpected))))


def _check_identifier(value, where):
    if not isinstance(value, string_types) or not value:
        raise ATBTopologyError("%s must be a non-empty string" % where)
    if not value[0].isalpha():
        raise ATBTopologyError("%s must start with a letter" % where)
    for c in value:
        if not (c.isalnum() or c in "_.-"):
            raise ATBTopologyError("%s contains invalid character %r" %
                                   (where, c))


def _check_nonnegative_integer(value, where):
    if type(value) not in integer_types or value < 0:
        raise ATBTopologyError("%s must be a non-negative integer" % where)


def _parse_hex(value, where):
    if not isinstance(value, string_types) or not value.startswith("0x"):
        raise ATBTopologyError("%s must be a hexadecimal string" % where)
    try:
        return int(value, 16)
    except ValueError:
        raise ATBTopologyError("%s is not a valid hexadecimal address: %s" %
                               (where, value))


class ATBTopology:
    """
    CoreSight ATB devices and links supplementing discovered CMN DTCs.

    All capture options are validated against the same devices and links.
    captures and paths describe the selected option. With no explicit name,
    use top-level captures if present, otherwise the first named option.
    """
    DEVICE_TYPES = ["funnel", "replicator", "tmc-etf", "tmc-etr",
                    "tmc-etb", "etb", "tpiu", "atb-bridge"]

    def __init__(self, data, filename=None, capture=None):
        self.filename = filename
        _check_object(data, ["version", "sources", "devices", "links"],
                      ["system", "generator", "captures", "capture_options"],
                      "topology")
        if "captures" not in data and "capture_options" not in data:
            raise ATBTopologyError("topology requires captures or capture_options")
        if type(data["version"]) not in integer_types or data["version"] != 1:
            raise ATBTopologyError("unsupported topology version: %s" %
                                   data["version"])
        self.system = data.get("system", {})
        _check_object(self.system, [], ["name", "description"], "system")
        if "name" in self.system and not isinstance(self.system["name"], string_types):
            raise ATBTopologyError("system.name must be a string")
        if "description" in self.system and not isinstance(
                self.system["description"], string_types):
            raise ATBTopologyError("system.description must be a string")
        if "generator" in data and not isinstance(data["generator"], string_types):
            raise ATBTopologyError("generator must be a string")
        self.sources = {}
        self.source_by_dtc = {}
        self.devices = {}
        self.device_by_address = {}
        self.links = []
        self.edges = {}
        self.capture_options = {}
        self._load_sources(data["sources"])
        self._load_devices(data["devices"])
        self._load_links(data["links"])
        selected = None
        if "captures" in data:
            selected = self._load_captures(data["captures"], "captures")
        if "capture_options" in data:
            self._check_array(data["capture_options"], "capture_options")
            for i, option in enumerate(data["capture_options"]):
                where = "capture_options[%u]" % i
                _check_object(option, ["name", "captures"], ["description"], where)
                name = option["name"]
                _check_identifier(name, where + ".name")
                if name in self.capture_options:
                    raise ATBTopologyError("duplicate capture option name: %s" % name)
                if "description" in option and not isinstance(
                        option["description"], string_types):
                    raise ATBTopologyError("%s.description must be a string" % where)
                option = dict(option)
                option.update(self._load_captures(option["captures"], where + ".captures"))
                self.capture_options[name] = option
                if selected is None:
                    selected = option
        if capture is not None:
            _check_identifier(capture, "capture option name")
            if capture not in self.capture_options:
                available = ", ".join(sorted(self.capture_options)) or "none"
                raise ATBTopologyError("unknown capture option %s; available: %s" %
                                       (capture, available))
            selected = self.capture_options[capture]
        self.capture_name = selected.get("name")
        self.captures = selected["captures"]
        self.paths = selected["paths"]

    @classmethod
    def from_file(cls, filename, capture=None):
        try:
            with open(filename) as f:
                data = json.load(f)
        except (IOError, ValueError) as e:
            raise ATBTopologyError("cannot load ATB topology %s: %s" %
                                   (filename, e))
        return cls(data, filename=filename, capture=capture)

    def _check_array(self, value, where):
        if not isinstance(value, list) or not value:
            raise ATBTopologyError("%s must be a non-empty array" % where)

    def _load_sources(self, sources):
        self._check_array(sources, "sources")
        for (i, source) in enumerate(sources):
            where = "sources[%u]" % i
            _check_object(source, ["id", "cmn_instance", "dtc_domain"],
                          ["cmn_base", "description"], where)
            source = dict(source)
            sid = source["id"]
            _check_identifier(sid, where + ".id")
            if sid in self.sources:
                raise ATBTopologyError("duplicate source id: %s" % sid)
            _check_nonnegative_integer(source["cmn_instance"],
                                       where + ".cmn_instance")
            _check_nonnegative_integer(source["dtc_domain"],
                                       where + ".dtc_domain")
            if source["dtc_domain"] > 3:
                raise ATBTopologyError("%s.dtc_domain must be at most 3" % where)
            if "cmn_base" in source:
                source["cmn_base_value"] = _parse_hex(source["cmn_base"],
                                                        where + ".cmn_base")
            key = (source["cmn_instance"], source["dtc_domain"])
            if key in self.source_by_dtc:
                raise ATBTopologyError("duplicate CMN DTC source: CMN%u DTC%u" % key)
            self.sources[sid] = source
            self.source_by_dtc[key] = sid

    def _load_devices(self, devices):
        self._check_array(devices, "devices")
        for (i, device) in enumerate(devices):
            where = "devices[%u]" % i
            _check_object(device, ["id", "type", "address"],
                          ["part_number", "input_ports", "output_ports",
                           "buffer", "description"], where)
            device = dict(device)
            did = device["id"]
            _check_identifier(did, where + ".id")
            if did in self.devices:
                raise ATBTopologyError("duplicate device id: %s" % did)
            if not isinstance(device["type"], string_types) or \
                    device["type"] not in self.DEVICE_TYPES:
                raise ATBTopologyError("%s has unsupported device type: %s" %
                                       (where, device["type"]))
            address = _parse_hex(device["address"], where + ".address")
            if address in self.device_by_address:
                raise ATBTopologyError("duplicate device address: 0x%x" % address)
            device["address_value"] = address
            if "part_number" in device:
                device["part_number_value"] = _parse_hex(
                    device["part_number"], where + ".part_number")
            for name in ["input_ports", "output_ports"]:
                if name in device:
                    _check_nonnegative_integer(device[name], where + "." + name)
                    if device[name] == 0:
                        raise ATBTopologyError("%s.%s must be positive" %
                                               (where, name))
            if device["type"] == "replicator":
                # The programmable Arm ATB replicator has one input and
                # two outputs (CoreSight SoC-400 TRM, section 3.5).
                for name, count in [("input_ports", 1), ("output_ports", 2)]:
                    if device.get(name, count) != count:
                        raise ATBTopologyError("%s.%s must be %u for a replicator" %
                                               (where, name, count))
                    device[name] = count
            self.devices[did] = device
            self.device_by_address[address] = did

    def _endpoint(self, endpoint, where, allow_source):
        if not isinstance(endpoint, dict):
            raise ATBTopologyError("%s must be an object" % where)
        if set(endpoint.keys()) == set(["source"]):
            if not allow_source:
                raise ATBTopologyError("%s must be a device endpoint" % where)
            sid = endpoint["source"]
            _check_identifier(sid, where + ".source")
            if sid not in self.sources:
                raise ATBTopologyError("%s references unknown source: %s" %
                                       (where, sid))
            return ("source", sid)
        _check_object(endpoint, ["device"], ["port"], where)
        did = endpoint["device"]
        _check_identifier(did, where + ".device")
        if did not in self.devices:
            raise ATBTopologyError("%s references unknown device: %s" %
                                   (where, did))
        if "port" in endpoint:
            _check_nonnegative_integer(endpoint["port"], where + ".port")
        else:
            device = self.devices[did]
            direction = "output" if allow_source else "input"
            # Funnel input counts must be declared to infer a single input.
            # Other devices have one port unless their descriptor says otherwise.
            default_count = 1
            if direction == "input" and device["type"] == "funnel":
                default_count = None
            if device.get(direction + "_ports", default_count) != 1:
                raise ATBTopologyError("%s.port is required for a device with multiple %s ports" %
                                       (where, direction))
        return ("device", did)

    def _load_links(self, links):
        self._check_array(links, "links")
        seen = set()
        for (i, link) in enumerate(links):
            where = "links[%u]" % i
            _check_object(link, ["from", "to"], [], where)
            source = self._endpoint(link["from"], where + ".from", True)
            target = self._endpoint(link["to"], where + ".to", False)
            # Normalize implicit port zero without modifying the
            # caller's descriptor. Path consumers always see explicit ports.
            link = {"from": dict(link["from"]), "to": dict(link["to"])}
            if source[0] == "device":
                link["from"].setdefault("port", 0)
            link["to"].setdefault("port", 0)
            edge = (source, link["from"].get("port"),
                    target, link["to"]["port"])
            if edge in seen:
                raise ATBTopologyError("duplicate ATB link at %s" % where)
            seen.add(edge)
            self._check_port(link["from"], "output_ports", where + ".from")
            self._check_port(link["to"], "input_ports", where + ".to")
            self.links.append(link)
            self.edges.setdefault(source, []).append((target, link))

    def _check_port(self, endpoint, count_name, where):
        if "device" not in endpoint:
            return
        device = self.devices[endpoint["device"]]
        if count_name in device and endpoint["port"] >= device[count_name]:
            raise ATBTopologyError("%s port %u is outside %s %s" %
                                   (where, endpoint["port"], device["id"],
                                    count_name))

    def _load_captures(self, captures, where):
        self._check_array(captures, where)
        capture_map = {}
        paths = {}
        for (i, capture) in enumerate(captures):
            entry = "%s[%u]" % (where, i)
            _check_object(capture, ["source", "sink"], ["description"], entry)
            sid = capture["source"]
            sink = capture["sink"]
            _check_identifier(sid, entry + ".source")
            _check_identifier(sink, entry + ".sink")
            if "description" in capture and not isinstance(
                    capture["description"], string_types):
                raise ATBTopologyError("%s.description must be a string" % entry)
            if sid not in self.sources:
                raise ATBTopologyError("%s references unknown source: %s" %
                                       (entry, sid))
            if sink not in self.devices:
                raise ATBTopologyError("%s references unknown sink: %s" %
                                       (entry, sink))
            if sid in capture_map:
                raise ATBTopologyError("%s: source has multiple capture sinks: %s" %
                                       (where, sid))
            path = self._find_path(("source", sid), ("device", sink))
            if path is None:
                raise ATBTopologyError("%s: no ATB path from %s to %s" % (entry, sid, sink))
            capture_map[sid] = sink
            paths[sid] = path
        return {"captures": capture_map, "paths": paths}

    def _find_path(self, source, sink):
        paths = []

        def walk(node, seen, path):
            if len(paths) > 1:
                return
            if node == sink:
                paths.append(list(path))
                return
            for (target, link) in self.edges.get(node, []):
                if target in seen:
                    continue
                walk(target, seen | set([target]), path + [link])

        walk(source, set([source]), [])
        if len(paths) > 1:
            raise ATBTopologyError("multiple ATB paths from %s to %s" %
                                   (source[1], sink[1]))
        return paths[0] if paths else None

    def source_id_for_dtc(self, dtc):
        key = (dtc.CMN().cmn_seq, dtc.dtc_domain())
        sid = self.source_by_dtc.get(key)
        if sid is None:
            raise ATBTopologyError("no ATB topology source for CMN%u DTC%u" % key)
        source = self.sources[sid]
        if "cmn_base_value" in source:
            if source["cmn_base_value"] != dtc.CMN().periphbase:
                raise ATBTopologyError(
                    "%s CMN base is 0x%x, discovered 0x%x" %
                    (sid, source["cmn_base_value"], dtc.CMN().periphbase))
        if sid not in self.captures:
            raise ATBTopologyError("no capture sink selected for source %s" % sid)
        return sid


def _format_endpoint(endpoint):
    if "source" in endpoint:
        return endpoint["source"]
    return "%s:%u" % (endpoint["device"], endpoint["port"])


def format_topology(topology):
    """
    Return a compact, deterministic description of an ATB topology.
    """
    lines = []
    system_name = topology.system.get("name")
    if system_name:
        lines.append("System: %s" % system_name)
    if topology.filename:
        lines.append("File: %s" % topology.filename)
    if topology.capture_options:
        lines.append("Capture options: %s" % ", ".join(sorted(topology.capture_options)))
        lines.append("Selected capture: %s" %
                     (topology.capture_name or "captures (default)"))

    lines.append("Devices:")
    for did in sorted(topology.devices):
        device = topology.devices[did]
        description = "  %s: %s at %s" % (
            did, device["type"], device["address"])
        if "part_number" in device:
            description += " (part %s)" % device["part_number"]
        lines.append(description)

    lines.append("Capture paths:")
    source_ids = sorted(
        topology.captures,
        key=lambda sid: (topology.sources[sid]["cmn_instance"],
                         topology.sources[sid]["dtc_domain"], sid))
    for sid in source_ids:
        source = topology.sources[sid]
        edges = []
        for link in topology.paths[sid]:
            edge = "%s -> %s" % (
                _format_endpoint(link["from"]),
                _format_endpoint(link["to"]))
            did = link["to"]["device"]
            if topology.devices[did]["type"] == "tmc-etf" or \
                    (topology.devices[did]["type"] == "tmc-etr" and
                     did == topology.captures[sid]):
                mode = ("capture sink" if did == topology.captures[sid]
                        else "hardware FIFO")
                edge += " (%s)" % mode
            edges.append(edge)
        lines.append("  CMN%u DTC%u (%s): %s" % (
            source["cmn_instance"], source["dtc_domain"], sid,
            "; ".join(edges)))
    return "\n".join(lines)


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(
        description="validate and display a CMN CoreSight ATB topology")
    parser.add_argument(
        "--atb-topology", default=default_atb_topology_file(),
        help="topology JSON file (default: %(default)s)")
    parser.add_argument("--atb-capture", metavar="NAME",
                        help="named capture option (default: captures, otherwise first option)")
    opts = parser.parse_args(argv)
    try:
        topology = ATBTopology.from_file(opts.atb_topology, capture=opts.atb_capture)
    except ATBTopologyError as e:
        print("%s" % e, file=sys.stderr)
        return 1
    print(format_topology(topology))
    return 0


class ETF:

    def __init__(self, etf, verbose=0, diagnostics=False):
        self.etf = etf
        self.verbose = verbose
        self.diagnostics = diagnostics
        self.name = None
        self.mode = None
        self.diagnostic_context = None
        self._history = []
        self._manual_flush_attempted = False
        self._flush_complete = False
        self._readback_pending = False
        self._needs_disable = False
        self.capture_incomplete = False
        self._fifo_data = None
        self._fifo_capacity = None
        self._fifo_total = 0
        self._fifo_offset = 0

    def __str__(self):
        return "ETF %s%s" % (self.etf, " (%s)" % self.name if self.name else "")

    def _diagnostic(self, message):
        if self.diagnostics:
            print("%s: %s" % (self, message), file=sys.stderr)

    def _record_action(self, message):
        """
        Retain recent actions for failure reports without additional device reads.
        """
        self._history.append(message)
        if len(self._history) > 32:
            del self._history[0]

    def enable(self):
        self._flush_complete = False
        self._readback_pending = False
        self.capture_incomplete = False
        if self.verbose >= 3:
            csbuffer.sink_show_status(self.etf, title="before ETF configuration")
        if self.is_enabled():
            raise ATBDeviceError("%s: cannot start with CTL.TraceCaptEn=1" % self)
        self._record_action("observed CTL.TraceCaptEn=0 before checking "
                            "TMCReady for capture enable")
        self._wait_ready("before capture enable")
        self.etf.write32(0x014, 0, check=True)   # set read-pointer (RRP) to start
        self.etf.write32(0x018, 0, check=True)   # set write-pointer (RWP) to start
        if self.verbose >= 3:
            csbuffer.sink_show_status(self.etf, title="after ETF configuration, before CMN trace enable")
        if self.mode == TMC_MODE_SOFTWARE_FIFO:
            self._needs_disable = True
        self.etf.write32(0x020, 0x01)            # start ETF collecting
        self._record_action("CTL.TraceCaptEn=1 write returned (start capture)")
        return self

    def disable(self):
        """
        Request a capture sink flush before its forwarding path is closed.

        Arm DDI 0461B, sections 2.2.1 and 2.2.2: wait for TMCReady before
        reading a circular buffer or disabling upstream hardware FIFOs.
        Drain software FIFOs during the wait to make room for the flush tail.
        Retain at most one buffer of trace, discarding any excess while draining.
        Limit status polling to 100 reads, separated by 10ms pauses.
        """
        self._flush_complete = False
        if not self.is_enabled():
            # A partial start may never have enabled this sink. Recover its
            # disabled state without issuing an ineffective manual flush.
            return self.stop()
        self._manual_flush_attempted = True
        self._record_action("attempted manual flush: set FFCR.FlushMan=1; "
                            "wait target was Stopped (CTL=1, STS.TMCReady=1)")
        self.etf.set32(0x304, 0x40, check=False)     # Request manual flush
        self._record_action("FFCR.FlushMan write returned; no readback check")
        if self.mode in TMC_SOFTWARE_FIFO_MODES:
            # DDI 0461B section 2.2.1: a full software FIFO cannot reach
            # Stopped until software reads data and makes room for the tail.
            # Keep forwarding enabled until the flush tail has also drained.
            self._fifo_data = bytearray()
            self._fifo_capacity = None
            self._fifo_total = 0
            self._fifo_offset = 0
            try:
                self._wait_ready("after software FIFO flush", drain_fifo=True)
                self._flush_complete = True
                progress(self.verbose, "%s: software FIFO flush complete; retained %u bytes, "
                         "discarded %u excess bytes" %
                         (self.name or "TMC", len(self._fifo_data),
                          self._fifo_total - len(self._fifo_data)))
            except ATBReadyTimeout as error:
                self.capture_incomplete = True
                progress(1, "%s: WARNING: %s; preserving %u bytes of incomplete software FIFO "
                         "trace before forced upstream disable" %
                         (self.name or "TMC", error, len(self._fifo_data)))
            self._readback_pending = True
            return self
        self._wait_ready("after flush; trace may be incomplete")
        self._flush_complete = True
        if self.verbose >= 3:
            csbuffer.sink_show_status(self.etf, title="after trace enable, before collection")
        return self

    def _wait_ready(self, reason, drain_fifo=False):
        """
        Bound device reads while waiting for a TMC state transition.
        """
        started = time.time()
        first_status = None
        for attempt in range(100):
            status = self.etf.read32(0x00C)
            if first_status is None:
                first_status = status
            if drain_fifo:
                self._drain_fifo(status)
            if status & 0x04:
                self._record_action("wait %s: TMCReady=1 at poll %u/100; STS=0x%08x" %
                                    (reason, attempt + 1, status))
                return True
            if attempt < 99:
                time.sleep(0.01)
        self._record_action("wait %s: TMCReady=0 throughout 100 polls over %.3fs; "
                            "first STS=0x%08x, last STS=0x%08x; 10ms between polls" %
                            (reason, time.time() - started, first_status, status))
        if self.diagnostics:
            self._diagnostic("POST-MORTEM: STS.TMCReady was not observed as 1 %s. "
                             "Evidence below was captured before further cleanup writes." % reason)
            self._diagnostic("recent ETF actions in this process (oldest first, up to 32 entries):")
            for action in self._history:
                self._diagnostic("  %s" % action)
            # Diagnostic failures must not replace the timeout or prevent cleanup.
            try:
                self._timeout_diagnostics()
            except Exception as error:
                self._diagnostic("could not interpret ETF snapshot: %s" % error)
            if self.diagnostic_context is not None:
                try:
                    self.diagnostic_context()
                except Exception as error:
                    self._diagnostic("could not report ATB paths: %s" % error)
        raise ATBReadyTimeout("%s: timed out waiting for STS.TMCReady %s "
                             "(last STS=0x%08x)%s" %
                             (self, reason, status, "" if self.diagnostics else
                              "; use --atb-diagnostics for ETF and path details"))

    def _timeout_diagnostics(self):
        """
        Read only the six diagnostic registers on this ETF, once per timeout.

        SoC-600 TRM (100806 r4p0), sections 4.8.1 and 4.8.4 and the ETF
        FFSR/FFCR register descriptions define access conditions and states.
        AMBA ATB IHI 0032B sections 4.2 and 4.4 distinguish flush from SYNCREQ.
        Never read buffer RAM or pointers here, or enter integration mode.
        """
        self._diagnostic("ETF snapshot (sequential reads, not an atomic sample):")
        values = {}
        for name, offset in [("ITCTRL", 0xf00), ("CTL", 0x020), ("STS", 0x00c),
                             ("MODE", 0x028), ("FFSR", 0x300), ("FFCR", 0x304)]:
            try:
                value = self.etf.read32(offset)
                values[name] = value
                self._diagnostic("  %s[0x%03x]=0x%08x" % (name, offset, value))
            except Exception as error:
                self._diagnostic("  %s[0x%03x]: read failed: %s" % (name, offset, error))
        if self._manual_flush_attempted:
            self._diagnostic("the manual flush write attempted an AFVALID/AFREADY flush "
                             "handshake, not a SYNCREQ pulse; completion required "
                             "upstream trace draining/acknowledgement and ETF data writes")
        else:
            self._diagnostic("no manual flush was issued to this ETF by this process; "
                             "the recovery action was CTL disable, not a new "
                             "AFVALID flush or SYNCREQ request")
        if "ITCTRL" not in values or values["ITCTRL"] & 1:
            self._diagnostic("normal-operation interpretation unavailable: "
                             "ITCTRL.IME is unknown or 1 (integration mode)")
            return
        enabled = None if "CTL" not in values else bool(values["CTL"] & 1)
        ready = None if "STS" not in values else bool(values["STS"] & 4)
        if enabled is not None and ready is not None:
            state = {(False, False): "Disabling", (False, True): "Disabled",
                     (True, False): "Running/Stopping", (True, True): "Stopped"}
            self._diagnostic("observed %s: TraceCaptEn=%u, TMCReady=%u" %
                             (state[(enabled, ready)], enabled, ready))
            if ready:
                self._diagnostic("TMCReady became 1 after polling ended; "
                                 "the timeout snapshot shows a later state")
            elif not enabled:
                self._diagnostic("forced disable has not completed; clearing CTL "
                                 "is not a platform reset and cannot cancel an "
                                 "ATB flush already issued")
        if "STS" in values and enabled:
            self._diagnostic("STS.FtEmpty=%u, STS.Empty=%u (formatter and buffer)" %
                             ((values["STS"] >> 3) & 1, (values["STS"] >> 4) & 1))
            if ready is False and not values["STS"] & 8:
                self._diagnostic("FtEmpty=0: capture/formatter completion has not "
                                 "been reported; upstream flushing or internal "
                                 "data writes may still be pending")
        elif enabled is not True:
            self._diagnostic("STS.FtEmpty/Empty and MODE are not interpreted "
                             "with CTL=0 or unknown; reads can be UNKNOWN")
        if "MODE" in values and enabled:
            mode = values["MODE"] & 3
            self._diagnostic("MODE=%u (%s)" % (mode, {
                0: "circular buffer", 1: "software FIFO", 2: "hardware FIFO",
                3: "software FIFO 2"
            }.get(mode, "reserved")))
        if "FFCR" in values:
            ffcr = values["FFCR"]
            self._diagnostic("FFCR: FlushMan=%u, StopOnFl=%u, EnFt=%u, EnTI=%u" %
                             ((ffcr >> 6) & 1, (ffcr >> 12) & 1,
                              ffcr & 1, (ffcr >> 1) & 1))
            if ffcr & 0x40:
                self._diagnostic("FlushMan is still set: manual flush has not "
                                 "completed its acknowledgement and data-write sequence")
                if not self._manual_flush_attempted:
                    self._diagnostic("this process did not issue a manual flush to this ETF; "
                                     "the pending flush may predate recovery or come from "
                                     "another controller")
            if self._manual_flush_attempted and enabled and not ffcr & 0x1000:
                self._diagnostic("StopOnFl=0 at snapshot: manual flush alone "
                                 "does not stop capture")
        if "FFSR" in values:
            self._diagnostic("FFSR: FlInProg=%u, FtStopped=%u" %
                             (values["FFSR"] & 1, (values["FFSR"] >> 1) & 1))
            if ready and enabled is False:
                self._diagnostic("FFSR is retained in Disabled state; it may describe "
                                 "an earlier flush")
            elif values["FFSR"] & 1:
                self._diagnostic("FlInProg=1: flush remains active at the ETF input "
                                 "or in its internal pipeline; this does not prove "
                                 "AFREADY is missing upstream")
            else:
                self._diagnostic("FlInProg=0: no input/pipeline flush is reported; "
                                 "this does not prove the configured source paths are correct")
        self._diagnostic("ETF registers do not expose individual funnel/replicator "
                         "AFVALID, AFREADY or ATREADY signals; no particular "
                         "upstream port can be identified as stalled from this snapshot")
        self._diagnostic("upstream ATB response: NOT OBSERVED. Neither a received "
                         "AFREADY acknowledgement nor a missing one is established. "
                         "The recorded failure is the ETF's incomplete state transition.")

    def is_enabled(self):
        return self.etf.read32(0x020) & 1

    def is_tmc_ready(self):
        return self.etf.test32(0x00C, 0x04)

    def stop(self):
        """
        Force the TMC into Disabled state, discarding unflushed trace.

        Arm DDI 0461B section 2.2.1 and SoC-600 TRM (100806) section 4.8.4:
        clearing TraceCaptEn enters the emergency Disabling state. Do not
        reprogram the formatter or mode until TMCReady confirms Disabled.
        An ATB flush already issued cannot be cancelled (IHI 0032B, 4.2).
        """
        self._flush_complete = False
        self._readback_pending = False
        self._record_action("attempted forced disable: clear CTL.TraceCaptEn "
                            "with readback check; wait target was Disabled "
                            "(CTL=0, STS.TMCReady=1)")
        result = self.etf.clr32(0x020, 0x01, check=True)
        self._record_action("CTL clear returned; TraceCaptEn=0 readback check %s" %
                            {True: "passed", False: "FAILED", None: "unavailable"}[result])
        if result is False:
            raise ATBDeviceError("%s: CTL.TraceCaptEn did not go to zero" % self)
        self._wait_ready("after forced disable; a platform CoreSight reset may be required")
        self._needs_disable = False
        return self

    def set_collection_mode(self, mode=TMC_MODE_CIRCULAR):
        self.etf.write32(0x028, mode, mask=0x3)
        if mode in TMC_SOFTWARE_FIFO_MODES:
            # DDI 0461B section 3.3.11: BUFWM=0 makes Full mean no free
            # space, so Full can be used to determine the captured byte count.
            self.etf.write32(0x034, 0, check=False)
        self.mode = mode
        self._record_action("MODE write returned: %u" % mode)
        return self

    def set_config(self, formatting=True, stop_on_flush=True):
        ctl = 0x0000
        if stop_on_flush:
            ctl |= 0x1000                        # continuous with stop-on-flush
        if formatting:
            ctl |= 0x0003                   # format as 16-byte frames with ATID and triggers
        result = self.etf.write32(0x304, ctl)
        self._record_action("FFCR configuration write returned: 0x%08x; readback check %s" %
                            (ctl, {True: "passed", False: "FAILED", None: "unavailable"}[result]))
        if result is False:
            raise ATBDeviceError("%s: FFCR did not accept configuration after forced "
                                 "disable; a platform CoreSight reset may be required" % self)
        return self

    def collect(self):
        if self.mode in TMC_SOFTWARE_FIFO_MODES:
            return self._collect_fifo()
        if not self._flush_complete:
            raise RuntimeError("%s: capture sink has not completed flushing" % self)
        self._flush_complete = False
        return csbuffer.sink_buffer(self.etf)

    def _collect_fifo(self):
        """
        Return trace retained while flushing, without accessing the device.
        """
        if not self._readback_pending:
            raise ATBDeviceError("%s: software FIFO flush has not been requested" % self)
        self._readback_pending = False
        self._flush_complete = False
        data = self._fifo_data
        self._fifo_data = None
        return data

    def _drain_fifo(self, status):
        """
        Read up to one FIFO capacity per status poll, including pending tail data.
        DDI 0461B section 2.2.2 requires RRD reads until ready, then reading the
        remaining FIFO contents. Formatting makes 0xffffffff an empty sentinel.
        Bound each batch as well as the number of polls if a source keeps sending.
        """
        if self._fifo_capacity is None:
            size = self.etf.read32(0x004) * 4
            if size <= 0 or size > (1 << 32):
                raise ATBDeviceError("%s: invalid FIFO capacity %u" % (self, size))
            count = 0 if status & 0x10 else size if status & 1 else self.etf.read32(0x018)
            if count < 0 or count > size or count % 4:
                raise ATBDeviceError("%s: invalid FIFO byte count %u (capacity %u)" % (self, count, size))
            self._fifo_capacity = size
            progress(1, "%s: ETF reports %u bytes collected of %u before draining (software FIFO)" %
                     (self.name or "ETF", count, size))
        if status & 0x10:
            return
        size = self._fifo_capacity
        for i in range(size // 4):
            word = self.etf.read32(0x010)
            if word == 0xffffffff:
                break
            self._fifo_total += 4
            if len(self._fifo_data) < size:
                self._fifo_data.extend(struct.pack("I", word))

    def close(self):
        if self._needs_disable:
            self.stop()


class ETR(ETF):
    """
    Trace capture into a userspace-allocated physical RAM buffer.

    Register programming follows Arm DDI 0461B section 3.3 and SoC-600 TRM
    (100806 r4p0) section 9.15.2. The platform must provide an identity-mapped
    ETR path to RAM: pagemap PAs are used directly as AXI addresses. Cache
    maintenance is local to AArch64 Linux; ETF paths retain debugger support.
    """
    def __init__(self, etr, verbose=0, diagnostics=False,
                 buffer_size=DEFAULT_ETR_BUFFER_SIZE):
        validate_etr_buffer_size(buffer_size)
        ETF.__init__(self, etr, verbose=verbose, diagnostics=diagnostics)
        self.buffer_size = buffer_size
        self.memory = None
        self.buffer_pa = None
        self._devid = None

    def __str__(self):
        return "ETR %s%s" % (self.etf, " (%s)" % self.name if self.name else "")

    def _progress(self, message, always=False):
        # Do not format the underlying device: some device descriptions lazily
        # read registers. Progress output must precede the intended access.
        progress(1 if always else self.verbose, "%s: %s" % (self.name or "ETR", message))

    def probe(self):
        """
        Probe identification and status before ETR programming or RAM allocation.
        DEVID is retained for buffer alignment and AXI address width checks.
        """
        self._progress("probing ETR identification: reading DEVID (0xfc8)")
        devid = self.etf.read32(0xfc8)
        self._progress("ETR DEVID=0x%08x; reading STS (0x00c)" % devid)
        status = self.etf.read32(0x00c)
        self._progress("ETR probe complete: STS=0x%08x (TMCReady=%u)" %
                       (status, bool(status & 4)))
        if ((devid >> 6) & 3) != 1:
            raise ATBDeviceError("%s: DEVID does not identify a TMC-ETR" % self)
        self._devid = devid
        return self

    def _allocate_buffer(self):
        """
        Allocate and fault in RAM only when capture starts, so reset needs no RAM.
        """
        if self._devid is None:
            self.probe()
        if ((self._devid >> 6) & 3) != 1:
            raise ATBDeviceError("%s: DEVID does not identify a TMC-ETR" % self)
        alignment = max(16, 1 << ((self._devid >> 8) & 7))
        if self.buffer_size % alignment:
            raise ValueError("%s: buffer size must be aligned to %u bytes" % (self, alignment))
        if self.memory is None:
            # Target OS memory allocation must not become an import dependency
            # for register-level ETF access from a Jython debugger.
            import physmem
            self._progress("allocating locked, physically contiguous trace buffer (%u bytes requested)" %
                           self.buffer_size)
            self.memory = physmem.PhysMem(self.buffer_size, lock=True,
                                          huge=physmem.HUGE_ALLOC, contiguous=True,
                                          verbose=self.verbose)
        self._progress("rechecking buffer contiguity and physical address stability")
        if not self.memory.is_contiguous(refresh=True) or not self.memory.check_pa():
            raise ATBDeviceError("%s: physical buffer is no longer contiguous at its original PA" % self)
        self.buffer_pa = self.memory.pa()
        address_width = (self._devid >> 17) & 0x7f if self._devid & (1 << 16) else 40
        if not 32 <= address_width <= 64:
            raise ATBDeviceError("%s: invalid AXI address width %u" % (self, address_width))
        if (self.buffer_pa is None or self.buffer_pa % alignment or
                self.buffer_pa >= (1 << address_width) or
                self.buffer_size >= (1 << address_width) - self.buffer_pa):
            raise ATBDeviceError("%s: physical buffer does not fit its %u-bit AXI address space" %
                                 (self, address_width))
        self._progress("buffer verified: VA 0x%x, PA 0x%x, %u bytes allocated, %u trace bytes" %
                       (self.memory.va, self.buffer_pa, self.memory.alloc_size, self.buffer_size))

    def _write_pointer(self, high, low, address):
        for offset, value in [(high, address >> 32), (low, address & 0xffffffff)]:
            self._progress("programming ETR register 0x%03x = 0x%08x" % (offset, value))
            if self.etf.write32(offset, value, check=True) is False:
                raise ATBDeviceError("%s: buffer address register 0x%x rejected 0x%x" %
                                     (self, offset, value))

    def set_collection_mode(self, mode=TMC_MODE_CIRCULAR):
        """
        Use SWF2 for direct RAM readout (SoC-600 TRM, sections 4.8.5 and 9.15.2).
        SWF1 requires APB RRD reads and cannot acknowledge direct RAM extraction.
        """
        if mode in TMC_SOFTWARE_FIFO_MODES:
            # PIDR was cached by CSROM discovery. Older TMCs reserve MODE=3
            # and do not implement RURP; do not probe either by programming it.
            if not self.etf.is_arm_part_number(0x9e8):
                raise ATBDeviceError("%s: direct RAM software FIFO readout requires a "
                                     "SoC-600 TMC-ETR (part 0x9e8); use --circular" % self)
            mode = TMC_MODE_SOFTWARE_FIFO_2
        return ETF.set_collection_mode(self, mode)

    def enable(self):
        self._flush_complete = False
        self._readback_pending = False
        self.capture_incomplete = False
        validate_etr_buffer_size(self.buffer_size, circular=(self.mode not in TMC_SOFTWARE_FIFO_MODES))
        if self._devid is None:
            self.probe()
        self._progress("checking ETR CTL.TraceCaptEn and waiting for TMCReady before capture")
        if self.is_enabled():
            raise ATBDeviceError("%s: cannot start with CTL.TraceCaptEn=1" % self)
        self._wait_ready("before capture enable")
        self._allocate_buffer()
        # Complete CPU writes and remove stale cache lines before transferring
        # ownership. No CPU reads or writes of this RAM occur during capture.
        self._progress("cleaning and invalidating buffer cache lines before ETR ownership")
        self.memory.cache_clean_invalidate()
        self._progress("cache maintenance complete; checking physical addresses before programming ETR")
        if not self.memory.check_pa():
            raise ATBDeviceError("%s: physical addresses changed before capture" % self)
        self._progress("programming ETR RSZ (0x004) = 0x%x (%u bytes)" %
                       (self.buffer_size // 4, self.buffer_size))
        if self.etf.write32(0x004, self.buffer_size // 4, check=True) is False:
            raise ATBDeviceError("%s: RSZ rejected the requested buffer size" % self)
        # Non-secure, non-cacheable AXI transfers; up to 16-beat bursts. SG=0
        # selects a flat contiguous buffer on older TMCs. SoC-600 reserves SG.
        memory_width = 1 << ((self._devid >> 8) & 7)
        burst_beats = min(16, self.buffer_size // memory_width)
        axictl = ((burst_beats - 1) << 8) | 2
        self._progress("programming ETR AXICTL (0x110) = 0x%x" % axictl)
        if self.etf.write32(0x110, axictl, check=True) is False:
            raise ATBDeviceError("%s: AXICTL rejected flat-buffer configuration" % self)
        self._write_pointer(0x11c, 0x118, self.buffer_pa)  # DBA
        self._write_pointer(0x038, 0x014, self.buffer_pa)  # RRP
        self._write_pointer(0x03c, 0x018, self.buffer_pa)  # RWP
        self._progress("clearing ETR STS.Full (0x00c) and TRG (0x01c)")
        self.etf.write32(0x00c, 0, check=False)           # clear saved STS.Full
        if self.etf.write32(0x01c, 0, check=True) is False:  # TRG
            raise ATBDeviceError("%s: TRG rejected initialization" % self)
        self._progress("ETR buffer programming complete")
        # Retain before the enable write: even a failed readback may mean that
        # the device has started DMA. Only a confirmed disable releases it.
        if self.memory not in _active_etr_buffers:
            _active_etr_buffers.append(self.memory)
        self._progress("starting ETR capture: writing CTL.TraceCaptEn=1 (0x020)")
        if self.etf.write32(0x020, 1, check=True) is False:
            raise ATBDeviceError("%s: CTL.TraceCaptEn enable readback failed" % self)
        self._record_action("CTL.TraceCaptEn=1 write returned (start ETR capture)")
        self._progress("ETR capture enabled")
        return self

    def disable(self):
        """
        Attempt a normal flush, preserving RAM for best-effort timeout readback.
        Do not force-disable the ETR before sampling its pointers and trace RAM.
        close() still requires confirmed disable before releasing the allocation.
        """
        self._readback_pending = False
        self._progress("flushing ETR and waiting for TMCReady")
        try:
            return ETF.disable(self)
        except ATBReadyTimeout as error:
            if self.memory is None or self.memory not in _active_etr_buffers:
                raise
            self.capture_incomplete = True
            self._readback_pending = True
            self._progress("WARNING: %s; attempting best-effort RAM readback. "
                           "The byte count and trace may be incomplete or changing; "
                           "ETR disable is deferred until after readback." % error, always=True)
            return self

    def collect(self):
        """
        Report the ETR byte count, then copy trace RAM, oldest bytes first.
        After a flush timeout this is a best-effort, non-atomic snapshot. Arm
        DDI 0461B section 3.3.5 permits circular-buffer RWP reads only when
        Stopped or Disabled, so the sampled pointer is not reliable until ready.
        No RRD reads or device-initiated RAM reads are used for collection.
        """
        if self.mode in TMC_SOFTWARE_FIFO_MODES:
            return self._collect_fifo()
        if not (self._flush_complete or self._readback_pending) or self.memory is None:
            raise ATBDeviceError("%s: capture sink has not completed flushing" % self)
        allow_not_ready = self._readback_pending
        best_effort = self.capture_incomplete
        self._readback_pending = False
        self._flush_complete = False
        self._progress("reading ETR status and write pointer for buffer collection")
        status = self.etf.read32(0x00c)
        if not status & 4 and not allow_not_ready:
            raise ATBDeviceError("%s: ETR is not ready for buffer collection" % self)
        if status & 0x10:
            offset = 0
            count = 0
            pointer_text = "not sampled (Empty=1)"
        else:
            wp = (self.etf.read32(0x03c) << 32) | self.etf.read32(0x018)
            pointer_text = "0x%x" % wp
            offset = wp - self.buffer_pa
            alignment = 1 << ((self._devid >> 8) & 7)
            if offset < 0 or offset >= self.buffer_size or offset % alignment:
                self._progress("ETR byte count unavailable: STS=0x%08x, RWP=%s" %
                               (status, pointer_text), always=True)
                raise ATBDeviceError("%s: RWP 0x%x is outside or misaligned in the trace buffer" % (self, wp))
            count = self.buffer_size if status & 1 else offset
        self._progress("ETR reports %u bytes collected of %u: STS=0x%08x, RWP=%s, "
                       "Full=%u, Empty=%u, TMCReady=%u%s" %
                       (count, self.buffer_size, status, pointer_text,
                        bool(status & 1), bool(status & 0x10), bool(status & 4),
                        " (best-effort estimate after flush timeout)" if best_effort else ""), always=True)
        if status & 0x20:
            raise ATBDeviceError("%s: AXI memory error during capture (STS.MemErr)" % self)
        if not self.memory.check_pa():
            raise ATBDeviceError("%s: physical addresses changed; trace is unreliable" % self)
        if count == 0:
            return bytearray()
        self._progress("cleaning and invalidating cache lines before reading trace RAM")
        self.memory.cache_clean_invalidate()
        self._progress("copying trace data from RAM")
        import ctypes
        if status & 1:
            data = ctypes.string_at(self.memory.va + offset, self.buffer_size - offset)
            data += ctypes.string_at(self.memory.va, offset)
        else:
            data = ctypes.string_at(self.memory.va, count)
        if not self.memory.check_pa():
            raise ATBDeviceError("%s: physical addresses changed during readback; trace is unreliable" % self)
        self._progress("readback complete: %u bytes; physical addresses unchanged" % len(data))
        return bytearray(data)

    def _drain_fifo(self, status):
        """
        Copy the earliest trace and acknowledge consumed RAM through SWF2 RURP.
        Keep the read offset in software: no extra read-pointer registers are read.
        SoC-600 TRM section 9.15.2 permits aligned RURP increments up to 1 MiB.
        Copy retained bytes before freeing space for more AXI writes. Excess data
        need not be copied, but must be acknowledged so the flush can complete.
        """
        if status & 0x20:
            raise ATBDeviceError("%s: AXI memory error during capture (STS.MemErr)" % self)
        if status & 0x10:
            count = 0
            pointer_text = "not sampled (Empty=1)"
        else:
            wp = (self.etf.read32(0x03c) << 32) | self.etf.read32(0x018)
            pointer_text = "0x%x" % wp
            offset = wp - self.buffer_pa
            alignment = max(16, 1 << ((self._devid >> 8) & 7))
            if offset < 0 or offset >= self.buffer_size or offset % alignment:
                raise ATBDeviceError("%s: RWP 0x%x is outside or misaligned in the trace buffer" %
                                     (self, wp))
            count = self.buffer_size if status & 1 else (offset - self._fifo_offset) % self.buffer_size
        if self._fifo_capacity is None:
            self._fifo_capacity = self.buffer_size
            self._progress("ETR reports %u bytes collected of %u before draining: "
                           "STS=0x%08x, RWP=%s (software FIFO)" %
                           (count, self.buffer_size, status, pointer_text), always=True)
        if count == 0:
            return
        keep = min(count, self.buffer_size - len(self._fifo_data))
        if keep:
            if not self.memory.check_pa():
                raise ATBDeviceError("%s: physical addresses changed; trace is unreliable" % self)
            self._progress("cleaning and invalidating cache lines before reading trace RAM")
            self.memory.cache_clean_invalidate()
            import ctypes
            first = min(keep, self.buffer_size - self._fifo_offset)
            data = ctypes.string_at(self.memory.va + self._fifo_offset, first)
            if keep > first:
                data += ctypes.string_at(self.memory.va, keep - first)
            if not self.memory.check_pa():
                raise ATBDeviceError("%s: physical addresses changed during readback; trace is unreliable" % self)
            self._fifo_data.extend(data)
        if self._fifo_total == 0:
            self._progress("draining ETR software FIFO: acknowledging consumed RAM through RURP (0x120)")
        self._fifo_total += count
        remaining = count
        while remaining:
            chunk = min(remaining, 1024 * 1024)
            self.etf.write32(0x120, chunk, check=False)  # RURP is write-only
            self._fifo_offset = (self._fifo_offset + chunk) % self.buffer_size
            remaining -= chunk

    def stop(self):
        self._readback_pending = False
        self._progress("disabling ETR and waiting for TMCReady")
        ETF.stop(self)
        if self.memory in _active_etr_buffers:
            _active_etr_buffers.remove(self.memory)
        self._progress("ETR disabled")
        return self

    def close(self):
        if self.memory is None:
            return
        try:
            self.stop()
        except BaseException:
            print("%s: ETR disable could not be confirmed; buffer retained until process exit" %
                  self, file=sys.stderr)
            raise
        self._progress("releasing trace buffer after confirmed ETR disable")
        self.memory.close()
        self.memory = None


class ATBPath:
    pass


class PathFunnel(ATBPath):
    def __init__(self, fun):
        self.fun = fun
        self.ports = set()
        self.requested_mask = None
        self.last_write_check = None
        self.last_write_returned = False
        self.last_write_action = "none"

    def add_input(self, port):
        self.ports.add(port)
        return self

    def disable_all(self):
        self.requested_mask = 0
        self.last_write_check = None
        self.last_write_returned = False
        self.last_write_action = "disable all inputs"
        self.last_write_check = self.fun.write32(0x000, 0x00)
        self.last_write_returned = True
        return self

    def enable(self):
        for port in sorted(self.ports):
            if self.requested_mask is not None:
                self.requested_mask |= 1 << port
            self.last_write_check = None
            self.last_write_returned = False
            self.last_write_action = "enable input %u" % port
            self.last_write_check = self.fun.set32(0x000, 1 << port)
            self.last_write_returned = True
        return self


class PathReplicator(ATBPath):
    """
    Select outputs of an Arm programmable ATB replicator.

    CoreSight SoC-400 TRM (100536), sections 3.5.2 and 3.5.3: IDFILTER0
    and IDFILTER1 at offsets 0x000 and 0x004 filter groups of trace IDs.
    Zero passes all IDs and 0xff blocks all IDs on that output. SoC-600
    uses the same layout for IDFILT0 and IDFILT1 (100806, sections 10.7.1
    and 10.7.2 in revision r6p0).
    """
    def __init__(self, rep):
        self.rep = rep
        self.ports = set()
        self.requested_filters = {}
        self.filter_write_status = {}

    def add_output(self, port):
        if type(port) not in integer_types or port not in [0, 1]:
            raise ValueError("replicator output port must be 0 or 1")
        self.ports.add(port)
        return self

    def disable_all(self):
        errors = []
        for port in [0, 1]:
            try:
                # Full writes avoid reading filter registers during setup
                # and cleanup; every defined filter bit is programmed.
                self._write_filter(port, 0xff)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]
        return self

    def enable(self):
        for port in sorted(self.ports):
            self._write_filter(port, 0x00)
        return self

    def _write_filter(self, port, value):
        """
        Record the attempted filter write separately from its return status.
        A returned write without readback does not confirm hardware state.
        """
        self.requested_filters[port] = value
        self.filter_write_status[port] = "call did not return (exception/interruption)"
        self.rep.write32(4 * port, value, check=False)
        self.filter_write_status[port] = "call returned; no readback"


class ATBDeviceManager:
    """
    Configure the CoreSight devices on selected source-to-sink paths.
    """
    def __init__(self, topology, active_sources, formatting=True,
                 verbose=0, checking=True, open_all_ports=False, diagnostics=False,
                 etr_buffer_size=DEFAULT_ETR_BUFFER_SIZE, circular=False):
        validate_etr_buffer_size(etr_buffer_size, circular=circular)
        if not formatting and not circular:
            raise ValueError("unformatted capture requires --circular; software FIFO mode requires formatting")
        self.topology = topology
        self.active_sources = list(active_sources)
        self.formatting = formatting
        self.circular = circular
        self.verbose = verbose
        self.checking = checking
        self.open_all_ports = open_all_ports
        self.diagnostics = diagnostics
        self.etr_buffer_size = etr_buffer_size
        self.sinks = []
        self.fifos = []
        self.funnels = []
        self.replicators = []
        self.sink_for_source = {}
        self._etfs = []
        self._path_devices = {}
        self._diagnostic_phase = "startup recovery: trace isolation writes preceded ETF disable"
        self._configuration_started = False
        self._configured = False
        self._enabled = False
        self._needs_cleanup = False

    def configure(self):
        """
        Configure paths explicitly, after the owner has retained this manager.
        """
        if self._configuration_started:
            raise RuntimeError("ATB paths have already been configured or configuration failed")
        self._configuration_started = True
        self._needs_cleanup = True
        self._configure()
        self._configured = True
        self._needs_cleanup = False
        self._diagnostic_phase = "capture setup completed"

    def _create_coresight_device(self, config):
        addr = config["address_value"]
        if config["type"] == "tmc-etr":
            progress(self.verbose, "%s: probing ETR at 0x%x: mapping and reading CoreSight "
                     "identification (CIDR/PIDR, DEVARCH/DEVTYPE)" % (config["id"], addr))
        elif self.verbose >= 2:
            print("Configuring %s %s at 0x%x..." %
                  (config["type"], config["id"], addr))
        device = self.coresight.create_device_at(addr)
        if config["type"] == "tmc-etr":
            progress(self.verbose, "%s: CoreSight identification read completed" % config["id"])
        if "part_number_value" in config:
            if not device.is_arm_part_number(config["part_number_value"]):
                raise ATBTopologyError(
                    "%s at 0x%x has part number %s, expected 0x%x" %
                    (config["id"], addr, device.arm_part_number(),
                     config["part_number_value"]))
        if config["type"] == "funnel" and not device.is_funnel():
            raise ATBTopologyError("%s at 0x%x is not a funnel" %
                                   (config["id"], addr))
        if config["type"] == "replicator" and not device.is_replicator():
            raise ATBTopologyError("%s at 0x%x is not a replicator" %
                                   (config["id"], addr))
        if config["type"] == "tmc-etf" and not \
                device.is_coresight_device_type(2, 3):
            raise ATBTopologyError("%s at 0x%x is not a TMC-ETF" %
                                   (config["id"], addr))
        if config["type"] == "tmc-etr" and not device.is_coresight_device_type(1, 2):
            raise ATBTopologyError("%s at 0x%x is not a TMC-ETR" % (config["id"], addr))
        # ETR identification and status must be probed before any setup writes.
        if config["type"] != "tmc-etr":
            device.write_enable()
            device.unlock()
        return device

    def _configure_etf(self, config):
        etf = self._create_coresight_device(config)
        if config["type"] == "tmc-etr":
            wrapper = ETR(etf, verbose=self.verbose, diagnostics=self.diagnostics,
                          buffer_size=self.etr_buffer_size)
        else:
            wrapper = ETF(etf, verbose=self.verbose, diagnostics=self.diagnostics)
        wrapper.name = config["id"]
        if config["type"] == "tmc-etr":
            wrapper.probe()
            wrapper._progress("enabling register writes and unlocking ETR")
            etf.write_enable()
            etf.unlock()
        wrapper.diagnostic_context = lambda: self._diagnose_paths(config["id"])
        self._path_devices[config["id"]] = wrapper
        self._etfs.append(wrapper)    # Own it even if recovery fails.
        return wrapper.stop()

    def _diagnose_paths(self, failing_id):
        """
        Report upstream control actions and the limits of the observed response.
        Report before cleanup changes the forwarding configuration.
        """
        def report(message):
            print("ATB post-mortem for %s: %s" % (failing_id, message), file=sys.stderr)

        report("capture=%s; %s" % (self.topology.capture_name or "captures",
                                  self._diagnostic_phase))
        if not self._configured:
            report("recovery changed forwarding controls before this wait; "
                   "pre-recovery port state was not captured")
        affected = set()
        for sid in sorted(self.active_sources):
            path = self.topology.paths[sid]
            ids = [link["to"]["device"] for link in path]
            if failing_id in ids:
                # Report connections ending at this ETF; only upstream devices
                # can acknowledge its input-side flush.
                path = path[:ids.index(failing_id) + 1]
                report("JSON upstream connection for %s: %s" % (sid, "; ".join([
                    "%s -> %s" % (_format_endpoint(link["from"]),
                                    _format_endpoint(link["to"])) for link in path])))
                affected.update([link["to"]["device"] for link in path])
        report("upstream control actions recorded before the failed wait "
               "(write-time results, not live handshake samples):")
        for did in sorted(affected):
            if did == failing_id:
                continue
            config = self.topology.devices[did]
            device = self._path_devices.get(did)
            prefix = "%s at 0x%x" % (did, config["address_value"])
            if device is None:
                report("%s: no device access recorded" % prefix)
            elif config["type"] == "funnel":
                check = {True: "passed", False: "FAILED", None: "unavailable"}[device.last_write_check]
                report("%s: funnel last action=%s; input mask from write attempts=%s; "
                       "last write returned=%s; last readback check=%s" %
                       (prefix, device.last_write_action,
                        "unknown" if device.requested_mask is None else
                        "0x%08x" % device.requested_mask,
                        "yes" if device.last_write_returned else "no", check))
            elif config["type"] == "replicator":
                report("%s: replicator control writes:" % prefix)
                for port in [0, 1]:
                    if port in device.requested_filters:
                        value = device.requested_filters[port]
                        report("  %s: last IDFILTER%u write attempt=0x%02x (%s); %s" %
                               (did, port, value, "pass all IDs" if value == 0 else "block all IDs",
                                device.filter_write_status[port]))
                    else:
                        report("  %s: IDFILTER%u write not attempted" % (did, port))
            elif config["type"] == "tmc-etf":
                report("%s: upstream ETF recent actions (no new status reads):" % prefix)
                for action in device._history[-3:]:
                    report("  %s" % action)
        incoming = {}
        for link in self.topology.links:
            target = link["to"]
            if target["device"] in affected:
                key = (target["device"], target["port"])
                incoming.setdefault(key, set()).add(_format_endpoint(link["from"]))
        for (did, port), sources in sorted(incoming.items()):
            if len(sources) > 1:
                report("ambiguous topology: %s input %u has multiple upstream endpoints: "
                       "%s. Check placeholder port numbers or a missing merge device." %
                       (did, port, ", ".join(sorted(sources))))
        report("upstream ATB response: NOT OBSERVED; no per-port AFVALID/AFREADY "
               "or ATREADY samples were taken. Control write returns/readback "
               "checks do not establish a flush acknowledgement. Missing upstream "
               "acknowledgement and incomplete ETF internal draining remain "
               "indistinguishable with this evidence.")

    def _configure(self):
        for sid in self.active_sources:
            if sid not in self.topology.captures:
                raise ATBTopologyError("no capture sink selected for source %s" %
                                       sid)

        sink_ids = set([self.topology.captures[sid]
                        for sid in self.active_sources])
        used_ids = set()
        intermediate_ids = set()
        fifo_ids = []
        for sid in self.active_sources:
            path = self.topology.paths[sid]
            sink_id = self.topology.captures[sid]
            for link in path:
                for endpoint in [link["from"], link["to"]]:
                    if "device" in endpoint:
                        used_ids.add(endpoint["device"])
                if link["to"]["device"] != sink_id:
                    intermediate_ids.add(link["to"]["device"])
            for link in reversed(path):
                did = link["to"]["device"]
                if did != sink_id and \
                        self.topology.devices[did]["type"] == "tmc-etf":
                    if did not in fifo_ids:
                        fifo_ids.append(did)

        supported_types = ["funnel", "replicator", "tmc-etf", "tmc-etr"]
        for did in sorted(used_ids):
            device_type = self.topology.devices[did]["type"]
            if device_type not in supported_types:
                raise ATBTopologyError(
                    "ATB device %s uses unsupported type %s" %
                    (did, device_type))
        for sink_id in sink_ids:
            if self.topology.devices[sink_id]["type"] not in ("tmc-etf", "tmc-etr"):
                raise ATBTopologyError("capture sink %s is not a TMC-ETF or TMC-ETR" %
                                       sink_id)
        for did in used_ids:
            if self.topology.devices[did]["type"] == "tmc-etr":
                if did not in sink_ids or did in intermediate_ids:
                    raise ATBTopologyError("TMC-ETR %s must be a capture sink" % did)
                if "buffer" in self.topology.devices[did]:
                    raise ATBTopologyError("%s: reserved ETR buffers are unsupported; "
                                           "omit buffer to allocate RAM" % did)
        if sink_ids & intermediate_ids:
            raise ATBTopologyError(
                "a TMC-ETF cannot be both a sink and an intermediate FIFO")
        if not self.formatting:
            for sink_id in sink_ids:
                n_sources = len([sid for sid in self.active_sources
                                 if self.topology.captures[sid] == sink_id])
                if n_sources > 1:
                    raise ATBTopologyError(
                        "sink %s combines multiple DTCs and requires formatting" %
                        sink_id)

        if any(self.topology.devices[did]["type"] == "tmc-etr" for did in sink_ids) and \
                isinstance(csscan.g_devmem, csscan.DevMemRemote):
            raise ATBTopologyError("ETR RAM allocation requires local device access")

        self.coresight = csscan.CSROM(checking=self.checking)
        configured = {}
        for did in sorted(used_ids):
            config = self.topology.devices[did]
            if config["type"] == "funnel":
                funnel = PathFunnel(self._create_coresight_device(config))
                configured[did] = funnel
                self._path_devices[did] = funnel
                self.funnels.append(funnel)
                funnel.disable_all()
            elif config["type"] == "replicator":
                replicator = PathReplicator(
                    self._create_coresight_device(config))
                configured[did] = replicator
                self._path_devices[did] = replicator
                self.replicators.append(replicator)
                replicator.disable_all()
        # Isolate the selected paths before recovering TMCs left running or
        # flushing by an earlier capture. No formatter programming is allowed
        # until each TMC has reached Disabled state.
        for did in sorted(used_ids):
            config = self.topology.devices[did]
            if config["type"] in ("tmc-etf", "tmc-etr"):
                configured[did] = self._configure_etf(config)

        for sid in self.active_sources:
            for link in self.topology.paths[sid]:
                target = link["to"]
                if self.topology.devices[target["device"]]["type"] == "funnel":
                    configured[target["device"]].add_input(target["port"])
                source = link["from"]
                if "device" in source and \
                        self.topology.devices[source["device"]]["type"] == "replicator":
                    configured[source["device"]].add_output(source["port"])

        for did in sorted(used_ids):
            config = self.topology.devices[did]
            path_device = configured[did]
            if config["type"] == "funnel":
                if self.open_all_ports:
                    # CoreSight SoC-400 TRM (100536), DEVID register:
                    # PORTNUM gives the number of implemented inputs.
                    # Read it once, only for the open-all-ports debug mode.
                    n_inputs = path_device.fun.atb_in_ports()
                    if n_inputs < 1 or n_inputs > 8:
                        raise ATBTopologyError(
                            "%s: invalid hardware funnel input count %u" %
                            (did, n_inputs))
                    if "input_ports" in config and config["input_ports"] != n_inputs:
                        print("warning: %s: JSON input_ports=%u, hardware input_ports=%u; "
                              "opening all hardware inputs" %
                              (did, config["input_ports"], n_inputs), file=sys.stderr)
                    # A mistaken declared path may name a nonexistent input.
                    # The debug mode opens exactly the implemented inputs.
                    path_device.ports = set(range(n_inputs))
                if self.verbose >= 2:
                    print("%s: funnel inputs to enable: %s%s" %
                          (did, ", ".join([str(p) for p in sorted(path_device.ports)]),
                           " (debug: all ports)" if self.open_all_ports else ""))
            elif config["type"] == "replicator":
                if self.open_all_ports:
                    path_device.add_output(0).add_output(1)
                if self.verbose >= 2:
                    print("%s: replicator outputs to enable: %s%s" %
                          (did, ", ".join([str(p) for p in sorted(path_device.ports)]),
                           " (debug: all ports)" if self.open_all_ports else ""))

        for did in sorted(sink_ids):
            sink = configured[did]
            mode = TMC_MODE_CIRCULAR if self.circular else TMC_MODE_SOFTWARE_FIFO
            mode_name = "circular buffer" if self.circular else "stop-on-full software FIFO"
            progress(self.verbose, "%s: programming trace sink formatter and %s mode" % (did, mode_name))
            sink.set_config(formatting=self.formatting, stop_on_flush=True)
            sink.set_collection_mode(mode)
            self.sinks.append(sink)
            if self.verbose >= 2:
                print("%s: %s configured in %s mode (capture sink)" %
                      (did, "ETR" if isinstance(sink, ETR) else "ETF", mode_name))
        for did in fifo_ids:
            fifo = configured[did]
            # Arm DDI 0461B, sections 2.2.2 and 2.2.3: hardware FIFOs
            # require formatting even when the final sink is unformatted.
            fifo.set_config(formatting=True, stop_on_flush=False)
            fifo.set_collection_mode(TMC_MODE_HARDWARE_FIFO)
            self.fifos.append(fifo)
            if self.verbose >= 2:
                print("%s: ETF configured in hardware FIFO mode (pass-through)" % did)

        for sid in self.active_sources:
            self.sink_for_source[sid] = configured[self.topology.captures[sid]]

    def enable(self):
        if not self._configured:
            raise RuntimeError("ATB paths must be configured before enabling")
        self._enabled = True    # stop() also handles a partially enabled path.
        self._needs_cleanup = True
        self._diagnostic_phase = "capture start in progress"
        for sink in self.sinks:
            sink.enable()
        for fifo in self.fifos:
            fifo.enable()
        for replicator in self.replicators:
            replicator.enable()
        for funnel in self.funnels:
            funnel.enable()
        self._diagnostic_phase = "capture started"

    def stop(self):
        """
        Flush sinks while shared routes remain open, then disable forwarding.
        Software FIFOs drain while waiting for TMCReady, retaining their first
        buffer of trace before disabling forwarding. Circular sinks wait for
        TMCReady. A timeout permits explicitly incomplete FIFO readback. ETR flush
        timeouts permit best-effort RAM collection; other failed flushes prevent
        collection and are force-disabled to attempt recovery for another capture.
        Partial configuration is also cleaned up without requesting flushes.
        Attempt every device even if one fails, then raise the first error.
        """
        if not self._enabled and not self._needs_cleanup:
            return
        was_enabled = self._enabled
        self._enabled = False
        self._needs_cleanup = False
        errors = []
        force_stop = list(reversed(self.fifos)) if was_enabled else list(self._etfs)
        if was_enabled:
            self._diagnostic_phase = "sink flush: cleanup has not changed forwarding controls"
            for sink in self.sinks:
                try:
                    sink.disable()
                except BaseException as error:
                    errors.append(error)
                    force_stop.append(sink)
            if any(sink.capture_incomplete for sink in self.sinks):
                progress(self.verbose, "ATB flush timed out; forcing upstream disable for recovery")
        self._diagnostic_phase = "forced ETF disable: cleanup has not changed forwarding controls"
        for etf in force_stop:
            try:
                etf.stop()
            except BaseException as error:
                errors.append(error)
        for funnel in self.funnels:
            try:
                funnel.disable_all()
            except BaseException as error:
                errors.append(error)
        for replicator in self.replicators:
            try:
                replicator.disable_all()
            except BaseException as error:
                errors.append(error)
        if errors:
            for error in errors[1:]:
                print("ATB recovery failed: %s" % error, file=sys.stderr)
            raise errors[0]

    def close(self):
        """
        Stop paths and finish deferred sink disables before releasing ETR RAM.
        Attempt every cleanup even if another device failed to stop.
        """
        errors = []
        try:
            self.stop()
        except BaseException as error:
            errors.append(error)
        for sink in self._etfs:
            try:
                sink.close()
            except BaseException as error:
                errors.append(error)
        if errors:
            for error in errors[1:]:
                print("ATB buffer cleanup failed: %s" % error, file=sys.stderr)
            raise errors[0]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
