#!/usr/bin/python

"""
CoreSight ATB topology loading and device management.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import print_function

import json
import os
import sys

import app_data
import csscan
import csbuffer

TMC_MODE_CIRCULAR = 0
TMC_MODE_HARDWARE_FIFO = 2


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
    """
    DEVICE_TYPES = ["funnel", "replicator", "tmc-etf", "tmc-etr",
                    "tmc-etb", "etb", "tpiu", "atb-bridge"]

    def __init__(self, data, filename=None):
        self.filename = filename
        _check_object(data, ["version", "sources", "devices", "links", "captures"],
                      ["system", "generator"], "topology")
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
        self.captures = {}
        self.paths = {}
        self._load_sources(data["sources"])
        self._load_devices(data["devices"])
        self._load_links(data["links"])
        self._load_captures(data["captures"])

    @classmethod
    def from_file(cls, filename):
        try:
            with open(filename) as f:
                data = json.load(f)
        except (IOError, ValueError) as e:
            raise ATBTopologyError("cannot load ATB topology %s: %s" %
                                   (filename, e))
        return cls(data, filename=filename)

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
        _check_object(endpoint, ["device", "port"], [], where)
        did = endpoint["device"]
        _check_identifier(did, where + ".device")
        if did not in self.devices:
            raise ATBTopologyError("%s references unknown device: %s" %
                                   (where, did))
        _check_nonnegative_integer(endpoint["port"], where + ".port")
        return ("device", did)

    def _load_links(self, links):
        self._check_array(links, "links")
        seen = set()
        for (i, link) in enumerate(links):
            where = "links[%u]" % i
            _check_object(link, ["from", "to"], [], where)
            source = self._endpoint(link["from"], where + ".from", True)
            target = self._endpoint(link["to"], where + ".to", False)
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

    def _load_captures(self, captures):
        self._check_array(captures, "captures")
        for (i, capture) in enumerate(captures):
            where = "captures[%u]" % i
            _check_object(capture, ["source", "sink"], ["description"], where)
            sid = capture["source"]
            sink = capture["sink"]
            _check_identifier(sid, where + ".source")
            _check_identifier(sink, where + ".sink")
            if sid not in self.sources:
                raise ATBTopologyError("%s references unknown source: %s" %
                                       (where, sid))
            if sink not in self.devices:
                raise ATBTopologyError("%s references unknown sink: %s" %
                                       (where, sink))
            if sid in self.captures:
                raise ATBTopologyError("source has multiple capture sinks: %s" % sid)
            path = self._find_path(("source", sid), ("device", sink))
            if path is None:
                raise ATBTopologyError("no ATB path from %s to %s" % (sid, sink))
            self.captures[sid] = sink
            self.paths[sid] = path

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
            edges.append("%s -> %s" % (
                _format_endpoint(link["from"]),
                _format_endpoint(link["to"])))
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
    opts = parser.parse_args(argv)
    try:
        topology = ATBTopology.from_file(opts.atb_topology)
    except ATBTopologyError as e:
        print("%s" % e, file=sys.stderr)
        return 1
    print(format_topology(topology))
    return 0


class ETF:

    def __init__(self, etf, verbose=0):
        self.etf = etf
        self.verbose = verbose

    def __str__(self):
        return "ETF %s" % self.etf

    def enable(self):
        if self.verbose >= 2:
            csbuffer.sink_show_status(self.etf, title="before ETF configuration")
        assert not self.is_enabled() and self.is_tmc_ready(), "need CTL.TraceCaptEn==0 and STS.TMCReady=1"
        self.etf.write32(0x014, 0, check=True)   # set read-pointer (RRP) to start
        self.etf.write32(0x018, 0, check=True)   # set write-pointer (RWP) to start
        if self.verbose >= 2:
            csbuffer.sink_show_status(self.etf, title="after ETF configuration, before CMN trace enable")
        self.etf.write32(0x020, 0x01)            # start ETF collecting
        return self

    def disable(self):
        assert self.etf.test32(0x020, 0x01)   # Check that the ETF is currently enabled
        self.etf.set32(0x304, 0x40, check=False)     # Request manual flush
        #self.stop()
        #fun.write32(0x000, 0x00)    # Block all trace sources
        if self.verbose >= 2:
            csbuffer.sink_show_status(self.etf, title="after trace enable, before collection")
        return self

    def is_enabled(self):
        return self.etf.read32(0x020) & 1

    def is_tmc_ready(self):
        return self.etf.test32(0x00C, 0x04)

    def stop(self):
        self.etf.clr32(0x020, 0x01, check=True)  # stop ETF
        return self

    def set_collection_mode(self, mode=TMC_MODE_CIRCULAR):
        self.etf.write32(0x028, mode, mask=0x3)
        return self

    def set_config(self, formatting=True, stop_on_flush=True):
        ctl = 0x0000
        if stop_on_flush:
            ctl |= 0x1000                        # continuous with stop-on-flush
        if formatting:
            ctl |= 0x0003                   # format as 16-byte frames with ATID and triggers
        self.etf.write32(0x304, ctl)
        return self

    def collect(self):
        return csbuffer.sink_buffer(self.etf)


class ATBPath:
    pass


class PathFunnel(ATBPath):
    def __init__(self, fun):
        self.fun = fun
        self.ports = set()

    def add_input(self, port):
        self.ports.add(port)
        return self

    def disable_all(self):
        self.fun.write32(0x000, 0x00)            # initially enable no input ports
        return self

    def enable(self):
        for port in sorted(self.ports):
            self.fun.set32(0x000, 1 << port)
        return self


class ATBDeviceManager:
    """
    Configure the CoreSight devices on selected source-to-sink paths.
    """
    def __init__(self, topology, active_sources, formatting=True,
                 verbose=0, checking=True):
        self.topology = topology
        self.active_sources = list(active_sources)
        self.formatting = formatting
        self.verbose = verbose
        self.checking = checking
        self.sinks = []
        self.fifos = []
        self.funnels = []
        self.sink_for_source = {}
        self._configuration_started = False
        self._configured = False
        self._enabled = False

    def configure(self):
        """
        Configure paths explicitly, after the owner has retained this manager.
        """
        if self._configuration_started:
            raise RuntimeError("ATB paths have already been configured or configuration failed")
        self._configuration_started = True
        self._configure()
        self._configured = True

    def _create_coresight_device(self, config):
        addr = config["address_value"]
        if self.verbose:
            print("Configuring %s %s at 0x%x..." %
                  (config["type"], config["id"], addr))
        device = self.coresight.create_device_at(addr)
        if "part_number_value" in config:
            if not device.is_arm_part_number(config["part_number_value"]):
                raise ATBTopologyError(
                    "%s at 0x%x has part number %s, expected 0x%x" %
                    (config["id"], addr, device.arm_part_number(),
                     config["part_number_value"]))
        if config["type"] == "funnel" and not device.is_funnel():
            raise ATBTopologyError("%s at 0x%x is not a funnel" %
                                   (config["id"], addr))
        if config["type"] == "tmc-etf" and not \
                device.is_coresight_device_type(2, 3):
            raise ATBTopologyError("%s at 0x%x is not a TMC-ETF" %
                                   (config["id"], addr))
        device.write_enable()
        device.unlock()
        return device

    def _configure_etf(self, config):
        etf = self._create_coresight_device(config)
        wrapper = ETF(etf, verbose=self.verbose).stop()
        if wrapper.is_enabled():
            raise RuntimeError("%s: CTL.TraceCaptEn did not go to zero" %
                               wrapper)
        return wrapper

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

        supported_types = ["funnel", "tmc-etf"]
        for did in sorted(used_ids):
            device_type = self.topology.devices[did]["type"]
            if device_type not in supported_types:
                raise ATBTopologyError(
                    "ATB device %s uses unsupported type %s" %
                    (did, device_type))
        for sink_id in sink_ids:
            if self.topology.devices[sink_id]["type"] != "tmc-etf":
                raise ATBTopologyError("capture sink %s is not a TMC-ETF" %
                                       sink_id)
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

        self.coresight = csscan.CSROM(checking=self.checking)
        configured = {}
        for did in sorted(used_ids):
            config = self.topology.devices[did]
            if config["type"] == "funnel":
                funnel = PathFunnel(
                    self._create_coresight_device(config)).disable_all()
                configured[did] = funnel
                self.funnels.append(funnel)
            elif config["type"] == "tmc-etf":
                configured[did] = self._configure_etf(config)

        for sid in self.active_sources:
            for link in self.topology.paths[sid]:
                target = link["to"]
                if self.topology.devices[target["device"]]["type"] == "funnel":
                    configured[target["device"]].add_input(target["port"])

        for did in sorted(sink_ids):
            sink = configured[did]
            sink.set_config(formatting=self.formatting, stop_on_flush=True)
            sink.set_collection_mode(TMC_MODE_CIRCULAR)
            self.sinks.append(sink)
        for did in fifo_ids:
            fifo = configured[did]
            fifo.set_config(formatting=self.formatting, stop_on_flush=False)
            fifo.set_collection_mode(TMC_MODE_HARDWARE_FIFO)
            self.fifos.append(fifo)

        for sid in self.active_sources:
            self.sink_for_source[sid] = configured[self.topology.captures[sid]]

    def enable(self):
        if not self._configured:
            raise RuntimeError("ATB paths must be configured before enabling")
        self._enabled = True    # stop() also handles a partially enabled path.
        for sink in self.sinks:
            sink.enable()
        for fifo in self.fifos:
            fifo.enable()
        for funnel in self.funnels:
            funnel.enable()

    def stop(self):
        """
        Stop sinks, intermediate FIFOs in reverse order, and funnels.
        Attempt every device even if one fails, then raise the first error.
        This also handles a partially completed enable().
        """
        if not self._enabled:
            return
        self._enabled = False
        errors = []
        for sink in self.sinks:
            try:
                sink.disable()
            except BaseException as error:
                errors.append(error)
        for fifo in reversed(self.fifos):
            try:
                fifo.stop()
            except BaseException as error:
                errors.append(error)
        for funnel in self.funnels:
            try:
                funnel.disable_all()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
