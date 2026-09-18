#!/usr/bin/python3

"""
CMN mesh interconnect

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This module provides classes to model the structure of one or
more CMN mesh interconnects. Each mesh consists of a rectangular
grid of crosspoints (XPs), to which are attached devices such
as requestors and home nodes.

The classes (System, CMN, CMNNode... and CPU) can be used directly,
or subclassed to provide more detailed functionality.

The CPU class is intended to help tools associate CPUs with RN-Fs.
CMN itself has no knowledge of which CPUs are connected where.
"""

from __future__ import print_function

import sys
from cmn_enum import *
from cmn_config import *
from memsize_str import memsize_str


SYSTEM_DESC_VERSION = 1

# node_info encodes node type, node ID and logical ID in 16-bit fields.
# See Arm CMN-600 TRM (100180), por_*_node_info register descriptions:
# https://documentation-service.arm.com/static/5e7c897716d2907d59406268
NODE_INFO_FIELD_MAX = 0xffff


def BITS(x, p, n):
    return (x >> p) & ((1 << n) - 1)


def port_device_id(port, device_number):
    """
    Get the CHI node id for a device slot on a port-like object.
    """
    return port.base_id() + device_number


def port_device_number(port, id):
    """Get the device number relative to the port's recorded base id."""
    return id - port.base_id()


def port_device_numbers(port, explicit_numbers):
    """
    Combine CAL-implied slots (or D0 without a CAL) with explicit slots.
    Used by the offline model, which need not have an object for every slot.
    The live model instead enumerates its fully populated device cache.
    """
    return sorted(set(range(port.cal or 1)).union(explicit_numbers))


def port_ids(port):
    """Yield represented CHI ids in device-number order."""
    for dn in port.device_numbers():
        yield port_device_id(port, dn)


def port_device_at_id(port, id, create=False):
    """
    Resolve a represented id to a device slot, rejecting ids outside the port.
    Validation uses the model's slot numbers without discovering child nodes.
    """
    if not port.is_valid_id(id):
        raise IndexError("%s: invalid device id 0x%x" % (port, id))
    return port.device(port_device_number(port, id), create=create)


def port_devices(port, create=False, properties=CMN_PROP_none, device_numbers=None):
    """
    Yield device-slot objects for all slots represented by a port-like object.
    An explicit device-number sequence can restrict iteration to stored objects.
    Creation remains the responsibility of port.device(); the live model never
    creates slots here. Only property matching that falls back to explicit
    nodes can discover children, and only when the iterator is consumed.
    """
    if device_numbers is None:
        device_numbers = port.device_numbers()
    for dn in device_numbers:
        dev = port.device(dn, create=create)
        if dev is not None and (properties in [None, CMN_PROP_none] or dev.has_properties(properties)):
            yield dev


def device_has_properties(device, props):
    """
    Match a slot's attachment role, falling back to its explicit device nodes.
    Do not inspect nodes when the port already satisfies the request: in the
    live model that would trigger otherwise unnecessary child discovery.
    """
    if props in [None, CMN_PROP_none] or device.port.has_properties(props):
        return True
    return any([n.has_properties(props) for n in device.device_nodes])


def cmn_device_at_id(cmn, id, create=False):
    """Resolve an id via its XP, or return None if the XP or slot is absent."""
    xp = cmn.XP(id & ~7)
    return xp.device_at_id(id, create=create) if xp is not None else None


def port_has_properties(port, props):
    """
    Match a complete attachment role on a port in either object model.
    Test the connected type and HCAL3's HN-I role separately. For example,
    RN-F contributes CMN_PROP_F and HN-I contributes CMN_PROP_HN. Their union
    would match CMN_PROP_HNF (HN | F), although neither role is HN-F.
    Only inspect the CAL when its HN-I role could satisfy the request.
    """
    if cmn_port_device_type_has_properties(port.connected_type, props):
        return True
    return (CMN_PROP_HNI & props) == props and port.cal == 3


class CMNException(Exception):
    pass


class CMNNoCPUMappings(CMNException):
    def __str__(self):
        return "System description has no CPU locations - run cmn_detect_cpu.py"


class CMNBadStructure(CMNException, ValueError):
    """
    Attempt to create something impossible in the data model - e.g. too many devices on a port,
    a node with bad coordinates etc. May indicate broken JSON.
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class CMNBadDevice(CMNBadStructure):
    pass


class C2CLinkEndpoint(object):
    """
    One end of a direct chip-to-chip connection, bound to a device slot.

    mseq is the mesh's cmn_seq, not a hardware chip ID. An optional node_type
    selects an explicit node at the slot; an absent node remains unresolved.
    interface identifies an interface within this gateway attachment, not an
    XP port. None means unspecified, and is distinct from interface zero.
    Binding can materialize an offline slot but never discovers live nodes.
    """
    def __init__(self, system, mseq, node_id, node_type=None, interface=None):
        if not isinstance(system, System):
            raise TypeError("C2C endpoint owner must be a System")
        check_integer(mseq, "C2C mesh number")
        check_integer(node_id, "C2C node ID", maximum=NODE_INFO_FIELD_MAX)
        if node_type is not None:
            check_integer(node_type, "C2C node type", maximum=NODE_INFO_FIELD_MAX)
        if interface is not None:
            check_integer(interface, "C2C interface")
        meshes = [c for c in system.CMNs if c.cmn_seq == mseq]
        if len(meshes) != 1:
            raise ValueError("C2C endpoint requires exactly one mesh numbered %u" % mseq)
        device = meshes[0].device_at_id(node_id, create=True)
        if device is None:
            raise ValueError("C2C endpoint CMN#%u has no device at ID 0x%x" % (mseq, node_id))
        self.system = system
        self.device = device
        self.node_type = node_type
        self.interface = interface
        self.link = None

    @property
    def node(self):
        """The selected node if already captured/discovered, otherwise None."""
        if self.node_type is None:
            return None
        return self.device.cached_node_by_type(self.node_type)

    def __str__(self):
        s = "CMN#%u ID=0x%x" % (self.device.CMN().cmn_seq, self.device.node_id())
        if self.node_type is not None:
            s += " type=%s(0x%x)" % (cmn_node_type_str(self.node_type), self.node_type)
            if self.node is None:
                s += " [unresolved node]"
        if self.interface is not None:
            s += " interface=%u" % self.interface
        return s


class C2CLink(object):
    """
    A system-owned direct connection with two C2CLinkEndpoint objects.

    Endpoints have no source/destination ordering. This describes adjacency,
    not a route through intermediate chips or a port aggregation group.
    See CMN S3(AE) TRM (107858), multi-chip port-to-port forwarding topology:
    https://documentation-service.arm.com/static/678ac7553f2a9a07789e5224

    Construction validates the whole connection before registering it with
    the system, meshes and devices. Node type annotates an endpoint; it does
    not create another interface on a slot shared by several node roles.
    """
    def __init__(self, system, id, endpoints, protocol=None, description=None):
        if not isinstance(system, System):
            raise TypeError("C2C link owner must be a System")
        if not isinstance(id, basestring):
            raise TypeError("C2C link ID must be a string")
        if not id.strip():
            raise ValueError("C2C link ID must not be empty")
        for name, value in [("protocol", protocol), ("description", description)]:
            if value is not None and not isinstance(value, basestring):
                raise TypeError("C2C %s must be a string" % name)
        if not isinstance(endpoints, (list, tuple)):
            raise TypeError("C2C endpoints must be a list or tuple")
        if len(endpoints) != 2:
            raise ValueError("C2C link must have exactly two endpoints")
        if any(link.id == id for link in system.c2c_links):
            raise ValueError("duplicate C2C link ID: %s" % id)
        for endpoint in endpoints:
            if not isinstance(endpoint, C2CLinkEndpoint):
                raise TypeError("C2C link endpoints must be C2CLinkEndpoint objects")
            if endpoint.system is not system or endpoint.device.CMN() not in system.CMNs:
                raise ValueError("C2C endpoint belongs to a different system")
            if endpoint.link is not None:
                raise ValueError("C2C endpoint already belongs to a link")
            for previous in endpoint.device.c2c_endpoints():
                if (endpoint.interface is None or previous.interface is None or
                        endpoint.interface == previous.interface):
                    raise ValueError("C2C endpoint %s conflicts with link %s; "
                                     "parallel connections require distinct interfaces" %
                                     (endpoint, previous.link.id))
        if endpoints[0].device.CMN() is endpoints[1].device.CMN():
            raise ValueError("C2C link endpoints must belong to different meshes")
        self.system = system
        self.id = id
        self.endpoints = tuple(endpoints)
        self.protocol = protocol
        self.description = description
        system.c2c_links.append(self)
        for endpoint in self.endpoints:
            endpoint.link = self
            endpoint.device._c2c_endpoints.append(endpoint)
            endpoint.device.CMN()._c2c_links.append(self)

    def other_endpoint(self, endpoint):
        """Return the peer of an endpoint belonging to this link."""
        if endpoint is self.endpoints[0]:
            return self.endpoints[1]
        if endpoint is self.endpoints[1]:
            return self.endpoints[0]
        raise ValueError("endpoint does not belong to C2C link %s" % self.id)


class IOAddressResource:
    """A named physical-address resource within an I/O SAM region."""
    def __init__(self, start, end, name):
        check_integer(start, "resource start")
        check_integer(end, "resource end", minimum=start)
        if not isinstance(name, basestring):
            raise TypeError("resource name must be a string")
        self.start = start
        self.end = end
        self.name = name


class IOAddressRegion:
    """A non-hashed SAM region homed by an I/O node."""
    def __init__(self, start, end, status="ok", resources=None):
        check_integer(start, "region start")
        check_integer(end, "region end", minimum=start)
        if status not in ["ok", "inconsistent"]:
            raise ValueError("invalid I/O region status: %r" % status)
        self.start = start
        self.end = end
        self.status = status
        self.resources = [] if resources is None else list(resources)
        for resource in self.resources:
            if not isinstance(resource, IOAddressResource):
                raise TypeError("I/O region resources must be IOAddressResource objects")
            if resource.start < start or resource.end > end:
                raise ValueError("I/O resource extends outside its region")


class IOAddressHome:
    """An I/O home-node reference and the physical regions it hosts."""
    def __init__(self, mseq, node_id, type_s, regions=None):
        check_integer(mseq, "I/O home mesh number")
        check_integer(node_id, "I/O home node ID", maximum=NODE_INFO_FIELD_MAX)
        if not isinstance(type_s, basestring):
            raise TypeError("I/O home node type must be a string")
        self.mseq = mseq
        self.node_id = node_id
        self.type_s = type_s
        self.regions = [] if regions is None else list(regions)
        if any(not isinstance(region, IOAddressRegion) for region in self.regions):
            raise TypeError("I/O home regions must be IOAddressRegion objects")


class IOAddressMap:
    """Optional whole-system capture of non-hashed I/O address homing."""
    def __init__(self, discovery_time=None, homes=None):
        self.discovery_time = discovery_time
        self.homes = [] if homes is None else list(homes)
        if any(not isinstance(home, IOAddressHome) for home in self.homes):
            raise TypeError("I/O map homes must be IOAddressHome objects")


class NodeGroup:
    """
    Abstract base class for a group of nodes, either one mesh or several.
    """
    def home_nodes(self):
        for node in self.nodes():
            if node.has_properties(CMN_PROP_HNF):
                yield node


class System(NodeGroup):
    """
    Represent a complete system consisting of one or more CMN meshes,
    and perhaps some uniquely numbered CPUs.
    """
    def __init__(self, filename=None, timestamp=None):
        self.filename = filename  # Name of the descriptor file, if known
        self.version = SYSTEM_DESC_VERSION
        self.timestamp = timestamp    # topology discovery time
        self.cpu_timestamp = None     # CPU location discovery time
        self.system_type = None  # SoC type, e.g. "Arm N1SDP"
        self.system_uuid = None  # System UUID, if known - should be Python uuid.UUID object
        self.processor_type = None  # Processor (CPU) type
        self.CMNs = []           # CMN mesh instances - order should match kernel PMU "arm_cmn_<n>" numbering
        self.cpu_node = {}       # CPU number -> CPU object
        self.io_address_map = None  # optional non-hashed I/O address capture
        self.c2c_links = []      # direct chip-to-chip connections, possibly incomplete
        self._has_HNS = None     # system uses HN-S rather than HN-F - cached value

    def cmn_version(self):
        """
        Assuming all the CMNs in a system are the same version,
        return the version number. Conceivably a system might be
        designed with different types of CMN.
        """
        v = None
        for c in self.CMNs:
            if c.product_config is None:
                return None      # CMN with unknown version
            if v is not None and c.product_config != v:
                return None      # CMN version mismatch (possible, but unlikely)
            v = c.product_config
        return v

    def has_multiple_cmn(self):
        """
        Return true if this system has multiple instances of CMN. In this case,
        CHI SRCID/TGTID will need to be interpreted relative to an instance number.
        """
        return len(self.CMNs) > 1

    def cmn_at_base(self, addr):
        """
        Find CMN instance object by PERIPHBASE address.
        """
        for c in self.CMNs:
            if addr == c.periphbase:
                return c
        return None

    def cmn_instances(self, instance=None):
        for (i, c) in enumerate(self.CMNs):
            if instance is None or instance == i:
                yield c

    def create_CMN(self, dimX=None, dimY=None, extra_ports=None, config=None):
        """
        Create a CMN instance in the system.
        """
        if config is None:
            raise TypeError("CMN product configuration must be provided")
        c = CMN(self, dimX=dimX, dimY=dimY, cmn_seq=len(self.CMNs), config=config, extra_ports=extra_ports)
        self.CMNs.append(c)
        return c

    def has_cpu_mappings(self):
        """
        Return True if this system description object has been populated with CPU locations.
        These are typically discovered empirically and may vary from instance to instance.
        """
        return bool(self.cpu_node)

    def create_c2c_link(self, id, endpoints, protocol=None, description=None):
        """Validate and register a direct connection between two meshes."""
        return C2CLink(self, id, endpoints, protocol=protocol, description=description)

    def cpu(self, n):
        if not self.has_cpu_mappings():
            raise CMNNoCPUMappings()
        return self.cpu_node[n]

    def cpus(self):
        if not self.has_cpu_mappings():
            raise CMNNoCPUMappings()
        for cn in sorted(self.cpu_node.keys()):
            yield self.cpu_node[cn]

    def discard_cpu_mappings(self):
        for cmn in self.CMNs:
            cmn.id_lpid_cpu = {}
        for port in self.ports():
            for dn in port.device_numbers():
                dev = port.device(dn)
                if dev is not None:
                    dev.cpus = []
        self.cpu_node = {}
        self.cpu_timestamp = None
        assert not self.has_cpu_mappings()

    def set_cpu(self, cpu, port, id, lpid=0):
        check_integer(cpu, "CPU number")
        if cpu in self.cpu_node:
            raise CMNBadStructure("duplicate CPU number: %u" % cpu)
        if not isinstance(port, CMNPort):
            raise TypeError("CPU port must be a CMNPort")
        if port.CMN().owner is not self:
            raise ValueError("CPU port belongs to a different system")
        if lpid is not None:
            check_integer(lpid, "CPU LPID")
        if id is not None:
            check_integer(id, "CPU node ID", maximum=NODE_INFO_FIELD_MAX)
        if id is None:
            device = port.device(0, create=True)
        else:
            device = port.device_at_id(id, create=True)
        co = CPU(cpu, device, lpid=lpid)
        port.add_cpu(co)
        self.cpu_node[cpu] = co

    def ports(self, properties=0):
        for c in self.CMNs:
            for port in c.ports(properties=properties):
                yield port

    def devices(self, properties=0):
        for c in self.CMNs:
            for d in c.devices(properties=properties):
                yield d

    def XPs(self):
        for c in sorted(self.CMNs, key=lambda c: c.cmn_seq):
            for xp in c.XPs():
                yield xp

    def nodes(self, properties=0):
        for c in self.CMNs:
            for node in c.nodes(properties=properties):
                yield node

    def has_HNS(self):
        """
        Return True if this system uses HN-S rather than HN-F.
        (This impacts on named PMU events.)
        """
        if self._has_HNS is None:
            for p in self.ports(properties=CMN_PROP_HNF):
                self._has_HNS = (p.connected_type == CMN_PORT_DEVTYPE_HNS)
                break
            assert self._has_HNS is not None, "no HN-F/HN-S nodes detected!"
        return self._has_HNS

    def __str__(self):
        """Keep a common product label only when configuration and dimensions agree."""
        if not self.CMNs:
            return "System 0 meshes"
        version = self.cmn_version()
        first = self.CMNs[0]
        if version is not None and all(
                (c.dimX, c.dimY) == (first.dimX, first.dimY) for c in self.CMNs):
            return "System %u x %s" % (len(self.CMNs), version.product_name(revision=True))
        return "System %u meshes: %s" % (len(self.CMNs), "; ".join(
            "%s: %s %ux%u" % (c, c.product_config if c.product_config is not None else
                               "unknown configuration", c.dimX, c.dimY)
            for c in self.CMNs))


class Requester:
    """
    A requester behind a CMN device slot, identified by CHI id and LPID.
    """
    def __init__(self, device, lpid=0):
        if not isinstance(device, CMNDevice):
            raise TypeError("requester device must be a CMNDevice")
        if lpid is not None:
            check_integer(lpid, "requester LPID")
        self.device = device
        self.lpid = lpid

    @property
    def port(self):
        return self.device.port

    @property
    def id(self):
        return self.device.node_id()

    def CMN(self):
        return self.port.CMN()


class CPU(Requester):
    """
    A CPU associated with an RN-F port. Multiple CPUs can be on the
    same port (e.g. with a DSU) but should be distinguished by LPID.
    """
    def __init__(self, cpu, device, lpid=0):
        check_integer(cpu, "CPU number")
        self.cpu = cpu      # unique CPU number as known to OS
        Requester.__init__(self, device, lpid=lpid)

    def __str__(self):
        s = "CPU#%u at %s SRCID=0x%x" % (self.cpu, self.port, self.id)
        if self.lpid is not None:
            s += " LPID=%u" % (self.lpid)
        return s


def id_coord_bits(dimX, dimY):
    """
    The number of bits used for both X and Y coordinates in device ids
    is derived from the larger of the two dimensions.
    """
    md = max(dimX, dimY)
    if md > 8:
        return 4
    elif md > 4:
        return 3
    else:
        return 2


class CMN(NodeGroup):
    """
    A CMN rectangular mesh, comprising a set of crosspoints (XPs).

    There may be multiple CMN meshes in a system.
    """
    def __init__(self, owner=None, dimX=None, dimY=None, cmn_seq=None, config=None, extra_ports=None):
        if owner is not None and not isinstance(owner, System):
            raise TypeError("CMN owner must be a System")
        if config is not None and not isinstance(config, CMNConfig):
            raise TypeError("CMN product configuration must be a CMNConfig")
        # The current model's coordinate encoding uses at most four bits.
        check_integer(dimX, "CMN X dimension", minimum=1, maximum=16)
        check_integer(dimY, "CMN Y dimension", minimum=1, maximum=16)
        if cmn_seq is not None:
            check_integer(cmn_seq, "CMN sequence number")
        if extra_ports is not None and not isinstance(extra_ports, bool):
            raise TypeError("extra_ports must be a boolean or None")
        self.owner = owner     # e.g. System
        self.product_config = config
        self.cmn_seq = cmn_seq          # sequence number within the system
        self.periphbase = None
        self.rootnode_offset = None     # For early CMNs: None means not known
        self.node_skiplist = None
        self.dimX = dimX
        self.dimY = dimY
        self.id_coord_bits = id_coord_bits(self.dimX, self.dimY)
        self.xy_xp = {}        # map (x, y) -> xp
        self.id_xp = {}        # map xp id -> xp
        self.debug_nodes = []
        self.id_nodes = {}     # map node id -> (type -> node)
        self.id_lpid_cpu = {}  # map (id, lpid) -> cpu
        self.extra_ports = extra_ports    # set to True when we see an XP with >2 ports
        self.frequency = None  # clock frequency not generally known (yet)
        self._home_node_type = None     # populated as ports/nodes are added
        self._c2c_links = []

    def home_node_type(self):
        """Return the recorded home-node type code, or None; no discovery."""
        return self._home_node_type

    def _record_home_node_type(self, node_type):
        """Record existing topology metadata, rejecting mixed home types in one mesh."""
        if not cmn_node_type_has_properties(node_type, CMN_PROP_HNF):
            return
        if self._home_node_type is not None and self._home_node_type != node_type:
            raise CMNBadStructure("CMN#%s: conflicting home-node types: %s and %s" %
                                  (self.cmn_seq, cmn_node_type_str(self._home_node_type),
                                   cmn_node_type_str(node_type)))
        self._home_node_type = node_type

    def c2c_links(self):
        """Iterate recorded links incident on this mesh without discovery."""
        return iter(self._c2c_links)

    def is_live(self):
        """
        This model describes topology only; it does not provide status queries.
        """
        return False

    def XPs(self):
        """
        Yield all XPs in this mesh, sorted by node id, or equivalently,
        sorted by (X, Y) tuple, i.e lower left first, then up, then right.
        """
        for xpi in sorted(self.id_xp.keys()):
            yield self.id_xp[xpi]

    def XP_at(self, x, y):
        """
        Return the XP at a specific (x, y) coordinate.
        """
        return self.xy_xp[(x, y)]

    def XP(self, id):
        """
        Return the XP with the given node id, or None if it is not present.
        """
        return self.id_xp.get(id, None)

    def xy_id(self, x, y):
        """
        Calculate the XP id from coordinates
        """
        return (x << (3 + self.id_coord_bits)) | (y << 3)

    def id_xy(self, id):
        """
        Calculate the (X, Y) coordinates from a device id
        """
        return (BITS(id, 3+self.id_coord_bits, self.id_coord_bits), BITS(id, 3, self.id_coord_bits))

    def XP_port_device(self, id):
        """
        Return (XP, port number, device number) for a device id.
        """
        xp = self.XP(id & ~7)
        if xp is None:
            return (None, None, None)
        (port, dev) = xp.id_port_device(id)
        return (xp, port, dev)

    def ports(self, properties=0):
        """
        Yield all CMNPort objects for the mesh
        """
        for xp in self.XPs():
            for p in xp.ports():
                if p.has_properties(properties):
                    yield p

    def cpus(self):
        """
        Yield all CPUs in this mesh
        """
        for cpu in self.owner.cpus():
            if cpu.CMN() == self:
                yield cpu

    def has_cpu_mappings(self):
        return self.owner.has_cpu_mappings()

    def add_cpu(self, co):
        """
        Add a CPU to this mesh's (id, lpid) map.
        We check for conflicting entries for a given id:
          (id, n) and (id, n)
          (id, n) and (id, None)
        """
        k = (co.id, co.lpid)
        ex = None
        if k in self.id_lpid_cpu:
            ex = self.id_lpid_cpu[k]
        elif (co.id, None) in self.id_lpid_cpu:
            ex = self.id_lpid_cpu[(co.id, None)]
        elif co.lpid is None:
            cpus_here = list(self.cpus_at_id(co.id))
            if cpus_here:
                ex = cpus_here[0]
        if ex is not None:
            raise CMNBadStructure("%s: duplicate CPU index: %s vs %s" % (self, ex, co))
        self.id_lpid_cpu[(co.id, co.lpid)] = co

    def port_at_id(self, id):
        """
        Get the CMNPort object which owns a given id.
        """
        xp_id = (id & ~7)
        if xp_id not in self.id_xp:
            return None
        xp = self.id_xp[xp_id]
        for p in xp.ports():
            if p.is_valid_id(id):
                return p
        return None

    def device_at_id(self, id, create=False):
        """
        Get the CMNDevice object represented by a given id.
        """
        return cmn_device_at_id(self, id, create=create)

    def cpus_at_id(self, id):
        for co in self.id_lpid_cpu.values():
            if co.id == id:
                yield co

    def xp_ports(self):
        """
        Yield (xp, n) pairs
        """
        for p in self.ports():
            yield (p.xp, p.port_number)

    def nodes(self, properties=0):
        """
        Yield CMN device nodes matching properties. This does not include
        RN-F and SN-F nodes, as these are external to the CMN.
        """
        for (xp, p) in self.xp_ports():
            for node in xp.port_nodes(p):
                if node.has_properties(properties):
                    yield node

    def devices(self, properties=0, props=None):
        """
        Yield CMN device slots matching properties. Unlike nodes(), this includes
        external attachments such as RN-F and SN-F.
        """
        if props is not None:
            properties = props
        for p in self.ports():
            for dev in port_devices(p, create=True, properties=properties):
                yield dev

    def ids(self, properties=0):
        """
        Yield CHI node ids for all nodes matching properties.
        """
        for p in self.ports(properties=properties):
            for id in p.ids():
                yield id

    def rnf_ids(self):
        """
        Yield CHI node ids for all RN-Fs in this mesh.
        RN-Fs are special, as there may be more than one on a port
        but they don't have associated device nodes.
        """
        for id in self.ids(properties=CMN_PROP_RNF):
            yield id

    def sn_ids(self):
        """
        Yield CHI node ids for all subordinate nodes (SNs) in this mesh.
        SN-Fs are special, c.f. rnf_ids() above.
        """
        for id in self.ids(properties=CMN_PROP_SN):
            yield id

    def node_by_id_type(self, id, type):
        if id not in self.id_nodes:
            return None
        elif type in self.id_nodes[id]:
            return self.id_nodes[id][type]
        else:
            return None

    def node_by_type_and_logical_id(self, node_type, nid):
        if node_type == CMN_NODE_XP:
            for xp in self.XPs():
                if xp.logical_id() == nid:
                    return xp
        else:
            for types in self.id_nodes.values():
                node = types.get(node_type, None)
                if node is not None and node.logical_id() == nid:
                    return node
        raise KeyError((node_type, nid))

    def cpu_from_id(self, id, lpid=0):
        return self.id_lpid_cpu.get((id, lpid), None)

    def create_xp(self, x, y, id=None, n_ports=None, logical_id=None, dtc=None, disabled=False):
        """
        Create a new XP within this CMN instance.
        n_ports indicates the configured number of ports, which might not
        all be in use. E.g. if the XP is configured with 3 ports of which P0 and P2
        are in use, pass in n_ports=3.
        """
        xp = CMNNodeXP(owner=self, id=id, logical_id=logical_id, n_ports=n_ports, x=x, y=y, disabled=disabled)
        if dtc is not None:
            check_integer(dtc, "DTC domain", maximum=NODE_INFO_FIELD_MAX)
        xy = (x, y)
        if xy in self.xy_xp:
            raise CMNBadStructure("XP (%u,%u) already registered" % (x, y))
        if xp.id in self.id_xp:
            raise CMNBadStructure("duplicate XP ID: 0x%x" % xp.id)
        self.xy_xp[xy] = xp
        self.id_xp[xp.id] = xp
        xp.dtc = dtc
        # This deprecated summary flag must not override per-XP port counts.
        if n_ports > 2:
            self.extra_ports = True
        return xp

    def create_node(self, type, type_s=None, port_number=None, xp=None, id=None, logical_id=None, disabled=False):
        """
        Create a device node associated with a port
        """
        if not isinstance(xp, CMNNodeXP):
            raise TypeError("device node XP must be a CMNNodeXP")
        if xp.owner is not self:
            raise ValueError("device node XP belongs to a different CMN")
        check_integer(type, "node type", maximum=NODE_INFO_FIELD_MAX)
        check_integer(id, "node ID", maximum=NODE_INFO_FIELD_MAX)
        check_integer(port_number, "port number", maximum=xp.n_ports - 1)
        if self.node_by_id_type(id, type) is not None:
            raise CMNBadStructure("duplicate node type 0x%x at ID 0x%x" % (type, id))
        if type == CMN_NODE_DT:
            check_integer(logical_id, "DTC logical ID", maximum=NODE_INFO_FIELD_MAX)
            if logical_id < len(self.debug_nodes) and self.debug_nodes[logical_id] is not None:
                raise CMNBadStructure("duplicate DTC logical ID: %u" % logical_id)
        pd = xp.port(port_number)
        n = CMNNodeDev(type=type, type_s=type_s, owner=pd, id=id, logical_id=logical_id, disabled=disabled)
        pd.device_nodes.append(n)
        if n.id not in self.id_nodes:
            self.id_nodes[n.id] = {}
        self.id_nodes[n.id][type] = n
        if type == CMN_NODE_DT:
            # add to the CMN's debug_nodes array
            while len(self.debug_nodes) < logical_id:
                self.debug_nodes.append(None)
            self.debug_nodes = self.debug_nodes[:logical_id] + [n] + self.debug_nodes[logical_id+1:]
        return n

    def __str__(self):
        s = "CMN#%u" % self.cmn_seq
        if False:
            s += " (%s)" % self.product_config.product_name()
        if False and self.periphbase is not None:
            # Show where the CMN lives in device space - experts only
            s += " @0x%x" % self.periphbase
        return s


class CMNDevice:
    """
    A CHI-addressable device slot on a port, identified by a device number
    and corresponding node id. This may comprise several internal device nodes,
    or no explicit CMN nodes at all for external attachments such as RN-Fs.
    """
    def __init__(self, port=None, node_id=None, device_number=None):
        if not isinstance(port, CMNPort):
            raise TypeError("device port must be a CMNPort")
        check_integer(node_id, "device node ID", maximum=NODE_INFO_FIELD_MAX)
        check_integer(device_number, "device number", maximum=7)
        if node_id != port_device_id(port, device_number):
            raise ValueError("device node ID does not match port base ID and device number")
        if not port.xp.is_valid_id(node_id):
            raise ValueError("%s: bad node ID 0x%x" % (port, node_id))
        self.port = port
        self._node_id = node_id
        self.device_number = device_number
        self.device_credited_slices = None
        self.device_nodes = []       # Order of device nodes is not significant
        self.cpus = []
        self._c2c_endpoints = []

    def c2c_endpoints(self):
        """Iterate recorded link endpoints attached to this device slot."""
        return iter(self._c2c_endpoints)

    def cached_node_by_type(self, node_type):
        """Resolve an explicit node using captured topology only."""
        for node in self.device_nodes:
            if node.type() == node_type:
                return node
        return None

    def node_id(self):
        return port_device_id(self.port, self.device_number)

    def CMN(self):
        return self.port.CMN()

    def XP(self):
        return self.port.XP()

    def PD(self):
        return (self.port.port_number, self.device_number)

    def has_properties(self, props):
        return device_has_properties(self, props)

    def __str__(self):
        return "%s.d%u" % (self.port.path_str(), self.device_number)


class CMNPort:
    """
    Not a separate device, but a port on an XP.
    This may have a "connected device type".
    """
    def __init__(self, xp=None, port_number=None, type=None, type_s=None, cal=None, base_id=None):
        if not isinstance(xp, CMNNodeXP):
            raise TypeError("port XP must be a CMNNodeXP")
        check_integer(port_number, "port number", maximum=xp.n_ports - 1)
        check_integer(base_id, "port base ID", maximum=NODE_INFO_FIELD_MAX)
        if type is not None:
            check_integer(type, "port type", maximum=NODE_INFO_FIELD_MAX)
        if type_s is not None and not isinstance(type_s, basestring):
            raise TypeError("port type description must be a string")
        if not xp.is_valid_id(base_id):
            raise ValueError("%s P%u: bad port base ID 0x%x" % (xp, port_number, base_id))
        if cal is not None:
            check_integer(cal, "CAL count", maximum=8)
            if not xp.is_valid_id(base_id + max(cal, 1) - 1):
                raise ValueError("CAL device IDs extend outside the XP")
        self.xp = xp
        self.port_number = port_number
        self._base_id = base_id
        self.connected_type = type
        if type_s is None and type is not None:
            type_s = cmn_port_device_type_str(type)
        self.connected_type_s = type_s
        self.cal = cal
        self.cal_credited_slices = None
        self.device_nodes = []     # will be populated with connected CMNNodeDevs
        self.pdevices = {}    # CMNDevice objects, indexed by device number

    @property
    def port(self):
        """
        Compatibility alias for port_number.
        """
        return self.port_number

    def device_type(self):
        """
        Compatibility alias for connected_type.
        """
        return self.connected_type

    def base_id(self):
        """
        The base id for devices on this port. Now recorded explicitly.
        """
        return self._base_id

    def ids(self):
        """
        The CHI id(s) for devices on this port.
        """
        for id in port_ids(self):
            yield id

    def devices(self, properties=CMN_PROP_none):
        """
        Stored devices on this port, in device number order, optionally filtered.
        This does not materialize slots implied only by the CAL.
        """
        for dev in port_devices(self, properties=properties,
                                device_numbers=sorted(self.pdevices.keys())):
            yield dev

    def is_valid_id(self, id):
        """
        Check if a device id is valid for this port.
        """
        return port_device_number(self, id) in self.device_numbers()

    def create_device(self, device_number):
        """
        Create a device on this port.
        """
        check_integer(device_number, "device number", maximum=7)
        if device_number not in self.pdevices:
            self.pdevices[device_number] = CMNDevice(self, node_id=port_device_id(self, device_number), device_number=device_number)
        return self.pdevices[device_number]

    def device(self, device_number, create=False):
        if create:
            return self.create_device(device_number)
        return self.pdevices.get(device_number, None)

    def device_at_id(self, id, create=False):
        return port_device_at_id(self, id, create=create)

    def device_numbers(self):
        return port_device_numbers(self, self.pdevices.keys())

    def device_credited_slices(self, d):
        dn = self.pdevices.get(d, None)
        return dn.device_credited_slices if dn is not None else None

    def device_has_explicit_description(self, d):
        dev = self.device(d)
        if dev is None:
            return False
        return bool(dev.device_nodes) or (dev.device_credited_slices not in [None, 0])

    def nodes(self, discover=True):
        """Yield stored nodes; discover is accepted for live-model compatibility."""
        for dev in self.devices():
            for n in dev.device_nodes:
                yield n

    @property
    def cpus(self):
        """
        Aggregate CPUs attached to device slots on this port, preserving device order.
        """
        cpus = []
        for dev in self.devices():
            for cpu in dev.cpus:
                if cpu not in cpus:
                    cpus.append(cpu)
        return cpus

    def add_cpu(self, co):
        """
        Add a CPU object to this port, and to port's mesh's node-to-CPU map.
        """
        self.CMN().add_cpu(co)
        if co not in co.device.cpus:
            co.device.cpus.append(co)

    def XP(self):
        return self.xp

    def CMN(self):
        return self.xp.owner

    def has_properties(self, props):
        return port_has_properties(self, props)

    def path_str(self):
        return "%s.p%u" % (self.XP().path_str(), self.port_number)

    def __str__(self):
        """
        String method identifies the port uniquely in the whole system
        """
        #s = "CMN#%u P%u: %s" % (self.CMN().cmn_seq, self.port, self.connected_type_s)
        s = "%s(%s)" % (self.path_str(), self.connected_type_s)
        if self.cal:
            s += " CAL"
        return s


class CMNNodeBase:
    """
    A CMN node, addressed by a node id. This may be an XP, or a
    device node attached to an XP port.
    """
    def __init__(self, type=None, type_s=None, owner=None, id=None, logical_id=None, disabled=False):
        if not isinstance(disabled, bool):
            raise TypeError("node disabled must be a boolean")
        self.disabled = disabled
        check_integer(type, "node type", maximum=NODE_INFO_FIELD_MAX)
        check_integer(id, "node ID", maximum=NODE_INFO_FIELD_MAX)
        if logical_id is not None:
            check_integer(logical_id, "logical ID", maximum=NODE_INFO_FIELD_MAX)
        if type_s is not None and not isinstance(type_s, basestring):
            raise TypeError("node type description must be a string")
        self.owner = owner       # Either CMN (for XP) or port (for device node)
        self._type = type
        if type_s is None and type is not None:
            type_s = cmn_node_type_str(type)
        self.type_s = type_s
        self.id = id
        # The logical ID is user-allocated and should be unique for a given type
        self._logical_id = logical_id
        self.is_external = None

    def owning_cmn(self):
        """
        Compatibility alias for CMN().
        """
        return self.XP().owner

    def CMN(self):
        return self.XP().owner

    def logical_id(self):
        return self._logical_id

    def type(self):
        return self._type

    def type_str(self):
        return self.type_s

    def properties(self):
        return cmn_node_properties.get(self._type, CMN_PROP_none)

    def has_properties(self, props):
        return (self.properties() & props) == props

    def node_id(self):
        return self.id

    def is_XP(self):
        return self._type == CMN_NODE_XP

    def is_disabled(self):
        """Return the recorded disabled state, without discovering hardware state."""
        return self.disabled

    def is_rootnode(self):
        return False

    def XY(self):
        xp = self.XP()
        return (xp.x, xp.y)

    def coords(self):
        """
        Return (x, y, port, device)
        These are encoded into the 'id', but the encoding varies.
        """
        if self.is_XP():
            return (self.x, self.y, 0, 0)
        else:
            (x, y) = (self.owner.xp.x, self.owner.xp.y)
            return (x, y, self.owner.port_number, self.device_number)

    def dtc_domain(self):
        return self.XP().dtc

    def __repr__(self):
        return "%s(%x)" % (self.type_s, self.id)

    def __str__(self):
        """
        String method should identify the node uniquely in the entire system.
        """
        if self.is_XP():
            s = "%s(0x%x)" % (self.path_str(), self.id)
        else:
            s = "%s.%s" % (self.device_object, self.type_s)
        if self._logical_id is not None:
            s += "#%u" % self._logical_id
        if self.is_disabled():
            s += " (disabled)"
        return s


class CMNNodeDev(CMNNodeBase):
    """
    A CMN device node (not XP), on a port of an XP.

    The device node has its own node id, which should match the X/Y coordinate
    of the XP and the port number. Violations of this have been observed on
    some CMN-600 silicon.
    """
    def __init__(self, type=None, type_s=None, owner=None, id=None, logical_id=None, disabled=False):
        if not isinstance(owner, CMNPort):
            raise TypeError("device node owner must be a CMNPort")
        if type in [CMN_NODE_XP, CMN_NODE_CFG]:
            raise ValueError("XP and configuration nodes cannot be port device nodes")
        CMNNodeBase.__init__(self, type=type, type_s=type_s, owner=owner, id=id, logical_id=logical_id, disabled=disabled)
        dn = id - owner.base_id()
        if not 0 <= dn < 4:
            raise ValueError("%s: bad node ID 0x%x" % (owner, id))
        self.CMN()._record_home_node_type(type)
        self.device_object = self.owner.create_device(dn)
        self.device_object.device_nodes.append(self)
        self.device_number = dn

    @property
    def port(self):
        return self.owner

    @property
    def port_number(self):
        return self.owner.port_number

    def XP(self):
        return self.owner.xp

    def is_home_node(self):
        return self.has_properties(CMN_PROP_HNF)


# XP position in the mesh, which affects maximum number of ports.
# All combinations are possible, because the mesh might be 1 in some dimension.
POS_LEFT_EDGE    = 0x01
POS_RIGHT_EDGE   = 0x02
POS_BOTTOM_EDGE  = 0x04
POS_TOP_EDGE     = 0x08

_pos_n_links = [4, 3, 3, 2, 3, 2, 2, 1, 3, 2, 2, 1, 2, 1, 1, 0]

# Before recent versions of CMN S3, XPs were limited to at most 4 ports.
# Corner XPs can have 4 ports, edge XPs can have 3, others can have max 2
# This implies that the middle XP in a 3x1 mesh can only have 3 ports.
_links_max_ports = [4, 4, 4, 3, 2]


class CMNNodeXP(CMNNodeBase):
    """
    A CMN crosspoint (XP). This has device ports - often two, but sometimes more
    (for edge and corner crosspoints) or fewer.
    """
    def __init__(self, owner=None, id=None, logical_id=None, n_ports=None, x=None, y=None, disabled=False):
        if not isinstance(owner, CMN):
            raise TypeError("XP owner must be a CMN")
        if owner.product_config is None:
            raise ValueError("CMN product configuration is required to create an XP")
        check_integer(x, "XP X coordinate", maximum=owner.dimX - 1)
        check_integer(y, "XP Y coordinate", maximum=owner.dimY - 1)
        check_integer(n_ports, "XP port count", maximum=8)
        calc_id = owner.xy_id(x, y)
        if id is not None:
            check_integer(id, "XP node ID", maximum=NODE_INFO_FIELD_MAX)
            if calc_id != id:
                raise ValueError("(%u,%u) should have ID 0x%x, has 0x%x" % (x, y, calc_id, id))
        else:
            id = calc_id
        CMNNodeBase.__init__(self, type=CMN_NODE_XP, type_s="XP", owner=owner, id=id, logical_id=logical_id, disabled=disabled)
        self._port = {}
        self.x = x
        self.y = y
        if owner.product_config.is_before_gen(CMN_GEN_S3):
            max_ports = _links_max_ports[self.n_links()]
            if n_ports > max_ports:
                raise ValueError("%s: XP with %u links cannot have %u ports" % (self, self.n_links(), n_ports))
        self.n_ports = n_ports
        self.skipped_nodes = None
        self.mcs_east = None
        self.mcs_north = None

    def XP(self):
        return self

    def dtc_domains(self):
        """
        Return a list containing the saved DTC domain (None if unknown).
        The offline topology records one common domain, not individual DTMs.
        """
        return [self.dtc]

    def position(self):
        pos = 0
        if self.x == 0:
            pos |= POS_LEFT_EDGE
        if self.x == self.owner.dimX-1:
            pos |= POS_RIGHT_EDGE
        if self.y == 0:
            pos |= POS_BOTTOM_EDGE
        if self.y == self.owner.dimY-1:
            pos |= POS_TOP_EDGE
        return pos

    def n_links(self):
        """
        Return the number of mesh links, e.g. 2 for corner, 3 for edge, 4 for interior
        """
        return _pos_n_links[self.position()]

    def links(self):
        if self.y < self.owner.dimY-1:
            yield "n"
        if self.x < self.owner.dimX-1:
            yield "e"
        if self.x > 0:
            yield "w"
        if self.y > 0:
            yield "s"

    def mesh_credited_slices(self, i):
        return [self.mcs_east, self.mcs_north][i]

    def create_port(self, port_number, type=None, type_s=None, cal=None, base_id=None):
        check_integer(port_number, "port number", maximum=self.n_ports - 1)
        if port_number in self._port:
            raise CMNBadStructure("%s: duplicate port P%u" % (self, port_number))
        p = CMNPort(self, port_number, type=type, type_s=type_s, cal=cal, base_id=base_id)
        self.owner._record_home_node_type(
            {CMN_PORT_DEVTYPE_HNF: CMN_NODE_HNF, CMN_PORT_DEVTYPE_HNS: CMN_NODE_HNS}.get(type))
        self._port[port_number] = p
        return p

    def port(self, pn):
        return self._port.get(pn, None)

    def ports(self, properties=CMN_PROP_none):
        for pn in sorted(self._port.keys()):
            port = self._port[pn]
            if port.has_properties(properties):
                yield port

    def device_at_id(self, id, create=False):
        for p in self.ports():
            if p.is_valid_id(id):
                return p.device_at_id(id, create=create)
        return None

    def has_any_ports(self, props):
        """
        Return True if this XP has any ports with the given properties.
        """
        return any([port.has_properties(props) for port in self.ports()])

    def n_device_ports(self):
        return self.n_ports

    def is_valid_id(self, id):
        """
        Check if a node id is valid for this XP.
        """
        return (id & ~7) == self.id

    @property
    def n_children(self):
        return sum([len(p.device_nodes) for p in self.ports()])

    @property
    def children(self):
        return [d for p in self.ports() for d in p.device_nodes]

    def port_is_used(self, p):
        return (p in self._port)

    def port_device_type(self, p):
        return self._port[p].connected_type if self.port_is_used(p) else None

    def port_device_type_str(self, p):
        return self._port[p].connected_type_s

    def port_nodes(self, p):
        """
        The list of all device nodes for a given port. Indexes in this list
        are not the "device number" - the list may include several CMN nodes
        for a given device number.
        """
        return self._port[p].device_nodes

    def port_base_id(self, p):
        port = self.port(p)
        if port is None:
            raise IndexError("%s: bad port number P%u" % (self, p))
        return port.base_id()

    def id_port_device(self, id):
        """
        Resolve a node id into a port number and device number
        """
        d = self.device_at_id(id)
        if d is None:
            raise KeyError(id)
        return d.PD()

    def path_str(self):
        (x, y, p, d) = self.coords()
        return "%s.mxp(%u,%u)" % (self.CMN(), x, y)


class CacheGeometry:
    """
    Represent the size, arrangement etc. of a cache or cache slice.
    """
    def __init__(self, n_ways=None, n_sets_log2=None, line_size=64):
        self.n_ways = n_ways
        self.n_sets_log2 = n_sets_log2
        self.line_size = line_size
        self.sf_ways = None
        self.sf_n_sets_log2 = None

    def exists(self):
        return self.n_sets_log2 is not None

    def __eq__(self, c):
        return (self.n_ways == c.n_ways and
                self.n_sets_log2 == c.n_sets_log2 and
                self.sf_ways == c.sf_ways and
                (self.sf_ways is None or self.sf_n_sets_log2 == c.sf_n_sets_log2))

    @property
    def n_sets(self):
        return 1 << self.n_sets_log2

    @property
    def sf_n_sets(self):
        return 1 << self.sf_n_sets_log2

    @property
    def size_bytes(self):
        return self.n_ways * self.n_sets * self.line_size

    @property
    def sf_size(self):
        return (1 << self.sf_n_sets_log2) * self.sf_n_ways

    def cache_str(self):
        if self.exists():
            s = "%s (%u sets) %u-way" % (memsize_str(self.size_bytes), self.n_sets, self.n_ways)
        else:
            s = "none"
        return s

    def sf_str(self):
        return "%s (%u sets) %u-way" % (memsize_str(self.sf_size), self.sf_n_sets, self.sf_n_ways)

    def __str__(self):
        s = self.cache_str()
        if self.sf_n_ways is not None:
            s += ", SF: " + self.sf_str()
        return s


def main(argv):
    assert False, "not designed to run as main program"


if __name__ == "__main__":
    main(sys.argv[1:])
