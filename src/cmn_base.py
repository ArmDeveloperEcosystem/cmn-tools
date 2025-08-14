#!/usr/bin/python3

"""
CMN mesh interconnect

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This module provides classes to model the structure of one or
more CMN mesh interconnects. Each mesh consists of a rectangular
grid of crosspoints (XPs), to which are attached devices such
as requestors and home nodes.

The classes (System, CMN, CMNNode and CPU) can be used directly,
or subclassed to provide more detailed functionality.

The CPU class is intended to help tools associate CPUs with RN-Fs.
CMN itself has no knowledge of which CPUs are connected where.
"""

from __future__ import print_function

from cmn_enum import *
from memsize_str import memsize_str


SYSTEM_DESC_VERSION = 1


def BITS(x, p, n):
    return (x >> p) & ((1 << n) - 1)


class CMNException(Exception):
    pass


class CMNNoCPUMappings(CMNException):
    def __str__(self):
        return "System description has no CPU locations - run cmn_detect_cpu.py"


class NodeGroup:
    """
    Abstract base class for a group of nodes, either one mesh or several.
    """
    def home_nodes(self, include_device=False):
        for node in self.nodes():
            if node.is_home_node(include_device=include_device):
                yield node


class System(NodeGroup):
    """
    Represent a complete system consisting of one or more CMN meshes,
    and perhaps some uniquely numbered CPUs.
    """
    def __init__(self, filename=None, timestamp=None):
        self.filename = filename  # Name of the descriptor file, if known
        self.version = SYSTEM_DESC_VERSION
        self.timestamp = timestamp    # discovery time of system info
        self.system_type = None  # SoC type, e.g. "Arm N1SDP"
        self.system_uuid = None  # System UUID, if known - should be Python uuid.UUID object
        self.processor_type = None  # Processor (CPU) type
        self.CMNs = []           # CMN mesh instances - order should match kernel PMU "arm_cmn_<n>" numbering
        self.cpu_node = {}       # CPU number -> CPU object
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

    def create_CMN(self, dimX=None, dimY=None, extra_ports=None):
        c = CMN(self, dimX=dimX, dimY=dimY, seq=len(self.CMNs), extra_ports=extra_ports)
        self.CMNs.append(c)
        return c

    def has_cpu_mappings(self):
        """
        Return True if this system description object has been populated with CPU locations.
        These are typically discovered empirically and may vary from instance to instance.
        """
        return bool(self.cpu_node)

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
        for cpu in self.cpu_node.values():
            cpu.port.cpus = []
        self.cpu_node = {}
        assert not self.has_cpu_mappings()

    def set_cpu(self, cpu, port, id, lpid=0):
        assert cpu not in self.cpu_node
        assert isinstance(port, CMNPort)
        co = CPU(cpu, port, id, lpid)
        self.cpu_node[cpu] = co
        port.add_cpu(co)

    def ports(self, properties=0):
        for c in self.CMNs:
            for port in c.ports(properties=properties):
                yield port

    def XPs(self):
        for c in self.CMNs:
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
        return self._has_HNS

    def __str__(self):
        s = "System %u x %s" % (len(self.CMNs), self.cmn_version().product_name(revision=True))
        return s


class CPU:
    """
    A CPU associated with an RN-F port. Multiple CPUs can be on the
    same port but should be distinguished by LPID.
    """
    def __init__(self, cpu, port, id, lpid=0):
        assert isinstance(port, CMNPort)
        if id is not None:
            assert port.is_valid_id(id)
        else:
            id = port.base_id()
        self.cpu = cpu      # unique CPU number as known to OS
        self.port = port
        self.id = id        # CHI SRCID/TGTID - includes port and device bits
        self.lpid = lpid

    def CMN(self):
        return self.port.CMN()

    def __str__(self):
        s = "CPU#%u at %s SRCID=0x%x LPID=%u" % (self.cpu, self.port, self.id, self.lpid)
        return s


PART_CMN600 = 0x434
PART_CMN650 = 0x436
PART_CMN600AE = 0x438
PART_CMN700 = 0x43c
PART_CI700  = 0x43a
PART_CMN_S3 = 0x43e


_cmn_product_names_by_id = {
    0x434: "CMN-600",
    0x436: "CMN-650",
    0x438: "CMN-600AE",
    0x43c: "CMN-700",
    0x43a: "CI-700",
    0x43e: "CMN S3",
}


def product_id_str(n):
    if n is None:
        return "CMN-unknown"
    elif n in _cmn_product_names_by_id:
        return _cmn_product_names_by_id[n]
    elif n in [600, 650, 700]:
        return "CMN-%u" % n   # Legacy
    return "CMN-0x%x??" % n


def canon_product_id(n):
    if n == 600:
        return PART_CMN600
    if n == 650:
        return PART_CMN650
    if n == 700:
        return PART_CMN700
    return n


cmn_products_by_name = {
    "CMN-600": 0x434,
    "CMN-650": 0x436,
    "CMN-700": 0x43c,
    "CI-700": 0x43a,
    "CMN-S3": 0x43e,
}


# map the periph_id_2 codes on to releases.
# Not systematic - CMN-600 r2p1 has a higher code than r3p0
# TBD: the CMN-600 r2p1 and r3p2 TRMs disagree on the numbering.
# TBD: CMN S3 r2p1, r2p2 and r2p3 are tentative awaiting documentation.

cmn_revisions = {
    0x434: ["r1p0", "r1p1", "r1p2", "r1p3", "r2p0", "r3p0", "r2p1"],
    0x436: ["r0p0", "r1p0", "r1p1", "r2p0", "r1p2"],
    0x43c: ["r0p0", "r1p0", "r2p0", "r3p0"],
    0x43a: ["r0p0", "r1p0", "r2p0"],
    0x43e: ["r0p0", "r0p1", "r1p0", "r2p0", "r2p1", "r2p2", "r2p3"],
}


class CMNConfig:
    """
    CMN product and major configuration. This object models the overall
    identity of the CMN product that we're dealing with, namely:
      - which out of CMN-600, CMN-650, CMN-700, CI-700 etc.
      - revision number
    Instance-specific configuration e.g. X and Y dimensions,
    is not modelled here.

    It is tempting to assign a linear correspondence between product versions/releases,
    and features, but we don't know if that's a valid assumption. E.g. maybe some feature
    is added in product N+1 but also in release R+1 of a previous product.
    """
    def __init__(self, product_id=None, product_name=None, revision=None, chi_version=None, mpam_enabled=None):
        self.product_id = product_id
        if product_name is not None:
            assert product_id is None
            product_name = product_name.upper().replace(' ', '-')
            self.product_id = cmn_products_by_name[product_name]
        self.mpam_enabled = mpam_enabled
        self.chi_version = chi_version
        self.revision = revision

    def product_name(self, revision=False):
        """
        Look up the product id and revision to get a product name,
        e.g. "CMN 700 r1p0"
        """
        try:
            s = _cmn_product_names_by_id[self.product_id]
        except LookupError:
            s = "unknown product (%s)" % str(self.product_id)
        if revision:
            if self.revision is not None:
                try:
                    s += " " + cmn_revisions[self.product_id][self.revision]
                except LookupError:
                    s += " rev=%u?" % self.revision
            else:
                s += " rev?"
        return s

    def chi_version_str(self):
        if self.chi_version is None:
            return None
        else:
            try:
                return "CHI-" + ("?ABCDEFGHI"[self.chi_version])
            except LookupError:
                return "CHI-?(%s)" % self.chi_version

    def __eq__(self, b):
        return isinstance(b, CMNConfig) and self.product_id == b.product_id and self.mpam_enabled == b.mpam_enabled

    def __ne__(self, b):
        return not self == b

    def __str__(self):
        s = self.product_name()
        if self.mpam_enabled:
            s += " (MPAM)"
        return s


def cmn_version(s):
    """
    Given a string, e.g. "cmn-700", return a CMNConfig object.
    """
    if s.find('-') < 0:
        s = "cmn-" + s
    return CMNConfig(product_name=s)


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
    def __init__(self, owner=None, dimX=None, dimY=None, seq=None, config=None, extra_ports=None):
        self.owner = owner     # e.g. System
        self.product_config = config
        self.seq = seq         # sequence number within the system
        self.periphbase = None
        self.rootnode_offset = None     # For early CMNs: None means not known
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

    def xp_ports(self):
        """
        Yield (xp, n) pairs
        """
        for p in self.ports():
            yield (p.xp, p.port)

    def nodes(self, properties=0):
        """
        Yield CMN nodes matching properties. This does not include
        RN-F and SN-F nodes, as these are external to the CMN.
        """
        for (xp, p) in self.xp_ports():
            for node in xp.port_nodes(p):
                if node.has_properties(properties):
                    yield node

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

    def cpu_from_id(self, id, lpid=0):
        return self.id_lpid_cpu.get((id, lpid), None)

    def create_xp(self, x, y, id=None, n_ports=None, logical_id=None, dtc=None):
        """
        Create a new XP within this CMN instance.
        n_ports indicates the configured number of ports, which might not
        all be in use. E.g. if the XP is configured with 3 ports of which P0 and P2
        are in use, pass in n_ports=3.
        """
        xp = CMNXP(owner=self, id=id, logical_id=logical_id, n_ports=n_ports, x=x, y=y)
        xy = (x, y)
        assert xy not in self.xy_xp, "XP (%u,%u) already registered" % (x, y)
        self.xy_xp[xy] = xp
        assert xp.id not in self.id_xp
        self.id_xp[xp.id] = xp
        xp.dtc = dtc
        # If at least one XP has >2 ports, it changes the ID scheme for all devices
        if n_ports > 2 and not self.extra_ports:
            assert self.extra_ports is None
            self.extra_ports = True
        return xp

    def create_node(self, type, type_s=None, port=None, xp=None, id=None, logical_id=None):
        assert type != CMN_NODE_XP        # use create_xp to create XP node
        assert type != CMN_NODE_CFG       # config node not explicit in data structure
        pd = xp.port[port]
        n = CMNNode(type=type, type_s=type_s, owner=pd, id=id, logical_id=logical_id)
        pd.devices.append(n)
        n.port = port
        if n.id not in self.id_nodes:
            self.id_nodes[n.id] = {}
        self.id_nodes[n.id][type] = n
        if type == CMN_NODE_DT:
            # add to the CMN's debug_nodes array
            assert logical_id is not None
            while len(self.debug_nodes) < logical_id:
                self.debug_nodes.append(None)
            self.debug_nodes = self.debug_nodes[:logical_id] + [n] + self.debug_nodes[logical_id+1:]
        return n

    def __str__(self):
        s = "CMN#%u" % self.seq
        s += " (%s)" % self.product_config.product_name()
        if False and self.periphbase is not None:
            # Show where the CMN lives in device space - experts only
            s += " @0x%x" % self.periphbase
        return s


class CMNPort:
    """
    Not a separate device, but a port on an XP.
    This may have a "connected device type".
    """
    def __init__(self, xp=None, port=None, type=None, type_s=None, cal=None):
        assert isinstance(xp, CMNXP), "attempt to create port on non-XP: %s" % xp
        assert port in [0, 1, 2, 3], "unexpected port number: %s" % port
        self.xp = xp
        self.port = port
        self.connected_type = type
        if type_s is None and type is not None:
            type_s = cmn_port_device_type_strings[type]
        self.connected_type_s = type_s
        self.cal = cal
        self.devices = []     # will be populated with connected CMNNodes
        self.cpus = []        # for RN-Fs, will be populated with CPU objects

    def base_id(self):
        """
        The base id for devices on this port. With a CAL, multiple devices
        will be distinguished by LSBs. The port base id is itself distinguished
        from the XP id, by bit 2 or bits 2:1.
        """
        return self.xp.node_id() + (self.port << self.xp.id_device_bits())

    def ids(self):
        """
        The CHI id(s) for devices on this port.
        """
        yield self.base_id()
        if self.cal:
            yield self.base_id() + 1
            if self.cal == 3 or self.cal == 4:
                yield self.base_id() + 2
                if self.cal == 4:
                    yield self.base_id() + 3

    def is_valid_id(self, id):
        """
        Check if a device id is valid for this port.
        """
        bid = self.base_id()
        if not self.cal:
            mask = 0
        else:
            mask = (1 << self.xp.id_device_bits()) - 1
        return (id & ~mask) == bid

    def add_cpu(self, co):
        self.CMN().id_lpid_cpu[(co.id, co.lpid)] = co
        self.cpus.append(co)

    def XP(self):
        return self.xp

    def CMN(self):
        return self.xp.owner

    def properties(self):
        return cmn_port_properties[self.connected_type]

    def has_properties(self, props):
        return (self.properties() & props) == props

    def __str__(self):
        """
        String method identifies the port uniquely in the whole system
        """
        #s = "CMN#%u P%u: %s" % (self.CMN().seq, self.port, self.connected_type_s)
        s = "%s P%u: %s" % (self.XP(), self.port, self.connected_type_s)
        if self.cal:
            s += " CAL"
        return s


class CMNNodeBase:
    """
    A CMN node, addressed by a node id. This may be an XP, or a
    device node attached to an XP port.
    """
    def __init__(self, type=None, type_s=None, owner=None, id=None, logical_id=None):
        self.owner = owner       # Either CMN (for XP) or port (for device node)
        self._type = type
        if type_s is None and type is not None:
            type_s = cmn_node_type_strings[type]
        self.type_s = type_s
        self.id = id
        # The logical ID is user-allocated and should be unique for a given type
        self._logical_id = logical_id
        self.is_external = None

    def owning_cmn(self):
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
            return (x, y, self.owner.port, self.device)

    def dtc_domain(self):
        return self.XP().dtc

    def __repr__(self):
        return "%s(%x)" % (self.type_s, self.id)

    def __str__(self):
        """
        String method should identify the node uniquely in the entire system.
        """
        (x, y, p, d) = self.coords()
        if self.is_XP():
            s = "%s: XP 0x%x(%u,%u)" % (self.owning_cmn(), self.id, x, y)
        else:
            s = "%s: P%u D%u %s" % (self.XP(), p, d, self.type_s)
        if self._logical_id is not None:
            # The logical id is generally unique within a given device class
            s += " #%u" % self._logical_id
        return s


class CMNNode(CMNNodeBase):
    """
    A CMN device node (not XP), on a port of an XP.

    The device node has its own node id, which should match the X/Y coordinate
    of the XP and the port number. Violations of this have been observed on
    some CMN-600 silicon.
    """
    def __init__(self, type=None, type_s=None, owner=None, id=None, logical_id=None):
        assert isinstance(owner, CMNPort)
        assert type != CMN_NODE_XP
        device_mask = (1 << owner.XP().id_device_bits()) - 1
        assert device_mask in [0x1, 0x3]
        if (id & ~device_mask) != owner.base_id():
            if owner.CMN().product_config.product_id != PART_CMN600:
                assert False, "unexpected node id 0x%03x on %s" % (id, owner)
        CMNNodeBase.__init__(self, type=type, type_s=type_s, owner=owner, id=id, logical_id=logical_id)
        self.device = id & device_mask

    def XP(self):
        return self.owner.xp

    def is_home_node(self, include_device=False):
        if include_device:
            return self._type in CMN_NODE_all_HN
        else:
            return self.has_properties(CMN_PROP_HNF)


# XP position in the mesh, which affects maximum number of ports.
# All combinations are possible, because the mesh might be 1 in some dimension.
POS_LEFT_EDGE    = 0x01
POS_RIGHT_EDGE   = 0x02
POS_BOTTOM_EDGE  = 0x04
POS_TOP_EDGE     = 0x08

_pos_n_links = [4, 3, 3, 2, 3, 2, 2, 1, 3, 2, 2, 1, 2, 1, 1, 0]

# Corner XPs can have 4 ports, edge XPs can have 3, others can have max 2
# This implies that the middle XP in a 3x1 mesh can only have 3 ports.
_links_max_ports = [4, 4, 4, 3, 2]


class CMNXP(CMNNodeBase):
    """
    A CMN crosspoint (XP). This has device ports - often two, but sometimes more
    (for edge and corner crosspoints) or fewer.
    """
    def __init__(self, owner=None, id=None, logical_id=None, n_ports=None, x=None, y=None):
        assert isinstance(owner, CMN)
        calc_id = owner.xy_id(x, y)
        if id is not None:
            assert calc_id == id, "(%u,%u) should have id=0x%x, has 0x%x" % (x, y, calc_id, id)
        else:
            id = calc_id
        CMNNodeBase.__init__(self, type=CMN_NODE_XP, type_s="XP", owner=owner, id=id, logical_id=logical_id)
        self.port = {}
        self.x = x
        self.y = y
        max_ports = _links_max_ports[self.n_links()]
        assert n_ports <= max_ports, "%s: XP with %u links cannot have %u ports" % (self, self.n_links(), n_ports)
        self.n_ports = n_ports

    def XP(self):
        return self

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

    def create_port(self, port, type=None, type_s=None, cal=None):
        p = CMNPort(self, port, type=type, type_s=type_s, cal=cal)
        self.port[port] = p
        return p

    def ports(self):
        for pn in sorted(self.port.keys()):
            yield self.port[pn]

    def n_device_ports(self):
        return self.n_ports

    @property
    def n_children(self):
        return sum([len(p.devices) for p in self.ports()])

    @property
    def children(self):
        return [d for p in self.ports() for d in p.devices]

    def id_device_bits(self):
        """
        How many bits are used for port number vs. device, on this XP?
        The numbering scheme can be either 1:2 or 2:1. For an XP with more
        than two ports, it must be 2:1, but the question is what applies
        when some XPs in the mesh have more than two ports but this one
        doesn't. Documentation (CMN-700 TRM 3.4.2) strongly suggests that
        the scheme is mesh-wide, but in practice it turns out to be per-XP.
        """
        if True:
            extra_ports = self.n_ports > 2
        else:
            extra_ports = self.CMN().extra_ports
        return 1 if extra_ports else 2

    def port_is_used(self, p):
        return (p in self.port)

    def port_device_type(self, p):
        return self.port[p].connected_type if self.port_is_used(p) else None

    def port_device_type_str(self, p):
        return self.port[p].connected_type_s

    def port_nodes(self, p):
        """
        The list of all device nodes for a given port. Indexes in this list
        are not the "device number" - the list may include several CMN nodes
        for a given device number.
        """
        return self.port[p].devices

    def port_nodes_by_device(self, p, d):
        """
        All device nodes with a given device number.
        """
        for dev in self.port[p].devices:
            if dev.device == d:
                yield dev

    def port_has_cal(self, p):
        return self.port[p].cal

    def port_base_id(self, p):
        return self.port[p].base_id()


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


if __name__ == "__main__":
    assert False, "not designed to run as main program"
