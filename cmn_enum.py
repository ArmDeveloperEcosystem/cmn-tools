#!/usr/bin/python3

"""
Enumerators and strings for CMN-related constants.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

Mostly these are relevant when using the memory-mapped interface,
but they may be helpful for higher-level tools.

E.g. with Linux perf, CMN node type numbers can be used in the
'type' field of CMN PMU events.
"""

#
# Node/port properties.
#
# These provide a more systematic view of node (or port) types,
# than the raw "node type" or "connected device type" enumerators
# used by CMN itself.
#

CMN_PROP_none  = 0
CMN_PROP_RN    = 0x0001     # Requester e.g. RN-F, RN-I. Does not include HN-F.
CMN_PROP_HN    = 0x0002     # Home node e.g. HN-F, HN-I
CMN_PROP_SN    = 0x0004     # Memory controller
CMN_PROP_D     = 0x0010     # non-coherent
CMN_PROP_I     = 0x0020     # I/O coherent but not fully coherent
CMN_PROP_F     = 0x0040     # Fully coherent
CMN_PROP_CCG   = 0x0100     # Chip-to-chip gateway
CMN_PROP_RNF   = CMN_PROP_RN|CMN_PROP_F
CMN_PROP_RNI   = CMN_PROP_RN|CMN_PROP_I
CMN_PROP_RND   = CMN_PROP_RN
CMN_PROP_HNF   = CMN_PROP_HN|CMN_PROP_F
CMN_PROP_HNI   = CMN_PROP_HN|CMN_PROP_I
CMN_PROP_HND   = CMN_PROP_HN|CMN_PROP_D
CMN_PROP_SNF   = CMN_PROP_SN|CMN_PROP_F


# Node types. These are sub-objects within the CMN configuration space,
# either CFG, XP, or devices attached to XP ports.
# Note that RN-F and SN-F do not appear. They are discovered as
# a connected device type (see port_device_type) but have no nodes.
CMN_NODE_DN      = 1      # "DVM" in Table 2-7; home node for DVMOp operations
CMN_NODE_CFG     = 2      # Root node
CMN_NODE_DT      = 3      # Debug and Trace Controller
CMN_NODE_HNI     = 4
CMN_NODE_HNF     = 5      # Fully coherent Home Node inc. system cache (SLC) and/or SF
CMN_NODE_XP      = 6      # Switch/router node (mesh crosspoint)
CMN_NODE_SBSX    = 7      # CHI to ACE5-Lite bridge
CMN_NODE_MPAM_S  = 8      # new in CMN-650
CMN_NODE_MPAM_NS = 9      # new in CMN-650
CMN_NODE_RNI     = 10     # I/O-coherent Request Node bridge
CMN_NODE_RND     = 13
CMN_NODE_RNSAM   = 15
CMN_NODE_MTSX    = 16
CMN_NODE_HNP     = 17     # HN-I optimized for peer-to-peer traffic
CMN_NODE_CXRA    = 0x100  # CCIX Request Agent
CMN_NODE_CXHA    = 0x101  # CCIX Home Agent
CMN_NODE_CXLA    = 0x102  # CCIX Link Agent
CMN_NODE_CCG_RA  = 0x103
CMN_NODE_CCG_HA  = 0x104
CMN_NODE_CCLA    = 0x105
CMN_NODE_CCLA_RNI= 0x106
CMN_NODE_HNS     = 0x200
CMN_NODE_HNS_MPAM_S  = 0x201
CMN_NODE_HNS_MPAM_NS = 0x202
CMN_NODE_APB     = 0x1000 # APB interface

CMN_NODE_all_HN = [CMN_NODE_HNI, CMN_NODE_HNF, CMN_NODE_HNP, CMN_NODE_HNS]


cmn_node_properties = {
    CMN_NODE_HNI         : CMN_PROP_HNI,
    CMN_NODE_HNF         : CMN_PROP_HNF,
    CMN_NODE_RNI         : CMN_PROP_RNI,
    CMN_NODE_RND         : CMN_PROP_RN,
    CMN_NODE_HNP         : CMN_PROP_HNI,
    CMN_NODE_CXRA        : CMN_PROP_RN|CMN_PROP_CCG,
    CMN_NODE_CXHA        : CMN_PROP_HN|CMN_PROP_CCG,
    CMN_NODE_CCG_RA      : CMN_PROP_RN|CMN_PROP_CCG,
    CMN_NODE_CCG_HA      : CMN_PROP_HN|CMN_PROP_CCG,
    CMN_NODE_HNS         : CMN_PROP_HNF,
}


cmn_node_type_strings = {
    0: "?0",
    1: "DN", 2: "CFG", 3: "DT", 4: "HN-I", 5: "HN-F", 6: "XP", 7: "SBSX",
    8: "MPAM_S", 9: "MPAM_NS", 10: "RN-I", 13: "RN-D", 15: "RN-SAM",
    16: "MTSX", 17: "HN-P",                                              # 7xx
    256: "CXRA", 257: "CXHA", 258: "CXLA",                               # 6xx
    0x103: "CCG-RA", 0x104: "CCG-HA", 0x105: "CCLA", 0x106: "CCLA-RNI",  # 7xx
    0x200: "HN-S", 0x201: "MPAM_S(S)", 0x202: "MPAM_NS(S)",
    0x1000: "APB"
}


def cmn_node_type_str(n):
    return cmn_node_type_strings[n] if n in cmn_node_type_strings else "node(0x%x)" % n


# Descriptions for the "connected device type" codes in the XP port.
# These are not the same enumeration as the device type codes in the
# device itself, for which see CMN_NODE_xxx enumerators.
# Note that RN-F and SN-F are included here, even though as nodes they
# are external to CMN and have no node type number.
# TBD: HCAL allows two different device types to be connected.
cmn_port_device_type_strings = {
    # 0x00 is reserved, but seems to mean that there is no device on the port
    0x01: "RN-I",            # Non-caching requester
    0x02: "RN-D",            # RN-I that can accept snoops on the DVM channel
    0x04: "RN-F_CHIB",       # CHI Issue B processor/cluster with built-in SAM
    0x05: "RN-F_CHIB_ESAM",  # CHI Issue B processor/cluster with external SAM
    0x06: "RN-F_CHIA",       # CHI Issue A processor/cluster with built-in SAM
    0x07: "RN-F_CHIA_ESAM",  # CHI Issue A processor/cluster with external SAM
    0x08: "HN-T",            # HN-I with debug/trace control
    0x09: "HN-I",            # Home Node I/O, non-coherent
    0x0a: "HN-D",            # HN-T, with CFG and DVM, power control etc.
    0x0b: "HN-P",
    0x0c: "SN-F",            # Memory controller
    0x0d: "SBSX",            # CHI to AXI bridge
    0x0e: "HN-F",            # Home Node Full, fully coherent, with SLC and/or SF
    0x0f: "SN-F_CHIE",
    0x10: "SN-F_CHID",
    0x11: "CXHA",
    0x12: "CXRA",
    0x13: "CXRH",
    0x14: "RN-F_CHID",
    0x15: "RN-F_CHID_ESAM",
    0x16: "RN-F_CHIC",
    0x17: "RN-F_CHIC_ESAM",
    0x18: "RN-F_CHIE",
    0x19: "RN-F_CHIE_ESAM",
    0x1a: "HN-S",
    0x1b: "LCN",
    0x1c: "MTSX",
    0x1d: "HN-V",
    0x1e: "CCG"
}


CMN_PORT_DEVTYPE_RNI            = 0x01
CMN_PORT_DEVTYPE_RND            = 0x02
CMN_PORT_DEVTYPE_RNF_CHIB       = 0x04
CMN_PORT_DEVTYPE_RNF_CHIB_ESAM  = 0x05
CMN_PORT_DEVTYPE_RNF_CHIA       = 0x06
CMN_PORT_DEVTYPE_RNF_CHIA_ESAM  = 0x07
CMN_PORT_DEVTYPE_HNT            = 0x08
CMN_PORT_DEVTYPE_HNI            = 0x09
CMN_PORT_DEVTYPE_HND            = 0x0a
CMN_PORT_DEVTYPE_HNP            = 0x0b
CMN_PORT_DEVTYPE_SNF            = 0x0c
CMN_PORT_DEVTYPE_SBSX           = 0x0d
CMN_PORT_DEVTYPE_HNF            = 0x0e
CMN_PORT_DEVTYPE_SNF_CHIE       = 0x0f
CMN_PORT_DEVTYPE_SNF_CHID       = 0x10
CMN_PORT_DEVTYPE_CXHA           = 0x11
CMN_PORT_DEVTYPE_CXRA           = 0x12
CMN_PORT_DEVTYPE_CXRH           = 0x13
CMN_PORT_DEVTYPE_RNF_CHID       = 0x14
CMN_PORT_DEVTYPE_RNF_CHID_ESAM  = 0x15
CMN_PORT_DEVTYPE_RNF_CHIC       = 0x16
CMN_PORT_DEVTYPE_RNF_CHIC_ESAM  = 0x17
CMN_PORT_DEVTYPE_RNF_CHIE       = 0x18
CMN_PORT_DEVTYPE_RNF_CHIE_ESAM  = 0x19
CMN_PORT_DEVTYPE_HNS            = 0x1a
CMN_PORT_DEVTYPE_LCN            = 0x1b
CMN_PORT_DEVTYPE_MTSX           = 0x1c
CMN_PORT_DEVTYPE_HNV            = 0x1d
CMN_PORT_DEVTYPE_CCG            = 0x1e


cmn_port_properties = {
    CMN_PORT_DEVTYPE_RNI              : CMN_PROP_RNI,
    CMN_PORT_DEVTYPE_RND              : CMN_PROP_RN,
    CMN_PORT_DEVTYPE_RNF_CHIB         : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHIB_ESAM    : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHIA         : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHIA_ESAM    : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_HNT              : CMN_PROP_HND,
    CMN_PORT_DEVTYPE_HNI              : CMN_PROP_HNI,
    CMN_PORT_DEVTYPE_HND              : CMN_PROP_HND,
    CMN_PORT_DEVTYPE_HNP              : CMN_PROP_HNI,
    CMN_PORT_DEVTYPE_SNF              : CMN_PROP_SNF,
    CMN_PORT_DEVTYPE_SBSX             : CMN_PROP_none,
    CMN_PORT_DEVTYPE_HNF              : CMN_PROP_HNF,
    CMN_PORT_DEVTYPE_SNF_CHIE         : CMN_PROP_SNF,
    CMN_PORT_DEVTYPE_SNF_CHID         : CMN_PROP_SNF,
    CMN_PORT_DEVTYPE_CXHA             : CMN_PROP_HN|CMN_PROP_CCG,
    CMN_PORT_DEVTYPE_CXRA             : CMN_PROP_RN|CMN_PROP_CCG,
    CMN_PORT_DEVTYPE_CXRH             : CMN_PROP_RN|CMN_PROP_CCG,
    CMN_PORT_DEVTYPE_RNF_CHID         : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHID_ESAM    : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHIC         : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHIC_ESAM    : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHIE         : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_RNF_CHIE_ESAM    : CMN_PROP_RNF,
    CMN_PORT_DEVTYPE_HNS              : CMN_PROP_HNF,
    CMN_PORT_DEVTYPE_LCN              : CMN_PROP_none,
    CMN_PORT_DEVTYPE_MTSX             : CMN_PROP_none,
    CMN_PORT_DEVTYPE_HNV              : CMN_PROP_HNI,
    CMN_PORT_DEVTYPE_CCG              : CMN_PROP_CCG,
}


CMN_PORT_DEVTYPE_all_HN = [
    CMN_PORT_DEVTYPE_HNT, CMN_PORT_DEVTYPE_HNI, CMN_PORT_DEVTYPE_HND,
    CMN_PORT_DEVTYPE_HNP, CMN_PORT_DEVTYPE_HNF, CMN_PORT_DEVTYPE_HNS,
    CMN_PORT_DEVTYPE_HNV
]


def cmn_port_device_type_str(dev):
    if dev in cmn_port_device_type_strings:
        return cmn_port_device_type_strings[dev]
    else:
        return "dev?%u" % dev


def print_all_enums():
    print("Node types:")
    for (k, v) in globals().items():
        if k.startswith("CMN_NODE_") and not k.startswith("CMN_NODE_all_"):
            props = cmn_node_properties.get(v, CMN_PROP_none)
            print("  %-30s %04x  %04x  %s" % (k, v, props, cmn_node_type_str(v)))
    print("Connected device types:")
    for (k, v) in globals().items():
        if k.startswith("CMN_PORT_DEVTYPE_") and not k.startswith("CMN_PORT_DEVTYPE_all_"):
            props = cmn_port_properties[v]
            print("  %-30s %04x  %04x  %s" % (k, v, props, cmn_port_device_type_str(v)))


if __name__ == "__main__":
    print_all_enums()