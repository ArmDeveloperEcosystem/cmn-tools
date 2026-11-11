#!/usr/bin/python3

"""
Built-in top-down analysis recipes for CMN interconnects.

Copyright (C) Arm Ltd. 2025. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

import cmnwatch
from cmn_enum import *


RECIPE_LEVEL1 = {
    "name": "Level 1 analysis",
    "categories": ["RN-F", "RN-I", "RN-D", "CCG"],
    "measure": [
        {"measure": "CCG", "ports": CMN_PROP_CCG, "watchpoint_up": {"opcode": "PrefetchTgt", "exclusive": True}},
        {"measure": "RN-F", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "PrefetchTgt", "exclusive": True}},
        {"measure": "RN-I", "ports": CMN_PROP_RNI, "ports_exclude": [CMN_PROP_RND, CMN_PROP_CCG], "watchpoint_up": {"opcode": "PrefetchTgt", "exclusive": True}},
        {"measure": "RN-D", "ports": CMN_PROP_RND, "watchpoint_up": {"opcode": "PrefetchTgt", "exclusive": True}},
    ],
}


RECIPE_LEVEL2 = {
    "name": "Level 2 analysis",
    "categories": ["local", "remote"],
    "run_if": ["multisocket"],
    "measure": [
        {"measure": "local", "ports": CMN_PROP_HNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": True}},
        {"measure": "remote,-local,-local", "ports": CMN_PROP_CCG, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": True}},
    ],
}


RECIPE_LEVEL3_RNF = {
    "name": "Level 3 request analysis",
    "categories": ["HN-F hit", "HN-F snoop", "HN-F DRAM", "HN-I", "HN-D"],
    "measure": [
        {"measure": "#all,HN-F hit", "event": "hnf_slc_sf_cache_access"},
        {"measure": "#miss,HN-F snoop,-HN-F hit", "event": "hnf_cache_miss"},
        {"measure": "HN-F DRAM,-HN-F snoop", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnp"}},
        {"measure": "HN-F DRAM,-HN-F snoop", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnpSep"}},
        {"measure": "HN-I", "ports": CMN_PROP_HNI, "ports_exclude": [CMN_PROP_HND, CMN_PROP_CCG], "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnp"}},
        {"measure": "HN-D", "ports": CMN_PROP_HND, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnp"}},
    ],
}


RECIPE_PREFETCH = {
    "name": "PrefetchTgt request analysis",
    "categories": ["normal", "prefetch"],
    "measure": [
        {"measure": "normal", "ports": CMN_PROP_RNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": True}},
        {"measure": "prefetch", "ports": CMN_PROP_RNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "PrefetchTgt", "exclusive": False}},
    ],
}


# cpu-bus: CPU bandwidth by CPU BUS_ACCESS events: counting every RXDAT/TXDAT flit, not just first/critical ones
# TBD: assumes 32-byte bus interface, i.e. 2 DAT flits per line
RECIPE_BANDWIDTH_CPU = {
    "name": "CPU bandwidth (CPU PMU BUS_ACCESS... events)",
    "categories": ["read", "write"],
    "rate_bandwidth": 32,
    "measure": [
        {"measure": "read", "cpu-event": "bus_access_rd"},
        {"measure": "write", "cpu-event": "bus_access_wr"},
    ],
}


def filter_retries(ms, wp):
    """
    Apply "allowretry = 1" to REQ watchpoints. The rationale is that actual bandwidth is consumed by:
     - initial REQs with allowretry = 1 that don't get a retry response
     - retried REQs with allowretry = 0, which are guaranteed to be serviced
    Assuming that it's rare for the source to return a credit without retrying, we can estimate
    bandwidth usage by filtering on allowretry = 1.
    """
    def filter_retries_m(m, wp):
        m[wp]["allowretry"] = 1
        return m
    return [filter_retries_m(m, wp) for m in ms]


def rnf_opcodes(ports, wp, prefix=""):
    ms = [
        {"measure": prefix + "read", "ports": ports, wp: {"opcode": "ReadNotSharedDirty"}},
        {"measure": prefix + "read", "ports": ports, wp: {"opcode": "ReadUnique"}},
        {"measure": prefix + "write clean", "ports": ports, wp: {"opcode": "WriteEvictFull"}},
        {"measure": prefix + "write clean", "ports": ports, wp: {"opcode": "WriteEvictOrEvict"}},
        {"measure": prefix + "write dirty", "ports": ports, wp: {"opcode": "WriteBackFull"}},
        {"measure": prefix + "write dirty", "ports": ports, wp: {"opcode": "WriteCleanFull"}},
        {"measure": prefix + "write dirty", "ports": ports, wp: {"opcode": "WriteUniqueFull"}},
    ]
    ms = filter_retries(ms, wp)
    return ms


RECIPE_BANDWIDTH_RNF = {
    "name": "CPU/SLC bandwidth at CPU (REQ, excluding retries)",
    "categories": ["read", "write clean", "write dirty"],
    "rate_bandwidth": 64,
    "measure": rnf_opcodes(CMN_PROP_RNF, "watchpoint_up"),
}


#
# Measure bandwidth on the DAT channel - all reads, and all writes including
#
# We select dataid=0 which should be good for all bus widths as long as we're
# doing full-line transfers. The recipe will overestiamte for sub-line transfers.
#
RECIPE_BANDWIDTH_RNF_DAT = {
    "name": "CPU data bandwidth (DAT)",
    "categories": ["read", "write"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read",  "ports": CMN_PROP_RNF, "watchpoint_down": {"chn": cmnwatch.DAT, "dataid": 0}},
        {"measure": "write", "ports": CMN_PROP_RNF, "watchpoint_up":   {"chn": cmnwatch.DAT, "dataid": 0}},
    ]
}


RECIPE_BANDWIDTH_RNF_DAT_QOS = {
    "name": "CPU data bandwidth (DAT with QoS)",
    "categories": ["read 14", "read 10", "write 14", "write 10"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read 14",  "ports": CMN_PROP_RNF, "watchpoint_down": {"chn": cmnwatch.DAT, "dataid": 0, "qos": 14}},
        {"measure": "read 10",  "ports": CMN_PROP_RNF, "watchpoint_down": {"chn": cmnwatch.DAT, "dataid": 0, "qos": 10}},
        {"measure": "write 14", "ports": CMN_PROP_RNF, "watchpoint_up":   {"chn": cmnwatch.DAT, "dataid": 0, "qos": 14}},
        {"measure": "write 10", "ports": CMN_PROP_RNF, "watchpoint_up":   {"chn": cmnwatch.DAT, "dataid": 0, "qos": 10}},
    ]
}


def opcodes(ports, wp, ops):
    other = [{"measure": "other", "ports": ports, wp: {"allowretry": 1}}]
    return other + [{"measure": op+",-other", "ports": ports, wp: {"opcode": op, "allowretry": 1}} for op in ops]


# Opcode categories - not all of these result in moving data, e.g. a WriteEvictOrEvict lets the completer choose.
# MakeUnique can be used to upgrade line held as Shared, and also to claim a line prior to a streaming write -
# we can't distinguish those in the watchpoints.
# Not covered: atomics, sub-line device access

read_opcodes =  ["ReadNotSharedDirty", "ReadUnique", "ReadPreferUnique", "MakeUnique", "ReadNoSnp"]

write_opcodes = ["WriteEvictFull", "WriteEvictOrEvict", "WriteBackFull", "WriteCleanFull", "WriteUniqueFull"]

other_opcodes = ["Evict", "PrefetchTgt"]


# cpu-opcodes
RECIPE_RNF_OPCODES = {
    "name": "CPU opcodes",
    "measure": opcodes(CMN_PROP_RNF, "watchpoint_up", read_opcodes + write_opcodes + other_opcodes)
}


# cpu-qos: Classify RN-F requests by QoS, using the default values used by current Neoverse cores.
# Higher values indicate higher priority - although an interconnect may apply coarser bands.
# Cores may have an override register (CPUBUSQOS) that can vary these values.
# There is no distinction between demand load and L1 prefetch, or between data and instructions.
RECIPE_BANDWIDTH_RNF_QOS = {
    "name": "CPU read bandwidth at interconnect, classified by QoS",
    "categories": ["demand/L1", "demand/L1 for write", "L2 prefetch", "L2 prefetch for write"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "demand/L1",             "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadNotSharedDirty", "qos": 0xe, "allowretry": 1}},
        {"measure": "demand/L1 for write",   "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadUnique", "qos": 0xe, "allowretry": 1}},
        {"measure": "demand/L1 for write",   "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadPreferUnique", "qos": 0xe, "allowretry": 1}},
        {"measure": "L2 prefetch",           "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadNotSharedDirty", "qos": 0xa, "allowretry": 1}},
        {"measure": "L2 prefetch for write", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadUnique", "qos": 0xa, "allowretry": 1}},
        {"measure": "L2 prefetch for write", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadPreferUnique", "qos": 0xa, "allowretry": 1}},
        {"measure": "make unique",           "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "MakeUnique", "allowretry": 1}},
    ]
}


# cpu-qos-all
RECIPE_RNF_QOS_ALL = {
    "name": "CPU request QoS banding",
    "categories": ["15", "14", "10", "1", "other"],
    "measure": [
        {"measure": "15,-other", "ports": CMN_PROP_RNF, "watchpoint_up": {"qos": 15}},
        {"measure": "14,-other", "ports": CMN_PROP_RNF, "watchpoint_up": {"qos": 14}},
        {"measure": "10,-other", "ports": CMN_PROP_RNF, "watchpoint_up": {"qos": 10}},
        {"measure": "1,-other",  "ports": CMN_PROP_RNF, "watchpoint_up": {"qos": 1}},
        {"measure": "other",  "ports": CMN_PROP_RNF, "watchpoint_up": {}},
    ]
}


# This will count requests seen at SLC, either local RNs, or forwarded via CCGs.
# This is subject to double-counting on multi-mesh systems.
RECIPE_BANDWIDTH_HNF = {
    "name": "Requester/CCG bandwidth at SLC",
    "categories": ["read", "write clean", "write dirty"],
    "rate_bandwidth": 64,
    "measure": rnf_opcodes(CMN_PROP_HNF, "watchpoint_down"),
}


# cmn_events will translate these into local_all - i.e. excluding requests on behalf of remote mesh
RECIPE_BANDWIDTH_HNF_MC = {
    "name": "SLC local bandwidth to memory controller or CCG",
    "categories": ["all"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "all", "event": "hnf_mc_reqs"},
        {"measure": "-all", "event": "hnf_mc_retries"},
    ]
}


# Specific to HN-S where we can separate requests by local vs remote origin
RECIPE_BANDWIDTH_HNF_MC_C2C = {
    "name": "SLC bandwidth to memory controller",
    "categories": ["local to mem", "local to other", "remote to mem", "remote to other"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "local to mem,-local to other", "event": "hns_mc_reqs_local_sn"},
        {"measure": "local to other", "event": "hns_mc_reqs_local_all"},
        {"measure": "remote to mem,-remote to other", "event": "hns_mc_reqs_remote_sn"},
        {"measure": "remote to other", "event": "hns_mc_reqs_remote_all"},
    ]
}


RECIPE_BANDWIDTH_HNF_REQ = {
    "name": "SLC outgoing requests (excluding retries)",
    "categories": ["read", "write", "evict", "make unique", "other"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read,-other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnp", "allowretry": 1}},
        {"measure": "read,-other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnpSep", "allowretry": 1}},
        {"measure": "read,-other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "ReadNotSharedDirty", "allowretry": 1}},
        {"measure": "write,-other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "WriteNoSnpFull", "allowretry": 1}},
        {"measure": "write,-other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "WriteBackFull", "allowretry": 1}},
        {"measure": "evict,-other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "Evict", "allowretry": 1}},
        {"measure": "make unique,-other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "opcode": "MakeUnique", "allowretry": 1}},
        {"measure": "other", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.REQ, "allowretry": 1}},
    ],
}


# Measure DRAM read and write bandwidth by looking at requests downloaded from the interconnect to the DMCs.
RECIPE_BANDWIDTH_DRAM = {
    "name": "DRAM bandwidth at memory controller",
    "categories": ["read", "write", "other"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read,-other", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnp", "allowretry": 1}},
        {"measure": "read,-other", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnpSep", "allowretry": 1}},
        {"measure": "write,-other", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "WriteNoSnpFull", "allowretry": 1}},
        {"measure": "other", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "allowretry": 1}},
    ],
}


RECIPE_BANDWIDTH_DRAM_DAT = {
    "name": "DRAM bandwidth at controller (DAT)",
    "categories": ["read", "write"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read", "ports": CMN_PROP_SNF, "watchpoint_up": {"chn": cmnwatch.DAT, "dataid": 0 }},
        {"measure": "write", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.DAT, "dataid": 0 }},
    ],
}


# Measure requests going into and out of the C2C link
RECIPE_BANDWIDTH_C2C = {
    "name": "Bandwidth at C2C",
    "rate_bandwidth": 64,
    "measure": rnf_opcodes(CMN_PROP_CCG, "watchpoint_up", prefix="from: ") + rnf_opcodes(CMN_PROP_CCG, "watchpoint_down", prefix="to: "),
}


# N.b. bandwidth is scaled assuming each DAT with dataid=0 is part of a 64-byte transfer.
# Significant numbers of device reads across C2C interface may skew this.
RECIPE_BANDWIDTH_C2C_DAT = {
    "name": "Bandwidth at C2C (DAT)",
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "from", "ports": CMN_PROP_CCG, "watchpoint_up": {"chn": cmnwatch.DAT, "dataid": 0 }},
        {"measure": "to", "ports": CMN_PROP_CCG, "watchpoint_down": {"chn": cmnwatch.DAT, "dataid": 0 }},
    ]
}


RECIPE_BANDWIDTH = {
    "name": "Bandwidth",
    "subrecipes": [RECIPE_BANDWIDTH_CPU, RECIPE_BANDWIDTH_RNF, RECIPE_BANDWIDTH_RNF_DAT, RECIPE_BANDWIDTH_HNF, RECIPE_BANDWIDTH_HNF_MC, RECIPE_BANDWIDTH_HNF_REQ, RECIPE_BANDWIDTH_DRAM, RECIPE_BANDWIDTH_C2C],
}


RECIPE_RETRIES_HNF = {
    "name": "Retried requests from CPU to SLC",
    "categories": ["retry", "non-retry"],
    "measure": [
        {"measure": "non-retry", "event": "hnf_pocq_reqs_recvd"},
        {"measure": "retry,-non-retry", "event": "hnf_pocq_retry"},
    ],
}


RECIPE_RETRIES_SNF = {
    "name": "Retried requests from SLC to DRAM/CCG",
    "categories": ["retry", "non-retry"],
    "measure": [
        {"measure": "non-retry", "event": "hnf_mc_reqs"},
        {"measure": "retry,-non-retry", "event": "hnf_mc_retries"},
    ],
}


RECIPE_RETRIES = {
    "name": "Retried requests",
    "subrecipes": [RECIPE_RETRIES_HNF, RECIPE_RETRIES_SNF],
}


RECIPE_CBUSY_HNF = {
    "name": "CBusy indicated by SLC",
    "categories": ["very-busy", "50%", "not-busy"],
    "measure": [
        {"measure": "very-busy", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.DAT, "cbusy": "0bx1x"}},
        {"measure": "50%", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.DAT, "cbusy": "0bx01"}},
        {"measure": "not-busy", "ports": CMN_PROP_HNF, "watchpoint_up": {"chn": cmnwatch.DAT, "cbusy": "0bx00"}},
    ],
}


RECIPE_CBUSY_SNF = {
    "name": "CBusy indicated by DRAM",
    "categories": ["very-busy", "50%", "not-busy"],
    "measure": [
        {"measure": "very-busy", "ports": CMN_PROP_SNF, "watchpoint_up": {"chn": cmnwatch.DAT, "cbusy": "0bx1x"}},
        {"measure": "50%", "ports": CMN_PROP_SNF, "watchpoint_up": {"chn": cmnwatch.DAT, "cbusy": "0bx01"}},
        {"measure": "not-busy", "ports": CMN_PROP_SNF, "watchpoint_up": {"chn": cmnwatch.DAT, "cbusy": "0bx00"}},
    ],
}


RECIPE_CBUSY = {
    "name": "CBusy",
    "subrecipes": [RECIPE_CBUSY_HNF, RECIPE_CBUSY_SNF],
}


RECIPE_C2C = {
    "name": "c2c",
    "categories": ["xfer"],
    "measure": [
        {"measure": "xfer", "ports": CMN_PROP_CCG, "watchpoint_up": {"chn": cmnwatch.REQ}},
    ],
}


BUILTIN_LEVELS = {
    "1": RECIPE_LEVEL1,
    "2": RECIPE_LEVEL2,
    "3": RECIPE_LEVEL3_RNF,
    "prefetch": RECIPE_PREFETCH,
    "bandwidth": RECIPE_BANDWIDTH,
    "dram": RECIPE_BANDWIDTH_DRAM,
    "dram-data": RECIPE_BANDWIDTH_DRAM_DAT,
    "c2c-bandwidth": RECIPE_BANDWIDTH_C2C,
    "c2c-data": RECIPE_BANDWIDTH_C2C_DAT,
    "retries": RECIPE_RETRIES,
    "retries-home": RECIPE_RETRIES_HNF,
    "retries-dram": RECIPE_RETRIES_SNF,
    "hn-mc": RECIPE_BANDWIDTH_HNF_MC,
    "hn-mc-c2c": RECIPE_BANDWIDTH_HNF_MC_C2C,
    "hn-req": RECIPE_BANDWIDTH_HNF_REQ,
    "cpu-bus": RECIPE_BANDWIDTH_CPU,           # CPU: BUS_ACCESS events
    "cpu-dat": RECIPE_BANDWIDTH_RNF_DAT,       # CMN: DAT upload/download
    "cpu-dat-qos": RECIPE_BANDWIDTH_RNF_DAT_QOS,   # CMN: DAT upload/download (with QoS 14/10)
    "cpu-qos": RECIPE_BANDWIDTH_RNF_QOS,       # CMN: use QoS to distinguish demand and prefetch
    "cpu-qos-all": RECIPE_RNF_QOS_ALL,         # CMN: RN-F REQ QoS breakdown
    "cpu-opcodes": RECIPE_RNF_OPCODES,         # CMN: opcode breakdown
    "cbusy": RECIPE_CBUSY,
    "cbusy-home": RECIPE_CBUSY_HNF,
    "cbusy-dram": RECIPE_CBUSY_SNF,
    "ccg": RECIPE_C2C,
    "c2c": RECIPE_C2C,
}


DEFAULT_LEVELS_ALL = ["1", "2", "3", "bandwidth", "retries"]
