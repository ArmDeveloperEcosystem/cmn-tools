#!/usr/bin/python3

"""
Built-in top-down analysis recipes for CMN interconnects.
"""

import cmnwatch
from cmn_enum import *


RECIPE_LEVEL1 = {
    "name": "Level 1 analysis",
    "categories": ["RN-F", "RN-I", "RN-D", "CCG"],
    "measure": [
        {"measure": "CCG", "ports": CMN_PROP_CCG, "watchpoint_up": {"opcode": "PrefetchTgt", "exclusive": True}},
        {"measure": "RN-F", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "PrefetchTgt", "exclusive": True}},
        {"measure": "RN-I", "ports": CMN_PROP_RNI, "watchpoint_up": {"opcode": "PrefetchTgt", "exclusive": True}},
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
        {"measure": "HN-I", "ports": CMN_PROP_HNI, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnp"}},
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


RECIPE_BANDWIDTH_CPU = {
    "name": "CPU bandwidth",
    "categories": ["read", "write"],
    "rate_bandwidth": 32,
    "measure": [
        {"measure": "read", "cpu-event": "bus_access_rd"},
        {"measure": "write", "cpu-event": "bus_access_wr"},
    ],
}


RECIPE_BANDWIDTH_RNF = {
    "name": "CPU/SLC bandwidth at CPU",
    "categories": ["read", "write clean", "write dirty"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadNotSharedDirty"}},
        {"measure": "read", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "ReadUnique"}},
        {"measure": "write clean", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "WriteEvictFull"}},
        {"measure": "write clean", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "WriteEvictOrEvict"}},
        {"measure": "write dirty", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "WriteBackFull"}},
        {"measure": "write dirty", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "WriteCleanFull"}},
        {"measure": "write dirty", "ports": CMN_PROP_RNF, "watchpoint_up": {"opcode": "WriteUniqueFull"}},
    ],
}


RECIPE_BANDWIDTH_HNF = {
    "name": "CPU/SLC bandwidth at SLC",
    "categories": ["read", "write clean", "write dirty"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read", "ports": CMN_PROP_HNF, "watchpoint_down": {"opcode": "ReadNotSharedDirty"}},
        {"measure": "read", "ports": CMN_PROP_HNF, "watchpoint_down": {"opcode": "ReadUnique"}},
        {"measure": "write clean", "ports": CMN_PROP_HNF, "watchpoint_down": {"opcode": "WriteEvictFull"}},
        {"measure": "write clean", "ports": CMN_PROP_HNF, "watchpoint_down": {"opcode": "WriteEvictOrEvict"}},
        {"measure": "write dirty", "ports": CMN_PROP_HNF, "watchpoint_down": {"opcode": "WriteBackFull"}},
        {"measure": "write dirty", "ports": CMN_PROP_HNF, "watchpoint_down": {"opcode": "WriteCleanFull"}},
        {"measure": "write dirty", "ports": CMN_PROP_HNF, "watchpoint_down": {"opcode": "WriteUniqueFull"}},
    ],
}


# Measure DRAM read and write bandwidth by looking at requests downloaded from the interconnect to the DMCs.
RECIPE_BANDWIDTH_DRAM = {
    "name": "DRAM bandwidth at controller",
    "categories": ["read", "write"],
    "rate_bandwidth": 64,
    "measure": [
        {"measure": "read", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnp"}},
        {"measure": "read", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "ReadNoSnpSep"}},
        {"measure": "write", "ports": CMN_PROP_SNF, "watchpoint_down": {"chn": cmnwatch.REQ, "opcode": "WriteNoSnpFull"}},
    ],
}


RECIPE_BANDWIDTH = {
    "name": "Bandwidth",
    "subrecipes": [RECIPE_BANDWIDTH_CPU, RECIPE_BANDWIDTH_RNF, RECIPE_BANDWIDTH_HNF, RECIPE_BANDWIDTH_DRAM],
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
    "name": "Retried requests from SLC to DRAM",
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
    "retries": RECIPE_RETRIES,
    "cbusy": RECIPE_CBUSY,
    "ccg": RECIPE_C2C,
    "c2c": RECIPE_C2C,
}


DEFAULT_LEVELS_ALL = ["1", "2", "3", "bandwidth", "retries"]
