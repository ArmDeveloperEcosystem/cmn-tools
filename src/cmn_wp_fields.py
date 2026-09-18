#!/usr/bin/python3

"""
CMN watchpoint field definitions.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

The watchpoint field positions are defined by product. Field value decoders
are defined separately because they are properties of CHI fields, not of CMN
watchpoint product layouts.
"""

from __future__ import print_function

import sys

import chi_spec
import cmn_config
import value_mask


REQ = 0
RSP = 1
SNP = 2
DAT = 3


CMN600 = "cmn600"
CMN650 = "cmn650"
CMN700 = "cmn700"
CI700 = "ci700"
CMN_S3_R0 = "cmn_s3_r0"
CMN_S3_R2 = "cmn_s3_r2"
CMN_ALTA_CHI_LT_G = "cmn_alta_chi_lt_g"
CMN_ALTA = "cmn_alta"


_CHI_CHANNELS = ["REQ", "RSP", "SNP", "DAT"]
_PRODUCT_KEYS = [CMN600, CMN650, CMN700, CI700, CMN_S3_R0, CMN_S3_R2, CMN_ALTA_CHI_LT_G, CMN_ALTA]


_resperr = ["OK", "EXOK", "DERR", "NDERR"]
_resp_DAT = ["I", "SC", "UC", None, None, None, "UD_PD", "SD_PD"]


def snp_addr(s):
    """
    For convenience, allow the user to specify a line byte address, which
    is converted to the field value in a SNP packet.

    TBD: For CMN-600, the full SNP address field is split across two match
    groups - we don't handle this yet.
    """
    (v, m) = value_mask.convert_value(s).as_tuple()
    (v, m) = (v >> 3, m >> 3)
    return value_mask.unconvert_value_mask(v, m)


assert snp_addr(0x8000) == 0x1000
assert snp_addr("0xxx40") == "0bxxxxxxxx01000"


_FIELD_DECODERS = {
    REQ: {
        "opcode": chi_spec.opcodes_REQ,
        "ns": chi_spec.NS,
    },
    RSP: {
        "opcode": chi_spec.opcodes_RSP,
        "resperr": _resperr,
    },
    SNP: {
        "opcode": chi_spec.opcodes_SNP,
        "ns": chi_spec.NS,
        "addr": snp_addr,
    },
    DAT: {
        "opcode": chi_spec.opcodes_DAT,
        "resperr": _resperr,
        "resp": _resp_DAT,
    },
}


_DVM_FIELD_DEFS = [
    ("vavalid",   None,              1, 4,  1, 0),
    ("vmidvalid", None,              1, 5,  2, 0),
    ("asidvalid", None,              1, 6,  3, 0),
    ("sec",       None,              2, 7,  4, 0),
    ("el",        chi_spec.DVM_EL,   2, 9,  6, 0),
    ("type",      chi_spec.DVM_type, 3, 11, 8, 0),
    ("vmid",      None,              8, 14, 11, 0),
    ("asid",      None,              16, 22, 19, 0),
]


_DVM_FRAG = {}
for (_df, _dlookup, _dbits, _reqoff, _snpoff, _frag) in _DVM_FIELD_DEFS:
    _dvm_name = "dvm" + _df
    _DVM_FRAG[_dvm_name] = _frag
    if _dlookup is not None:
        _FIELD_DECODERS[REQ][_dvm_name] = _dlookup
        _FIELD_DECODERS[SNP][_dvm_name] = _dlookup


_CMN600_WP_FIELDS = {
    REQ: {
        "tracetag": [(0, 54, 1), (1, 59, 1)],
        "srcid": [(0, 0, 11)],
        "tgtid": [(0, 0, 11)],
        "returnnid": [(0, 11, 11)],
        "stashnid": [],
        "stashtgtvalid": [],
        "endian": [(0, 22, 1)],
        "opcode": [(0, 31, 6)],
        "size": [(0, 37, 3)],
        "ns": [(0, 40, 1)],
        "allowretry": [(0, 41, 1)],
        "order": [(0, 42, 2)],
        "pcrdtype": [(0, 44, 4)],
        "lpid": [(0, 48, 5)],
        "groupidext": [],
        "expcompack": [],
        "rsvdc": [(0, 55, 8)],
        "qos": [(1, 0, 4)],
        "addr": [(1, 4, 48)],
        "mpam": [],
        "likelyshared": [(1, 52, 1)],
        "memattr": [(1, 53, 4)],
        "snpattr": [(1, 57, 1)],
        "excl": [(1, 58, 1)],
        "snoopme": [(1, 58, 1)],
        "tagop": [],
        "mecid": [],
        "cah": [],
        "deep": [],
        "nse": [],
    },
    RSP: {
        "tracetag": [(0, 39, 1)],
        "qos": [(0, 0, 4)],
        "srcid": [(0, 4, 11)],
        "tgtid": [(0, 4, 11)],
        "opcode": [(0, 15, 4)],
        "resperr": [(0, 19, 2)],
        "resp": [(0, 21, 3)],
        "fwdstate": [(0, 24, 3)],
        "cbusy": [],
        "dbid": [(0, 27, 8)],
        "pcrdtype": [(0, 35, 4)],
        "devevent": [(0, 40, 2)],
        "tagop": [],
        "datapull": [],
    },
    SNP: {
        "tracetag": [(0, 27, 1), (1, 27, 1)],
        "srcid": [(0, 0, 11), (1, 0, 11)],
        "opcode": [(0, 19, 5), (1, 19, 5)],
        "fwdtxnid": [],
        "fwdnid": [],
        "ns": [(0, 24, 1), (1, 24, 1)],
        "donotgotosd": [(0, 25, 1), (1, 25, 1)],
        "rettosrc": [(0, 26, 1), (1, 26, 1)],
        "addr": [(0, 28, 36)],
        "addr13": [(1, 32, 32)],
        "mpam": [],
        "qos": [],
        "nse": [],
        "mecid": [],
        "streamid": [],
    },
    DAT: {
        "tracetag": [(0, 49, 1)],
        "qos": [(0, 0, 4)],
        "srcid": [(0, 4, 11)],
        "tgtid": [(0, 4, 11)],
        "homenid": [(0, 15, 11)],
        "opcode": [(0, 26, 3)],
        "resperr": [(0, 29, 2)],
        "resp": [(0, 31, 3)],
        "fwdstate": [(0, 34, 3)],
        "datasrc": [(0, 34, 3)],
        "stash": [],
        "cbusy": [],
        "dbid": [(0, 37, 8)],
        "ccid": [(0, 45, 2)],
        "dataid": [(0, 47, 2)],
        "poison": [(0, 50, 1)],
        "chunkv": [(0, 51, 2)],
        "devevent": [(0, 53, 2)],
        "cah": [],
        "rsvdc": [(0, 55, 8)],
        "tagop": [],
        "tag": [],
        "tu": [],
        "datapull": [],
        "numdat": [],
        "replicate": [],
    },
}


_CMN650_WP_FIELDS = {
    REQ: {
        "tracetag": [(1, 63, 1)],
        "srcid": [(0, 0, 11), (2, 0, 11)],
        "tgtid": [(0, 0, 11), (2, 0, 11)],
        "returnnid": [(0, 11, 11)],
        "stashnid": [(0, 11, 11)],
        "stashtgtvalid": [(0, 22, 1)],
        "endian": [(0, 22, 1)],
        "opcode": [(0, 29, 7), (2, 11, 7)],
        "size": [(0, 36, 3)],
        "ns": [(0, 39, 1)],
        "allowretry": [(0, 40, 1)],
        "order": [(0, 41, 2)],
        "pcrdtype": [(0, 43, 4)],
        "lpid": [(0, 47, 5)],
        "groupidext": [(0, 52, 3)],
        "expcompack": [(0, 55, 1)],
        "rsvdc": [(0, 56, 8)],
        "qos": [(1, 0, 4)],
        "addr": [(1, 4, 52)],
        "mpam": [(2, 18, 11)],
        "likelyshared": [(1, 56, 1)],
        "memattr": [(1, 57, 4)],
        "snpattr": [(1, 61, 1)],
        "excl": [(1, 62, 1)],
        "snoopme": [(1, 62, 1)],
        "tagop": [],
        "mecid": [],
        "cah": [],
        "deep": [],
        "nse": [],
    },
    RSP: {
        "tracetag": [(0, 49, 1)],
        "qos": [(0, 0, 4)],
        "srcid": [(0, 4, 11)],
        "tgtid": [(0, 4, 11)],
        "opcode": [(0, 15, 5)],
        "resperr": [(0, 20, 2)],
        "resp": [(0, 22, 3)],
        "fwdstate": [(0, 25, 3)],
        "cbusy": [(0, 28, 3)],
        "dbid": [(0, 31, 12)],
        "pcrdtype": [(0, 43, 4)],
        "devevent": [(0, 50, 2)],
        "tagop": [],
        "datapull": [],
    },
    SNP: {
        "tracetag": [(0, 38, 1)],
        "srcid": [(0, 0, 11), (1, 0, 11)],
        "opcode": [(0, 30, 5)],
        "fwdtxnid": [(0, 11, 8)],
        "fwdnid": [(0, 19, 11)],
        "ns": [(0, 35, 1)],
        "donotgotosd": [(0, 36, 1)],
        "rettosrc": [(0, 37, 1)],
        "addr": [(1, 11, 49)],
        "addr13": [],
        "mpam": [(0, 43, 11)],
        "qos": [(0, 39, 4)],
        "nse": [],
        "mecid": [],
        "streamid": [],
    },
    DAT: {
        "tracetag": [(1, 44, 1)],
        "qos": [(0, 0, 4)],
        "srcid": [(0, 4, 11), (1, 0, 11)],
        "tgtid": [(0, 4, 11), (1, 0, 11)],
        "homenid": [(0, 15, 11)],
        "opcode": [(0, 26, 4), (1, 11, 4)],
        "resperr": [(0, 30, 2), (1, 15, 2)],
        "resp": [(0, 32, 3), (1, 17, 3)],
        "fwdstate": [(0, 35, 4)],
        "datasrc": [(0, 35, 4)],
        "stash": [(0, 35, 4)],
        "cbusy": [(0, 39, 3)],
        "dbid": [(0, 42, 12), (1, 32, 12)],
        "ccid": [(0, 54, 2)],
        "dataid": [(0, 56, 2)],
        "poison": [(0, 58, 4)],
        "chunkv": [(1, 45, 2)],
        "devevent": [(0, 62, 2), (1, 47, 2)],
        "cah": [],
        "rsvdc": [(1, 49, 8)],
        "tagop": [],
        "tag": [],
        "tu": [],
        "datapull": [],
        "numdat": [],
        "replicate": [],
    },
}


_CMN700_WP_FIELDS = {
    REQ: {
        "tagop": [(2, 29, 2)],
        "mecid": [],
        "cah": [],
        "deep": [],
        "nse": [],
    },
    RSP: {
        "tagop": [(0, 47, 2)],
        "datapull": [],
    },
    SNP: {
        "addr": [(1, 11, 49)],
        "mpam": [(0, 43, 11)],
        "nse": [],
        "mecid": [],
        "streamid": [],
    },
    DAT: {
        "tagop": [(1, 20, 2)],
        "tag": [(1, 22, 8)],
        "tu": [(1, 30, 2)],
        "datapull": [],
        "numdat": [],
        "replicate": [],
    },
}


_CI700_WP_FIELDS = {}


_CMN_S3_R0_WP_FIELDS = {
    REQ: {
        "allowretry": [(0, 40, 1), (2, 32, 1)],
        "mpam": [(2, 18, 12)],
        "tagop": [(2, 30, 2)],
        "mecid": [],
        "cah": [(1, 62, 1)],
        "deep": [(0, 22, 1)],
        "nse": [],
    },
    RSP: {
        "datapull": [(0, 25, 3)],
    },
    SNP: {
        "mpam": [(0, 43, 11)],
        "nse": [],
    },
    DAT: {
        "fwdstate": [(0, 35, 5)],
        "datasrc": [(0, 35, 5)],
        "stash": [(0, 35, 5)],
        "cbusy": [(0, 40, 3)],
        "dbid": [(0, 43, 12), (1, 32, 12)],
        "ccid": [(0, 55, 2)],
        "dataid": [(0, 57, 2)],
        "poison": [(0, 59, 4)],
        "devevent": [(1, 47, 2)],
        "cah": [(1, 49, 1)],
        "rsvdc": [(1, 50, 8)],
    },
}


_CMN_S3_R2_WP_FIELDS = {
    REQ: {
        "allowretry": [(2, 35, 1)],
        "mpam": [(2, 18, 15)],
        "tagop": [(2, 33, 2)],
        "pbha": [(2, 36, 4)],
        "mecid": [(2, 40, 16)],
        "streamid": [(2, 40, 16)],
        "secsid": [(2, 56, 1)],
        "nse": [(0, 40, 1)],
    },
    SNP: {
        "tracetag": [(0, 39, 1)],
        "srcid": [(0, 0, 11)],
        "donotgotosd": [(0, 37, 1)],
        "rettosrc": [(0, 38, 1)],
        "addr": [(1, 0, 49)],
        "mpam": [(1, 49, 15)],
        "qos": [(0, 40, 4)],
        "nse": [(0, 36, 1)],
        "mecid": [(0, 44, 16)],
        "streamid": [(0, 44, 16)],
    },
    DAT: {
        "tracetag": [(1, 32, 1)],
        "fwdstate": [(0, 35, 8)],
        "datasrc": [(0, 35, 8)],
        "stash": [],
        "cbusy": [(0, 44, 3)],
        "dbid": [(0, 47, 16)],
        "ccid": [(1, 38, 2)],
        "dataid": [(1, 40, 2)],
        "poison": [(1, 42, 4)],
        "chunkv": [(1, 33, 2)],
        "devevent": [(1, 35, 2)],
        "cah": [(1, 37, 1)],
        "rsvdc": [(1, 49, 8)],
        "datapull": [(0, 43, 1)],
        "numdat": [(1, 46, 2)],
        "replicate": [(1, 48, 1)],
    },
}


_CMN_ALTA_CHI_LT_G_WP_FIELDS = {
    REQ: {
        "returnnid": [],
        "returntxnid": [(0, 23, 6)],
        "stashnidvalid": [(0, 22, 1)],
        "allowretry": [(2, 32, 1)],
        "mpam": [(2, 18, 12)],
        "tagop": [(2, 30, 2)],
        "pbha": [(2, 33, 4)],
        "mecid": [],
        "streamid": [],
        "secsid": [],
    },
    SNP: {
        "srcid": [(0, 0, 11), (1, 0, 11)],
        "addr": [(1, 11, 45)],
        "mpam": [(0, 44, 12)],
        "mecid": [],
        "streamid": [],
    },
    DAT: {
        "tracetag": [(1, 44, 1)],
        "srcid": [(0, 4, 11), (1, 0, 11)],
        "tgtid": [(0, 4, 11), (1, 0, 11)],
        "fwdstate": [(0, 35, 5)],
        "datasrc": [(0, 35, 5)],
        "cbusy": [(0, 40, 3)],
        "dbid": [(0, 43, 12), (1, 32, 12)],
        "ccid": [(0, 55, 2)],
        "dataid": [(0, 57, 2)],
        "poison": [(0, 59, 4)],
        "chunkv": [(1, 45, 2)],
        "devevent": [(1, 47, 2)],
        "cah": [(1, 49, 1)],
        "rsvdc": [(1, 50, 8)],
        "datapull": [],
        "numdat": [],
        "replicate": [],
    },
}


_CMN_ALTA_WP_FIELDS = {
    REQ: {
        "returnnid": [],
        "returntxnid": [(0, 23, 6)],
        "stashnidvalid": [(0, 22, 1)],
    },
    RSP: {
        "cg": [(0, 52, 1)],
        "condcomp": [(0, 53, 1)],
    },
    SNP: {
        "addr": [(1, 0, 45)],
        "mpam": [(1, 45, 15)],
    },
}


_WP_PRODUCT_TABLES = {
    CMN600: [_CMN600_WP_FIELDS],
    CMN650: [_CMN600_WP_FIELDS, _CMN650_WP_FIELDS],
    CMN700: [_CMN600_WP_FIELDS, _CMN650_WP_FIELDS, _CMN700_WP_FIELDS],
    CI700: [_CMN600_WP_FIELDS, _CMN650_WP_FIELDS, _CMN700_WP_FIELDS, _CI700_WP_FIELDS],
    CMN_S3_R0: [_CMN600_WP_FIELDS, _CMN650_WP_FIELDS, _CMN700_WP_FIELDS, _CMN_S3_R0_WP_FIELDS],
    CMN_S3_R2: [_CMN600_WP_FIELDS, _CMN650_WP_FIELDS, _CMN700_WP_FIELDS, _CMN_S3_R0_WP_FIELDS, _CMN_S3_R2_WP_FIELDS],
    CMN_ALTA_CHI_LT_G: [_CMN600_WP_FIELDS, _CMN650_WP_FIELDS, _CMN700_WP_FIELDS,
                         _CMN_S3_R0_WP_FIELDS, _CMN_S3_R2_WP_FIELDS,
                         _CMN_ALTA_CHI_LT_G_WP_FIELDS],
    CMN_ALTA: [_CMN600_WP_FIELDS, _CMN650_WP_FIELDS, _CMN700_WP_FIELDS,
                _CMN_S3_R0_WP_FIELDS, _CMN_S3_R2_WP_FIELDS, _CMN_ALTA_WP_FIELDS],
}


_PRODUCT_KEY_BY_ID = {
    cmn_config.PART_CMN600:   CMN600,
    cmn_config.PART_CMN600AE: CMN600,
    cmn_config.PART_CMN650:   CMN650,
    cmn_config.PART_CMN700:   CMN700,
    cmn_config.PART_CI700:    CI700,
}

def product_key_for_config(cfg):
    """
    Return the internal watchpoint-table key for a CMNConfig object.

    The key selects one product layout from _WP_PRODUCT_TABLES. CMN S3 needs
    revision handling because r2 changes watchpoint field positions.
    """
    if cfg.product_id == cmn_config.PART_CMN_ALTA:
        if cfg.chi_version is not None and cfg.chi_version < 7:
            return CMN_ALTA_CHI_LT_G
        return CMN_ALTA
    if cfg.product_id == cmn_config.PART_CMN_S3:
        assert cfg.revision_major is not None, "CMN S3 needs to know revision"
        return CMN_S3_R2 if cfg.revision_major >= 2 else CMN_S3_R0
    return _PRODUCT_KEY_BY_ID[cfg.product_id]


def _merge_channel_fields(product_key, chn):
    """
    Overlay the product tables for one channel and return field positions.

    Product tables are listed from oldest/base to newest/specific in
    _WP_PRODUCT_TABLES. Later tables override earlier entries. Each returned
    value is a positions list: [(group, lsb, width), ...]. An empty list means
    the field name is known, but cannot be matched for this product.
    """
    fields = {}
    for table in _WP_PRODUCT_TABLES[product_key]:
        fields.update(table.get(chn, {}))
    return fields


def _add_dvm_fields(fields_by_channel):
    """
    Add synthetic DVM fields derived from the REQ and SNP address fields.

    DVM selectors are encoded inside CHI address bits. The product tables only
    define the address field; this helper derives dvmtype, dvmvmid, etc. for
    each resolved product layout.
    """
    req_fields = fields_by_channel[REQ]
    snp_fields = fields_by_channel[SNP]
    req_addr = req_fields.get("addr", [])
    snp_addr_pos = snp_fields.get("addr", [])
    for (df, _dlookup, dbits, reqoff, snpoff, frag) in _DVM_FIELD_DEFS:
        name = "dvm" + df
        if frag == 0:
            req_fields[name] = [(grp, pos+reqoff, dbits) for (grp, pos, _width) in req_addr]
        snp_fields[name] = [(grp, pos+snpoff, dbits) for (grp, pos, _width) in snp_addr_pos]
    snp_fields["dvmfrag"] = [(grp, pos, 1) for (grp, pos, _width) in snp_addr_pos]


_resolved_cache = {}
_all_fields_cache = None


def _resolved_positions_by_channel(product_key):
    """
    Return cached resolved field-position maps for all channels of a product.

    The returned object is indexed by channel, then field name. Leaf values are
    positions lists: [(group, lsb, width), ...].
    """
    if product_key not in _resolved_cache:
        fields_by_channel = {}
        for chn in [REQ, RSP, SNP, DAT]:
            fields_by_channel[chn] = _merge_channel_fields(product_key, chn)
        _add_dvm_fields(fields_by_channel)
        _resolved_cache[product_key] = fields_by_channel
    return _resolved_cache[product_key]


def _known_channel_fields():
    """
    Return all known field names for each channel across all products.

    This lets callers distinguish an invalid field for a channel from a valid
    field that is unsupported on the selected product.
    """
    names = {}
    for chn in [REQ, RSP, SNP, DAT]:
        names[chn] = {}
    for product_key in _PRODUCT_KEYS:
        by_channel = _resolved_positions_by_channel(product_key)
        for chn in [REQ, RSP, SNP, DAT]:
            for field in by_channel[chn].keys():
                names[chn][field] = True
    return names


def _meta(chn, field, positions):
    """
    Build the small metadata dictionary used by cmnwatch call sites.

    "positions" is the resolved watchpoint bit layout for one field on one
    selected product. "lookup" is the optional value decoder for that CHI
    field, such as an opcode table or the SNP address conversion function.
    """
    return {
        "lookup": _FIELD_DECODERS.get(chn, {}).get(field),
        "positions": positions,
    }


def fields_for_product(cfg, chn):
    """
    Return field metadata for one product and CHI channel.

    The result maps field name to a metadata dictionary with two entries:
    "positions" gives the already-resolved bit locations for cfg, and
    "lookup" gives the optional field-value decoder common to all products.
    """
    product_key = product_key_for_config(cfg)
    by_channel = _resolved_positions_by_channel(product_key)
    names = _known_channel_fields()[chn]
    fields = {}
    for field in names.keys():
        positions = by_channel[chn].get(field, [])
        if field == "mpam" and cfg.mpam_enabled is False:
            positions = []
        fields[field] = _meta(chn, field, positions)
    return fields


def all_fields_by_channel():
    """
    Return a compatibility metadata view covering all products.

    Older callers inspect cmnwatch._fields before a product has been selected.
    For those callers, each metadata dictionary stores "positions_by_product"
    instead of a single "positions" list. field_positions() resolves the right
    entry later from the product key argument.
    """
    global _all_fields_cache
    if _all_fields_cache is None:
        names = _known_channel_fields()
        all_fields = []
        for chn in [REQ, RSP, SNP, DAT]:
            channel_fields = {}
            for field in names[chn].keys():
                positions_by_product = {}
                for product_key in _PRODUCT_KEYS:
                    by_channel = _resolved_positions_by_channel(product_key)
                    positions_by_product[product_key] = by_channel[chn].get(field, [])
                channel_fields[field] = {
                    "lookup": _FIELD_DECODERS.get(chn, {}).get(field),
                    "positions_by_product": positions_by_product,
                }
            all_fields.append(channel_fields)
        _all_fields_cache = all_fields
    return _all_fields_cache


def field_positions(meta, product_key=None):
    """
    Extract positions from a field metadata dictionary.

    Product-specific metadata from fields_for_product() already contains a
    "positions" list. Compatibility metadata from all_fields_by_channel()
    contains "positions_by_product", so product_key selects the relevant list.
    """
    if "positions" in meta:
        return meta["positions"]
    return meta["positions_by_product"].get(product_key, [])


def field_decoder(meta):
    """
    Return the optional field-value decoder from a metadata dictionary.

    The decoder may be a list of enumerated strings or a callable. None means
    values are parsed directly as integers or wildcard bit strings.
    """
    return meta["lookup"]


def dvm_fragment(field):
    """
    Return which DVM SNP address fragment is implied by a synthetic DVM field.
    """
    return _DVM_FRAG[field]


def chi_field_names():
    """
    Return the sorted union of all CHI watchpoint field names.

    This is used to build command-line arguments and validate short-form
    watchpoint specifications before a channel/product-specific lookup.
    """
    fields = {}
    for channel_fields in all_fields_by_channel():
        for field in channel_fields.keys():
            fields[field] = True
    return sorted(fields.keys())


def _positions_by_group(fields, show_dvm=False):
    """
    Return a group-indexed list of resolved field positions.

    Each entry is (lsb, field, width). A field with positions in more than one
    watchpoint group appears once per group. Fields with no positions are
    unsupported for this product and are not included. Entries are sorted by
    low bit position; fields sharing a low bit are sorted by name. Synthetic
    DVM fields are suppressed unless show_dvm is true.
    """
    by_group = {}
    for (field, positions) in fields.items():
        if not show_dvm and field.startswith("dvm"):
            continue
        for (grp, pos, width) in positions:
            by_group.setdefault(grp, []).append((pos, field, width))
    for grp in by_group.keys():
        by_group[grp] = sorted(by_group[grp])
    return by_group


def print_product_fields(product_key, chn=None, show_dvm=False):
    """
    Print the cumulative resolved watchpoint field layout for one product.

    The product table is printed by CHI channel, then watchpoint group, then
    fields within that group ordered by bit position. The cumulative layout is
    the result after applying all base-product tables listed in
    _WP_PRODUCT_TABLES for product_key.
    """
    by_channel = _resolved_positions_by_channel(product_key)
    print("%s:" % product_key)
    channels = [chn] if chn is not None else [REQ, RSP, SNP, DAT]
    for c in channels:
        print("  %s:" % _CHI_CHANNELS[c])
        by_group = _positions_by_group(by_channel[c], show_dvm=show_dvm)
        for grp in sorted(by_group.keys()):
            print("    group %u:" % grp)
            for (pos, field, width) in by_group[grp]:
                print("      %-16s %2u bits [%u:%u]" % (field, width, pos+width-1, pos))


def _arg_chi_channel(s):
    """
    Convert a command-line channel selector to a CHI channel index.
    """
    if s in ["0", "1", "2", "3"]:
        return int(s)
    s = s.upper()
    if s in _CHI_CHANNELS:
        return _CHI_CHANNELS.index(s)
    raise ValueError("invalid CHI channel specifier")


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="list cumulative CMN watchpoint field definitions")
    parser.add_argument("--chn", type=_arg_chi_channel, default=None,
                        help="only list one CHI channel (REQ/RSP/SNP/DAT)")
    parser.add_argument("--show-dvm", action="store_true",
                        help="show synthetic DVM fields derived from address bits")
    opts = parser.parse_args(argv)
    for product_key in _PRODUCT_KEYS:
        print_product_fields(product_key, chn=opts.chn, show_dvm=opts.show_dvm)


if __name__ == "__main__":
    main(sys.argv[1:])
