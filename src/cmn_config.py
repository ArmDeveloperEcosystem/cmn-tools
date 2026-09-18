#!/usr/bin/python3

"""
CMN mesh interconnect product version information

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


import sys

try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)

try:
    basestring
except NameError:
    basestring = str


def check_integer(value, name, minimum=0, maximum=None):
    """
    Check an integer field without accepting booleans or truncating floats.
    Return the value, accepting Python 2 long integers as well as int.
    """
    if isinstance(value, bool) or not isinstance(value, integer_types):
        raise TypeError("%s must be an integer: %r" % (name, value))
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError("%s out of range: %r" % (name, value))
    return value


class CMNProductValueError(ValueError):
    def __init__(self, s):
        self.msg = s

    def __str__(self):
        return self.msg


# Each CMN product has a 3-digit part identifier.
# (However, there are cases of significant functional difference
# between revisions of the same product.)

PART_CMN600   = 0x434
PART_CMN650   = 0x436
PART_CMN600AE = 0x438
PART_CMN700   = 0x43c
PART_CI700    = 0x43a
PART_CMN_S3   = 0x43e
# Synthetic id for an obfuscated product configuration accepted by tools.
PART_CMN_ALTA = 0x410


# CMN generation - monotonic, for feature comparisons etc.
CMN_GEN_600   = 1
CMN_GEN_650   = 2
CMN_GEN_700   = 3
CMN_GEN_S3    = 6
CMN_GEN_S3r1  = 7
CMN_GEN_S3r2  = 8
CMN_GEN_ALTA  = 10


# Generation for r0 of each product
_cmn_generation = {
    PART_CMN600:   CMN_GEN_600,
    PART_CMN600AE: CMN_GEN_600,
    PART_CMN650:   CMN_GEN_650,
    PART_CMN700:   CMN_GEN_700,
    PART_CI700:    CMN_GEN_700,
    PART_CMN_S3:   CMN_GEN_S3,
    PART_CMN_ALTA: CMN_GEN_ALTA,
}


_cmn_product_names_by_id = {
    PART_CMN600:   "CMN-600",
    PART_CMN650:   "CMN-650",
    PART_CMN600AE: "CMN-600AE",
    PART_CMN700:   "CMN-700",
    PART_CI700:    "CI-700",
    PART_CMN_S3:   "CMN S3",
    PART_CMN_ALTA: "CMN-ALTA",
}


cmn_products_by_name = {
    "CMN-600":   PART_CMN600,
    "CMN-650":   PART_CMN650,
    "CMN-600AE": PART_CMN600AE,
    "CMN-700":   PART_CMN700,
    "CI-700":    PART_CI700,
    "CMN-S3":    PART_CMN_S3,
    "CMN-ALTA":  PART_CMN_ALTA,
}


def _parse_chi_version(s):
    su = s.upper()
    if su.startswith("CHI-"):
        su = su[4:]
    elif su.startswith("CHI"):
        su = su[3:]
    if len(su) == 1 and su in "ABCDEFGHI":
        n = "ABCDEFGHI".index(su) + 1
    else:
        n = int(su, 0)
    if n <= 0 or n >= len("?ABCDEFGHI"):
        raise CMNProductValueError("invalid CHI version: %s" % s)
    return n


assert _parse_chi_version("CHI-G") == 7


def _parse_bool(s):
    sl = s.lower()
    if sl in ["1", "y", "yes", "true", "on", "enable", "enabled"]:
        return True
    if sl in ["0", "n", "no", "false", "off", "disable", "disabled"]:
        return False
    raise CMNProductValueError("invalid boolean value: %s" % s)


def _parse_product_config_options(s):
    """
    Parse synthesis-time configuration overrides from a product string suffix.

    The suffix form is:
        cmn-alta-r0p2:chi=g,mpam=on,pa=48,req_pa=48,rsvdc=8
    """
    chi_version = None
    mpam_enabled = None
    pa_width = None
    req_pa_width = None
    rsvdc_width = None
    if s == "":
        raise CMNProductValueError("empty CMN product configuration suffix")
    for opt in s.split(","):
        if opt == "":
            raise CMNProductValueError("empty CMN product configuration option")
        kv = opt.split("=", 1)
        if len(kv) != 2 or kv[0] == "" or kv[1] == "":
            raise CMNProductValueError("invalid CMN product configuration option: %s" % opt)
        k = kv[0].lower()
        v = kv[1]
        if k in ["chi", "chix", "chi_version"]:
            chi_version = _parse_chi_version(v)
        elif k in ["mpam", "mpam_enabled"]:
            mpam_enabled = _parse_bool(v)
        elif k in ["pa", "pa_width"]:
            pa_width = int(v, 0)
        elif k in ["req_pa", "req_pa_width"]:
            req_pa_width = int(v, 0)
        elif k in ["rsvdc", "rsvdc_width"]:
            rsvdc_width = int(v, 0)
        else:
            raise CMNProductValueError("unknown CMN product configuration option: %s" % k)
    return (chi_version, mpam_enabled, pa_width,
            req_pa_width, rsvdc_width)


def product_id_str(n):
    if n is None:
        return "CMN-unknown"
    elif n in _cmn_product_names_by_id:
        return _cmn_product_names_by_id[n]
    elif n in [600, 650, 700]:
        return "CMN-%u" % n   # Legacy
    return "CMN-0x%x??" % n


# map the periph_id_2 codes on to releases.
# Not systematic - CMN-600 r2p1 has a higher code than r3p0
# TBD: the CMN-600 r2p1 and r3p2 TRMs disagree on the numbering.
# TBD: CMN S3 r2p1, r2p2 and r2p3 are tentative awaiting documentation.

_cmn_revisions = {
    PART_CMN600: ["r1p0", "r1p1", "r1p2", "r1p3", "r2p0", "r3p0", "r2p1", "r3p2"],
    PART_CMN650: ["r0p0", "r1p0", "r1p1", "r2p0", "r1p2"],
    PART_CMN700: ["r0p0", "r1p0", "r2p0", "r3p0"],
    PART_CI700:  ["r0p0", "r1p0", "r2p0"],
    PART_CMN_S3: ["r0p0", "r0p1", "r1p0", "r2p0", "r2p1", "r2p2", "r2p3"],
    PART_CMN_ALTA: ["r0p0", "r0p1", "r0p2"],
}


# Distinguish an omitted width (use the legacy default) from an unknown width.
_DEFAULT_PARTID_WIDTH = object()


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

    The object has two fields indicating the revision:
      - revision_code is the field as it occurs in por_cfgm_periph_id_2_periph_id_3.periph_id_2
      - revision_major is the major revision number, i.e. 'x' in 'rxpy'
    """
    def __init__(self, product_id=None, product_name=None, revision_code=None,
                 chi_version=None, mpam_enabled=None, mpam_partid_width=_DEFAULT_PARTID_WIDTH,
                 mte_enabled=None, pa_width=None, req_pa_width=None,
                 rsvdc_width=None):
        self.product_id = product_id        # 3-digit hex code e.g. 0x434
        self.revision_code = revision_code
        if mte_enabled is not None and not isinstance(mte_enabled, bool):
            raise TypeError("MTE enabled must be a boolean")
        self.mte_enabled = mte_enabled
        parsed_chi_version = None
        parsed_mpam_enabled = None
        parsed_req_pa_width = None
        parsed_rsvdc_width = None
        parsed_pa_width = None
        if product_name is not None:
            # A product name e.g. "cmn-700" or "cmn s3 r2"
            if product_id is not None:
                raise ValueError("specify a product name or product id, not both")
            if not isinstance(product_name, basestring):
                raise TypeError("CMN product name must be a string")
            if product_name.find(":") >= 0:
                (product_name, opt_suffix) = product_name.split(":", 1)
                (parsed_chi_version, parsed_mpam_enabled, parsed_pa_width,
                 parsed_req_pa_width,
                 parsed_rsvdc_width) = _parse_product_config_options(opt_suffix)
            product_name = product_name.upper().replace(' ', '-')
            if not product_name.startswith(("CMN", "CI-")):
                product_name = "CMN-" + product_name
            # strip off a revision suffix? e.g. cmn-700-r0
            rix = product_name.rindex('-')
            if rix > product_name.index('-'):
                rev_suffix = product_name[rix+1:]
                product_name = product_name[:rix]
            else:
                rev_suffix = None
            if product_name not in cmn_products_by_name:
                raise CMNProductValueError("Unknown product name: '%s'" % product_name)
            self.product_id = cmn_products_by_name[product_name]
            if rev_suffix is not None:
                if len(rev_suffix) < 4:
                    rev_suffix += "p0"
                self.revision_code = _cmn_revisions[self.product_id].index(rev_suffix.lower())
        if mpam_enabled is None:
            mpam_enabled = parsed_mpam_enabled
        if chi_version is None:
            chi_version = parsed_chi_version
        if pa_width is None:
            pa_width = parsed_pa_width
        if pa_width is not None:
            check_integer(pa_width, "physical address width")
        if pa_width is not None and not 3 <= pa_width <= 52:
            raise CMNProductValueError("invalid physical address width: %s" % pa_width)
        self.pa_width = pa_width
        if req_pa_width is None:
            req_pa_width = parsed_req_pa_width
        if req_pa_width is not None:
            check_integer(req_pa_width, "REQ physical address width")
        if req_pa_width is not None and not 3 <= req_pa_width <= 52:
            raise CMNProductValueError(
                "invalid REQ physical address width: %s" % req_pa_width)
        self.req_pa_width = req_pa_width
        if rsvdc_width is None:
            rsvdc_width = parsed_rsvdc_width
        if rsvdc_width is not None:
            check_integer(rsvdc_width, "RSVDC width")
        if rsvdc_width is not None and not 0 <= rsvdc_width <= 255:
            raise CMNProductValueError("invalid RSVDC width: %s" % rsvdc_width)
        self.rsvdc_width = rsvdc_width
        if mpam_enabled is not None and not isinstance(mpam_enabled, bool):
            raise TypeError("MPAM enabled must be a boolean")
        if chi_version is not None:
            check_integer(chi_version, "CHI version", minimum=1)
        self.mpam_enabled = mpam_enabled
        if mpam_partid_width is _DEFAULT_PARTID_WIDTH:
            mpam_partid_width = 9 if self.mpam_enabled else None
        if mpam_partid_width is not None:
            check_integer(mpam_partid_width, "MPAM PARTID width", minimum=1)
        self.mpam_partid_width = mpam_partid_width
        self.chi_version = chi_version
        check_integer(self.product_id, "CMN product id")
        if self.product_id not in _cmn_generation:
            raise CMNProductValueError("unknown CMN product id: 0x%x" % self.product_id)
        if revision_code is not None:
            check_integer(revision_code, "CMN revision code", maximum=len(_cmn_revisions[self.product_id]) - 1)
        self.update_revision_major()
        self.gen = _cmn_generation[self.product_id]
        if self.product_id == PART_CMN_S3 and self.revision_major is not None:
            if self.revision_major >= 2:
                self.gen = CMN_GEN_S3r2
            elif self.revision_major == 1:
                self.gen = CMN_GEN_S3r1
        if self.mpam_enabled is None and self.is_before_gen(CMN_GEN_700):
            self.mpam_enabled = False

    def set_revision_code(self, revision_code):
        if revision_code is not None:
            check_integer(revision_code, "CMN revision code", maximum=len(_cmn_revisions[self.product_id]) - 1)
        self.revision_code = revision_code
        self.update_revision_major()

    def update_revision_major(self):
        if self.revision_code is not None:
            check_integer(self.revision_code, "CMN revision code", maximum=len(_cmn_revisions[self.product_id]) - 1)
            rev_str = _cmn_revisions[self.product_id][self.revision_code]
            pix = rev_str.index('p')
            self.revision_major = int(rev_str[1:pix])
        else:
            self.revision_major = None

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
            if self.revision_code is not None:
                try:
                    s += " " + _cmn_revisions[self.product_id][self.revision_code]
                except LookupError:
                    s += " rev=%u?" % self.revision_code
            else:
                s += " rev?"
        return s

    def chi_version_str(self):
        if self.chi_version is None:
            return "CHI-?"
        else:
            try:
                return "CHI-" + ("?ABCDEFGHI"[self.chi_version])
            except LookupError:
                return "CHI-?(%s)" % self.chi_version

    def is_at_least_gen(self, gen):
        return self.gen >= gen

    def is_before_gen(self, gen):
        return self.gen < gen

    def summary_fields(self):
        """Return ordered (label, value) pairs for reporting product settings."""
        return [
            ("CMN version", self.product_name(revision=True)),
            ("CHI", self.chi_version_str()),
            ("MPAM enabled", self.mpam_enabled),
            ("MPAM PARTID width", self.mpam_partid_width),
            ("MTE enabled", self.mte_enabled),
            ("PA width", self.pa_width),
            ("REQ PA width", self.req_pa_width),
            ("RSVDC width", self.rsvdc_width),
        ]

    def __eq__(self, b):
        """Compare recorded product settings; unknown values remain distinct from known ones.

        Mesh dimensions are instance topology, outside this configuration. The
        generation and major revision are derived from product_id/revision_code.
        """
        return (isinstance(b, CMNConfig)
                and self.product_id == b.product_id
                and self.revision_code == b.revision_code
                and self.mpam_enabled == b.mpam_enabled
                and self.mpam_partid_width == b.mpam_partid_width
                and self.mte_enabled == b.mte_enabled
                and self.pa_width == b.pa_width
                and self.req_pa_width == b.req_pa_width
                and self.rsvdc_width == b.rsvdc_width
                and self.chi_version == b.chi_version)

    def __ne__(self, b):
        return not self == b

    def __str__(self):
        s = self.product_name(revision=True)
        attrs = []
        if self.chi_version is not None:
            attrs.append(self.chi_version_str())
        if self.mpam_enabled:
            attrs.append("MPAM")
        if self.pa_width is not None:
            attrs.append("PA=%u" % self.pa_width)
        if self.req_pa_width is not None:
            attrs.append("REQ-PA=%u" % self.req_pa_width)
        if self.rsvdc_width is not None:
            attrs.append("RSVDC=%u" % self.rsvdc_width)
        if attrs:
            s += " (" + ", ".join(attrs) + ")"
        return s


def cmn_version(s):
    """
    Given a string, e.g. "cmn-700" or "cmn-alta-r0p2:chi=g,mpam=on",
    return a CMNConfig object.
    """
    return CMNConfig(product_name=s)


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="CMN product versions and configurations")
    parser.add_argument("version", type=str, nargs="*", help="versions")
    parser.add_argument("--list", action="store_true", help="list known revisions")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args(argv)
    if opts.list or not opts.version:
        print("CMN revisions:")
        for id in sorted(_cmn_revisions.keys()):
            print("  %s:" % (_cmn_product_names_by_id[id]))
            for (i, s) in enumerate(_cmn_revisions[id]):
                cfg = CMNConfig(product_id=id, revision_code=i)
                print("   %2u: %s (%s)" % (i, s, cfg))
    for vs in opts.version:
        try:
            v = cmn_version(vs)
        except CMNProductValueError as e:
            print("bad version: %s" % str(e), file=sys.stderr)
            continue
        print("%s (major %s)" % (v, v.revision_major))


if __name__ == "__main__":
    main(sys.argv[1:])
