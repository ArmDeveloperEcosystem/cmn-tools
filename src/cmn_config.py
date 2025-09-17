#!/usr/bin/python3

"""
CMN mesh interconnect product version information

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

from __future__ import print_function


# Each CMN product has a 3-digit part identifier.
# (However, there are cases of significant functional difference
# between revisions of the same product.)

PART_CMN600   = 0x434
PART_CMN650   = 0x436
PART_CMN600AE = 0x438
PART_CMN700   = 0x43c
PART_CI700    = 0x43a
PART_CMN_S3   = 0x43e


_cmn_product_names_by_id = {
    0x434: "CMN-600",
    0x436: "CMN-650",
    0x438: "CMN-600AE",
    0x43c: "CMN-700",
    0x43a: "CI-700",
    0x43e: "CMN S3",
}


cmn_products_by_name = {
    "CMN-600": 0x434,
    "CMN-650": 0x436,
    "CMN-600AE": 0x438,
    "CMN-700": 0x43c,
    "CI-700": 0x43a,
    "CMN-S3": 0x43e,
}


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
    0x434: ["r1p0", "r1p1", "r1p2", "r1p3", "r2p0", "r3p0", "r2p1", "r3p2"],
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
    def __init__(self, product_id=None, product_name=None, revision_code=None, chi_version=None, mpam_enabled=None):
        self.product_id = product_id
        self.revision_code = revision_code
        if product_name is not None:
            # A product name e.g. "cmn-700" or "cmn s3 r2"
            assert product_id is None
            product_name = product_name.upper().replace(' ', '-')
            # strip off a revision suffix?
            rix = product_name.rindex('-')
            if rix > product_name.index('-'):
                rev_suffix = product_name[rix+1:]
                product_name = product_name[:rix]
            else:
                rev_suffix = None
            self.product_id = cmn_products_by_name[product_name]
            if rev_suffix is not None:
                if len(rev_suffix) < 4:
                    rev_suffix += "p0"
                self.revision_code = _cmn_revisions[self.product_id].index(rev_suffix.lower())
        self.mpam_enabled = mpam_enabled
        self.chi_version = chi_version
        self.update_revision_major()

    def set_revision_code(self, revision_code):
        self.revision_code = revision_code
        self.update_revision_major()

    def update_revision_major(self):
        if self.revision_code is not None:
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
            return None
        else:
            try:
                return "CHI-" + ("?ABCDEFGHI"[self.chi_version])
            except LookupError:
                return "CHI-?(%s)" % self.chi_version

    def __eq__(self, b):
        return isinstance(b, CMNConfig) and self.product_id == b.product_id and self.revision_code == b.revision_code and self.mpam_enabled == b.mpam_enabled

    def __ne__(self, b):
        return not self == b

    def __str__(self):
        s = self.product_name(revision=True)
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


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CMN product versions and configurations")
    parser.add_argument("version", type=cmn_version, nargs="+", help="versions")
    parser.add_argument("--list", action="store_true", help="list known revisions")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    if opts.list:
        print("CMN revisions:")
        for id in sorted(_cmn_revisions.keys()):
            print("  %s:" % (_cmn_product_names_by_id[id]))
            for (i, s) in enumerate(_cmn_revisions[id]):
                print("   %2u: %s" % (i, s))
    for v in opts.version:
        print("%s (major %s)" % (v, v.revision_major))
