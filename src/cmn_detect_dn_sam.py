#!/usr/bin/python

"""Populate requester DN domains from accessible RN-SAM status registers.

Copyright (C) Arm Ltd. 2026. All rights reserved.
SPDX-License-Identifier: Apache 2.0

CMN-700 and later expose a DN node ID in rnsam_status. This tool reads that
single register for each discovered requester RN-SAM, resolves the node ID to
a DN logical ID, and updates the cached topology. Isolated nodes remain
excluded by normal cmn_devmem discovery. CMN-600/650 do not expose this field.
"""

from __future__ import print_function

import argparse
import sys

import cmn_base
import cmn_detect_dn
import cmn_devmem
import cmn_devmem_find
import cmn_enum
import cmn_json
import devmem_base


RNSAM_STATUS = 0x1100


def requester_sam(node):
    """Whether this RN-SAM belongs to a DVM requester slot."""
    if node.type() != cmn_enum.CMN_NODE_RNSAM or node.is_disabled():
        return False
    device = node.device_object
    if device.has_properties(cmn_enum.CMN_PROP_RNF) or device.has_properties(cmn_enum.CMN_PROP_RND):
        return True
    # Arm CMN-700 TRM (102308), section 3.9.4: CML RAs belong to DN domains.
    # CCG-RA is the node type used by CMN-700 and later.
    return any(n.type() in (cmn_enum.CMN_NODE_CXRA, cmn_enum.CMN_NODE_CCG_RA)
               for n in device.device_nodes)


def dn_id_from_status(cmn, value):
    """Extract the DN target ID from rnsam_status; field moved in CMN-S4."""
    if not cmn.part_ge_700():
        raise ValueError('this CMN has no DN node ID field in RN-SAM status')
    if cmn.part_ge_S4():
        return (value >> 16) & 0xffff
    return (value >> 8) & 0x7ff


def scan_mesh(cmn, report=print):
    """
    Read one status word per accessible requester SAM; return assignments.

    Arm CMN-700 TRM (102308), rnsam_status.dn_nodeid:
    https://documentation-service.arm.com/static/64c001a8df6cd61d528c8a55
    The CMN-S4 field moves to bits [31:16]. No DN ID field is present in
    CMN-600/650 rnsam_status.
    """
    if not cmn.part_ge_700():
        report('CMN#%u: RN-SAM status has no DN node ID field' % cmn.cmn_seq)
        return [], 0
    nodes = list(cmn.nodes())
    dns = dict((n.node_id(), n) for n in nodes
               if n.type() == cmn_enum.CMN_NODE_DN and not n.is_disabled())
    if not dns:
        report('CMN#%u: no DN nodes discovered; skipping RN-SAM reads' % cmn.cmn_seq)
        return [], 0
    assignments = []
    unresolved = 0
    for sam in nodes:
        if not requester_sam(sam):
            continue
        source_id = sam.node_id()
        access = None
        try:
            if cmn.secure_accessible:
                value = sam.read64(RNSAM_STATUS)
            else:
                access = devmem_base.SecureAccess(sam, cmn.root_security)
                with access:
                    value = sam.read64(RNSAM_STATUS)
        except Exception as error:
            if access is not None and access.restore_failed:
                raise OSError('CMN#%u requester 0x%x: could not restore memory access mode' %
                              (cmn.cmn_seq, source_id))
            if isinstance(error, (TypeError, ValueError, IndexError,
                                  AttributeError, KeyError, AssertionError)):
                raise
            report('CMN#%u requester 0x%x: RN-SAM unreadable: %s' %
                   (cmn.cmn_seq, source_id, error))
            unresolved += 1
            continue
        if not (value & 2):
            report('CMN#%u requester 0x%x: RN-SAM requests are stalled' %
                   (cmn.cmn_seq, source_id))
            unresolved += 1
            continue
        dn_id = dn_id_from_status(cmn, value)
        dn = dns.get(dn_id)
        if dn is None or dn.logical_id() is None:
            report('CMN#%u requester 0x%x: DN node 0x%x is absent from topology' %
                   (cmn.cmn_seq, source_id, dn_id))
            unresolved += 1
            continue
        cmn_base.check_integer(dn.logical_id(), 'DN logical ID',
                               maximum=cmn_base.NODE_INFO_FIELD_MAX)
        source_ids = [source_id]
        if sam.device_object.has_properties(cmn_enum.CMN_PROP_RNF):
            # Arm CMN-700 TRM (102308), section 3.4.6: RN-Fs on a CAL
            # share one RN SAM. Enumerate cached slots without device reads.
            source_ids = [device.node_id() for device in sam.device_object.port.devices()]
        for requester_id in source_ids:
            assignments.append((cmn, requester_id, dn.logical_id()))
            report('CMN#%u requester 0x%x: DN#%u (node 0x%x)' %
                   (cmn.cmn_seq, requester_id, dn.logical_id(), dn_id))
    return assignments, unresolved


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    cmn_devmem_find.add_cmnloc_arguments(parser)
    parser.add_argument('--json', help='cached topology to update (default: standard CMN cache)')
    parser.add_argument('--no-update', action='store_true', help='report without updating the cache')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    return parser


def main(argv=None):
    opts = argument_parser().parse_args(argv)
    try:
        cmns = cmn_devmem.cmn_from_opts(opts)
        cache_path = None
        if not opts.no_update:
            cache_path = cmn_json.cmn_config_default(opts.json)
            cached = cmn_json.system_from_json_file(cache_path, missing_ok=True)
            if cached is None:
                raise ValueError('%s: cached topology not found; run cmn_discover first' % cache_path)
            cmn_detect_dn.cached_mesh_map(cached, cmns)
        assignments = []
        unresolved = 0
        for cmn in cmns:
            found, missing = scan_mesh(cmn)
            assignments.extend(found)
            unresolved += missing
        if cache_path is not None and assignments:
            cmn_detect_dn.update_cached_domains(cache_path, cmns, assignments)
        print('%u requester DN domains found; %u unresolved' % (len(assignments), unresolved))
        return 0 if not unresolved else 2
    except (TypeError, ValueError, IOError, OSError,
            cmn_devmem_find.CMNNotFound) as error:
        print('cmn_detect_dn_sam: %s' % error, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
