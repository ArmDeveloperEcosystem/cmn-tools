#!/usr/bin/python3

"""
Data definitions for AMBA CHI protocol.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

# Channels in order used by CMN wp_chn_sel.
channel = ["REQ", "RSP", "SNP", "DAT"]

opcode_bits = [6, 4, 4, 3]      # recent CHI has 7 bits for REQ, so use this array with caution


# CHI-G Table B13.12
opcodes_REQ = [
    "ReqLCrdReturn",
    "ReadShared",
    "ReadClean",
    "ReadOnce",
    "ReadNoSnp",
    "PCrdReturn",
    "?0x06",
    "ReadUnique",
    "CleanShared",
    "CleanInvalid",
    "MakeInvalid",
    "CleanUnique",
    "MakeUnique",
    "Evict",
    "CleanInvalidStorage",   # CHI-H
    "?0x0F",
    "?0x10",
    "ReadNoSnpSep",
    "?0x12",
    "CleanSharedPersistSep",
    "DVMOp",
    "WriteEvictFull",
    "?0x16",
    "WriteCleanFull",
    "WriteUniquePtl",
    "WriteUniqueFull",
    "WriteBackPtl",
    "WriteBackFull",
    "WriteNoSnpPtl",
    "WriteNoSnpFull",
    "?0x1E",
    "?0x1F",
    "WriteUniqueFullStash",
    "WriteUniquePtlStash",
    "StashOnceShared",
    "StashOnceUnique",
    "ReadOnceCleanInvalid",
    "ReadOnceMakeInvalid",
    "ReadNotSharedDirty",
    "CleanSharedPersist",
    "AtomicStoreADD",
    "AtomicStoreCLR",
    "AtomicStoreEOR",
    "AtomicStoreSET",
    "AtomicStoreSMAX",
    "AtomicStoreSMIN",
    "AtomicStoreUMAX",
    "AtomicStoreUMIN",
    "AtomicLoadADD",
    "AtomicLoadCLR",
    "AtomicLoadEOR",
    "AtomicLoadSET",
    "AtomicLoadSMAX",
    "AtomicLoadSMIN",
    "AtomicLoadUMAX",
    "AtomicLoadUMIN",
    "AtomicSwap",
    "AtomicCompare",
    "PrefetchTgt",
    "?0x3B",
    "?0x3C",
    "?0x3D",
    "?0x3E",
    "?0x3F",
    "?0x40",
    "MakeReadUnique",
    "WriteEvictOrEvict",
    "WriteUniqueZero",
    "WriteNoSnpZero",
    "?0x45",
    "?0x46",
    "StashOnceSepShared",
    "StashOnceSepUnique",
    "?0x49",
    "?0x4A",
    "?0x4B",
    "ReadPreferUnique",
    "?0x4D",
    "?0x4E",
    "?0x4F",
    "WriteNoSnpFullCleanSh",
    "WriteNoSnpFullCleanInv",
    "WriteNoSnpFullCleanShPerSep",
    "?0x53",
    "WriteUniqueFullCleanSh",
    "?0x55",
    "WriteUniqueFullCleanShPerSep",
    "WriteUniqueFullCleanInvStrg",
    "WriteBackFullCleanSh",
    "WriteBackFullCleanInv",
    "WriteBackFullCleanShPerSep",
    "WriteBackFullCleanInvStrg",
    "WriteCleanFullCleanSh",
    "?0x5D",
    "WriteCleanFullCleanShPerSep",
    "?0x5F",
    "WriteNoSnpPtlCleanSh",
    "WriteNoSnpPtlCleanInv",
    "WriteNoSnpPtlCleanShPerSep",
    "?0x63",
    "WriteUniquePtlCleanSh",
    "?0x65",
    "WriteUniquePtlCleanShPerSep",
    "?0x67",
    "?0x68",
    "?0x69",
    "?0x6A",
    "?0x6B",
    "?0x6C",
    "?0x6D",
    "?0x6E",
    "?0x6F",
    "WriteNoSnpPtlCleanInvPoPA",
    "WriteNoSnpFullCleanInvPoPA",
    "WriteNoSnpFullCleanInvStrg",
    "?0x73",
    "?0x74",
    "?0x75",
    "?0x76",
    "?0x77",
    "?0x78",
    "WriteBackFullCleanInvPoPA",
    "?0x7A",
    "?0x7B",
    "?0x7C",
    "?0x7D",
    "?0x7E",
    "?0x7F",
]

assert len(opcodes_REQ) == 0x80


opcodes_RSP = [
    "RespLCrdReturn",
    "SnpResp",
    "CompAck",
    "RetryAck",
    "Comp",
    "CompDBIDResp",
    "DBIDResp",
    "PCrdGrant",
    "ReadReceipt",
    "SnpRespFwded",
    "TagMatch",
    "RespSepData",
    "Persist",
    "CompPersist",
    "DBIDRespOrd",
    "?0xF",
    "StashDone",
    "CompStashDone",
    "?0x12",
    "?0x13",
    "CompCMO",
    "?0x15",
    "?0x16",
    "?0x17",
    "?0x18",
    "?0x19",
    "?0x1A",
    "?0x1B",
    "?0x1C(CTC)",
    "?0x1D(CTC)",
    "?0x1E(CTC)",
    "?0x1F(CTC)",
]

assert len(opcodes_RSP) == 0x20


# CHI-F Table 13-15
opcodes_SNP = [
    "SnpLCrdReturn",
    "SnpShared",
    "SnpClean",
    "SnpOnce",
    "SnpNotSharedDirty",
    "SnpUniqueStash",
    "SnpMakeInvalidStash",
    "SnpUnique",
    "SnpCleanShared",
    "SnpCleanInvalid",
    "SnpMakeInvalid",
    "SnpStashUnique",
    "SnpStashShared",
    "SnpDVMOp",
    "?0x0E",
    "?0x0F",
    "SnpQuery",
    "SnpSharedFwd",
    "SnpCleanFwd",
    "SnpOnceFwd",
    "SnpNotSharedDirtyFwd",
    "SnpPreferUnique",
    "SnpPreferUniqueFwd",
    "SnpUniqueFwd",
]


# CHI-G Table B13.16
opcodes_DAT = [
    "DataLCrdReturn",
    "SnpRespData",
    "CopyBackWrData",
    "NonCopyBackWrData",
    "CompData",
    "SnpRespDataPtl",
    "SnpRespDataFwded",
    "WriteDataCancel",
    "?0x8",
    "?0x9",
    "?0xA",
    "DataSepResp",
    "NCBWrDataCompAck",    # NonCopyBackWriteDataCompAck in CHI-H
    "?0xD(CTC)",
    "?0xE",
    "?0xF",
]


opcodes = [
    opcodes_REQ, opcodes_RSP, opcodes_SNP, opcodes_DAT
]


NS = ["S", "NS"]


DVM_type = [
    "TLBI",
    "BPI",
    "PICI",
    "VICI",
    "sync",
    "?5",
    "?6",
    "?7",
]


DVM_EL = ["hypguest", "EL3", "guest", "hyp"]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CHI opcode lookup")
    parser.add_argument("ops", type=str, nargs="*", help="opcode names or codes to look up")
    opts = parser.parse_args()
    # Check that all opcode names are unique, across channels
    ops_by_name = {}
    for (ch, ops) in enumerate(opcodes):
        for (op, op_name) in enumerate(ops):
            if op_name.startswith("?"):
                continue
            op_namel = op_name.lower()
            if op_namel in ops_by_name:
                (xch, xop) = ops_by_name[op_namel]
                print("duplicate operator '%s': %s 0x%x vs %s 0x%x" % (op_name, channel[xch], xop, channel[ch], op))
            else:
                ops_by_name[op_namel] = (ch, op)
    for op in opts.ops:
        print("%s:" % op)
        if op.lower().startswith("0x"):
            op = int(op, 16)
            for (ch, ops) in enumerate(opcodes):
                print("  %s %#3x: %s" % (channel[ch], op, ops[op]))
        else:
            if op.lower() in ops_by_name:
                (ch, opc) = ops_by_name[op.lower()]
                print("  %s %#3x: %s" % (channel[ch], opc, opcodes[ch][opc]))
