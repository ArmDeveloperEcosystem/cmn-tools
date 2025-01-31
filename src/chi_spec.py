#!/usr/bin/python3

"""
Data definitions for AMBA CHI protocol.

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0
"""

# Channels in order used by CMN wp_chn_sel.
channel = ["REQ", "RSP", "SNP", "DAT"]

opcode_bits = [6, 4, 4, 3]      # recent CHI has 7 bits for REQ

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
    "?0x0E",
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
    # ... a lot more, including the ones with Opcode[6] == 1
]

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
]

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
    "NCPWrDataCompAck",
    "?0xD",
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
    # Check that opcodes are unique
    for (i, ops1) in enumerate(opcodes[:-1]):
        for op in ops1:
            for ops2 in opcodes[i+1:]:
                if op in ops2:
                    print("duplicate: %s" % op)
