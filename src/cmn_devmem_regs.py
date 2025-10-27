#!/usr/bin/python3

"""
CMN (Coherent Mesh Network) memory-mapped register offsets

Copyright (C) Arm Ltd. 2024. All rights reserved.
SPDX-License-Identifier: Apache 2.0

This is a userspace device driver. It is not expected to disrupt CMN
interconnect operation, but the PMU configuration features might come
into conflict with the Linux driver (drivers/perf/arm-cmn.c).
"""

from __future__ import print_function


# Register offsets
# 'any' generally means offset is valid for any node type,
# or any node type except XP.
CMN_any_NODE_INFO       = 0x0000
CMN_any_CHILD_INFO      = 0x0080

# As of CMN-700, node info regisers are at some or all of 0x900, 0x908 and 0x910
# under various names, not consistent. The fields are node-specific anyway.
CMN_any_UNIT_INFO       = 0x0900     # For most nodes. CMN-700 CCLA it's at 0x910.
CMN_any_UNIT_INFO1      = 0x0908     # CMN-700 on. Some nodes call it unit_info2

CMN_any_AUX_CTL         = 0x0A08

CMN_CFG_PERIPH_01       = 0x0008
CMN_CFG_PERIPH_23       = 0x0010

CMN_any_SECURE_ACCESS   = 0x0980


# Port connectivity information.
# For CMN-600/650 this is max 2 ports with east/north immediately following.
# For CMN-700 it is up to 6 ports, with east/north following those (at offset 6).
CMN_XP_DEVICE_PORT_CONNECT_INFO_P0  = 0x08
CMN_XP_DEVICE_PORT_CONNECT_INFO_P1  = 0x10
def CMN_XP_DEVICE_PORT_CONNECT_INFO_P(p):
    return 0x08 + 8*p
CMN_XP_DEVICE_PORT_CAL_CONNECTED_BIT = 7

def CMN_XP_DEVICE_PORT_CONNECT_LDID_INFO_P(p):
    return 0x48 + 8*p


CMN650_DTM_UNIT_INFO           =  0x910    # CMN-650
CMN700_DTM_UNIT_INFO           =  0x960    # CMN-700

# Debug/Trace Monitor registers in XP.
# DTM base is at 0x2000 before S3, then at 0xD900 in S3 r0, then 0xA000.
CMN_DTM_BASE_OLD   = 0x2000
CMN_DTM_BASE_S3r0  = 0xD900
CMN_DTM_BASE_S3r1  = 0xA000

CMN_DTM_CONTROL_off         = 0x100
CMN_DTM_CONTROL_DTM_ENABLE             = 0x01
CMN_DTM_CONTROL_TRACE_TAG_ENABLE       = 0x02     # set TraceTag on a match
CMN_DTM_CONTROL_SAMPLE_PROFILE_ENABLE  = 0x04     # use PMSIRR/PMSICR countdown
CMN_DTM_CONTROL_TRACE_NO_ATB           = 0x08     # trace to FIFO in XP

CMN_DTM_FIFO_ENTRY_READY_off    = 0x118     # write 1 to clear
CMN_DTM_FIFO_ENTRY0_0_off       = 0x120
def CMN_DTM_FIFO_ENTRY_off(fn,dn):
    return CMN_DTM_FIFO_ENTRY0_0_off + (fn * 24) + (dn * 8)
CMN_DTM_WP0_CONFIG_off          = 0x1A0
CMN_DTM_WP0_VAL_off             = 0x1A8
CMN_DTM_WP0_MASK_off            = 0x1B0    # 1 bit means ignore
# CMN_DTM_WP1_CONFIG           = 0x1B8
CMN_DTM_PMU_PMSICR_off          = 0x200    # sampling interval counter
CMN_DTM_PMU_PMSIRR_off          = 0x208    # sampling interval reload (bits 7:0 must be zero)
CMN_DTM_PMU_CONFIG_off          = 0x210
CMN_DTM_PMU_CONFIG_PMU_EN              = 0x01   # DTM PMU enable - other fields are valid only when this is set
CMN_DTM_PMU_CONFIG_PMEVCNT01_COMBINED  = 0x02   # combine PMU counters 0 and 1
CMN_DTM_PMU_CONFIG_PMEVCNT23_COMBINED  = 0x04   # combine PMU counters 2 and 3
CMN_DTM_PMU_CONFIG_PMEVENTALL_COMBINED = 0x08   # combine PMU counters 0,1,2 and 3
CMN_DTM_PMU_CONFIG_CNTR_RST           = 0x100   # clear live counters upon assertion of snapshot
CMN_DTM_PMU_PMEVCNT_off         = 0x220    # DTM event counters 0 to 3: 16 bits each
CMN_DTM_PMU_PMEVCNTSR_off       = 0x240    # DTM event counter shadow


# Debug/Trace Controller registers (e.g. CMN-600 TRM Table 3-4)
CMN_DTC_CTL         = 0xA00
CMN_DTC_CTL_DT_EN                   = 0x01    # Enable debug, trace and PMU features
CMN_DTC_CTL_DBGTRIGGER_EN           = 0x02    # DBGWATCHTRIG enable
CMN_DTC_CTL_ATBTRIGGER_EN           = 0x04    # ATB trigger enable
CMN_DTC_CTL_DT_WAIT_FOR_TRIGGER     = 0x08    # Wait for cross trigger before trace enable
CMN_DTC_CTL_CG_DISABLE             = 0x400    # Disable DT architectural clock gates
CMN_DTC_TRACECTRL   = 0xA30
CMN_DTC_TRACECTRL_CC_ENABLE        = 0x100    # Cycle count enable
CMN_DTC_TRACEID     = 0xA48

# DTC PMU registers relative to dtc.PM_BASE
CMN_DTC_PM_BASE_OLD    = 0x2000
CMN_DTC_PM_BASE_S3     = 0xd900

CMN_DTC_PMEVCNT_off    = 0x0000    # AB at 0x2000, CD at 0x2010, EF at 0x2020, GH at 0x2030
CMN_DTC_PMCCNTR_off    = 0x0040    # cycle counter (40-bit)
CMN_DTC_PMEVCNTSR_off  = 0x0050    # AB at 0x2050, CD at 0x2060, EF at 0x2070, GH at 0x2080 (shadow regs)
CMN_DTC_PMCCNTRSR_off  = 0x0090    # cycle counter (shadow register)
CMN_DTC_PMCR_off       = 0x0100    # PMU control register
CMN_DTC_PMCR_PMU_EN        = 0x01
CMN_DTC_PMCR_OVFL_INTR_EN  = 0x40
CMN_DTC_PMOVSR_off     = 0x0118    # PMU overflow status (read-only)
CMN_DTC_PMOVSR_CLR_off = 0x0120    # PMU overflow clear (write-only)
CMN_DTC_PMSSR_off      = 0x0128    # PMU snapshot status (read-only)
CMN_DTC_PMSSR_SS_STATUS     =  0x01ff   # Snapshot status (7:0 events; 8 cycles)
CMN_DTC_PMSSR_SS_CFG_ACTIVE =  0x8000   # PMU snapshot activated from configuration write
CMN_DTC_PMSSR_SS_PIN_ACTIVE = 0x10000   # PMU snapshot activated from PMUSNAPSHOTREQ
CMN_DTC_PMSRR_off      = 0x0130    # PMU snapshot request (write-only)
CMN_DTC_PMSRR_SS_REQ          = 0x01    # Write-only - request a snapshot

# PrimeCell regs are offset 0x1E00 on CMN-600
CMN_DTC_PC_CLAIM      = 0xFA0    # set (lower 32 bits) or clear (upper 32 bits) claim tags
CMN_DTC_PC_AUTHSTATUS_DEVARCH = 0xFB8


if __name__ == "__main__":
    pass
