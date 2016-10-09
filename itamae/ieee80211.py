#!/usr/bin/env python

""" ieee80211.py: Constants/Definitions from Std 802.11-2012

Copyright (C) 2016  Dale V. Patterson (wraith.wireless@yandex.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

Redistribution and use in source and binary forms, with or without
modifications, are permitted provided that the following conditions are met:
 o Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 o Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 o Neither the name of the orginal author Dale V. Patterson nor the names of
    any contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

Defines constants as found in the Standard IEEE 802.11-2012

"""

__name__ = 'ieee80211'
__license__ = 'GPL v3.0'
__version__ = '0.0.3'
__date__ = 'October 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

#### Frame Control Std 8.2.4.1.1
# Frame Control is 2 bytes and has the following format
#  Protocol Vers 2 bits: always '00'
#  Type 2 bits: '00' Management, '01' Control,'10' Data,'11' Reserved
#  Subtype 4 bits
#  This comes down the wire as:
#       ST|FT|PV|FLAGS
# bits   4| 2| 2|    8
FT_TYPES = ['mgmt','ctrl','data','rsrv']
FT_MGMT              =  0
FT_CTRL              =  1
FT_DATA              =  2
FT_RSRV              =  3
ST_MGMT_TYPES = ['assoc-req','assoc-resp','reassoc-req','reassoc-resp','probe-req',
                 'probe-resp','timing-adv','mgmt-rsrv-7','beacon','atim','disassoc',
                 'auth','deauth','action','action-noack','mgmt-rsrv-15']
ST_MGMT_ASSOC_REQ    =  0
ST_MGMT_ASSOC_RESP   =  1
ST_MGMT_REASSOC_REQ  =  2
ST_MGMT_REASSOC_RESP =  3
ST_MGMT_PROBE_REQ    =  4
ST_MGMT_PROBE_RESP   =  5
ST_MGMT_TIMING_ADV   =  6 # 802.11p
ST_MGMT_RSRV_7       =  7
ST_MGMT_BEACON       =  8
ST_MGMT_ATIM         =  9
ST_MGMT_DISASSOC     = 10
ST_MGMT_AUTH         = 11
ST_MGMT_DEAUTH       = 12
ST_MGMT_ACTION       = 13
ST_MGMT_ACTION_NOACK = 14
ST_MGMT_RSRV_15      = 15
ST_CTRL_TYPES = ['ctrl-rsrv-0','ctrl-rsrv-1','ctrl-rsrv-2','ctrl-rsrv-3',
                 'ctrl-rsrv-4','ctrl-rsrv-5','ctrl-rsrv-6','wrapper','block-ack-req',
                 'block-ack','pspoll','rts','cts','ack','cfend','cfend-cfack']
ST_CTRL_RSRV_0        =  0
ST_CTRL_RSRV_1        =  1
ST_CTRL_RSRV_2        =  2
ST_CTRL_RSRV_3        =  3
ST_CTRL_RSRV_4        =  4
ST_CTRL_RSRV_5        =  5
ST_CTRL_RSRV_6        =  6
ST_CTRL_WRAPPER       =  7
ST_CTRL_BLOCK_ACK_REQ =  8
ST_CTRL_BLOCK_ACK     =  9
ST_CTRL_PSPOLL        = 10
ST_CTRL_RTS           = 11
ST_CTRL_CTS           = 12
ST_CTRL_ACK           = 13
ST_CTRL_CFEND         = 14
ST_CTRL_CFEND_CFACK   = 15
ST_DATA_TYPES = ['data','cfack','cfpoll','cfack-cfpoll','null','null-cfack',
                 'null-cfpoll','null-cfack-cfpoll','qos-data','qos-data-cfack',
                 'qos-data-cfpoll','qos-data-cfack-cfpoll','qos-null',
                 'data-rsrv-13','qos-cfpoll','qos-cfack-cfpoll']
ST_DATA_DATA                  =  0
ST_DATA_CFACK                 =  1
ST_DATA_CFPOLL                =  2
ST_DATA_CFACK_CFPOLL          =  3
ST_DATA_NULL                  =  4
ST_DATA_NULL_CFACK            =  5
ST_DATA_NULL_CFPOLL           =  6
ST_DATA_NULL_CFACK_CFPOLL     =  7
ST_DATA_QOS_DATA              =  8
ST_DATA_QOS_DATA_CFACK        =  9
ST_DATA_QOS_DATA_CFPOLL       = 10
ST_DATA_QOS_DATA_CFACK_CFPOLL = 11
ST_DATA_QOS_NULL              = 12
ST_DATA_RSRV_13               = 13
ST_DATA_QOS_CFPOLL            = 14
ST_DATA_QOS_CFACK_CFPOLL      = 15

# QoS ACCESS CATEGORY CONSTANTS
QOS_AC_BE_BE = 0
QOS_AC_BK_BK = 1
QOS_AC_BK_NN = 2
QOS_AC_BE_EE = 3
QOS_AC_VI_CL = 4
QOS_AC_VI_VI = 5
QOS_AC_VO_VO = 6
QOS_AC_VO_NC = 7

# constants for status codes Std Table 8-37 (see also ieee80211.h)
STATUS_SUCCESS                                =   0
STATUS_UNSPECIFIED_FAILURE                    =   1
STATUS_TLDS_WAKEUP_REJECTED_ALT               =   2
STATUS_TLDS_WAKEUP_REJECTED                   =   3
STATUS_SECURITY_DISABLED                      =   5
STATUS_UNACCEPTABLE_LIFETIME                  =   6
STATUS_NOT_IN_SAME_BSSECTED                   =   7
STATUS_CAPS_MISMATCH                          =  10
STATUS_REASSOC_NO_ASSOC_EXISTS                =  11
STATUS_ASSOC_DENIED_UNSPEC                    =  12
STATUS_AUTH_ALG_NOT_SUPPORTED                 =  13
STATUS_TRANS_SEQ_UNEXPECTED                   =  14
STATUS_CHALLENGE_FAIL                         =  15
STATUS_AUTH_TIMEOUT                           =  16
STATUS_NO_ADDITIONAL_STAS                     =  17
STATUS_BASIC_RATES_MISMATCH                   =  18
STATUS_ASSOC_DENIED_NOSHORTPREAMBLE           =  19
STATUS_ASSOC_DENIED_NOPBCC                    =  20
STATUS_ASSOC_DENIED_NOAGILITY                 =  21
STATUS_ASSOC_DENIED_NOSPECTRUM                =  22
STATUS_ASSOC_REJECTED_BAD_POWER               =  23
STATUS_ASSOC_REJECTED_BAD_SUPP_CHAN           =  24
STATUS_ASSOC_DENIED_NOSHORTTIME               =  25
STATUS_ASSOC_DENIED_NODSSSOFDM                =  26
STATUS_ASSOC_DENIED_NOHTSUPPORT               =  27
STATUS_ROKH_UNREACHABLE                       =  28
STATUS_ASSOC_DENIED_NOPCO                     =  29
STATUS_REFUSED_TEMPORARILY                    =  30
STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION     =  31
STATUS_UNSPECIFIED_QOS                        =  32
STATUS_ASSOC_DENIED_NOBANDWIDTH               =  33
STATUS_ASSOC_DENIED_POOR_CONDITIONS           =  34
STATUS_ASSOC_DENIED_UNSUPP_QOS                =  35
STATUS_REQUEST_DECLINED                       =  37
STATUS_INVALID_PARAMETERS                     =  38
STATUS_REJECTED_WITH_SUGGESTED_CHANGES        =  39
STATUS_INVALID_ELEMENT                        =  40
STATUS_INVALID_GROUP_CIPHER                   =  41
STATUS_INVALID_PAIRWISE_CIPHER                =  42
STATUS_INVALID_AKMP                           =  43
STATUS_UNSUPP_RSNE_VERSION                    =  44
STATUS_INVALID_RSNE_CAP                       =  45
STATUS_CIPHER_SUITE_REJECTED                  =  46
STATUS_REJECTED_FOR_DELAY_PERIOD              =  47
STATUS_DLS_NOT_ALLOWED                        =  48
STATUS_NOT_PRESENT                            =  49
STATUS_NOT_QOS_STA                            =  50
STATUS_ASSOC_DENIED_LISTEN_INT                =  51
STATUS_INVALID_FT_SPEC_MGMT_CNT               =  52
STATUS_INVALID_PMKID                          =  53
STATUS_INVALID_MDE                            =  54
STATUS_INVALID_FTE                            =  55
STATUS_TCLAS_NOT_SUPPORTED                    =  56
STATUS_INSUFFICIENT_TCLAS                     =  57
STATUS_SUGGEST_TRANSISTION                    =  58
STATUS_GAS_ADV_PROTOCOL_NOT_SUPPORTED         =  59
STATUS_NO_OUTSTANDING_GAS_REQUEST             =  60
STATUS_GAS_RESPONSE_NOT_RECEIVED_FROM_SERVER  =  61
STATUS_GAS_QUERY_TIMEOUT                      =  62
STATUS_GAS_QUERY_RESPONSE_TOO_LARGE           =  63
STATUS_REJECTED_HOME_WITH_SUGGESTED_CHANGES   =  64
STATUS_SERVER_UNREACHABLE                     =  65
STATUS_REJECTED_FOR_SSP_PERMISSIONS           =  67
STATUS_NO_UNAUTHENTICATED_ACCESS              =  68
STATUS_INVALID_RSNE_CONTENTS                  =  72
STATUS_UAPSD_COEXIST_NOTSUPPORTED             =  73
STATUS_REQUESTED_UAPSD_COEXIST_NOTSUPPORTED   =  74
STATUS_REQUESTED_UAPSD_INTERVAL_NOTSUPPORTED  =  75
STATUS_ANTI_CLOG_TOKEN_REQUIRED               =  76
STATUS_FCG_NOT_SUPP                           =  77
STATUS_CANNOT_FIND_ALTERNATIVE_TBTT           =  78
STATUS_TRANSMISSION_FAILURE                   =  79
STATUS_REQUESTED_TCLAS_NOT_SUPPORTED          =  80
STATUS_TCLAS_RESOURCES_EXHAUSTED              =  81
STATUS_REJECTED_WITH_SUGGESTED_BSS_TRANSITION =  82
STATUS_REFUSED_EXTERNAL_REASON                =  92
STATUS_REFUSED_AP_OUT_OF_MEMORY               =  93
STATUS_REJECTED_EMER_SERVICES_NOT_SUPPORTED   =  94
STATUS_QUERY_RESPONSE_OUTSTANDING             =  95
STATUS_MCCAOP_RESERVATION_CONFLICT            = 100
STATUS_MAF_LIMIT_EXCEEDED                     = 101
STATUS_MCCA_TRACK_LIMIT_EXCEEDED              = 102

# authentication algorithm numbers Std Table 8-36 (see also ieee80211.h)
AUTH_ALGORITHM_OPEN   =     0
AUTH_ALGORITHM_SHARED =     1
AUTH_ALGORITHM_FAST   =     2
AUTH_ALGORITHM_SAE    =     3
AUTH_ALGORITHM_VENDOR = 63535

# reason code Std Table 8-36
REASON_UNSPECIFIED                    =  1
REASON_PREV_AUTH_NOT_VALID            =  2
REASON_DEAUTH_LEAVING                 =  3
REASON_DISASSOC_DUE_TO_INACTIVITY     =  4
REASON_DISASSOC_AP_BUSY               =  5
REASON_CLASS2_FRAME_FROM_NONAUTH_STA  =  6
REASON_CLASS3_FRAME_FROM_NONASSOC_STA =  7
REASON_DISASSOC_STA_HAS_LEFT          =  8
REASON_STA_REQ_ASSOC_WITHOUT_AUTH     =  9
REASON_DISASSOC_BAD_POWER             = 10
REASON_DISASSOC_BAD_SUPP_CHAN         = 11
REASON_INVALID_IE                     = 13
REASON_MIC_FAILURE                    = 14
REASON_4WAY_HANDSHAKE_TIMEOUT         = 15
REASON_GROUP_KEY_HANDSHAKE_TIMEOUT    = 16
REASON_IE_DIFFERENT                   = 17
REASON_INVALID_GROUP_CIPHER           = 18
REASON_INVALID_PAIRWISE_CIPHER        = 19
REASON_INVALID_AKMP                   = 20
REASON_UNSUPP_RSN_VERSION             = 21
REASON_INVALID_RSN_IE_CAP             = 22
REASON_IEEE8021X_FAILED               = 23
REASON_CIPHER_SUITE_REJECTED          = 24
REASON_TDLS_Dl_TEARDOWN_UNREACHABLE   = 25
REASON_TDLS_DL_TEARDOWN_UNSPECIFIED   = 26
REASON_SSP_REQUEST                    = 27
REASON_NO_SSP_ROAMING_AGREEMENT       = 28
REASON_SSP_CIPHER_SUITE               = 29
REASON_NOT_AUTHORIZED_LOCATION        = 30
REASON_SERVICE_CHANGE_PRECLUDES_TS    = 31
REASON_DISASSOC_UNSPECIFIED_QOS       = 32
REASON_DISASSOC_QAP_NO_BANDWIDTH      = 33
REASON_DISASSOC_LOW_ACK               = 34
REASON_DISASSOC_QAP_EXCEED_TXOP       = 35
REASON_STA_LEAVING                    = 36
REASON_STA_NOT_USING_MECH             = 37
REASON_QSTA_REQUIRE_SETUP             = 38
REASON_QSTA_TIMEOUT                   = 39
REASON_QSTA_CIPHER_NOT_SUPP           = 45
REASON_MESH_PEER_CANCELED             = 52
REASON_MESH_MAX_PEERS                 = 53
REASON_MESH_CONFIG                    = 54
REASON_MESH_CLOSE                     = 55
REASON_MESH_MAX_RETRIES               = 56
REASON_MESH_CONFIRM_TIMEOUT           = 57
REASON_MESH_INVALID_GTK               = 58
REASON_MESH_INCONSISTENT_PARAM        = 59
REASON_MESH_INVALID_SECURITY          = 60
REASON_MESH_PATH_ERROR                = 61
REASON_MESH_PATH_NOFORWARD            = 62
REASON_MESH_PATH_DEST_UNREACHABLE     = 63
REASON_MAC_EXISTS_IN_MBSS             = 64
REASON_MESH_CHAN_REGULATORY           = 65
REASON_MESH_CHAN                      = 66

# action category codes Std Table 8-38
CATEGORY_SPECTRUM_MGMT             =   0
CATEGORY_QOS                       =   1
CATEGORY_DLS                       =   2
CATEGORY_BLOCK_ACK                 =   3
CATEGORY_PUBLIC                    =   4
CATEGORY_HT                        =   7
CATEGORY_SA_QUERY                  =   8
CATEGORY_PROTECTED_DUAL_OF_ACTION  =   9
CATEGORY_TDLS                      =  12
CATEGORY_MESH_ACTION               =  13
CATEGORY_MULTIHOP_ACTION           =  14
CATEGORY_SELF_PROTECTED            =  15
CATEGORY_DMG                       =  16
CATEGORY_WMM                       =  17
CATEGORY_FST                       =  18
CATEGORY_UNPROT_DMG                =  20
CATEGORY_VHT                       =  21
CATEGORY_VENDOR_SPECIFIC_PROTECTED = 126
CATEGORY_VENDOR_SPECIFIC           = 127
# 128 to 255 are error codes

#### MGMT FRAMES

# CONSTANTS for action frames Std 8.5.1
SPEC_MGMT_MSMT_REQ  = 0
SPEC_MGMT_MSMT_REP  = 1
SPEC_MGMT_TPC_REQ   = 2
SPEC_MGMT_TPC_REP   = 3
SPEC_MGMT_CH_SWITCH = 4

# CONSTANTS for element ids Std 8.4.2.1
# reserved 17 to 31, 47, 49, 128, 129, 133-136, 143-173, 175-220, 222-255
# undefined 77,103
EID_SSID                    =   0 # Std 8.4.2.2
EID_SUPPORTED_RATES         =   1
EID_FH                      =   2
EID_DSSS                    =   3
EID_CF                      =   4
EID_TIM                     =   5
EID_IBSS                    =   6
EID_COUNTRY                 =   7
EID_HOP_PARAMS              =   8
EID_HOP_TABLE               =   9
EID_REQUEST                 =  10
EID_BSS_LOAD                =  11
EID_EDCA                    =  12
EID_TSPEC                   =  13
EID_TCLAS                   =  14
EID_SCHED                   =  15
EID_CHALLENGE               =  16
EID_PWR_CONSTRAINT          =  32
EID_PWR_CAPABILITY          =  33
EID_TPC_REQ                 =  34
EID_TPC_RPT                 =  35
EID_CHANNELS                =  36
EID_CH_SWITCH               =  37
EID_MSMT_REQ                =  38
EID_MSMT_RPT                =  39
EID_QUIET                   =  40
EID_IBSS_DFS                =  41
EID_ERP                     =  42
EID_TS_DELAY                =  43
EID_TCLAS_PRO               =  44
EID_HT_CAP                  =  45 # Std 8.4.2.58
EID_QOS_CAP                 =  46
EID_RSNE                    =  48
EID_EXTENDED_RATES          =  50
EID_AP_CH_RPT               =  51
EID_NEIGHBOR_RPT            =  52
EID_RCPI                    =  53
EID_MDE                     =  54
EID_FTE                     =  55
EID_TIE                     =  56
EID_RDE                     =  57
EID_DSE_REG_LOC             =  58
EID_OP_CLASSES              =  59 # Std 8.4.2.56
EID_EXT_CH_SWITCH           =  60
EID_HT_OP                   =  61 # Std 8.4.2.59
EID_SEC_CH_OFFSET           =  62 # Std 8.4.2.22
EID_BSS_AVG_DELAY           =  63
EID_ANTENNA                 =  64
EID_RSNI                    =  65
EID_MSMT_PILOT              =  66 # Std 8.4.2.44
EID_BSS_AVAIL               =  67
EID_BSS_AC_DELAY            =  68
EID_TIME_ADV                =  69
EID_RM_ENABLED              =  70 # Std 8.4.2.47
EID_MULT_BSSID              =  71 # Std 8.4.2.48
EID_20_40_COEXIST           =  72
EID_20_40_INTOLERANT        =  73
EID_OVERLAPPING_BSS         =  74
EID_RIC_DESC                =  75
EID_MGMT_MIC                =  76
EID_EVENT_REQ               =  78
EID_EVENT_RPT               =  79
EID_DIAG_REQ                =  80
EID_DIAG_RPT                =  81
EID_LOCATION                =  82
EID_NONTRANS_BSS            =  83
EID_SSID_LIST               =  84
EID_MULT_BSSID_INDEX        =  85
EID_FMS_DESC                =  86
EID_FMS_REQ                 =  87
EID_FMS_RESP                =  88
EID_QOS_TRAFFIC_CAP         =  89
EID_BSS_MAX_IDLE            =  90
EID_TFS_REQ                 =  91
EID_TFS_RESP                =  92
EID_WNM_SLEEP               =  93
EID_TIM_REQ                 =  94
EID_TIM_RESP                =  95
EID_COLLOCATED_INTERFERENCE =  96
EID_CH_USAGE                =  97
EID_TIME_ZONE               =  98
EID_DMS_REQ                 =  99
EID_DMS_RESP                = 100
EID_LINK_ID                 = 101
EID_WAKEUP_SCHED            = 102
EID_CH_SWITCH_TIMING        = 104
EID_PTI_CTRL                = 105
EID_TPU_BUFF_STATUS         = 106
EID_INTERWORKING            = 107
EID_ADV_PROTOCOL            = 108
EID_EXPEDITED_BW_REQ        = 109
EID_QOS_MAP_SET             = 110
EID_ROAMING_CONS            = 111
EID_EMERGENCY_ALERT_ID      = 112
EID_MESH_CONFIG             = 113
EID_MESH_ID                 = 114
EID_MESH_LINK_METRIC_RPT    = 115
EID_CONGESTION              = 116
EID_MESH_PEERING_MGMT       = 117
EID_MESH_CH_SWITCH_PARAM    = 118
EID_MESH_AWAKE_WIN          = 119
EID_BEACON_TIMING           = 120
EID_MCCAOP_SETUP_REQ        = 121
EID_MCCAOP_SETUP_REP        = 122
EID_MCCAOP_ADV              = 123
EID_MCCAOP_TEARDOWN         = 124
EID_GANN                    = 125
EID_RANN                    = 126
EID_EXT_CAP                 = 127
EID_PREQ                    = 130
EID_PREP                    = 131
EID_PERR                    = 132
EID_PXU                     = 137
EID_PXUC                    = 138
EID_AUTH_MESH_PEER_EXC      = 139
EID_MIC                     = 140
EID_DEST_URI                = 141
EID_UAPSD_COEXIST           = 142
EID_MCCAOP_ADV_OVERVIEW     = 174
EID_VEND_SPEC               = 221 # Std 8.4.2.28

# CONSTANTS for subelement ids for Neighbor Report Std Table 8-115
EID_NR_TSF              =   1
EID_NR_COUNTRY_STRING   =   2
EID_NR_BSS_TX_CAND_PREF =   3
EID_NR_BSS_TERM_DUR     =   4
EID_NR_BEARING          =   5
EID_NR_HT_CAP           =  45
EID_NR_HT_OP            =  61
EID_NR_SEC_CH_OFFSET    =  62
EID_NR_MSMT_PILOT_TX    =  66
EID_NR_RM_ENABLED_CAP   =  70
EID_NR_MULT_BSSID       =  71
EID_NR_VEND_SPEC        = 221
# Note: reserved 0, 6-44, 46-60, 67-69,72-220,222-255

# CONSTANTS for subelement ids for FTE Std Table 9-121
EID_FTE_RSRV   = 0
EID_FTE_PMK_R1 = 1
EID_FTE_GTK    = 2
EID_FTE_PMK_R0 = 3
EID_FTE_IGTK   = 4
# NOTE: 5 - 255 are reserved

# FMS Element Sttus and TFS Response Status definitions Std Table 8-160
EID_FMS_STATUS_ACCEPT          =  1
EID_FMS_STATUS_DENY_ERR        =  2
EID_FMS_STATUS_DENY_MATCH      =  3
EID_FMS_STATUS_DENY_POLICY     =  4
EID_FMS_STATUS_DENY_UNSPEC     =  5
EID_FMS_STATUS_ALT_STREAM      =  6
EID_FMS_STATUS_ALT_POLICY      =  7
EID_FMS_STATUS_ALT_DELV_CHANGE =  8
EID_FMS_STATUS_ALT_AP_MAST     =  9
EID_FMS_STATUS_TERM_POLICY     = 10
EID_FMS_STATUS_TERM_RESOURCES  = 11
EID_FMS_STATUS_TERM_PRIORITY   = 12
EID_FMS_STATUS_ALT_MAX         = 13
EID_FMS_STATUS_ALT_TCLAS       = 14
# Note: 15 - 255 are reserved

# TFS Request subelement definitions Std Table 8-163
# 0 is reserved
EID_TFS_SUBELEMENT_TFS  =   1
# 2-220 are reserved
EID_TFS_SUBELEMENT_VEND = 221
# 222 - 255 are resrved

# WNM Sleep Mode constants See Std 10.2.1.18
# Action type definitions Std Table 8-165
EID_WNM_SLEEP_ACTION_ENTER = 0
EID_WNM_SLEEP_ACTION_EXIT  = 1
# NOTE 2-255 are reserved

# Response Status definitions Std Table 8-166
EID_WNM_SLEEP_STATUS_ACCEPT   = 0
EID_WNM_SLEEP_STATUS_UPDATE   = 1
EID_WNM_SLEEP_STATUS_DENIED   = 2 # AP cannot perform request
EID_WNM_SLEEP_STATUS_TEMP     = 3 # temporary, try again later
EID_WNM_SLEEP_STATUS_EXPIRE   = 4 # key is pending expiration
EID_WNM_SLEEP_STATUS_SERVICES = 5 # STA has other WNM services in use
# NOTE -255 are reserved

# Expedited Bandwith Request Precedence level definitions Std Table 8-176
EID_EXPEDITED_BW_REQ_CALL  = 16
EID_EXPEDITED_BW_REQ_PUB   = 17
EID_EXPEDITED_BW_REQ_PRIV  = 18
EID_EXPEDITED_BW_REQ_LVL_A = 19
EID_EXPEDITED_BW_REQ_LVL_B = 20
EID_EXPEDITED_BW_REQ_LVL_0 = 21
EID_EXPEDITED_BW_REQ_LVL_1 = 22
EID_EXPEDITED_BW_REQ_LVL_2 = 23
EID_EXPEDITED_BW_REQ_LVL_3 = 24
EID_EXPEDITED_BW_REQ_LVL_4 = 25
# NOTE 0-15 and 26-255 are reserved

# Mesh configuration element definitions Std 8.4.2.100
# Std Table 8-177
EID_MESH_CONFIG_PATH_PROTO_HYBRID =   1
EID_MESH_CONFIG_PATH_PROTO_VENDOR = 255
# NOTE: 0, 2-254 are reserved

# Std Table 8-178
EID_MESH_CONFIG_PATH_METRIC_AIRTIME =   1
EID_MESH_CONFIG_PATH_METRIC_VENDOR  = 255
# NOTE: 0, 2-254 are reserved

# Std Table 8-179
EID_MESH_CONFIG_CONTROL_MODE_DEFAULT =   0
EID_MESH_CONFIG_CONTROL_MODE_SIGNAL  =   1
EID_MESH_CONFIG_CONTROL_MODE_VENDOR  = 255
# NOTE 2-254 are reserved

# Std Table 8-180
EID_MESH_CONFIG_SYNC_MODE_NEIGHBOR =   1
EID_MESH_CONFIG_SYNC_MODE_VENDOR   = 255
# NOTE: 0, 2-254 are reserved

# Std Table 8-181
EID_MESH_CONFIG_AUTH_PROTO_NONE   =   0
EID_MESH_CONFIG_AUTH_PROTO_SAE    =   1
EID_MESH_CONFIG_AUTH_PROTO_8021X  =   2
EID_MESH_CONFIG_AUTH_PROTO_VENDOR = 255
# NOTE: 3-254 are reserved

# Std Table 8-114
EID_NEIGHBOR_RPT_AP_REACH_RSRV = 0
EID_NEIGHBOR_RPT_AP_REACH_NO   = 1
EID_NEIGHBOR_RPT_AP_REACH_UNK  = 2
EID_NEIGHBOR_RPT_AP_REACH_YES  = 3

# Std Table 8-174 (Access Network Types)
EID_INTERWORKING_ANT_PRIV_NET        =  0
EID_INTERWORKING_ANT_PRIV_NET_GUEST  =  1
EID_INTERWORKING_ANT_PUB_NET_CHARGE  =  2
EID_INTERWORKING_ANT_PUB_NET_FREE    =  3
EID_INTERWORKING_ANT_PAN             =  4
EID_INTERWORKING_ANT_EMERG_SERVICE   =  5
EID_INTERWORKING_ANT_TEST            = 14
EID_INTERWORKING_ANT_WILDCARD        = 15
# NOTE: 6 to 13 are reserved

# Std Table 8-183 (MCCA Reply Code values)
EID_MCCA_REPLY_CODE_ACCEPT           = 0
EID_MCCA_REPLY_CODE_REJECT_CONFLICT  = 1 # MCCAOP resrvation conflict
EID_MCCA_REPLY_CODE_REJECT_MAF_LIM   = 2 # MAF limit exceeded
EID_MCCA_REPLY_CODE_REJECT_TRACK_LIM = 3 # MCCA track limit exceeded
# NOTE: 4-255 are reserved

# MSMT REQUEST->Measurement Type Std Table 8-59
EID_MSMT_REQ_TYPE_BASIC     =   0 # basic (spec mgmt)
EID_MSMT_REQ_TYPE_CCA       =   1 # clear channel assessment (spec mgmt)
EID_MSMT_REQ_TYPE_RPI       =   2 # receive power indication histogram (spec mgmt)
EID_MSMT_REQ_TYPE_CH_LOAD   =   3 # channel load (rdo msmt)
EID_MSMT_REQ_TYPE_NOISE     =   4 # noise histogram (rdo msmt)
EID_MSMT_REQ_TYPE_BEACON    =   5 # beacon (rdo msmt)
EID_MSMT_REQ_TYPE_FRAME     =   6 # frame (rdo msmt)
EID_MSMT_REQ_TYPE_STA       =   7 # STA statistics (rdo msmt & WNM)
EID_MSMT_REQ_TYPE_LCI       =   8 # LCI (rdo msmt & WNM)
EID_MSMT_REQ_TYPE_TX        =   9 # tx stream/category msmt (rdo msmt)
EID_MSMT_REQ_TYPE_MULTI     =  10 # multicasat diagnostics (WNM)
EID_MSMT_REQ_TYPE_LOC_CIVIC =  11 # location civic (rdo msmt & WNM)
EID_MSMT_REQ_TYPE_LOC_ID    =  12 # location identifier (rdo msmt & WNM)
# NOTE 13-254 are reserved
EID_MSMT_REQ_TYPE_PAUSE     = 255 # msmt pause (rdo msmt)

# MSMT REQUEST->TYPE CHANNEL LOAD->optional subelement ids Std Table 8-60
EID_MSMT_REQ_SUBELEMENT_CL_RSRV =   0
EID_MSMT_REQ_SUBELEMENT_CL_RPT  =   1
# 2 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_CL_VEND = 221
# 222 - 255 are reserved

# MSMT REQUEST->TYPE BEACON->optional subelement ids Std Table 8-65
EID_MSMT_REQ_SUBELEMENT_BEACON_SSID      =   0
EID_MSMT_REQ_SUBELEMENT_BEACON_BRI       =   1
EID_MSMT_REQ_SUBELEMENT_BEACON_RPT       =   2
# 3-9 are reserved
EID_MSMT_REQ_SUBELEMENT_BEACON_REQ       =  10
# 11-50 are reserved
EID_MSMT_REQ_SUBELEMENT_BEACON_AP_CH_RPT =  51
# 52 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_BEACON_VEND      = 221
# 222 - 255 are reserved

# MSMT REQUEST Group identify for STA statisics report Std Table 8-69
EID_MSMT_REQ_SUBELEMENT_STA_STA =  0
EID_MSMT_REQ_SUBELEMENT_STA_STA_MAC =  1
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP0 =  2
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP1 =  3
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP2 =  4
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP3 =  5
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP4 =  6
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP5 =  7
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP6 =  8
EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP7 =  9
EID_MSMT_REQ_SUBELEMENT_STA_BSS = 10
EID_MSMT_REQ_SUBELEMENT_STA_STA_AMSDU = 11
EID_MSMT_REQ_SUBELEMENT_STA_STA_AMPDU = 12
EID_MSMT_REQ_SUBELEMENT_STA_STA_BAR_CW_PSMP = 13
EID_MSMT_REQ_SUBELEMENT_STA_STA_RD_CTS_LSIG_TXOP = 14
EID_MSMT_REQ_SUBELEMENT_STA_STA_STBC = 15
EID_MSMT_REQ_SUBELEMENT_STA_RSNA = 16
# 17 - 255 are reserved
EID_MSMT_REQ_SUBELEMENT_STA_STA_CNT = [
    EID_MSMT_REQ_SUBELEMENT_STA_STA,
    EID_MSMT_REQ_SUBELEMENT_STA_STA_MAC,
    EID_MSMT_REQ_SUBELEMENT_STA_STA_AMSDU,
    EID_MSMT_REQ_SUBELEMENT_STA_STA_AMPDU,
    EID_MSMT_REQ_SUBELEMENT_STA_STA_BAR_CW_PSMP,
    EID_MSMT_REQ_SUBELEMENT_STA_STA_RD_CTS_LSIG_TXOP,
    EID_MSMT_REQ_SUBELEMENT_STA_STA_STBC
]
EID_MSMT_REQ_SUBELEMENT_STA_QOS_CNT = [
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP0,
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP1,
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP2,
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP3,
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP4,
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP5,
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP6,
    EID_MSMT_REQ_SUBELEMENT_STA_QOS_UP7
]

# MSMT REQUEST->TYPE CHANNEL LOAD->optional subelement ids Std Table 8-62
EID_MSMT_REQ_SUBELEMENT_NH_RSRV =   0
EID_MSMT_REQ_SUBELEMENT_NH_RPT  =   1
# 2 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_NH_VEND = 221
# 222 - 255 are reserved

# MSMT REQUEST->TYPE STA->optional subelement ids Std Table 8-70
EID_MSMT_REQ_SUBELEMENT_STA_RSRV =   0
EID_MSMT_REQ_SUBELEMENT_STA_RPT  =   1
# 2 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_STA_VEND = 221
# 222 - 255 are reserved

# MSMT REQUEST->TYPE LOCATION CONFIGURATION INFORMATION subelement ids Std Table 8-72
EID_MSMT_REQ_SUBELEMENT_LCI_RSRV       =   0
EID_MSMT_REQ_SUBELEMENT_LCI_AZIMUTH    =   1
EID_MSMT_REQ_SUBELEMENT_LCI_REQUESTING =   2
EID_MSMT_REQ_SUBELEMENT_LCI_TARGET     =   3
# 4 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_LCI_VEND       = 221
# 222 -225 are reserved

# MSMT REQUEST->TYPE TX->optional subelement ids Std Table 8-73
EID_MSMT_REQ_SUBELEMENT_TX_RSRV =   0
EID_MSMT_REQ_SUBELEMENT_TX_RPT  =   1
# 2 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_TX_VEND = 221
# 222 - 255 are reserved

# MSMT REQUEST->TYPE MULTICAST DIAG->optional subelement ids Std Table 8-76
EID_MSMT_REQ_SUBELEMENT_MCAST_RSRV    =   0
EID_MSMT_REQ_SUBELEMENT_MCAST_TRIGGER =   1
# 2 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_MCAST_VEND    = 221
# 222 - 255 are reserved

# MSMT REQUEST->Civic Location Types Std Table 8-77
EID_MSMT_REQ_SUBELEMENT_CIVIC_LOC_TYPE_RFC4776 = 0
EID_MSMT_REQ_SUBELEMENT_CIVIC_LOC_TYPE_VEND    = 1
# 2-255 are reserved

# MSMT REQUEST->TYPE LOCATION CIVIC sublement ids Std Table 8-79
EID_MSMT_REQ_SUBELEMENT_LOC_CIVIC_RSRV   =   0
EID_MSMT_REQ_SUBELEMENT_LOC_CIVIC_ORIGIN =   1
EID_MSMT_REQ_SUBELEMENT_LOC_CIVIC_TARGET =   2
# 3 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_LOC_CIVIC_VEND   = 221
# 222 -255 are reserved

# MSMT REQUEST->TYPE LOCATION ID sublement ids Std Table 8-80, Table 8-98
EID_MSMT_REQ_SUBELEMENT_LOC_ID_RSRV   =   0
EID_MSMT_REQ_SUBELEMENT_LOC_ID_ORIGIN =   1
EID_MSMT_REQ_SUBELEMENT_LOC_ID_TARGET =   2
# 3 - 220 are reserved
EID_MSMT_REQ_SUBELEMENT_LOC_ID_VEND   = 221
# 222 -255 are reserved

# MSMT REPORT->Measurement Report Type Std Table 8-81
EID_MSMT_RPT_TYPE_BASIC     =   0 # basic (spec mgmt)
EID_MSMT_RPT_TYPE_CCA       =   1 # clear channel assessment (spec mgmt)
EID_MSMT_RPT_TYPE_RPI       =   2 # receive power indication histogram (spec mgmt)
EID_MSMT_RPT_TYPE_CH_LOAD   =   3 # channel load (rdo msmt)
EID_MSMT_RPT_TYPE_NOISE     =   4 # noise histogram (rdo msmt)
EID_MSMT_RPT_TYPE_BEACON    =   5 # beacon (rdo msmt)
EID_MSMT_RPT_TYPE_FRAME     =   6 # frame (rdo msmt)
EID_MSMT_RPT_TYPE_STA       =   7 # STA statistics (rdo msmt & WNM)
EID_MSMT_RPT_TYPE_LCI       =   8 # LCI (rdo msmt & WNM)
EID_MSMT_RPT_TYPE_TX        =   9 # tx stream/category msmt (rdo msmt)
EID_MSMT_RPT_TYPE_MULTI     =  10 # multicasat diagnostics (WNM)
EID_MSMT_RPT_TYPE_LOC_CIVIC =  11 # location civic (rdo msmt & WNM)
EID_MSMT_RPT_TYPE_LOC_ID    =  12 # location identifier (rdo msmt & WNM)
# NOTE 13-255 are reserved

# IPI Definitions Std TABLE 8-84
IPI_LEVEL_LESS_92       =  0
IPI_LEVEL_BETWEEN_92_89 =  1
IPI_LEVEL_BETWEEN_89_86 =  2
IPI_LEVEL_BETWEEN_86_83 =  3
IPI_LEVEL_BETWEEN_83_80 =  4
IPI_LEVEL_BETWEEN_80_75 =  5
IPI_LEVEL_BETWEEN_75_70 =  6
IPI_LEVEL_BETWEEN_70_65 =  7
IPI_LEVEL_BETWEEN_65_60 =  8
IPI_LEVEL_BETWEEN_60_55 =  9
IPI_LEVEL_GREATER_55    = 10

# MSMT REPORT->Beacon Report optional subelement ids Std Table 8-86
EID_MSMT_RPT_BEACON_RSRV       =   0
EID_MSMT_RPT_BEACON_FRAME_BODY =   1
# 2-220 are reserved
EID_MSMT_RPT_BEACON_VEND       = 221
# 222 - 255 are reserved

# MSMT REPORT->Frame Report optional subelement ids Std Table 8-87
EID_MSMT_RPT_FRAME_RSRV    =   0
EID_MSMT_RPT_FRAME_CNT_RPT =   1
# 2-220 are reserved
EID_MSMT_RPT_FRAME_VEND    = 221
# 222 - 255 are reserved

# MSMT REPORT->Group Identify for STA Statistics Report Std Table 8-88
# The Group id is an index into the list of lengths of the statistics group data
EID_MST_STA_STATS_GID = [28,24,52,52,52,52,52,52,52,52,8,40,36,36,36,20,28]

# MSMT REPORT->STA Statistics Report optional subelement ids Std Table 8-89
EID_MSMT_RPT_STA_STAT_RSRV    =   0
EID_MSMT_RPT_STA_STAT_REASON  =   1
# 2-220 are reserved
EID_MSMT_RPT_STA_STAT_VEND    = 221
# 222 - 255 are reserved

# MSMT REPORT->LCI Report optional subelement ids Std Table 8-90
EID_MSMT_RPT_LCI_RSRV    =   0
EID_MSMT_RPT_LCI_AZIMUTH =   1
EID_MSMT_RPT_LCI_ORIGIN  =   2
EID_MSMT_RPT_LCI_TARGET  =   3
# 4 - 220 are reserved
EID_MSMT_RPT_LCI_VEND    = 221
# 222 - 255 are reserved

# MSMT REPORT->Location Civic Report subelement ids Std Table 8-95
EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_RSRV      =   0
EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_ORIGIN    =   1
EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_TARGET    =   2
EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_LOC_REF   =   3
EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_LOC_SHAPE =   4
EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_MAP_IMAGE =   5
# 6 - 220 are reserved
EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_VEND      = 221
# 221 - 255 are reserved

# Location Shape IDs Table 8-96
LOC_SHAPE_RSRV = 0
LOC_SHAPE_2D_PT = 1
LOC_SHAPE_3D_PT = 2
LOC_SHAPE_CIRCLE = 3
LOC_SHAPE_SPHERE = 4
LOC_SHAPE_POLYGON = 5
LOC_SHAPE_PRISM = 6
LOC_SHAPE_ELLIPSE = 7
LOC_SHAPE_ELLIPSOID = 8
LOC_SHAPE_ARCBAND = 9
# 10 - 255 are reserved

# Sublement IDs for Multiple BSSID info element Std Table 8-120
EID_MUL_BSSID_NONTRANS = 0
# 1 - 120 are reserved
EID_MUL_BSSID_VEND = 221
# 222 - 255 are reserved

# TIE interval type field values Std Table 8-122
EID_TIE_TYPE_REASSOC  = 1
EID_TIE_TYPE_KET_LIFE = 2
EID_TIE_TYPE_COMEBACK = 3
# NOTE 0, 4=255 are reserved

# Cipher suite selectors Std Table 8-99

# Cipher suite usage Std Table 8-100

# AKM suite selectors Std Table 8-101

# TSPEC->TS-INFO->Direction encoding Std Table 8-107
TSPEC_TSINFO_DIRECTION_UP     = 0
TSPEC_TSINFO_DIRECTION_DIRECT = 1
TSPEC_TSINFO_DIRECTION_DOWN   = 2
TSPEC_TSINFO_DIRECTION_BI     = 3

# TSPEC->TS-INFO->Access Policy encoding Std Table 8-108
TSPEC_TSINFO_ACCPOL_RSRV    = 0
TSPEC_TSINFO_ACCPOL_CONTROL = 1
TSPEC_TSINFO_ACCPOL_CONTENT = 2
TSPEC_TSINFO_ACCPOL_MIX     = 3

# TSPEC->TS-INFO->Ack Policy encoding Std Table 8-109
TSPEC_TSINFO_ACKPOL_NORMAL = 0
TSPEC_TSINFO_ACKPOL_RSRV   = 1
TSPEC_TSINFO_ACKPOL_NONE   = 2
TSPEC_TSINFO_ACKPOL_BLOCK  = 3

# TSPEC->TS-INFO->Schedule encoding Std Table 8-110
TSPEC_TSINFO_SCHED_NONE    = 0
TSPEC_TSINFO_SCHED_PSMP    = 1
TSPEC_TSINFO_SCHED_PSMP_UN = 2
TSPEC_TSINFO_SCHED_APSD    = 3

# TCLASS->FRAME CLASSIFIER->Frame Classifier Type Std Table 8-111
TCLAS_FRAMECLASS_TYPE_ETHERNET      = 0
TCLAS_FRAMECLASS_TYPE_TCPUDP        = 1
TCLAS_FRAMECLASS_TYPE_8021Q         = 2
TCLAS_FRAMECLASS_TYPE_FILTER_OFFSET = 3
TCLAS_FRAMECLASS_TYPE_IP            = 4
TCLAS_FRAMECLASS_TYPE_8021D         = 5
# Note 6-255 are reserved

# constants for TCLAS Processing Std Table 8-113
TCLAS_PRO_ALL_  = 0
TCLAS_PRO_ONE_  = 1
TCLAS_PRO_NONE_ = 2
# NOTE: 3-255 are reserved

# EVENT REQUEST->Event Type definitions Std Table 8-133
EVENT_REQUEST_TYPE_TRANSITION =   0
EVENT_REQUEST_TYPE_RSNA       =   1
EVENT_REQUEST_TYPE_P2P        =   2
EVENT_REQUEST_TYPE_WNM_LOG    =   3
# 4 - 220 are reserved
EVENT_REQUEST_TYPE_VEND       = 221
# 222-255 are reserved

# EVENT REQUEST->Event Type=Transistion Subelement IDs Std Table 8-134
EVENT_REQUEST_TYPE_TRANSITION_TARGET   = 0
EVENT_REQUEST_TYPE_TRANSITION_SOURCE   = 1
EVENT_REQUEST_TYPE_TRANSITION_TIME_TH  = 2
EVENT_REQUEST_TYPE_TRANSITION_RESULT   = 3
EVENT_REQUEST_TYPE_TRANSITION_FREQUENT = 4
# 5 - 255 are reserved

# EVENT REQUEST->Event Type=RSNA Subelement IDs Std Table 8-135
EVENT_REQUEST_TYPE_RSNA_TARGET   = 0
EVENT_REQUEST_TYPE_AUTH_TYPE   = 1
EVENT_REQUEST_TYPE_EAP_METHOD  = 2
EVENT_REQUEST_TYPE_RSNA_RESULT   = 3
# 4 - 255 are reserved

# EVENT REQUEST->Event Type=P2P link Subelement IDs Std Table 8-136
EVENT_REQUEST_TYPE_P2P_PEER   = 0
EVENT_REQUEST_TYPE_P2P_CH_NUM = 1

# EVENT REPORT->Event Report Status Std Table 8-137
EVENT_REPORT_STATUS_SUCCESS   = 0
EVENT_REPORT_STATUS_FAILED    = 1
EVENT_REPORT_STATUS_REFUSED   = 2
EVENT_REPORT_STATUS_INCAPABLE = 3
EVENT_REPORT_STATUS_FREQ      = 4
# Note 5-255 are reserved

# TRANSISTION AND TRANSISTION QUERY reasons
TRANSISTION_QUERY_UNSPEC           =  0
TRANSISTION_QUERY_EX_FRAME_LOSS    =  1
TRANSISTION_QUERY_EX_DELAY         =  2
TRANSISTION_QUERY_INSUFFICIENT_CAP =  3
TRANSISTION_QUERY_FIRST_ASSOC      =  4
TRANSISTION_QUERY_LOAD_BALANCE     =  5
TRANSISTION_QUERY_BETTER_AP        =  6
TRANSISTION_QUERY_DEAUTH           =  7
TRANSISTION_QUERY_FAILED_EAP       =  8
TRANSISTION_QUERY_FAILED_4WAY      =  9
TRANSISTION_QUERY_REPLY_CNTR_FAIL  = 10
TRANSISTION_QUERY_DATA_MIC_FAIL    = 11
TRANSISTION_QUERY_MAX_RETRANS      = 12
TRANSISTION_QUERY_BCAST_DISASSOC   = 13
TRANSISTION_QUERY_BCAST_DEAUTH     = 14
TRANSISTION_QUERY_PREV_FAILED      = 15
TRANSISTION_QUERY_LOW_RSSI         = 16
TRANSISTION_QUERY_NON_DOT_ROAM     = 17
TRANSISTION_QUERY_BSS_REQUEST      = 18
TRANSISTION_QUERY_PREF_BSS         = 19
TRANSISTION_QUERY_LEAVING_ESS      = 20
# 21 - 255 are resrved

# DIAGNOSTIC REPORT/REQUEST Type definitions Std Table 8-140
DIAGNOSTIC_REPORT_CDR        = 0 # cancel diagnostic request
DIAGNOSTIC_REPORT_MANUF_INFO = 1 # manufacturer info STA report
DIAGNOSTIC_REPORT_CONFIG     = 2 # configuration profile
DIAGNOSTIC_REPORT_ASSOC      = 3 # association diagnostic
DIAGNOSTIC_REPORT_IEEE_8021X = 4 # 802.1X Authentication diagnostic
# 5-220 are reserved
DIAGNOSTIC_REPORT_VEND       = 5 # vendor specific
# Note: 222-255 are reserved

# DIAGNOSTIC REPORT/REQUEST subelements ID definitions Std Table 8-143
EID_DIAG_SUBELEMENT_CRED        =   0 # credential type
EID_DIAG_SUBELEMENT_AKM         =   1 # akm suite
EID_DIAG_SUBELEMENT_AP          =   2 # AP descriptor
EID_DIAG_SUBELEMENT_ANT         =   3 # antenna type
EID_DIAG_SUBELEMENT_CS          =   4 # cipher suite
EID_DIAG_SUBELEMENT_RDO         =   5 # collocated radio type
EID_DIAG_SUBELEMENT_DEV         =   6 # device type
EID_DIAG_SUBELEMENT_EAP         =   7 # EAP method
EID_DIAG_SUBELEMENT_FW          =   8 # firmware version
EID_DIAG_SUBELEMENT_MAC         =   9 # firmware version
EID_DIAG_SUBELEMENT_MANUF_ID    =  10 # manufacturer ID
EID_DIAG_SUBELEMENT_MANUF_MODEL =  11 # manufacturer model
EID_DIAG_SUBELEMENT_MANUF_OI    =  12 # manufacturer OI
EID_DIAG_SUBELEMENT_MANUF_SER   =  13 # manufacturer serial number
EID_DIAG_SUBELEMENT_POW_SAVE    =  14 # power save mode
EID_DIAG_SUBELEMENT_PROFILE     =  15 # profile ID
EID_DIAG_SUBELEMENT_OP_CLASSES  =  16 # supported op classes
EID_DIAG_SUBELEMENT_STATUS      =  17 # status code
EID_DIAG_SUBELEMENT_SSID        =  18 # SSID
EID_DIAG_SUBELEMENT_TX_POWER    =  19 # to-power capability
EID_DIAG_SUBELEMENT_CERT        =  20 # certificate ID
# 21-220 are reserved
EID_DIAG_SUBELEMENT_VEND        = 221 # vendor specific
# Note: 221 - 255 are resrved

# DIAGNOSTIC REPORT/REQUEST->Collocated Radio type definitions Std Table 8-145
EID_DIAG_RDO_RSRV       =  0
EID_DIAG_RDO_CELLULAR   =  1
EID_DIAG_RDO_CORDLESS   =  2
EID_DIAG_RDO_GPS        =  3
EID_DIAG_RDO_IEEE_80211 =  4
EID_DIAG_RDO_IEEE_80215 =  5
EID_DIAG_RDO_IEEE_80216 =  6
EID_DIAG_RDO_IEEE_80220 =  7
EID_DIAG_RDO_IEEE_80222 =  8
EID_DIAG_RDO_DAB        =  9
EID_DIAG_RDO_DVB        = 10
# Note 11 - 255 are reserved

# DIAGNOSTIC REPORT/REQUEST->Device type definitions Std Table 8-146
EID_DIAG_DEV_RSRV              =   0
EID_DIAG_DEV_REF               =   1
EID_DIAG_DEV_SOHO_AP           =   2
EID_DIAG_DEV_ENT_AP            =   3
EID_DIAG_DEV_CABLE             =   4
EID_DIAG_DEV_STILL_CAMERA      =   5
EID_DIAG_DEV_VID_CAMERA        =   6
EID_DIAG_DEV_WEB_CAMERA        =   7
EID_DIAG_DEV_AUDIO_STAT        =   8
EID_DIAG_DEV_AUDIO_PORT        =   9
EID_DIAG_DEV_SET_TOP           =  10
EID_DIAG_DEV_DISP_DEV          =  11
EID_DIAG_DEV_GAME              =  12
EID_DIAG_DEV_GAME_PORT         =  13
EID_DIAG_DEV_MEDIA_SERVER      =  14
EID_DIAG_DEV_NET_STORAGE       =  15
EID_DIAG_DEV_EXT_CARD          =  16
EID_DIAG_DEV_INT_CARD          =  17
EID_DIAG_DEV_ULTRA_PC          =  18
EID_DIAG_DEV_NOTEBOOK          =  19
EID_DIAG_DEV_PDA               =  20
EID_DIAG_DEV_PRINTER           =  21
EID_DIAG_DEV_PHONE_DUAL        =  22
EID_DIAG_DEV_PHONE_SINGLE      =  23
EID_DIAG_DEV_SMARTPHONE_DUAL   =  24
EID_DIAG_DEV_SMARTPHONE_SINFLE =  25
# 26-220 are reserved
EID_DIAG_DEV_OTHER             = 221
# 222 - 225 are reserved

# DIAGNOSTIC REPORT->Manufacturer Info STA report contents from Std
# Tables 8-149, 8-150, 8-151, 8-152
# defines the order of elements present based on the type of report
EID_DIAG_RPT_ORDER = {
    DIAGNOSTIC_REPORT_MANUF_INFO:[EID_DIAG_SUBELEMENT_MANUF_OI,
                                  EID_DIAG_SUBELEMENT_MANUF_ID,
                                  EID_DIAG_SUBELEMENT_MANUF_MODEL,
                                  EID_DIAG_SUBELEMENT_MANUF_SER,
                                  EID_DIAG_SUBELEMENT_FW,
                                  EID_DIAG_SUBELEMENT_ANT,
                                  EID_DIAG_SUBELEMENT_RDO,
                                  EID_DIAG_SUBELEMENT_DEV,
                                  EID_DIAG_SUBELEMENT_CERT],
    DIAGNOSTIC_REPORT_CONFIG:[EID_DIAG_SUBELEMENT_PROFILE,
                              EID_DIAG_SUBELEMENT_OP_CLASSES,
                              EID_DIAG_SUBELEMENT_TX_POWER,
                              EID_DIAG_SUBELEMENT_CS,
                              EID_DIAG_SUBELEMENT_AKM,
                              EID_DIAG_SUBELEMENT_EAP,
                              EID_DIAG_SUBELEMENT_CRED,
                              EID_DIAG_SUBELEMENT_SSID,
                              EID_DIAG_SUBELEMENT_POW_SAVE],
    DIAGNOSTIC_REPORT_ASSOC:[EID_DIAG_SUBELEMENT_AP,EID_DIAG_SUBELEMENT_STATUS],
    DIAGNOSTIC_REPORT_IEEE_8021X:[EID_DIAG_SUBELEMENT_AP,
                                  EID_DIAG_SUBELEMENT_EAP,
                                  EID_DIAG_SUBELEMENT_CRED,
                                  EID_DIAG_SUBELEMENT_STATUS]
}

# LOCATION PARAMETERS->Location Subelements ID Std Table 8-153
EID_LOCATION_SUBELEMENT_LIP       =   1 # location indication parameters
EID_LOCATION_SUBELEMENT_LIC       =   2 # location indication channels
EID_LOCATION_SUBELEMENT_STATUS    =   3 # location status
EID_LOCATION_SUBELEMENT_RDO_INFO  =   4 # radio information
EID_LOCATION_SUBELEMENT_MOTION    =   5 # motion
EID_LOCATION_SUBELEMENT_LIBDR     =   6 # locaiton indication bcast data rate
EID_LOCATION_SUBELEMENT_DEPT_TIME =   7 # time of departure
EID_LOCATION_SUBELEMENT_LIO       =   8 # location indication options
# Note 9-220 are reserved
EID_LOCATION_SUBELEMENT_VENDOR    = 221 # vendor specific
# Note 222 - 225 are reserved

# FMS REQUEST->Request sublements id definitions Std Table 8-158
EID_FMS_REQ_SUBELEMENT_RSRV =   0
EID_FMS_REQ_SUBELEMENT_FMS  =   1
# 2 - 220 are reserved
EID_FMS_REQ_SUBELEMENT_VEND = 221
# 222 - 255 are reserved

# FMS RESPONSE->Status sublements id definitions Std Table 8-159
EID_FMS_RESP_SUBELEMENT_RSRV  =   0
EID_FMS_RESP_SUBELEMENT_FMS   =   1
EID_FMS_RESP_SUBELEMENT_TCLAS =   2
# 3 - 220 are reserved
EID_FMS_RESP_SUBELEMENT_VEND  = 221
# 222 - 255 are reserved


# ADVERTISEMENT PROTOCOL->Advertisement protocol ID definitions Std Table 8-175
ADV_PROTOCOL_ID_ANQP    =   0
ADV_PROTOCOL_ID_MIH     =   1
ADV_PROTOCOL_ID_MIH_CMD =   2
ADV_PROTOCOL_ID_EAS     =   3
# Note 4-220 are reserved
ADV_PROTOCOL_ID_VEND    = 221
# Note 222-225 are reserved