#!/usr/bin/env python

""" _mpdu.py: Mac Protocol Data Unit (MPDU) parsing (private).

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

Supports the parsing of 802.11 MAC Protocol Data Unit (MPDU) IAW IEEE 802.11-2012
(Std).

"""

__name__ = '_mpdu'
__license__ = 'GPL v3.0'
__version__ = '0.0.5'
__date__ = 'October 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

import struct
import binascii
import itamae.bits as bits
import itamae.ieee80211 as std

#### FRAME FIELDS Std 8.2.3

# FRAMECTRL|DUR/ID|ADDR1|ADDR2|ADDR3|SEQCTRL|ADDR4|QOS|HTC|BODY|FCS
# BYTES   2      2     6     6     6       2     6   2   4  var   4

# unpack formats
_S2F_ = {
    'framectrl':'BB',
    'duration':'H',
    'addr':'6B',
    'seqctrl':'H',
    'bactrl':'H',
    'barctrl':'H',
    'qos':"BB",
    'htc':'I',
    'capability':'H',
    'listen-int':'H',
    'status-code':'H',
    'aid':'H',
    'timestamp':'Q',
    'beacon-int':'H',
    'reason-code':'H',
    'algorithm-no':'H',
    'auth-seq':'H',
    'category':'B',
    'action':'B',
    'wep-keyid':'B',
    'fcs':'I'
}

# Frame Control Flags Std 8.2.4.1.1
# td -> to ds fd -> from ds mf -> more fragments r  -> retry pm -> power mgmt
# md -> more data pf -> protected frame o  -> order
# index of frame types and string titles
_FC_FLAGS_NAME_ = ['td','fd','mf','r','pm','md','pf','o']
_FC_FLAGS_ = {
    'td':(1<<0), # to ds
    'fd':(1<<1), # from ds
    'mf':(1<<2), # more fragments
    'r':(1<<3),  # retry
    'pm':(1<<4), # power mgmt
    'md':(1<<5), # more data
    'pf':(1<<6), # protected frame
    'o':(1<<7)   # order
}
def _fcflags_(mn): return bits.bitmask_list(_FC_FLAGS_,mn)

#### DURATION/ID Std 8.2.4.2 (also see Table 3.3 in CWAP)
# Duration/ID field is 2 bytes and has three functions
#  1. Virtual carrier-sense: value is the NAV timer (i.e. duration)
#  2. Legacy Power MGMT: value is an association id (AID) in PS-Poll frames
#  3. Contention-Free Period: indicates that a PCF process has begun
# Bit    0 - 13| 14| 15| value=
#         0 - 32767|  0| duration
#             0|  0|  1| CFP (fixed value of 32768)
#       1-16383|  0|  1| Reserved
#             0|  1|  1| Reserved
#        1-2007|  1|  1| AID (PS-Poll frames)
#         >2008|  1|  1| Reserved
_DUR_SIG_BITS_ = {'15':(1<<15), '14':(1<<14)}
_DUR_CFP_ = 32768
def _duration_(v):
    """
     parse duration
     :params v: unpacked duration value
     :returns: duration subdict
    """
    field = bits.bitmask_list(_DUR_SIG_BITS_,v)
    if not field['15']: return {'type':'vcs','dur':bits.leastx(15,v)}
    else:
        if not field['14']:
            if v == _DUR_CFP_: return {'type':'cfp'}
        else:
            x = bits.leastx(13,v)
            if x <= 2007: return {'type':'aid','aid':x}
    return {'type':None,'dur':'rsrv'}

#### ADDRESS Fields Std 8.2.4.3

def _hwaddr_(l):
    """
     converts list of packed ints to hw address (lower case)
     :params l: tuple of ints
     :returns: hw address of form XX:YY:ZZ:AA:BB:CC
    """
    return ":".join(['{0:02x}'.format(a) for a in l])

#### SEQUENCE CONTROL Std 8.2.4.4
# Seq. Ctrl is 2 bytes and consists of the follwoing
# Fragment Number (4 bits) number of each fragment of an MSDU/MMPDU
# Sequence Number (12 bits) number of a MSDU, A-MSDU or MMPDU
_SEQCTRL_DIVIDER_ = 4
def _seqctrl_(v):
    """
     converts v to to sequence control
     :param v: unpacked value
     :returns: sequence control sub-dict
    """
    return {'fragno':bits.leastx(_SEQCTRL_DIVIDER_,v),'seqno':bits.mostx(_SEQCTRL_DIVIDER_,v)}

#### QoS CONTROL Std 8.2.4.5
# QoS Ctrl is 2 bytes and consists of five or eight subfields depending on
# the sender and frame subtype
# See Table 8-4 for descriptions

# least signficant 8 bits
_QOS_FIELDS_ = {'eosp':(1<<4),'a-msdu':(1<<7)}
_QOS_TID_END_          = 4 # BITS 0 - 3
_QOS_ACK_POLICY_START_ = 5 # BITS 5-6
_QOS_ACK_POLICY_LEN_   = 2

def _qosctrl_(v):
    """
     parse the qos field from the unpacked values v
     :param v: unpacked value
     :returns: qos control sub-dict
    """
    lsb = v[0] # bits 0-7
    msb = v[1] # bits 8-15

    # bits 0-7 are TID (3 bits), EOSP (1 bit), ACK Policy (2 bits and A-MSDU-present(1 bit)
    qos = bits.bitmask_list(_QOS_FIELDS_,lsb)
    qos['tid'] = bits.leastx(_QOS_TID_END_,lsb)
    qos['ack-policy'] = bits.midx(_QOS_ACK_POLICY_START_,_QOS_ACK_POLICY_LEN_,lsb)
    qos['txop'] = msb # bits 8-15 can vary Std Table 8-4
    return qos

# most signficant 8 bits
#                                 |Sent by HC          |Non-AP STA EOSP=0  |Non-AP STA EOSP=1
# --------------------------------|----------------------------------------|----------------
# std.ST_DATA_QOS_CFPOLL              |TXOP Limit          |                   |
# std.ST_DATA_QOS_CFACK_CFPOLL        |TXOP Limit          |                   |
# std.ST_DATA_QOS_DATA_CFACK          |TXOP Limit          |                   |
# std.ST_DATA_QOS_DATA_CFACK_CFPOLL   |TXOP Limit          |                   |
# std.ST_DATA_QOS_DATA                |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# std.ST_DATA_QOS_DATA_CFACK          |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# std.ST_DATA_QOS_NULL                |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# In Mesh BSS: Mesh Field -> (Mesh Control,Mesh Power Save, RSPI, Reserved
# Othewise Reserved
#
# TXOP Limit:
# TXOP Duration Requested: EOSP bit not set
# AP PS Buffer State:
# Queue Size: sent by non-AP STA with EOSP bit set

# AP PS Buffer State
_QOS_AP_PS_BUFFER_FIELDS = {'rsrv':(1<<0),'buffer-state-indicated':(1<<1)}
_QOS_AP_PS_BUFFER_HIGH_PRI_START_ = 2 # BITS 2-3 (corresponds to 10 thru 11)
_QOS_AP_PS_BUFFER_HIGH_PRI_LEN_   = 2
_QOS_AP_PS_BUFFER_AP_BUFF_START_  = 4 # BITS 4-7 (corresponds to 12 thru 15
def _qosapbufferstate_(v):
    """
     parse the qos ap ps buffer state
     :param v: unpacked value
     :returns qos ps buffer sub-dict
    """
    apps = bits.bitmask_list(_QOS_FIELDS_,v)
    apps['high-pri'] = bits.midx(_QOS_AP_PS_BUFFER_HIGH_PRI_START_,
                            _QOS_AP_PS_BUFFER_HIGH_PRI_LEN_,v)
    apps['ap-buffered'] = bits.mostx(_QOS_AP_PS_BUFFER_AP_BUFF_START_,v)
    return apps

# QoS Mesh Fields
_QOS_MESH_FIELDS_ = {'mesh-control':(1<<0),'pwr-save-lvl':(1<<1),'rspi':(1<<2)}
_QOS_MESH_RSRV_START_  = 3
def _qosmesh_(v):
    """
     parse the qos mesh
     :param v: unpacked value
     :returns qos mesh sub-dict
    """
    mf = bits.bitmask_list(_QOS_MESH_FIELDS_,v)
    mf['high-pri'] = bits.mostx(_QOS_MESH_RSRV_START_,v)
    return mf

# QoS Info field Std 8.4.1.17
# QoS info field is 1 octet but the contents depend on the whether the STA is
# contained w/in an AP
# Sent by AP Std Figure 8-51
# EDCA Param|Q-Ack|Q-Request|TXOP Request|Reserved
#   B0-B3   | B4  | B5      |    B6      |  B7
_QOS_INFO_AP_ = {'q-ack':(1<<4),'q-req':(1<<5),'txop-req':(1<<6),'rsrv':(1<<7)}
_QOS_INFO_AP_EDCA_LEN_ = 4
def qosinfoap(v):
    """ :returns: parsed qos info field sent from an AP """
    qi = bits.bitmask_list(_QOS_INFO_AP_,v)
    qi['edca'] = bits.leastx(_QOS_INFO_AP_EDCA_LEN_,v)
    return qi

# Sent by non-AP STA Std Figure 8-52
# AC_VO_U_APSD|AC_VI_U_APSD|AC_BK_U_APSD|AC_BE_U_APSD|Q-Ack|Max SP Len|More data ACK
#           BO|          B1|          B2|          B3|   B4|   B5-B6  | B7
_QOS_INFO_STA_ = {
    'vo':(1<<0),
    'vi':(1<<1),
    'bk':(1<<2),
    'be':(1<<3),
    'q-ack':(1<<4),
    'more':(1<<7)
}
_QOS_INFO_STA_MAX_SP_START_ = 5
_QOS_INFO_STA_MAX_SP_LEN_   = 2
def qosinfosta(v):
    """ :returns: parsed qos info field sent from an AP """
    qi = bits.bitmask_list(_QOS_INFO_STA_, v)
    qi['max-sp-len'] = bits.midx(
        _QOS_INFO_STA_MAX_SP_START_,_QOS_INFO_STA_MAX_SP_LEN_,v
    )
    return qi

#### HT CONTROL Std 8.2.4.6
# HTC is 4 bytes
_HTC_FIELDS_ = {
    'lac-rsrv':(1<<0),
    'lac-trq':(1<<1),
    'lac-mai-mrq':(1<<2),
    'ndp-annoucement':(1<<24),
    'ac-constraint':(1<<30),
    'rdg-more-ppdu':(1<<31)
}
_HTC_LAC_MAI_MSI_START_      =  3
_HTC_LAC_MAI_MSI_LEN_        =  3
_HTC_LAC_MFSI_START_         =  6
_HTC_LAC_MFSI_LEN_           =  3
_HTC_LAC_MFBASEL_CMD_START_  =  9
_HTC_LAC_MFBASEL_CMD_LEN_    =  3
_HTC_LAC_MFBASEL_DATA_START_ = 12
_HTC_LAC_MFBASEL_DATA_LEN_   =  4
_HTC_CALIBRATION_POS_START_  = 16
_HTC_CALIBRATION_POS_LEN_    =  2
_HTC_CALIBRATION_SEQ_START_  = 18
_HTC_CALIBRATION_SEQ_LEN_    =  2
_HTC_RSRV1_START_            = 20
_HTC_RSRV1_LEN_              =  2
_HTC_CSI_STEERING_START_     = 22
_HTC_CSI_STEERING_LEN_       =  2
_HTC_RSRV2_START_            = 25
_HTC_RSRV2_LEN_              =  5

def _htctrl_(v):
    """
     parses htc field from v
     :param v: unpacked value
     :returns: ht control sub-dict
    """
    # unpack the 4 octets as a whole and parse out individual components
    htc = bits.bitmask_list(_HTC_FIELDS_,v)
    htc['lac-mai-msi'] = bits.midx(_HTC_LAC_MAI_MSI_START_,_HTC_LAC_MAI_MSI_LEN_,v)
    htc['lac-mfsi'] = bits.midx(_HTC_LAC_MFSI_START_,_HTC_LAC_MFSI_LEN_,v)
    htc['lac-mfbasel-cmd'] = bits.midx(_HTC_LAC_MFBASEL_CMD_START_,
                                  _HTC_LAC_MFBASEL_CMD_LEN_,v)
    htc['lac-mfbasel-data'] = bits.midx(_HTC_LAC_MFBASEL_DATA_START_,
                                   _HTC_LAC_MFBASEL_DATA_LEN_,v)
    htc['calibration-pos'] = bits.midx(_HTC_CALIBRATION_POS_START_,
                                  _HTC_CALIBRATION_POS_LEN_,v)
    htc['calibration-seq'] = bits.midx(_HTC_CALIBRATION_SEQ_START_,
                                  _HTC_CALIBRATION_SEQ_LEN_,v)
    htc['rsrv1'] = bits.midx(_HTC_RSRV1_START_,_HTC_RSRV1_LEN_,v)
    htc['csi-steering'] = bits.midx(_HTC_CSI_STEERING_START_,_HTC_CSI_STEERING_LEN_,v)
    htc['rsrv-2'] = bits.midx(_HTC_RSRV2_START_,_HTC_RSRV2_LEN_,v)
    return htc

################################################################################
#### MGMT Frames Std 8.3.3
################################################################################

def _parsemgmt_(f,m):
    """
     parse the mgmt frame f into the mac dict
     :param f: frame
     :param m: the mpdu dict
     NOTE: the mpdu is modified in place
    """
    fmt = _S2F_['addr'] + _S2F_['addr'] + _S2F_['seqctrl']
    try:
        v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
        m['addr2'] = _hwaddr_(v[0:6])
        m['addr3'] = _hwaddr_(v[6:12])
        m['seqctrl'] = _seqctrl_(v[-1])
        m['present'].extend(['addr2','addr3','seqctrl'])
    except struct.error as e:
        m['err'].append(('mgmt',"unpacking addr2,addr3,sequctrl {0}".format(e)))

    # HTC fields?
    #if mac.flags['o']:
    #    v,o = _unpack_from_(_S2F_['htc'],f,o)
    #    d['htc'] = _htctrl_(v)
    #    mac['present'].append('htc')

    # parse out subtype fixed parameters
    try:
        if m.subtype == std.ST_MGMT_ASSOC_REQ:
            # cability info, listen interval
            fmt = _S2F_['capability'] + _S2F_['listen-int']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'capability':_parsecapinfo_(v[0]),
                                 'listen-int':v[1]}
            m['present'].append('fixed-params')
        elif m.subtype == std.ST_MGMT_ASSOC_RESP or m.subtype == std.ST_MGMT_REASSOC_RESP:
            # capability info, status code and association id (only uses 14 lsb)
            fmt = _S2F_['capability'] + _S2F_['status-code'] + _S2F_['aid']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'capability':_parsecapinfo_(v[0]),
                                 'status-code':v[1],
                                 'aid':bits.leastx(14,v[2])}
            m['present'].append('fixed-params')
        elif m.subtype == std.ST_MGMT_REASSOC_REQ:
            fmt = _S2F_['capability'] + _S2F_['listen-int'] + _S2F_['addr']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'capability':_parsecapinfo_(v[0]),
                                 'listen-int':v[1],
                                 'current-ap':_hwaddr_(v[2:])}
            m['present'].append('fixed-params')
        elif m.subtype == std.ST_MGMT_PROBE_REQ: pass # all fields are info-elements
        elif m.subtype == std.ST_MGMT_TIMING_ADV:
            fmt = _S2F_['timestamp'] + _S2F_['capability']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'timestamp':v[0],
                                 'capability':_parsecapinfo_(v[1])}
            m['present'].append('fixed-params')
        elif m.subtype == std.ST_MGMT_PROBE_RESP or m.subtype == std.ST_MGMT_BEACON:
            fmt = _S2F_['timestamp'] + _S2F_['beacon-int'] + _S2F_['capability']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'timestamp':v[0],
                                 'beacon-int':v[1]*1024,  # return in microseconds
                                 'capability':_parsecapinfo_(v[2])}
            m['present'].append('fixed-params')
        elif m.subtype == std.ST_MGMT_DISASSOC or m.subtype == std.ST_MGMT_DEAUTH:
            v,m['offset'] = _unpack_from_(_S2F_['reason-code'],f,m['offset'])
            m['fixed-params'] = {'reason-code':v}
            m['present'].append('fixed-params')
        elif m.subtype == std.ST_MGMT_AUTH:
            fmt = _S2F_['algorithm-no'] + _S2F_['auth-seq'] + _S2F_['status-code']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'algorithm-no':v[0],
                                 'auth-seq':v[1],
                                 'status-code':v[2]}
            m['present'].append('fixed-params')
        elif m.subtype == std.ST_MGMT_ACTION or m.subtype == std.ST_MGMT_ACTION_NOACK:
            fmt = _S2F_['category'] + _S2F_['action']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'category':v[0],'action':v[1]}
            m['present'].append('fixed-params')

            # store the action element(s)
            if m['offset'] < len(f):
                m['action-el'] = f[m['offset']:]
                m['present'].append('action-els')
                m['offset'] = len(f)
        #else: # TODO: std.ST_MGMT_ATIM, RSRV_7, RSRV_8 or RSRV_15
    except Exception as e:
        m['err'].append(('mgmt.{0}'.format(std.ST_MGMT_TYPES[m.subtype]),
                         "parsing {0}".format(e)))

    # get information elements if any
    if m['offset'] < len(f):
        m['info-elements'] = {}
        m['present'].append('info-elements')
    while m['offset'] < len(f):
        try:
            # info elements have the structure (see Std 8.4.2.1)
            # Element ID|Length|Information
            #          1      1    variable
            # pull out info element id and info element len
            # before calculating new offset, pull out the info element
            v,m['offset'] = _unpack_from_('BB',f,m['offset'])
            eid,elen = v[0],v[1]
            ie = f[m['offset']:m['offset']+elen]
            m['offset'] += elen

            # parse the info element and add it
            try:
                ie = _parseie_(eid,ie)
                if eid in m['info-elements']: m['info-elements'][eid].append(ie)
                else: m['info-elements'][eid] = [ie]
            except RuntimeError:
                m['err'].append(("mgmt.info-elements.eid-{0}".format(eid),
                                 "parsing {0}-{1}".format(type(e),e)))
        except struct.error as e:
            # have to stop here or it will loop endlessly
            m['err'].append(("mgmt.info-elements","parsing {0}-{1}".format(type(e), e)))
            break

#### MGMT Frame subfields

# CAPABILITY INFO Std 8.4.1.4
_CAP_INFO_ = {
    'ess':(1<<0),
    'ibss':(1<<1),
    'cfpollable':(1<<2),
    'cf-poll-req':(1<<3),
    'privacy':(1<<4),
    'short-pre':(1<<5),
    'pbcc':(1<<6),
    'ch-agility':(1<<7),
    'spec-mgmt':(1<<8),
    'qos':(1<<9),
    'time-slot':(1<<10),
    'apsd':(1<<11),
    'rdo-meas':(1<<12),
    'dsss-ofdm':(1<<13),
    'delayed-ba':(1<<14),
    'immediate-ba':(1<<15)
}
def _parsecapinfo_(mn):
    """ :returns: parsed cap info field"""
    return bits.bitmask_list(_CAP_INFO_,mn)

# INFORMATION ELEMENTS Std 8.2.4

def _parseie_(eid,info):
    """
     parsea information elements
     :param eid: element id
     :param info: packed string of the information field
     :returns: a tuple (element id,parsed info field)
    """
    try:
        if eid == std.EID_SSID: # Std 8.4.2.2
            info = _iesubelssid_(info)
        elif eid == std.EID_SUPPORTED_RATES or eid == std.EID_EXTENDED_RATES: # Std 8.4.2.3, .15
            # split listofrates where each rate is Mbps. list is 1 to 8 octets,
            # each octect describes a single rate or BSS membership selector
            info = [_eidrates_(struct.unpack('=B',r)[0]) for r in info]
        elif eid == std.EID_FH: # Std 8.4.2.4
            # ttl length is 5 octets w/ 4 elements
            dtime,hset,hpattern,hidx = struct.unpack_from('=H3B',info)
            info = {'dwell-time':dtime,
                    'hop-set':hset,
                    'hop-patterin':hpattern,
                    'hop-index':hidx}
        elif eid == std.EID_DSSS: # Std 8.4.2.5
            # contains the dot11Currentchannel (1-14)
            info = struct.unpack('=B',info)[0]
        elif eid == std.EID_CF: # 8.4.2.6
            # ttl lenght is 6 octets w/ 4 elements
            cnt,per,mx,rem = struct.unpack_from('=2B2H',info)
            info = {'cfp-cnt':cnt,
                    'cfp-per':per,
                    'max-dur':mx,
                    'dur-remaining':rem}
        elif eid == std.EID_TIM: # Std 8.4.2.7
            # variable 4 element
            cnt,per,ctrl = struct.unpack_from('=3B',info)
            bm = binascii.hexlify(info[3:])
            info = {'dtim-cnt':cnt,
                    'dtim-per':per,
                    'bm-ctrl':{'tib':bits.leastx(1,ctrl),
                               'offset':bits.mostx(1,ctrl)},
                               'vir-bm':bm}
        elif eid == std.EID_IBSS: # Std 8.4.2.8
            # single element ATIM Window
            info = struct.unpack_from('=H',info)[0]
        elif eid == std.EID_COUNTRY: # Std 8.4.2.10
            # a pad bit is appended if the field length is not divisible by two
            # Country|Ch Num|Num Chs|Max Tx|<pad>
            #       3|      1|     1|     1|    1
            # the fields Ch Num, Num Chs and Max Tx are repeating

            # see Std, we assume all are unsigned ints for now & parse
            # out the operating triplet
            pad = None
            trips = []
            cstr = info[:3]
            for i in xrange(0,len(info),3):
                try:
                    trips.append(struct.unpack_from('=3B',info,i))
                except struct.error:
                    pad = struct.unpack_from('=B',info,i)
            info = {'country':cstr,'op-tuples':trips}
            if pad: info['pad'] = pad
        elif eid == std.EID_HOP_PARAMS: # Std 8.4.2.11
            # 2 elements
            rad,num = struct.unpack_from('=2B',info)
            info = {'prime-rad':rad,'num-channels':num}
        elif eid == std.EID_HOP_TABLE: # Std 8.4.2.12
            # 4 1-bte elements & 1 variable list of 1 octet
            flag,num,mod,off = struct.unpack_from('=4B',info)
            rtab = info[4:]
            info = {'flag':flag,
                    'num-sets':num,
                    'modulus':mod,
                    'offset':off,
                    'rtab':[struct.unpack('=B',r)[0] for r in rtab]}
        elif eid == std.EID_REQUEST: # Std 8.4.2.13
            # variable length, list of element ids
            info = list(struct.unpack_from("={0}B".format(len(info)),info))
        elif eid == std.EID_BSS_LOAD: # Std 8.4.2.30
            # 3 element
            cnt,util,cap = struct.unpack_from('=HBH',info)
            info = {'sta-cnt':cnt,'ch-util':util,'avail-cap':cap}
        elif eid == std.EID_EDCA: # Std 8.4.2.31
            # QoS|Rsrv|BE|BK|VI|VO
            #   1|   1| 4| 4| 4| 4
            # and each BE,BK,VI,VO is
            #  ACI/AIFSN|EC Min/Max|TXOP Lim
            #          1|         1|       2
            vs = struct.unpack_from('=4BH2BH2BH2BH',info)
            info = {'qos-info':vs[0],
                    'rsrv':vs[1],
                    'ac-be':{'aci':_eidedcaaci_(vs[2]),
                             'ecw':_eidedcaecw_(vs[3]),
                             'txop-lim':vs[4]},
                    'ac-bk':{'aci':_eidedcaaci_(vs[5]),
                             'ecw':_eidedcaecw_(vs[6]),
                             'txop-lim':vs[7]},
                    'ac-vi':{'aci':_eidedcaaci_(vs[8]),
                             'ecw':_eidedcaecw_(vs[9]),
                             'txop-lim':vs[10]},
                    'ac-vo':{'aci':_eidedcaaci_(vs[11]),
                             'ecw':_eidedcaecw_(vs[12]),
                             'txop-lim':vs[13]}}
        elif eid == std.EID_TSPEC: # Std 8.4.2.32
            # See Fig 8-196, 55 octet field with 16 subfields
            # the first field ts-info is 3 bytes which we append a null byte to
            # IOT to treat it as a 4-octet field
            # 3 1-octet elements
            tsinfo = _eidtspectsinfo_(struct.unpack_from('=I',info[0:3]+'\x00'))
            vs = struct.unpack_from('=2H11I2H',info,3)
            info = {'ts-info':tsinfo,
                    'nom-msdu-sz':{'sz':bits.leastx(15,vs[0]),
                                   'fixed':bits.mostx(15,vs[0])},
                    'max-msdu-sz':vs[1],
                    'min-ser-intv':vs[2],
                    'max-ser-intv':vs[3],
                    'inactivity-intv':vs[4],
                    'suspension-intv':vs[5],
                    'ser-start-time':vs[6],
                    'min-data-rate':vs[7],
                    'mean-data-rate':vs[8],
                    'peak-data-rate':vs[9],
                    'burst-sz':vs[10],
                    'delay-bound':vs[11],
                    'min-phy-rate':vs[12],
                    'surplus-bw-allowance':vs[13],
                    'medium-time':vs[14]}
        elif eid == std.EID_TCLAS: # Std 8.4.2.33
            # Std Fig 8-199 and Fig 8-200
            up,ct,cm = struct.unpack_from('=3B',info)
            ps = info[3:]
            info = {'user-pri':up,'cls-type':ct,'cls-mask':cm}

            # the classifier params is dependent on the classifier type
            if info['cls-type'] == std.TCLAS_FRAMECLASS_TYPE_ETHERNET:
                # Std Fig. 8-201
                vs = struct.unpack_from('=12BH',ps)
                info['cls-params'] = {'src-addr':_hwaddr_(vs[0:6]),
                                      'dest-addr':_hwaddr_(vs[6:12]),
                                      'frm-type':vs[12]}
            elif info['cls-type'] == std.TCLAS_FRAMECLASS_TYPE_TCPUDP:
                # Fig 8-202 and Fig 8-203
                # have to pull out ver to determine if ipv4 or ipv6
                vers = struct.unpack_from('=B',ps)[0]
                if vers == 4:
                    vs = struct.unpack_from('=8B2H3B',ps,1)
                    info['cls-params'] = {'vers':vers,
                                          'src-addr':vs[0:4],
                                          'dest-addr':vs[4:8],
                                          'src-port':vs[8],
                                          'dest-port':vs[9],
                                          'dscp':vs[10],
                                          'proto':vs[11],
                                          'rsrv':vs[12]}
                elif vers == 6:
                    # note: flow label is a 3-byte octet, append a null byte
                    src = ps[1:17]
                    dest = ps[17:33]
                    sp,dp,fl = struct.unpack_from('=2HI',ps+'\x00',33)
                    info['cls-params'] = {'vers':vers,
                                          'src-addr':src,
                                          'dest-addr':dest,
                                          'src-port':sp,
                                          'dest-port':dp,
                                          'flow-lbl':fl}
            elif info['cls-type'] == std.TCLAS_FRAMECLASS_TYPE_8021Q:
                # Fig 8-204
                info['cls-params'] = {'vlan-tci':struct.unpack_from('=H',ps)[0]}
            elif info['cls-type'] == std.TCLAS_FRAMECLASS_TYPE_FILTER_OFFSET:
                # Fig 8-205
                l = (len(ps)-2)/2
                info['cls-params'] = {
                    'filter-offset':struct.unpack_from('=H',ps)[0],
                    'filter-val':ps[2:2+l],
                    'filter-mask':ps[2+l:]
                }
            elif info['cls-type'] == std.TCLAS_FRAMECLASS_TYPE_IP:
                # Std Fig 8-206 and Fig 8-207
                # have to pull out ver to determine if ipv4 or ipv6
                vers = struct.unpack_from('=B',ps)[0]
                if vers == 4:
                    vs = struct.unpack_from('=8B2H3B',ps,1)
                    info['cls-params'] = {'vers':vers,
                                          'src-addr':vs[0:4],
                                          'dest-addr':vs[4:8],
                                          'src-port':vs[8],
                                          'dest-port':vs[9],
                                          'dscp':vs[10],
                                          'proto':vs[11],
                                          'rsrv':vs[12]}
                elif vers == 6:
                    # note: flow label is a 3-byte octet, append a null byte
                    src = ps[1:17]
                    dest = ps[17:33]
                    sp,dp,d,nh,fl = struct.unpack_from('=2H2BI',ps+'\x00',33)
                    info['cls-params'] = {'vers':vers,
                                          'src-addr':src,
                                          'dest-addr':dest,
                                          'src-port':sp,
                                          'dest-port':dp,
                                          'dscp':d,
                                          'next-hdr':nh,
                                          'flow-lbl':fl}
            elif info['cls-type'] == std.TCLAS_FRAMECLASS_TYPE_8021D:
                # Std Fig. 8-208
                p,c,v = struct.unpack_from('=2BH',ps)
                info['cls-params'] = {'802.1q-pcp':p,'802.1q-cfi':c,'802.1q-vid':v}
        elif eid == std.EID_SCHED: # Std 8.4.2.36
            # 12 bytes, 4 element
            sinfo,start,ser_int,spec_int = struct.unpack_from('=H3I',info)
            info = {'sched-info':_eidsched_(sinfo),
                    'ser-start':start,
                    'ser-int':ser_int,
                    'spec-int':spec_int}
        elif eid == std.EID_CHALLENGE: # Std 8.4.2.9
            # 1-253 octet challenge text (see Std 11.2.3.2)
            info = binascii.hexlify(info)
        elif eid == std.EID_PWR_CONSTRAINT: # Std 8.4.2.16
            info = struct.unpack_from('=B',info)[0] # in dBm
        elif eid == std.EID_PWR_CAPABILITY: # Std 8.4.2.17
            mn,mx = struct.unpack_from('=2B',info)
            info = {'min':mn,'max':mx}             # in dBm
        elif eid == std.EID_TPC_REQ: pass # Std 8.4.2.18 (a flag w/ no info
        elif eid == std.EID_TPC_RPT: # Std 8.4.2.19
            # 2 element, tx pwr in dBm & twos-complement dBm
            # see also 8,3,3,2, 8.3.3.10 8.5.2.5 & 19.8.6
            pwr,link = struct.unpack_from('=Bb',info)
            info = {'tx-power':pwr,'link-margin':link}
        elif eid == std.EID_CHANNELS: # Std 8.4.2.20
            # Repeating: First Ch Num|Num channels
            #                       1|           1
            # return as a list of tuples
            chs = []
            for i in xrange(0,len(info),2):
                try:
                    chs.append(struct.unpack_from('=2B',info,i))
                except struct.error:
                    break
            info = chs
        elif eid == std.EID_CH_SWITCH: # Std 8.4.2.21
            # 3 element
            mode,new,cnt = struct.unpack_from('=3B',info)
            info = {'mode':mode,'new-ch':new,'cnt':cnt}
        elif eid == std.EID_MSMT_REQ: # Std 8.4.2.23
            # Msmt Token|Msmt Mode|Msmt Type|Msmt Req
            #          1|        1|        1|     var
            tkn,mod,typ = struct.unpack_from('=3B',info)
            req = info[3:]
            info = {'tkn':tkn,
                    'mode':_eidmsmtreqmode_(mod),
                    'type':typ}

            # Msmt req format depends on the type
            if info['type'] <= std.EID_MSMT_REQ_TYPE_RPI:
                # types basic, cca and rpi have the same format
                # Std Figs. 1-106, 8-107, 8-108
                c,s,d = struct.unpack_from('=BQD',req)
                info['req'] = {'ch-num':c,'msmt-start':s,'msmt-dur':d}
            elif info['type'] == std.EID_MSMT_REQ_TYPE_CH_LOAD:
                # Std Fig. 8-109
                o,c,r,d = struct.unpack_from('=2B2H',req)
                opt = req[6:]
                info['req'] = {'op-class':o,'ch-num':c,'rand-intv':r,'msmt-dur':d}
                if opt:
                    info['rec']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqcl_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_NOISE:
                # Std Fig. 8-111
                # almost same as above except for optional subelements
                o,c,r,d = struct.unpack_from('=2B2H',req)
                opt = req[6:]
                info['req'] = {'op-class':o,'ch-num':c,'rand-intv':r,'msmt-dur':d}
                if opt:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqnh_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_BEACON:
                # Std Fig 8-113
                vs = struct.unpack_from('=2B2H7B',req)
                opt = req[struct.calcsize('=2B2H7B'):]
                info['req'] = {'op-class':vs[0],
                               'ch-num':vs[1],
                               'rand-intv':vs[2],
                               'msmt-dur':vs[3],
                               'msmt-mode':vs[4],
                               'bssid':_hwaddr_(vs[5:])}
                if opt:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqbeacon_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_FRAME:
                # Std Fig. 8-115
                vs = struct.unpack_from('=2B2H7B',req)
                opt = req[struct.calcsize('=2B2H7B'):]
                info['req'] = {'op-class':vs[0],
                               'ch-num':vs[1],
                               'rand-intv':vs[2],
                               'msmt-dur':vs[3],
                               'frame-req-type':vs[4],
                               'mac-addr':_hwaddr_(vs[5:])}
                if opt:
                    info['rec']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqframe_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_STA:
                # Std Fig. 8-116
                vs = struct.unpack_from('=6B2HB',req)
                opt = req[struct.calcsize('=6B2HB'):]
                info['req'] = {'peer-mac':_hwaddr_(vs[0:6]),
                               'rand-intv':vs[6],
                               'msmt-dur':vs[7],
                               'grp-id':vs[8]}

                # the format of the optional fields depends on the grp-id
                if info['req']['grp-id'] in std.EID_MSMT_REQ_SUBELEMENT_STA_STA_CNT:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqstasta_)
                elif info['req']['grp-id'] in std.EID_MSMT_REQ_SUBELEMENT_STA_QOS_CNT:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqstaqos_)
                elif info['req']['grp-id'] == std.EID_MSMT_REQ_SUBELEMENT_STA_RSNA:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqstarsna_)
                else:
                    if opt: info['req']['unparsed'] = opt
            elif info['type'] == std.EID_MSMT_REQ_TYPE_LCI:
                s,lat,lon,alt = struct.unpack_from('=4B',req)
                opt = req[4:]
                info['req'] = {'loc-subj':s,
                               'lat-res':lat,
                               'lon-res':lon,
                               'alt-res':alt}
                if opt:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqlci_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_TX:
                # Std Fig. 8-128
                vs = struct.unpack_from('=2H8B',req)
                opt = req[12:]
                info['req'] = {'rand-intv':vs[0],
                               'msmt-dur':vs[1],
                               'peer-sta':_hwaddr_(vs[2:8]),
                               'traffic-id':{'rsrv':bits.leastx(4,vs[8]), # Fig 8-129
                                             'tid':bits.mostx(4,vs[8])},
                               'bin0-range':vs[9]}
                if opt:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqtx_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_MULTI:
                # Fig 8-135
                vs = struct.unpack('=2H6B',req)
                rem = req[10:]
                info['req'] = {'rand-intv':vs[0],
                               'msmt-dur':vs[1],
                               'grp-mac':_hwaddr_(vs[2:])}

                # optional fields
                if rem:
                    # may be an optional mcast trigger condition prior to
                    # the optional subelements
                    sid = struct.unpack_from('=B',rem)[0]
                    if sid == std.EID_MSMT_REQ_SUBELEMENT_MCAST_TRIGGER:
                        c,t,d = struct.unpack_from('=3B',rem,2)
                        info['req']['mcast-trigger-rpt'] = {
                            'trigger-condition':c,
                            'inactivity-timeout':t,
                            'reactivation-delay':d}
                        rem = rem[5:]
                    if rem:
                        opt = _parseiesubel_(rem,_iesubelmsmtreqmcastdiag_)
                        info['req']['opt-subels'] = opt
            elif info['type'] == std.EID_MSMT_REQ_TYPE_LOC_CIVIC:
                # Fig 8-138
                s,t,u,i = struct.unpack_from('=3BH',req)
                opt = req[5:]
                info['req'] = {'loc-subj':s,'loc-type':t,'loc-units':u,'loc-intv':i}
                if opt:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqloccivic_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_LOC_ID:
                s,u,i = struct.unpack_from('=2BH',req)
                opt = req[4:]
                info['req'] = {'loc-subj':s,'loc-intv-units':u,'loc-serv-intv':i}
                if opt:
                    info['req']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtreqlid_)
            elif info['type'] == std.EID_MSMT_REQ_TYPE_PAUSE:
                p = struct.unpack_from('=H',req)[0]
                opt = req[2:]
                info['req'] = {'pause-time':p}
                if opt: info['req']=_parseiesubel_(opt,_iesubelmsmtreqpause_)
        elif eid == std.EID_MSMT_RPT: # Std 8.4.2.24
            # Msmt Token|Msmt Mode|Msmt Type|Msmt Rpt
            #          1|        1|        1|     var
            tkn,mod,typ = struct.unpack_from('=3B',info)
            rpt = info[3:]
            info = {'tkn':tkn,
                    'mode':_eidmstrptmode_(mod),
                    'type':typ}

            # msmt rpt depends on the type
            if info['type'] == std.EID_MSMT_RPT_TYPE_BASIC:
                # Std Fig. 8-142
                c,s,d,m = struct.unpack_from('=BQHB',rpt)
                info['rpt'] = {'ch-num':c,
                               'msmt-start-time':s,
                               'msmt-dur':d,
                               'map':_eidmsmtrptbasicmap_(m)}
            elif info['type'] == std.EID_MSMT_RPT_TYPE_CCA:
                # Std Fig 8-144
                c,s,d,f = struct.unpack_from('=BQHB',rpt)
                info['rpt'] = {'ch-num':c,
                               'msmt-start-time':s,
                               'msmt-dur':d,
                               'cca-busy-frac':f}
            elif info['type'] == std.EID_MSMT_RPT_TYPE_RPI:
                # Fig 8-145
                c,s,d = struct.unpack_from('=BQH',rpt)
                info['rpt'] = {'ch-num':c,
                               'msmt-start-time':s,
                               'msmt-dur':d}
                for i,r in enumerate(struct.unpack_from('=8B',rpt,11)):
                    info['rpt']['rpi-{0}'.format(i)] = r
            elif info['type'] == std.EID_MSMT_RPT_TYPE_CH_LOAD:
                # Std Fig. 8-146
                o,n,s,d,l = struct.unpack_from('=2BQHB',rpt)
                opt = info[struct.calcsize('=2BQHB'):]
                info['rpt'] = {'op-class':o,
                               'ch-num':n,
                               'start-time':s,
                               'msmt-dur':d,
                               'ch-load':l}
                if opt:
                    info['rpt']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtrptvend_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_NOISE:
                # Std Fig 8-147
                o,n,s,d,i,a = struct.unpack_from('=2BQH2B',rpt)
                ipis = struct.unpack_from('=11B',rpt,struct.calcsize('=2BQH2B'))
                opt = rpt[struct.calcsize('=2BQH13B'):]
                info['rpt'] = {'op-class':o,
                               'ch-num':n,
                               'start-time':s,
                               'msmt-dur':d,
                               'antenna-id':i,
                               'anpi':a}
                for i,ipi in enumerate(ipis):
                    info['rpt']['ipi-{0}-density'.format(i)] = ipi

                # optional subelements
                if opt:
                    info['rpt']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtrptvend_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_BEACON:
                # Std Fig 8-148
                vs = struct.unpack_from('=2BQH10BI',rpt)
                opt = rpt[struct.calcsize('=2BQH10BI'):]
                info['rpt'] = {'op-class':vs[0],
                               'ch-num':vs[1],
                               'start-time':vs[2],
                               'msmt-dur':vs[3],
                               'rpt-frame-info':{
                                   'condensed-phy-type':bits.leastx(7,vs[4]),
                                   'rpt-frame-type':bits.mostx(7,vs[4])
                               },
                               'rcpi':vs[5],
                               'rsni':vs[6],
                               'bssid':_hwaddr_(vs[7:13]),
                               'antenna-id':vs[13],
                               'parent-tsf':vs[14]}

                # optional subelements
                if opt:
                    info['rpt']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtrptbeacon_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_FRAME:
                # Std Fig 8-150
                o,n,s,d = struct.unpack_from('=2BQH',rpt)
                opt = info[struct.calcsize('=2BQH'):]
                info['rpt'] = {'op-class':o,
                               'ch-num':n,
                               'start-time':s,
                               'msmt-dur':d}

                # optional subelements
                if opt:
                    info['rpt']['opt-subels']=_parseiesubel_(opt,_iesubelmsmtrptframe_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_STA:
                # Std Fig. 8-153
                d,g = struct.unpack_from('=HB',rpt)
                info['rpt'] = {'msmt-dur':d,'grp-id':g}
                rem = rpt[3:]

                # statiscs group data
                glen = std.EID_MST_STA_STATS_GID[info['rpt']['grp-id']]
                info['rpt']['stats-grp-data'] = binascii.hexlify(rem[:glen])
                opt = rem[glen:]
                # TODO: See Std Fig 8-154 for parsing this

                # optional subelements
                if opt:
                    info['rpt']['opt-subels'] = _parseiesubel_(opt,_iesubelmsmtrptsta_)
                    # have to do additional proessing for all reason subelements
                    for i,(oid,o) in enumerate(info['rpt']['opt-subels']):
                        if oid == std.EID_MSMT_RPT_STA_STAT_REASON:
                            rs = _eidmsmtrptstareason_(o,info['rpt']['grp-id'])
                            info['rpt']['opt-subels'][i] = (oid,rs)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_LCI:
                # Std Fig. 8-162
                info['rpt'] = _parselcirpt_(rpt)
                opt = rpt[16:]

                # option subelements
                if opt:
                    info['rpt']['opt-subels'] = _parseiesubel_(opt,_iesubelmsmtrptlci_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_TX:
                # Std Fig. 8-165
                vs = struct.unpack_from('=QH8B7IB',rpt)
                info['rpt'] = {'msmt-start-time':vs[0],
                               'msmt-dur':vs[1],
                               'peer-addr':_hwaddr_(vs[2:8]),
                               'traffic-id':{'rsrv':bits.leastx(4,vs[8]),
                                             'tid':bits.mostx(4,vs[8])},
                               'rpt-reason':_eidmsmtrpttxrptreason_(vs[9]),
                               'tx-msdu-cnt':vs[10],
                               'msdu-discarded-cnt':vs[11],
                               'msdu-failed-cnt':vs[12],
                               'msdu-mult-retry-cnt':vs[13],
                               'qos-cf-polls-lost-cnt':vs[14],
                               'avg-q-delay':vs[15],
                               'avg-tx-delay':vs[16],
                               'bin-0-range':vs[17]}
                l = struct.calcsize('=QH8B7IB')
                for i in xrange(5):
                    info['rpt']['bin-'.format(i)] = struct.unpack_from('=I',rpt,l+(i*4))
                opt = rpt[l+20:]

                # optional subelements
                if opt:
                    info['rpt']['opt-subels'] = _parseiesubel_(opt,_iesubelmsmtrptvend_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_MULTI:
                # Std Fig. 8-167
                vs = struct.unpack_from('=QH7BI3H',rpt)
                opt = rpt[struct.calcsize('=QH7BI3H'):]
                info['rpt'] = {'msmt-time':vs[0],
                               'msmt-dur':vs[1],
                               'group-addr':_hwaddr_(vs[2:8]),
                               'rpt-reason':_eidmsmtrptmcastreason_(vs[8]),
                               'rx-msdu-cnt':vs[9],
                               'seq-num-1':vs[10],
                               'seq-num=n':vs[11],
                               'rate':vs[12]}

                # optional subelements
                if opt:
                    info['rpt']['opt-subels'] = _parseiesubel_(opt,_iesubelmsmtrptvend_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_LOC_CIVIC:
                # Std Fig. 8-169
                info['rpt'] = {'type':struct.unpack_from('=B',rpt)[0]}
                opt = rpt[1:]

                # after this is optional sublements followed by variable
                # civic location (IAW IETF RFC 4776 this is min. 3-octet field)
                # with similar header 1-octet ID|1-octet Length where ID = 99
                # therefore we'll attempt parsing as a sublement and hope that
                # civic location is left as is
                # EID_MSMT_REQ_SUBELEMENT_CIVIC_LOC_TYPE_RFC4776 = 0
                # EID_MSMT_REQ_SUBELEMENT_CIVIC_LOC_TYPE_VEND = 1
                if opt:
                    info['rpt']['opt-subels'] = _parseiesubel_(opt,_iesubelmsmtrptloccivic_)
            elif info['type'] == std.EID_MSMT_RPT_TYPE_LOC_ID:
                # Std Fig 8-182
                info['rpt'] = {'exp-tsf':struct.unpack_from('=Q',rpt)[0]}
                opt = rpt[8:]

                # see above, optional sublements come prior to variable URI
                # try to parse optional and hope URI gets included
                if opt:
                    info['rpt']['opt-subels'] = _parseiesubel_(opt,_iesubelmsmtrptlocid_)
        elif eid == std.EID_QUIET: # Std 8.4.2.25
            # elements: 1|1|2|2
            cnt,per,dur,off = struct.unpack_from('=2B2H',info)
            info = {'cnt':cnt,'per':per,'dur':dur,'offset':off}
        elif eid == std.EID_IBSS_DFS: # Std 8.4.2.26
            # DFS Owner|DFS Recv Intv|CH Map|
            #         6|            1|2*n
            vs = struct.unpack_from('=7B',info)
            rem = info[7:]
            info = {'owner':_hwaddr_(vs[0:6]),
                    'recv-intv':vs[6],
                    'ch-map':[]}

            # ch map is list of 2 1-octet subfields
            for i in xrange(0,len(rem),2):
                chn,chm = struct.unpack_from('=2B',rem,i)
                info['ch-map'].append({'ch-num':chn,'map':_eidmultchmap_(chm)})
        elif eid == std.EID_ERP: # Std 8.4.2.14
            # Caution: element length is flexible, may change
            info = _eiderp_(struct.unpack_from('=B',info)[0])
        elif eid == std.EID_TS_DELAY: # Std 8.4.2.34
            # 1 element, 4 bytes
            info = struct.unpack_from('=I',info)[0]
        elif eid == std.EID_TCLAS_PRO: # Std 8.4.2.35
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_HT_CAP: # Std 8.4.2.58
            # 6 elements 2|1|16|2|4|1
            hti,ampdu = struct.unpack_from('=HB',info)
            mcs = info[3:19]
            hte,bf,asel = struct.unpack_from('=HIB',info,19)
            info = {'ht-info':_eidhtcaphti_(hti),
                    'ampdu-param':_eidhtcapampdu_(ampdu),
                    'mcs-set':_parsemcsset_(mcs),
                    'ht-ext-cap':_eidhtcaphte_(hte),
                    'tx-beamform':_eidhtcaptxbf_(bf),
                    'asel-cap':_eidhtcapasel_(asel)}
        elif eid == std.EID_QOS_CAP: # Std 8.4.2.37, 8.4.1.17
            # 1 byte 1 element. Requires knowledge of frame being sent by
            # AP or non-AP STA
            info = {'qos-info':struct.unpack_from('=B',info)[0]}
            #_eidqoscap_(v,True) Sent by AP
            #_eidqoscap_(v,True) Sent by non-AP
        elif eid == std.EID_RSNE: # Std 8.4.2.27
            # contains up to and including the version field
            rem = info[2:]
            info = {'vers':struct.unpack_from('=H',info)[0]}

            # all fields after version are optional. All cipher suites are a
            # 4-byte octet which we treat as four 1-byte octets for handling by
            # _eidrsnesuitesel_()
            # group data cipher suite
            if rem:
                info['grp-data-cs'] = _parsesuitesel_(rem[:4])
                rem = rem[4:]

            # pairwise cipher suite count & list
            if rem:
                info['pairwise-cnt'] = struct.unpack_from('=H',rem)[0]
                info['pairwise-cs-list'] = []
                for i in xrange(info['pairwise-cnt']):
                    pwise = rem[2+(i*4):]
                    info['pairwise-cs-list'].append(_parsesuitesel_(pwise))
                rem = rem[2+(4*info['pairwise-cnt']):]

            # AKM suite count & list
            if rem:
                info['akm-cnt'] = struct.unpack_from('=H',rem)[0]
                info['akm-list'] = []
                for i in xrange(info['akm-cnt']):
                    akm = rem[2+(i*4):]
                    info['akm-list'].append(_parsesuitesel_(akm))
                rem = rem[2+(4*info['akm-cnt']):]

            # RSN capabilities
            if rem:
                info['rsn-cap'] = _eidrsnecap_(struct.unpack_from('=H',rem)[0])
                rem = rem[2:]

            # PMKID count & list
            if rem:
                info['pmkid-cnt'] = struct.unpack_from('=H',rem)[0]
                info['pmkid-list'] = []
                rem = rem[2:]
                for i in xrange(info['pmkid-cnt']):
                    info['pmkid-list'].append(binascii.hexlify(rem[:16]))
                    rem = rem[16:]

            # group mgmt cipher suite
            if rem: info['grp-mgmt-cs'] = _parsesuitesel_(rem)
        elif eid == std.EID_AP_CH_RPT: # Std 8.4.2.38
            # min 1 octet followed by variable list of channels
            opclass = struct.unpack_from('=B',info)[0]
            info = {'op-class':opclass,
                    'ch-list':[struct.unpack('=B',ch)[0] for ch in info[1:]]}
        elif eid == std.EID_NEIGHBOR_RPT: # Std 8.4.2.39
            # BSSID|BSSID INFO|OP CLASS|CH NUM|PHY TYPE|SUB ELS
            #     6|         4|       1|     1|       1| var
            binfo,op,ch,phy, = struct.unpack_from('=I3B',info,6)
            rem = info[struct.calcsize('=6BI3B'):]
            info = {'bssid':_hwaddr_(struct.unpack_from('=6B',info)),
                    'bssid-info':_eidneighrptinfo_(binfo),
                    'op-class':op,
                    'ch-num':ch,
                    'phy':phy}
            if rem: info['opt-subels'] = _parseiesubel_(rem,_iesubelneighrpt_)
        elif eid == std.EID_RCPI: # Std 8.4.2.40
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_MDE: # Std 84.2.49
            mdid,ft = struct.unpack_from('=HB',info)
            info = {'mdid':mdid,'ft-cap-pol':_eidftcappol_(ft)}
        elif eid == std.EID_FTE: # Std 8.4.2.50
            # MIC CTRL|MIC|ANonce|SNonce|OPT Params
            #        2| 16|    32|    32|       var
            # where MIC is current Rsrv(8)|Element count(8)
            rsrv,ecnt = struct.unpack_from('=2B',info)
            rem = info[2:]
            mic,anonce,snonce = rem[:16],rem[16:48],rem[48:80]
            info = {'mic-ctrl': {'rsrv': rsrv, 'el-cnt': ecnt},
                    'mic':binascii.hexlify(mic),
                    'anonce':binascii.hexlify(anonce),
                    'snonce':binascii.hexlify(snonce)}
            rem = rem[80:]
            if rem: info['opt-subels'] = _parseiesubel_(rem,_iesubelfte_)
        elif eid == std.EID_TIE: # Std 8.4.2.51
            typ,val = struct.unpack_from('=BI',info)
            info = {'int-type':typ,'int-val':val}
        elif eid == std.EID_RDE: # Std 8.4.2.52
            # 4 byte 3 element (See 8.4.1.9 for values of stat)
            rid,cnt,stat = struct.unpack_from('=2BH',info)
            info = {'rde-id':rid,'rd-cnt':cnt,'status':stat}
        elif eid == std.EID_DSE_REG_LOC: # Std 8.4.2.54
            # one 20-octet element w/ subfields of varying lengths
            # we let a helper parse this
            info = _parseinfoeldse_(info)
        elif eid == std.EID_OP_CLASSES: # Std 8.4.2.56
            # 2 elements, 1 byte, & 1 2 to 253
            # see 10.10.1 and 10.11.9.1 for use of op-classes element
            info = {
                'cur-op-class':struct.unpack_from('=B',info)[0],
                'op-classes':[struct.unpack_from('=B',x)[0] for x in info[1:]]
            }
        elif eid == std.EID_EXT_CH_SWITCH: # Std 8.4.2.55
            # 4 octect, 4 element
            mode,opclass,ch,cnt = struct.unpack_from('=4B',info)
            info = {'switch-mode':mode,
                    'op-class':opclass,
                    'new-ch':ch,
                    'switch-cnt':cnt}
        elif eid == std.EID_HT_OP: # Std 8.4.2.59
            # Pri Ch|HT OP Info|MCS Set
            #      1|         5|     16
            # The HT OP info can be further divided into 1|2|2
            pri,htop1,htop2,htop3 = struct.unpack_from('=2B2H',info)
            info = {'pri-ch':pri,
                    'ht-op-info':_eidhtopinfo_(htop1,htop2,htop3),
                    'mcs-set':_parsemcsset_(info[-16:])}
        elif eid == std.EID_SEC_CH_OFFSET: # 8.4.2.22
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_BSS_AVG_DELAY: # Std 8.4.2.41
            # a scalar indication of relative loading level
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_ANTENNA: # Std 8.4.2.42
            # 0: antenna id is uknown, 255: multiple antenneas &
            # 1-254: unique antenna or antenna configuration.
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_RSNI: # Std 8.4.2.43
            # 255: RSNI is unavailable
            # RSNI = (10 * log10((RCPI_power - ANPI_power / ANPI_power) + 10) * 2
            # where RCPI_power & ANPI_power indicate power domain values & not dB domain
            # values. RSNI in dB is scaled in steps of 0.5 dB to obtain 8-bit RSNI values,
            # which cover the range from -10 dB to +117 dB
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_MSMT_PILOT: # Std 8.4.2.44
            # 1 octet + variable length subelements
            opt = info[1:]
            info = {'msmt-pilot-tx':struct.unpack('=B',info)[0]}
            if opt: info['opt-subels'] = _parseiesubel_(opt,_iesubelmsmtpilot_)
        elif eid == std.EID_BSS_AVAIL: # Std 8.4.2.45
            # 2 element. Admin Cap bitmask is 2 octets & Admin Cap list is
            # variable 2 octet uint for nonzero bit in bitmask
            bm = struct.unpack_from('=H',info)[0]
            rem = info[2:]
            info = {'admin-cap-bm':_edibssavailadmin_(bm),'admin-cap-list':[]}
            for i in xrange(0,len(rem),2):
                info['admin-cap-list'].append(struct.unpack_from('=H',rem,i))
        elif eid == std.EID_BSS_AC_DELAY: # Std 8.4.2.46
            # four 1 byte elements, each is a scalar indicator as in BSS Average
            # Access delay
            be,bk,vi,vo = struct.unpack_from('=4B',info)
            info = {'ac-be':be, # best effort avg access delay
                    'ac-bk':bk, # background avg access delay
                    'ac-vi':vi, # video avg access delay
                    'ac-vo':vo} # voice avg access delay
        elif eid == std.EID_TIME_ADV: # Std 8.4.2.63
            # See Std Figure 8-261 Only timing capabilities guaranteed to be present
            tcap = struct.unpack_from('=B',info)[0]
            if tcap == 0: info = {'timing-cap':tcap}
            if tcap == 1:
                # time value field & time error field present
                info = {'timing-cap':tcap,
                        'time-val':info[1:11],
                        'time-err':struct.unpack_from('=Q',info[11:16]+'\x00\x00\x00')[0]}
            elif tcap == 2:
                # time value field, time error field & time update counter field present
                # for time value see Table 8-132
                info = {'timing-cap':tcap,
                        'time-val':_parsetimeval_(info[1:11]),
                        'time-err':struct.unpack_from('=Q',info[11:16]+'\x00\x00\x00')[0],
                        'time-update-cntr':struct.unpack_from('=B',info[-1])[0]}
        elif eid == std.EID_RM_ENABLED: # Std 8.4.2.47
            # 1 element, a 5-byte octet stream
            vs = struct.unpack_from('=5B',info)
            info = _eidrmenable_(vs)
        elif eid == std.EID_MULT_BSSID: # Std 8.4.2.48
            # 1 octet + variable length subelements
            mbi = struct.unpack('=B',info)[0]
            rem = info[1:]
            info = {'max-bssid-indicator':mbi}
            if rem: info['opt-subels'] = _parseiesubel_(rem,_iesubelmultbssid_)
        elif eid == std.EID_20_40_COEXIST: # Std 8.4.2.62
            # 1 element, 1 byte
            info = _eid2040coexist_(struct.unpack_from('=B',info)[0])
        elif eid == std.EID_20_40_INTOLERANT: # Std 8.4.2.60
            # min 1 octet followed by variable list of channels
            opclass = struct.unpack_from('=B',info)[0]
            info = {'op-class':opclass,
                    'ch-list':[struct.unpack('=B', ch)[0] for ch in info[1:]]}
        elif eid == std.EID_OVERLAPPING_BSS: # Std 8.4.2.61
            # 7 elements each 2 octets
            vs = struct.unpack_from('=7H',info)
            info = {'pass-dwell':vs[0],
                    'act-dwell':vs[1],
                    'trigger-scan-int':vs[2],
                    'pass-per-ch':vs[3],
                    'act-per-ch':vs[4],
                    'delay-factor':vs[5],
                    'threshold':vs[6]}
        elif eid == std.EID_RIC_DESC: # Std 8.4.2.53
            # 1 octect followed by variable parameters (based on resource type)
            info = {'res-type':struct.unpack_from('=B',info)[0],
                    'opt-subels':_parseiesubel_(info[1:])}
        elif eid == std.EID_MGMT_MIC: # Std 8.4.2.57
            # KeyID|IPIN|MIC
            #     2|   6|  8
            # to get 6 byte IPIN, we add 2 null bytes to end of the ipin element
            # and unpack using the 8 byte unsigned long
            info = {'key-id':struct.unpack_from('=H',info[0]),
                    'ipin':struct.unpack_from('=Q',info[2:8]+'\x00\x00')[0],
                    'mic':struct.unpack_from('=Q',info[-8:])[0]}
        elif eid == std.EID_EVENT_REQ: # Std 8.4.2.69
            # Token|Type|Resp limit|Request
            #     1|   1|         1|    var
            tkn,typ,lim = struct.unpack_from('=3B',info)
            rem = info[3:]
            info = {'tkn':tkn,'type':typ,'res-lim':lim}

            # based on event type (NOTE: for a WNM Log request, there is no field
            if info['type'] == std.EVENT_REQUEST_TYPE_TRANSITION: # Std 8.4.2.69.2
                info['request'] = _parseiesubel_(rem,_iesubelevreqtransistion_)
            elif info['type'] == std.EVENT_REQUEST_TYPE_RSNA: # Std 8.4.2.69.3
                info['request'] = _parseiesubel_(rem,_iesubelevreqrsna_)
            elif info['type'] == std.EVENT_REQUEST_TYPE_P2P:  # Std 8.4.2.69.4
                info['request'] = _parseiesubel_(rem,_iesubelevreqp2p_)
            elif info['type'] == std.EVENT_REQUEST_TYPE_VEND: # Std 8.4.2.69.5
                info['request'] = _parseiesubel_(rem,_iesubelevreqvend_)
        elif eid == std.EID_EVENT_RPT: # Std 8.4.2.70
            # Token|Type|RPT Stat|   TSF |   UTC | Time |Report
            #     1|   1|       1|(opt) 8|opt(10)|opt(5)|   var
            tkn,typ,rpt = struct.unpack_from('=3B',info)
            rem = info[3:]
            info = {'tkn':tkn,'type':typ,'rpt-stat':rpt}

            # remainder are only present if rpt is successful
            if info['rpt-stat'] == std.EVENT_REPORT_STATUS_SUCCESS:
                # IAW Std 6.3.42.2.2 TSF is an integer
                info['tsf'] = struct.unpack_from('=Q',rem)[0]
                info['utc-offset'] = _parsetimeval_(rem[8:18])
                info['time-err'] = struct.unpack_from('=Q',rem[18:23]+'\x00\x00\x00')[0]

                # the event report field contains 1 event report based on the
                # event type
                rpt = rem[23:]
                if info['type'] == std.EVENT_REQUEST_TYPE_TRANSITION:
                    # Std Fig. 8-282
                    src = _hwaddr_(struct.unpack_from('=6B',rpt)[0])
                    tgt = _hwaddr_(struct.unpack_from('=6B',rpt,6)[0])
                    vs = struct.unpack_from('=HBH4B',rpt,12)
                    info['report'] = {'src-bssid':src,
                                      'tgt-bssid':tgt,
                                      'trans-time':vs[0],
                                      'trans-reason':vs[1],
                                      'trans-result':vs[2],
                                      'src-rcpi':vs[3],
                                      'src-rsni':vs[4],
                                      'tgt-rcpi':vs[5],
                                      'tgt-rsni':vs[6]}
                elif info['type'] == std.EVENT_REQUEST_TYPE_RSNA:
                    # Std Fig. 8-283
                    info['report'] = {
                        'tgt-bssid':_hwaddr_(struct.unpack_from('=6B',rpt)),
                        'auth-type':_parsesuitesel_(rpt[6:])
                    }
                    rem = rpt[10:]
                    # look at para under fig 8-283. AKM suite is defined
                    # as a string of the form 00-0f-AC:1
                    # TODO: how to determine if EAP method is 1 octet or 8 octets
                    #at = "{0}:{1}".format(info['report']['auth-type']['oui'],
                    #                      info['report']['auth-type']['suite-type'])
                    #if at == '00-0F-AC:1' or at == '00-0F-AC:3':
                    info['report']['unparsed'] = rem
                elif info['type'] == std.EVENT_REQUEST_TYPE_P2P:
                    # Std Fig 8-284
                    peer = _hwaddr_(struct.unpack_from('=6B',rpt))
                    o,cn,p = struct.unpack_from('=3B',rpt,6)
                    ct = struct.unpack_from('=I',rpt[9:12]+'\x00')[0]
                    ps = struct.unpack_from('=B',rpt[-1])[0]
                    info['report'] = {'peer-addr':peer,
                                      'op-class':o,
                                      'ch-num':cn,
                                      'sta-tx-pwr':p,
                                      'conn-time':ct,
                                      'peer-status':ps}
                elif info['type'] == std.EVENT_REQUEST_TYPE_WNM_LOG:
                    # Std 8.4.2.70.5
                    info['report'] = {'wnm-log-msg':rpt}
                elif info['type'] == std.EVENT_REQUEST_TYPE_VEND:
                    # Std 8.4.2.70.6
                    info['report'] = _parseiesubel_(rpt,_iesubelevreqvend_)
        elif eid == std.EID_DIAG_REQ: # Std 8.3.2.71
            # Token|Type|Timeout|Optional
            #     1|   1|      2|     var
            tkn,typ,to = struct.unpack_from('=2BH',info)
            info = {'tkn':tkn,'type':typ,'timeout':to}
            if info['type'] > std.DIAGNOSTIC_REPORT_CONFIG:
                info['opt-subels'] = _parseiesubel_(info[4:],_iesubeldiag_)
        elif eid == std.EID_DIAG_RPT: # Std 8.3.2.72
            # Token|Type|Status|Optional
            #     1|   1|     1|     var
            # based on description each report will return a set of fields
            # in a specific order however, we assume for now that we can parse
            # as if this were an unordered optional sublements
            tkn,typ,stat = struct.unpack_from('=3B',info)
            info = {'tkn':tkn,
                    'type':typ,
                    'stat':stat,
                    'opt-subels':_parseiesubel_(info[3:],_iesubeldiag_)}
        elif eid == std.EID_LOCATION: # Std 8.3.2.73
            # it appears that each possible location subelement begins with
            # a subelement id references Table 1-183, length and a variable field
            # Subelement ID|Length|Paramaeters
            #             1|     1|       var
            # we'll save these as a list of tuples t = (id,param)
            info = {'loc-subels':_parseiesubel_(info,_iesubelloc_)}
        elif eid == std.EID_NONTRANS_BSS: # Std 8.4.2.74
            info = struct.unpack_from('=H',info)[0]
        elif eid == std.EID_SSID_LIST: # Std 8.4.2.75
            # a list of SSID elements
            # SSID element is EID|LEN|SSID
            #                   1|  1|0-32
            # where EID = std.EID_SSID
            info = {'ssids':_parseiesubel_(info,_iesubelssid_)}
        elif eid == std.EID_MULT_BSSID_INDEX: # Std 8.4.2.76
            # 1 element @ 1 octet, 2 optional 1 octet elements
            # from the section it appears that neither element is present
            # in a probe response, implying that they are otherwise present
            #fmt = "={}B".format(len(info))
            idx = struct.unpack_from('=B',info)[0]
            rem = info[1:]
            info = {'bssid-idx':idx}
            if len(rem) == 2:
                info['dtim-per'] = struct.unpack_from('=B',rem)[0]
                info['dtim-cnt'] = struct.unpack_from('=B',rem,1)[0]
            elif len(rem) == 1:
                # unsure how to handle this
                info['dtim-unk'] = struct.unpack_from('=B',rem)[0]
        elif eid == std.EID_FMS_DESC: # Std 8.4.2.77
            # 1 element @ 1 byte followed by n FMS counters & m FMSIDs
            # FMS counters are 1 octet as are FMSIDs
            n = struct.unpack_from('=B',info)[0]
            m = len(info) - n

            # parse out all fms counters
            fms = []
            for i in xrange(n):
                # Std Fig 8-325 parse the fms counter
                nxt = struct.unpack_from('=B',info,i)
                fms.append({'fms-cnt-id':bits.leastx(3,nxt),
                             'current-cnt':bits.mostx(3,nxt)})
            info = info[n:] # move index to fmsids

            # parse out all fmsids
            fmsid = []
            for i in xrange(m): fmsid.append(struct.unpack_from('=B',info,i))
            info = {'num-fms-cnt':n,'fms-cnt':fms,'fmsids':fmsid}
        elif eid == std.EID_FMS_REQ: # Std 8.4.2.78
            # FMS Token|Request Subelements
            #         1|                var
            info = {'fms-tkn':struct.unpack_from('=B',info),
                    'req-subels':_parseiesubel_(info[1:],_iesubelfmsreq_)}
        elif eid == std.EID_FMS_RESP: # Std 8.4.2.79
            # FMS Token|Request Subelements
            #         1|                var
            info = {'fms-tkn':struct.unpack_from('=B',info),
                    'stat-subels':_parseiesubel_(info[1:],_iesubelfmsresp_)}
        elif eid == std.EID_QOS_TRAFFIC_CAP: # Std 8.4.2.80
            # 1 1-octet element followed by variable list
            qt = _eidqostrafficcap_(struct.unpack_from('=B',info)[0])
            n = qt['ac-vo'] + qt['ac-vi']
            ls = struct.unpack_from('={}B'.format(n),info)
            info = {'flags':qt,'ac-sta-cnt-list':list(ls)}
        elif eid == std.EID_BSS_MAX_IDLE: # Std 8.4.2.81
            # 2 elements
            per,opts = struct.unpack_from('=HB',info)
            info = {'max-idle-per':per,'idle-ops':_eidbssmaxidle_(opts)}
        elif eid == std.EID_TFS_REQ: # Std 8.4.2.82
            # TFS ID|TFS Act Code|Subelements
            #      1|           1|        var
            # where TFS Act Code is parse IAW Std Table 8-162
            tid,tac = struct.unpack_from('=2B',info)
            info = {'tfs-id':tid,
                    'tfs-act-code':{'del':bits.leastx(1,tac),
                                    'notify':bits.midx(1,1,tac),
                                    'rsrv':bits.mostx(2,tac)},
                    'tfs-req-subels':_parseiesubel_(info[2:],_iesubeltfsreq_)}
        elif eid == std.EID_TFS_RESP: # Std 8.4.2.83
            # one or more status subelements @ 4 bytes
            # dox is confusing - see Table 8-164 implying that each subelement
            # may be greater than 4. for now, parse on 4 - any errors will be
            # caught by calling function
            ss = []
            for i in xrange(0,len(info),4):
                sid,slen,resp,tid = struct.unpack_from('=4B',info,i)
                if slen != 4:
                    raise EnvironmentError(eid,"subelement has length".format(slen))
                ss.append({'sub-id':sid,'tfs-resp':resp,'tfs-id':tid})
            info = ss
        elif eid == std.EID_WNM_SLEEP: # Std 8.4.2.84
            # 3 elements, 1,1 and 2 octets
            act,stat,intv = struct.unpack_from('=2BH',info)
            info = {'act-type':act,'resp-status':stat,'interval':intv}
        elif eid == std.EID_TIM_REQ: # Std 8.4.2.85
            # 1 octet element (TIM BCAST Interval
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_TIM_RESP: # Std 8.4.2.86
            # 1st element, Status determines precense of optional elements
            status = struct.unpack_from('=B',info)
            if status in [0,1,3]:
                timi,timo,hr,lr = struct.unpack_from('=Bi2H',info,1)
                info = {'status':status,
                        'tim-bcast-intv':timi,
                        'tim-bcast-offset':timo, # signed int
                        'high-rate-tim':hr,
                        'low-rate-tim':lr}
            else:
                info = {'status': status}
        elif eid == std.EID_COLLOCATED_INTERFERENCE: # Std 8.4.2.87
            # 8 elements 1|1|1|4|4|4|4|2
            vs = struct.unpack_from('=3B4IH',info)
            info = {'period':vs[0],
                    'intf-lvl':vs[1],
                    'accuracy':bits.leastx(4,vs[2]),
                    'intf-idx':bits.mostx(4,vs[2]),
                    'intf-intv':vs[3],
                    'intf-burst':vs[4],
                    'intf-cycle':vs[5],
                    'intf-cf':vs[6],
                    'intf-bw':vs[7]}
        elif eid == std.EID_CH_USAGE: # Std 8.4.2.88
            # 1 octet followed by a list of 2-octet channel entries
            mode = struct.unpack_from('=B',info)
            chs = []
            for i in xrange(1,len(info),2):
                opclass,ch = struct.unpack_from('=2B',info,i)
                chs.append({'op-class':opclass,'channel':ch})
            info = {'usage-mode':mode,'ch-entries':chs}
        elif eid == std.EID_TIME_ZONE: # Std 8.4.2.89
            # variable length Time Zone string as defined in IEEE 1003.1-2004
            # encoded in ASCII, we'll leave as is
            pass
        elif eid == std.EID_DMS_REQ: # Std 8.4.2.90
            # contains 1 or more DMS Descriptor defined as
            # DMSID|Len|Req Type|TCLAS Els|Tclas Processing|TSPEC El|Optional
            #     1|  1|       1|      var|     0 or 3     |0  or 57|     var
            ds = []
            while info:
                did,dlen,typ = struct.unpack_from('=3B',info)
                desc = {'dms-id':did,'req-type':typ,'unparsed':info[3:dlen+3]}
                ds.append(desc)
                info = info[dlen+3:]
            info = ds
        elif eid == std.EID_DMS_RESP: # Std 8.4.2.91
            # contains 1 or more DMS status defined as
            # DMSID|Len|Res Type|Last Seq Ctrl|TCLAS Els|TCLS Processing|TSPEC El|Optional
            #     1   1|       1|            2|      var|     0 or 3    | 0 or 57|     var
            ds = []
            while info:
                did,dlen,typ,lsc = struct.unpack_from('=3BH',info)
                stat = {'dms-id':did,
                        'res-type':typ,
                        'last-seq-ctrl':lsc,
                        'unparsed':info[5:5+dlen]}
                ds.append(stat)
                info = info[dlen+5:]
            info = ds
        elif eid == std.EID_LINK_ID: # Std 8.4.2.64
            # 3 elements, each is a mac address
            info = {'bssid':_hwaddr_(struct.unpack_from('=6B',info)),
                    'initiator':_hwaddr_(struct.unpack_from('=6B',info,6)),
                    'responder':_hwaddr_(struct.unpack_from('=6B',info,12))}
        elif eid == std.EID_WAKEUP_SCHED: # Std 8.4.2.65
            # 5 elements, 4 4 byte & 1 2 byte
            off,intv,slots,dur,cnt = struct.unpack_from('=4IH',info)
            info = {'offset':off,
                    'interval':intv,
                    'win-slots':slots,
                    'max-awake-dur':dur,
                    'idle-cnt':cnt}
        elif eid == std.EID_CH_SWITCH_TIMING: # Std 8.4.2.66 = 104
            # 2 element, each 2 byte
            swtime,swto = struct.unpack_from('=2H',info)
            info = {'switch-time':swtime,'switch-timeout':swto}
        elif eid == std.EID_PTI_CTRL: # Std 8.4.2.67
            # 2 elements 1 1 byte & 1 2 byte
            tid,seqctrl = struct.unpack_from('=BH',info)
            info = {'tid':tid,'seq-ctrl':seqctrl}
        elif eid == std.EID_TPU_BUFF_STATUS: # Std 8.4.2.68
            info = _eidtpubuffstat_(struct.unpack_from('=B',info)[0])
        elif eid == std.EID_INTERWORKING: # Std 8.4.2.94
            # 1 1-octet element followed by optional 2-octet and optional 6-octet
            # The 2-octet venue field is comprised of 2 1-octet values group & type
            ano = struct.unpack_from('=B',info)[0]
            n = len(info)-1
            venue = hessid = None
            if n == 2:
                # only venue is defined
                grp,typ = struct.unpack_from('=2B',info,1)
                venue = {'group':grp,'type':typ}
            elif n == 6:
                # only hessid is defined
                hessid = _hwaddr_(struct.unpack_from('=6B',info,1))
            elif n == 8:
                # both are defined
                vs = struct.unpack_from('=8B',info,1)
                venue = {'group':vs[0],'type':vs[1]}
                hessid = _hwaddr_(vs[2:])
            #else: # what should we do about this
            #    # error
            info = {'access-net-opts':_eidinterworkingano_(ano)}
            if venue: info['venue-info'] = venue
            if hessid: info['hessid'] = hessid
        elif eid == std.EID_ADV_PROTOCOL: # Std 8.4.2.95
            # var number of Advertisement protocol tuples defined as
            # Query Resp Info|Advertisement Protocol ID
            #               1|                      var
            apts = []
            while info:
                qri,apid = struct.unpack_from('=2B',info)
                apt = {'qry-resp-info':_eidadvprotoqryrep_(qri),
                       'adv-proto-id':apid}
                info = info[2:]

                # TODO: confirm this but unless the APID is Vend Specific (221)
                # it is one octet in length
                if apt['adv-proto-id'] == std.EID_VEND_SPEC:
                    # if understood correctly, the remainding is a vendor specific
                    # ID|length|oui|content
                    #  1|     1|  3|    var = length-3
                    # where id has already been unpacked
                    vs = struct.unpack_from('=4B',info)[0]
                    vlen = vs[0]
                    apt['oui'] = _hwaddr_(vs[1:])
                    apt['content'] = info[4:4+vlen]
                    info = info[4+vlen:]
                apts.append(apt)
            info = apts
        elif eid == std.EID_EXPEDITED_BW_REQ: # Std 8.4.2.96
            # 1 element (precedence level)
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_QOS_MAP_SET: # Std 8.4.2.97
            # Excption1|...|ExceptionN|UP0|UP1|...|UP7|
            #         2|   |         2|  2|  2|   |  2|
            # Std Fig 8-257. the length = 16 + 2xn where n is the number of
            # exception fields there are alwasy 8 UP (or DSCP range fields) and
            # up to 21 exception fields

            # get the list of exceptions Std Fig 8-358
            y = 16
            n = (len(info)-y)/2
            es = []
            for i in xrange(n):
                dval,upri = struct.unpack_from('=2B',info,i*2)
                es.append({'dscp-val':dval,'user-pri':upri})

            # then the list of exceptions Std Fib 8-359
            info = info[-y:]
            rs = []
            for i in xrange(0,y,2):
                low,high=struct.unpack_from('=2B',info,i)
                rs.append({'low':low,'high':high})

            # put them together
            info =  {'dscp-excepts':es,'dscp-ranges':rs}
        elif eid == std.EID_ROAMING_CONS: # Std 8.4.2.98
            # Num AQQP OIs|O1 #1 & #2 lengths|OI #1|OI #2|OI #3
            #            1|                 1|  var|  var|   var
            n,l = struct.unpack_from('=2B',info)
            l1,l2 = bits.leastx(4,l),bits.mostx(4,l)
            rem = info[2:]
            oi1,oi2,oi3 = rem[:l1],None,None
            if l2 > 0: oi2 = rem[l1:l1+2]
            if len(info) - (2+l1+l2) > 0: oi3 = info[l1+l2:]
            info = {'num-anqp-oi':n,'oi-1':oi1}
            if oi2: info['oi-2'] = oi2
            if oi3: info['oi-3'] = oi3
            # TODO: should we make the oi's a OUI as implied in Std 8.4.1.31
        elif eid == std.EID_EMERGENCY_ALERT_ID: # Std 8.4.2.99
            # info is an 8-octet hash value
            info = struct.unpack_from('=Q',info)
        elif eid == std.EID_MESH_CONFIG: # Std 8.4.2.100
            # 7 1 octet elements
            vs = struct.unpack_from('=7B',info)
            info = {'path-proto-id':vs[0],
                    'path-metric-id':vs[1],
                    'congest-mode-id':vs[2],
                    'sync-id':vs[3],
                    'auth-proto-id':vs[4],
                    'mesh-form-id':_eidmeshconfigform_(vs[5]),
                    'mesh-cap':_eidmeshconfigcap_(vs[6])}
        elif eid == std.EID_MESH_ID: # Std 8.4.2.101
            # mesh id is between 0 (wildcard Mesh ID) and 32
            # See 13.2.2 but appears to be a ssid
            try:
                # try to convert to utf8, if it fails leave as is
                info = info.decode('utf8')
            except UnicodeDecodeError:
                pass
        elif eid == std.EID_MESH_LINK_METRIC_RPT: # Std 8.4.2.102
            # 1 octet flags followed by variable link metric field
            # look at 8.4.2.100.3 and Table 13-5
            fs = struct.unpack_from('=B',info)
            lmetric = info[1:]
            info = {'flags':{'req':bits.leastx(1,fs),
                             'rsrv':bits.mostx(1,fs)},
                    'link-metric':lmetric}
        elif eid == std.EID_CONGESTION: # Std 8.4.2.103
            # 5 elements 6|2|2|2|2
            sta = _hwaddr_(struct.unpack_from('=6B',info)),
            bk,be,vi,vo = struct.unpack_from('=4H',info,6)
            info = {'mesh-sta':sta, # dest-sta address
                    'ac-be':be,     # best effort avg access delay
                    'ac-bk':bk,     # background avg access delay
                    'ac-vi':vi,     # video avg access delay
                    'ac-vo':vo}     # voice avg access delay
        elif eid == std.EID_MESH_PEERING_MGMT: # Std 8.4.2.104
            # 4 2-octet elements followed by option 16-octet PMK
            mp,llid,plid,rcode = struct.unpack_from('=4B',info)
            pmkid = info[-16:] if len(info) > struct.calcsize('=4B') else None
            info = {'mesh-peer-proto-id':mp,
                    'local-link-id':llid,
                    'peer-link-id':plid,
                    'reason-code':rcode}
            if pmkid: info['pmkid'] = binascii.hexlify(pmkid)
        elif eid == std.EID_MESH_CH_SWITCH_PARAM: # Std 8.4.2.105
            # 4 elements 1|1|1|2|2
            ttl,fs,res,pre = struct.unpack_from('=3B2H',info)
            info = {'ttl':ttl,
                    'flags':_eidmeshchswitch_(fs),
                    'reason':res,
                    'precedence':pre}
        elif eid == std.EID_MESH_AWAKE_WIN: # Std 8.4.2.106
            # 1 2-octect element
            info = struct.unpack_from('=H',info)[0]
        elif eid == std.EID_BEACON_TIMING: # Std 8.4.2.107
            # 1-octet followed by 0 or more 6-octet elements
            rpt = struct.unpack_from('=B',info)[0]
            btis = []
            for i in xrange(1,len(info),6):
                sid,tbtt,bint = struct.unpack_from('=B2H',info,i)
                btis.append({'neigh-sta-id':sid,
                             'neigh-tbtt':tbtt,
                             'neigh-beacon-intv':bint})
            info = {'rpt-ctrl':_eidbeacontimingrpt_(rpt),
                    'beacon-timing-info':btis}
        elif eid == std.EID_MCCAOP_SETUP_REQ: # Std 8.4.2.108
            # 1-octet element & 5-octet further broken into 1,1,3
            # to get the 4  byte offset, we add 1 null bytes to the end of info,
            # (end of offset subfield) and unpack using the 4 byte unsigned int
            rid = struct.unpack_from('=B',info)
            info = {'mccaop-res-id':rid,
                    'mccaop-res':_parsemccaopresfield_(info[1:])}
        elif eid == std.EID_MCCAOP_SETUP_REP: # Std 8.4.2.109
            # 2 1-octet elements followed by optional 5-octect
            rid,rcode = struct.unpack_from('=2B',info)
            if len(info) > 2:
                info = {'mccaop-res':_parsemccaopresfield_(info[2:])}
            info['mccaop-res-id'] = rid
            info['mccaop-reason-code'] = rcode
        elif eid == std.EID_MCCAOP_ADV: # Std 8.4.2.111
            # 2 1-octet elements, followed by 3 variable elements
            snum,adv = struct.unpack_from('=2B',info)
            rem = info[2:]
            info = {'adv-set-seq-num':snum,
                    'mccaop-adv':_eidmccaopadvinfo_(adv)}

            # determine if there are reservation reports
            for field in ['tx-rx','bcast','interference']:
                if info['mccaop-adv'][field]:
                    rpt = field+'rpt'
                    info[rpt] = []

                    # each report field has the form
                    # 1|5|...|5
                    # where the first octet identifies the number of following
                    # octets
                    n = struct.unpack_from('=B',rem)[0]
                    for i in range(1,n*5,5):
                        info[rpt].append(_parsemccaopresfield_(rem[i:i+5]))

                    # update rem
                    rem = rem[(n*5+1):]
        elif eid == std.EID_MCCAOP_TEARDOWN: # Std 8.4.2.112
            # 1 1-octet element followed by option 6-octet
            rid = struct.unpack_from('=B',info)[0]
            if len(info) == 1: info = {}
            else:
                owner = _hwaddr_(struct.unpack_from('=6B',info,1))
                info = {'mccaop-owner':owner}
            info['mccaop-res-id'] = rid
        elif eid == std.EID_GANN: # Std 8.4.2.113
            # 1|1|1|6|4|2
            vs = struct.unpack_from('=9BIH',info)
            info = {'flags':vs[0],
                    'hop-cnt':vs[1],
                    'element-ttl':vs[2],
                    'mesh-gate':_hwaddr_(vs[3:9]),
                    'gann-seq-num':vs[-2],
                    'interval':vs[-1]}
        elif eid == std.EID_RANN: # Std 8.4.2.114
            # 1|1|1|6|4|4|4
            fs,hop,ttl = struct.unpack_from('=3B',info)
            mesh = struct.unpack_from('=6B',info,3)
            seqn,intv,met = struct.unpack_from('=3I',info,9)
            info = {'flags':{'gate-announce':bits.leastx(1,fs),
                             'rsrv':bits.mostx(1,fs)},
                    'hop-cnt':hop,
                    'element-ttl':ttl,
                    'root-mesh':mesh,
                    'hwmp-seq-num':seqn,
                    'interval':intv,
                    'metric':met}
        elif eid == std.EID_EXT_CAP: # Std 8.4.2.29
            # capabilities bitmask a minimum of 49 individual bits
            # we convert to a 8-octet field by appending null bytes.
            # We however miss any reserved at bit 49 that were present
            try:
                n = 8-len(info) # additional null bytes to add to make 8-octet
                info = _eidextcap_(struct.unpack_from('=Q',info+('\x00'*n)))
            except TypeError:
                raise EnvironmentError(eid,"subelement has length".format(len(info)))
        elif eid == std.EID_PREQ: # Std 8.4.2.115
            # See Fig 8-369 initial mandatory fields are 1|1|1|4|6|4 & are
            # flags|hop count|ttl|path disc id|originator|originator seq #
            vs = struct.unpack_from('=3BI6BI',info)
            rem = info[struct.calcsize('=3BI6BI'):]
            info = {'flags':_eidpreqflags_(vs[0]),
                    'hop-cnt':vs[1],
                    'ttl':vs[2],
                    'path-disc-id':vs[3],
                    'origin-mesh-sta':_hwaddr_(vs[4:10]),
                    'origin-hwmp-seq-num':vs[-1]}

            # if the ae flag is set, the next element is the external address field
            if info['flags']['ae']:
                info['origin-ext-sta'] = _hwaddr_(struct.unpack_from('=6B',rem))
                rem = rem[6:]

            # the next fields are mandatory:
            # lifetime|metric|target count
            #        4|     1|           1
            lt,m,tc = struct.unpack_from('=H2B',rem)
            info['lifetime'] = lt
            info['metric'] = m
            rem = rem[struct.calcsize('=H2B'):]

            # the target count determines the number of remaining elements
            # there will be tc number of
            # Per Target flags|Target Address|Target HWMP Seq Num
            #                1|             6|                  4
            tlen = struct.calcsize('=7BI')
            info ['targets'] = []
            for i in xrange(tc):
                vs = struct.unpack_from('=7BI',rem,i*tlen)
                info['targets'].append({'tgt-flags':_eidpreqtgtflags_(vs[0]),
                                        'tgt-address':_hwaddr_(vs[1:7]),
                                        'tgt-hwmp-seq-num':vs[-1]})
        elif eid == std.EID_PREP: # Std 8.4.2.116
            # 5 initial mandatory fields
            # flags|hop count|ttl|target sta|target seq num
            #     1|        1|  1|         6|             4
            vs = struct.unpack_from('=9BI',info)
            rem = info[struct.calcsize('=9BI'):]
            info = {'flags':_eidprepflags_(vs[0]),
                    'hop-cnt':vs[1],
                    'ttl':vs[2],
                    'target-mesh-sta':_hwaddr_(vs[3:9]),
                    'target-hwmp-seq-num':vs[-1]}

            # if the ae flag is set, the next element is the external address field
            if info['flags']['ae']:
                info['target-ext-sta'] = _hwaddr_(struct.unpack_from('=6B',rem))
                rem = rem[6:]

            # the following fields are mandatory
            # lifetime|metric|origin sta|origin hwmp seq num
            #        4|     4|         6|                  4
            vs = struct.unpack_from('=2I6BI',rem)
            info['lifetime'] = vs[0]
            info['metric'] = vs[1]
            info['origin-mesh-sta'] = _hwaddr_(vs[2:8])
            info['origin-hwmp-seq-num'] = vs[-1]
        elif eid == std.EID_PERR: # Std 8.4.2.117
            # initial 2 elements are ttl(1)|num dest(1)
            ttl,n = struct.unpack_from('=2B',info)
            rem = info[2:]
            info = {'ttl':ttl,'num-dest':n,'destinations':[]}

            # there are then n number of the following
            # Flags|Dest|HWMP Seq num|Dest External|Reason Code
            #     1|   6|            4|      0 or 6|          2
            # we'll eat rem until there is nothing left
            while rem:
                vs = struct.unpack_from('=7BI',rem)
                rem = rem[struct.calcsize('=7BI'):]
                dest = {'flags':_eidperrflags_(vs[0]),
                        'dest-addr':_hwaddr_(vs[1:7]),
                        'hwmp-seq-num':vs[-1]}
                if dest['flags']['ae']:
                    dest['dest-ext-addr'] = _hwaddr_(struct.unpack_from('=6B',rem))
                    rem = rem[6:]
                dest['res-code'] = struct.unpack_from('=H',rem)
                rem = rem[2:]
                info['destinations'].append(dest)
        elif eid == std.EID_PXU: # Std 8.4.2.118
            # 3 mandatory fields
            # PXU ID|PXU Origin|Num Proxies
            #      1|         6|          1
            vs = struct.unpack_from('=8B',info)
            rem = info[struct.calcsize('=8B'):]
            info = {'pxu-id':vs[0],
                    'pxu-origin-addr':_hwaddr_(vs[1:7]),
                    'num-proxy':vs[-1],
                    'proxy-info':[]}

            # there are n proxy informantion fields where n = num-proxy
            # Flags|Ext MAC|Proxy Seq Num|Proxy MAC|Lifetime
            #     1|      6|            4|   0 or 6| 0 or 4
            while rem:
                vs = struct.unpack_from('=7BI',info,1)
                rem = info[struct.calcsize('=7BI'):]
                pinfo = {'flags':_eidpxuinfoflags_(vs[0]),
                         'ext-addr':_hwaddr_(vs[1:7]),
                         'proxy-seq-num':vs[-1]}

                # proxy mac is only present if flags->orig is proxy is not set
                if not pinfo['flags']['org-is-proxy']:
                    pinfo['proxy-mac'] = _hwaddr_(struct.unpack_from('=6B',rem))
                    rem = rem[struct.calcsize('=6B'):]

                # proxy lifetime is present if flags->lifetime is set
                if pinfo['flags']['lifetime']:
                    pinfo['lifetime'] = struct.unpack_from('=I',rem)
                    rem = rem[struct.calcsize('=I'):]

                # add ot proxy info list
                info['proxy-info'].append(pinfo)
        elif eid == std.EID_PXUC: # Std 8.4.2.119
            # 1 1-octet element & 1 6-octet element
            vs = struct.unpack_from('=7B',info)
            info = {'pxu-id':vs[0],'pxu-recipient':_hwaddr_(vs[1:])}
        elif eid == std.EID_AUTH_MESH_PEER_EXC: # Std 8.4.2.120
            # Suite|Local Nonce|Peer Nonce|Key Replay Counter|GTK data|IGTK Data
            #     4|         32|        32|           (opt) 8|     var|      var
            info = {
                'cipher-suite':_parsesuitesel_(info),
                'local-nonce':binascii.hexlify(info[4:36]),
                'peer-pnonce':binascii.hexlify(info[36:68]),
                'remainder':info[68:]
            }
        elif eid == std.EID_MIC: # Std 8.4.2.121
            info = binascii.hexlify(info)
        elif eid == std.EID_DEST_URI: # Std 8.4.2.92
            ess = struct.unpack_from('=B',info)[0]
            info = {'ess-intv':ess,'uri':info[1:]}
        elif eid == std.EID_UAPSD_COEXIST: # Std 8.4.2.93
            # TSF 0 offset|Interval/Dur|Subelements
            #            8|           4|  (opt) var
            tsfo,intv = struct.unpack_from('=QI',info)
            info = {'tsf0-offset':tsfo,
                    'interval':intv,
                    'opt-subels':_parseiesubel_(info[struct.calcsize('=QI'):])}
        elif eid == std.EID_MCCAOP_ADV_OVERVIEW: # Std 8.4.2.119
            # 1|1|1|1|2
            seqn,fs,frac,lim,bm = struct.unpack_from('=4BH', info)
            info = {'adv-seq-num':seqn,
                    'flags':{'accept':bits.leastx(1,fs),
                             'rsrv':bits.mostx(1,fs)},
                    'mcca-access-frac': frac,
                    'maf-lim':lim,
                    'adv-els-bm':bm}
        elif eid == std.EID_VEND_SPEC: # Std 8.4.2.28
            # split into tuple (tag,(oui,value))
            info = {'oui':_hwaddr_(struct.unpack_from('=3B',info)),
                    'content':info[3:]}
        else:
            info = {'rsrv':info}
    except (struct.error,IndexError) as e:
        raise RuntimeError(e)
    return info

# INFORMATION ELEMENT SUBELEMENT Std Fig 8-402
# Subelement ID|Length|Data
#             1|     1| var
def _iesubel_(s): return s # default subelement parsing, returns argument
def _parseiesubel_(info,f=_iesubel_):
    """
     parse a variable length info element sub element
     :param info: packed string, next element starts at index 0
     :param f: function to apply to each sub element for further parsing
     :returns: list of parsed subelements
    """
    opt = []
    offset = 0
    while len(info) >= 2: # may be flags (0-octet subelements)
        sid,slen = struct.unpack_from('=2B',info,offset)
        opt.append((sid,f(info[offset+2:offset+2+slen],sid)))
        offset += 2 + slen
    return opt

#### OPTIONAL SUBELEMENTS -> the sub element id and length have been stripped

def _iesubelssid_(s):
    """ :returns: a unicode ssid if able otherwise leave as is"""
    try:
        return s.decode('utf8')
    except UnicodeDecodeError:
        return s

# Neighbor Report optional subelements Std Table 8-115 & figure commented below
def _iesubelneighrpt_(s,sid):
    """ :returns: parsed subelement for neighbor report """
    # NOTE: where the optional subelements have the same format as an info_element
    # the constant appears to be the same for the subelement id and for the info
    # element id. However, just in case, we won't resuse the sid here
    ret = s
    if sid == std.EID_NR_TSF:
        o,b = struct.unpack_from('=2H',s) # Std Fig 8-218, 8.4.1.3
        ret = {'tsf-offset':o,'beacon-intv':b}
    elif sid == std.EID_NR_COUNTRY_STRING:
        # first 2 octets of the dot11CountryString (should be ascii?/utf-8?
        try:
            ret = s.decode('utf8')
        except UnicodeDecodeError:
            ret = s
    elif sid == std.EID_NR_BSS_TX_CAND_PREF:
        # Std Fig 8-219
        ret = {'pref':struct.unpack_from('=B',s)[0]}
    elif sid == std.EID_NR_BSS_TERM_DUR:
        # Std Fig 8-220 |8|2|
        t,d = struct.unpack_from('=QH',s)
        ret = {'bss-term-tsf':t,'duration':d}
    elif sid == std.EID_NR_BEARING:
        # Bearing(2)|Distance(4)|Height(2)|
        b,d,h = struct.unpack_from('=Hfh',s)
        ret = {'bearing':b,'distance':d,'rel-height':h}
    elif sid == std.EID_NR_HT_CAP:
        # same format as ht capabilities (8.4.2.58)
        ret = _parseie_(std.EID_HT_CAP,s)
    elif sid == std.EID_NR_HT_OP:
        # same format as ht operation (8.4.2.59)
        ret = _parseie_(std.EID_HT_OP,s)
    elif sid == std.EID_NR_SEC_CH_OFFSET:
        # same format as secondary channel offset (8.4.2.22)
        ret = _parseie_(std.EID_SEC_CH_OFFSET,s)
    elif sid == std.EID_NR_MSMT_PILOT_TX:
        # same format as msmt pilot tx (8.4.2.44)
        ret = _parseie_(std.EID_MSMT_PILOT,s)
    elif sid == std.EID_NR_RM_ENABLED_CAP:
        # same format as rm enabled capabilities (8.4.2.47)
        ret = _parseie_(std.EID_RM_ENABLED,s)
    elif sid == std.EID_NR_MULT_BSSID:
        # same format as multiple bssid (8.4.2.48)
        ret = _parseie_(std.EID_MULT_BSSID,s)
    elif sid == std.EID_NR_VEND_SPEC:
        # same format as vendor specific
        ret = _parseie_(std.EID_NR_VEND_SPEC,s)
    return ret

# MULT BSSID optional subelements Std Table 8-120 & figurs below
def _iesubelmultbssid_(s,sid):
    """ :returns: parsed opt subelement of mult bssid element """
    ret = s
    if sid == std.EID_MUL_BSSID_NONTRANS:
        # list of elements for one or more AP defined as
        ret = {'nontrans-bssid-profile':s}
    elif sid == std.EID_MUL_BSSID_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# FTE optional subelements Std Table 8-121 & figure commented below
def _iesubelfte_(s,sid):
    """ :returns: parsed opt subelement of FTE element """
    ret = s
    if sid == std.EID_FTE_RSRV: pass
    elif sid == std.EID_FTE_PMK_R1:
        # a 6-octed key
        ret = {'r1kh-id':struct.unpack_from('=Q',s+'\x00\x00')[0]}
    elif sid == std.EID_FTE_GTK:
        # Std Fig. 8-237 Key Info|Key Len|RSC|Wrapped Key
        #                       2|      1|  8|      24-40
        ki,kl,r = struct.unpack_from('=HBQ',s)
        ret = {'key-info':{'key-id':bits.leastx(2,ki),
                           'rsrv':bits.mostx(2,ki)},
               'key-leng':kl,
               'rsc':r,
               'wrapped-key':binascii.hexlify(s[struct.calcsize('=HBQ'):])}
    elif sid == std.EID_FTE_PMK_R0:
        # variable length 1-48 octets
        ret = {'r0kh-id':binascii.hexlify(s)}
    elif sid == std.EID_FTE_IGTK:
        # Std Fig 8-239 Key ID|IPN|Key Length|Wrapped Key
        #                    2|  6|         1|         24
        ki = struct.unpack_from('=H',s)[0]
        ipn = struct.unpack_from('=Q',s[2:8]+'\x00\x00')[0]
        kl = struct.unpack_from('=B',s,8)[0]
        ret = {'key-id':ki,
               'ipn':ipn,
               'key-len':kl,
               'wrapped-key':binascii.hexlify(s[9:])}
    return ret

# Diagnositc Report/Request optional subelements Std Table 8-143 & figures commented below
def _iesubeldiag_(s,sid):
    """ :returns: parsed diag rpt/req subelement """
    ret = s
    if sid == std.EID_DIAG_SUBELEMENT_CRED:
        # Std Fig. 8-288 TODO: see Table 8-144. Is this a list of 1-byte elements?
        ret = {'cred-vals':[struct.unpack('=B',x)[0] for x in s]}
    elif sid == std.EID_DIAG_SUBELEMENT_AKM:
        # Fig 8-289
        ret = _parsesuitesel_(s)
        #ret = {'oui':_hwaddr_(struct.unpack_from('=3B',s)),
        #       'akm-suite':struct.unpack_from('=B',s,3)[0]}
    elif sid == std.EID_DIAG_SUBELEMENT_AP:
        # Fig 8-290
        vs = struct.unpack_from('=8B',s)
        ret = {'bssid':_hwaddr_(vs[0:6]),
               'op-class':vs[6],
               'ch-num':vs[7]}
    elif sid == std.EID_DIAG_SUBELEMENT_ANT:
        # Std Fig. 8-291
        c,g = struct.unpack_from('=2B',s)
        ret = {'ant-cnt':c,'ant-gain':g,'ant-type':s[2:]}
    elif sid == std.EID_DIAG_SUBELEMENT_CS:
        # Std Fig. 8-292
        ret = {'oui':_hwaddr_(struct.unpack_from('=3B',s)),
               'suite-type':struct.unpack_from('=B',s,3)[0]}
    elif sid == std.EID_DIAG_SUBELEMENT_RDO:
        # Std Fig. 8-293
        ret = {'rdo-type':struct.unpack_from('=B',s)[0]}
    elif sid == std.EID_DIAG_SUBELEMENT_DEV:
        # Std Fig. 8-294
        ret = {'dev-type':struct.unpack_from('=B',s)[0]}
    elif sid == std.EID_DIAG_SUBELEMENT_EAP:
        # Std fig 8-295
        ret = {'eap-type':struct.unpack_from('=B',s)[0]}
        if ret['eap-type'] == 254:
            ret['eap-vend-id'] = _hwaddr_(struct.unpack_from('=3B',s,1))
            ret['eap-vend-type'] = struct.unpack_from('=I',s,4)[0]
    elif sid == std.EID_DIAG_SUBELEMENT_FW:
        # Std Fig. 8-296
        ret = {'fw-vers':s}
    elif sid == std.EID_DIAG_SUBELEMENT_MAC:
        # Std Fig. 8-297
        ret = {'mac-addr':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_DIAG_SUBELEMENT_MANUF_ID:
        # Std Fig. 8-298
        ret = {'manuf-id':s}
    elif sid == std.EID_DIAG_SUBELEMENT_MANUF_MODEL:
        # Std Fig. 8-299
        ret = {'manuf-model':s}
    elif sid == std.EID_DIAG_SUBELEMENT_MANUF_OI:
        # Std Fig. 8-300
        fmt = '=3B' if len(s) == 3 else '=5B'
        ret = {'manuf-oi':_hwaddr_(struct.unpack_from(fmt,s))}
    elif sid == std.EID_DIAG_SUBELEMENT_MANUF_SER:
        # Std Fig. 8-301
        ret = {'manuf-ser-num':s}
    elif sid == std.EID_DIAG_SUBELEMENT_POW_SAVE:
        # Std Fig. 8-302
        ret = _eiddiagsubelps_(struct.unpack_from('=I',s)[0])
    elif sid == std.EID_DIAG_SUBELEMENT_PROFILE:
        # Std Fig 8-303
        ret = {'profile-id':struct.unpack_from('=B',s[0])}
    elif sid == std.EID_DIAG_SUBELEMENT_OP_CLASSES:
        # Std Fig 8-304 same as supported operating classes
        ret = _parseie_(std.EID_OP_CLASSES,s)
    elif sid == std.EID_DIAG_SUBELEMENT_STATUS:
        # Std Fig 8-305
        ret = {'stat-code':struct.unpack_from('=H',s)[0]}
    elif sid == std.EID_DIAG_SUBELEMENT_SSID:
        # Std Fig 8-306
        ret = {'ssid':_parseie_(std.EID_SSID,s)}
    elif sid == std.EID_DIAG_SUBELEMENT_TX_POWER:
        # Std Fig. 8-307
        # TODO: parse tx-power - each tx power is encoded in a single octet
        # as a twos complement value in dBm
        ret = {'tx-pwr-mode':struct.unpack_from('=B',s)[0],
               'tx-power':[struct.unpack_from('=B',x)[0] for x in s[1:]]}
    elif sid == std.EID_DIAG_SUBELEMENT_CERT:
        # Std Fig. 8-308
        ret = {'cert-id':s}
    elif sid == std.EID_DIAG_SUBELEMENT_VEND:
        # same as vendor specific
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# DIAGNOSTIC REPORT/REQUEST->Power save subelement -> bitmap Std Table 8-147
_EID_DIAG_SUBELEMENT_PS_ = {
    'unknown':(1<<0),
    'none':(1<<1),
    'ps-mode-1':(1<<2),
    'ps-mode-2':(1<<3),
    'u-apsd':(1<<4),
    's-apsd':(1<<5),
    'u-psmp':(1<<6),
    's-psmp':(1<<7),
    'sm-pow-save':(1<<8),
    'wnm-sleep':(1<<9),
    'fms':(1<<10),
    'tim-bcast':(1<<11),
    'tfs':(1<<12),
    'tdls-peer-uapsd':(1<<13),
    'tdls-peer-psm':(1<<14),
}
_EID_DIAG_SUBELEMENT_PS_DIVIDER_ = 15
def _eiddiagsubelps_(v):
    """ :returns: parsed power save mode subelement """
    ps = bits.bitmask_list(_EID_DIAG_SUBELEMENT_PS_,v)
    ps['rsrv'] = bits.mostx(_EID_DIAG_SUBELEMENT_PS_DIVIDER_,v)
    return ps

# LOCATION ELEMENT subelements Std Table 8-153 & figures commented below
def _iesubelloc_(s,sid):
    """ :returns: parsed location subelement """
    ret = s
    if sid == std.EID_LOCATION_SUBELEMENT_LIP: # Fig 8-311
        addr = _hwaddr_(struct.unpack_from('=6B',s)[0])
        vs = struct.unpack_from('=BHBH4B',s,6)
        ret = {'mcast-addr':addr,
               'rpt-intv-units':vs[0],
               'normal-rpt-intv':vs[1],
               'normal-num-frames':vs[2],
               'in-motion-rpt-intv':vs[3],
               'in-motion-num-frames':vs[4],
               'burst-inter-frame-intv':vs[5],
               'tracking-dur':vs[6],
               'ess-detect-intv':vs[7]}
    elif sid == std.EID_LOCATION_SUBELEMENT_LIC: # Fig 8-312
        e = []
        offset = 0
        while len(s) > offset:
            o,c = struct.unpack_from('=2B',s,offset)
            e.append({'op-class':o,'ch':c})
        ret = {'ch-entry':e}
    elif sid == std.EID_LOCATION_SUBELEMENT_STATUS: # Fig 8-314
        c,s = struct.unpack_from('=2B',s)
        ret = {'config-sub-id':c,'status':s}
    elif sid == std.EID_LOCATION_SUBELEMENT_RDO_INFO: # Fig 8-315
        p,i,g,rs,rc = struct.unpack_from('=bBb2B',s)
        ret = {'tx-pwr':p,'ant-id':i,'ant-gain':g,'rsni':rs,'rcpi':rc}
    elif sid == std.EID_LOCATION_SUBELEMENT_MOTION: # Fig 8-316
        m,b,s,h,v = struct.unpack_from('=BHB2H',s)
        ret = {'motion-indicator':m,
               'bearing':b,
               'speed-units':s,
               'hor-speed':h,
               'ver-speed':v}
    elif sid == std.EID_LOCATION_SUBELEMENT_LIBDR: # Fig 8-317
        # defined in Std 8.4.1.32 in Figs. 8-69 and 8-70
        m,i,r = struct.unpack_from('=2BH',s)[0]
        ret = {'bcast-tgt-data-rate':{'mask':_rateidmask_(m),
                                      'mcs-index':i,
                                      'rate':r}}
    elif sid == std.EID_LOCATION_SUBELEMENT_DEPT_TIME: # Fig 8-318
        t,r,c = struct.unpack_from('=I2H',s)
        ret = {'tod-ts':t,'tod-rms':r,'tod-clock-rate':c}
    elif sid == std.EID_LOCATION_SUBELEMENT_LIO: # Fig. 8-319
        opts = struct.unpack_from('=B',s)[0]
        ret = {'opts':{'beacon-msmt-mode':bits.leastx(1,opts),
                       'rsrv':bits.mostx(1,opts)},
               'indication-params':ret[1:]}
    elif sid == std.EID_LOCATION_SUBELEMENT_VENDOR:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# RATE IDENTIFICATION FIELD Std Fig 8-70
_RATE_ID_MASK_SEL_DIVIDER_ = 3
_RATE_ID_MASK_RT_START_    = 3
_RATE_ID_MASK_RT_LEN_      = 2
_RATE_ID_MASK_RSRV_START_  = 5
def _rateidmask_(v):
    """ :returns: parsed rate identification field mask """
    rim = {}
    rim['mcs-sel'] = bits.leastx(_RATE_ID_MASK_SEL_DIVIDER_,v)
    rim['rate-type'] = bits.midx(_RATE_ID_MASK_RT_START_,
                                 _RATE_ID_MASK_RT_LEN_,
                                 v)
    rim['rsrv'] = bits.mostx(_RATE_ID_MASK_RSRV_START_,v)
    return rim

# FMS Request subelements Std Table 8-158 & figures commented below
def _iesubelfmsreq_(s,sid):
    """ :returns: parsed fms request subelement """
    ret = s
    if sid == std.EID_FMS_REQ_SUBELEMENT_FMS: # Std Fig. 8-327
        # Note: the 4-byte rate identification is defined in 8.4.1.32
        # as 1|1|2
        di,mi,m,i,r = struct.unpack_from('=4BH',s)
        rem = s[6:]
        ret = {'delv-intv':di,
               'max-delv-intv':mi,
               'rate-ident':{'mask':_rateidmask_(m),
                             'mcs-index':i,
                             'rate':r}}

        # there are one or more tclas elements folled by an option tclas
        # processing element
        while rem:
            eid,tlen = struct.unpack_from('=2B',rem)
            if eid == std.EID_TCLAS:
                if not 'tclas' in ret: ret['tclas'] = []
                ret['tclas'].append(_parseie_(std.EID_TCLAS,rem[:tlen]))
                ret = ret[2+tlen:]
            elif eid == std.EID_TCLAS_PRO:
                ret['tclas-pro'] = _parseie_(std.EID_TCLAS_PRO,ret)
                # could use a break here but want to make sure
                # there are not hanging elements
                ret = ret[3:]
    elif sid == std.EID_FMS_REQ_SUBELEMENT_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# FMS Response subelements Std Table 8-159 & figures commented below
def _iesubelfmsresp_(s,sid):
    """ :returns: parsed fms response subelement """
    ret = s
    if sid == std.EID_FMS_RESP_SUBELEMENT_FMS: # Std Fig. 8-329
        vs = struct.unpack_from('=7BH',s)
        a = _hwaddr_(struct.unpack_from('=6B',s,struct.calcsize('=7BH')))
        ret = {'el-stat':vs[0],
               'delv-intv':vs[1],
               'max-delv-intv':vs[2],
               'fms-id':vs[3],
               'fms-cntr':vs[4],
               'rate-ident':{'mask':_rateidmask_(vs[5]),
                             'mcs-index':vs[6],
                             'rate':vs[7]},
               'mcast-addr':a}
    elif sid == std.EID_FMS_RESP_SUBELEMENT_TCLAS: # Std Fig. 8-330
        ret = {'fms-id':struct.unpack_from('=B',s)}
        rem = s[1:]

        # there are one or more tclas elements folled by an option tclas
        # processing element
        while rem:
            eid,tlen = struct.unpack_from('=2B',rem)
            if eid == std.EID_TCLAS:
                if not 'tclas' in ret: ret['tclas'] = []
                ret['tclas'].append(_parseie_(std.EID_TCLAS,rem[:tlen]))
                ret = ret[2+tlen:]
            elif eid == std.EID_TCLAS_PRO:
                ret['tclas-pro'] = _parseie_(std.EID_TCLAS_PRO,ret)
                # could use a break here but want to make sure
                # there are not hanging elements
                ret = ret[3:]
    elif sid == std.EID_FMS_RESP_SUBELEMENT_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# TFS Request subelements Std Table 8-163 & figures commented below
def _iesubeltfsreq_(s,sid):
    """ :returns: parsed tfs request subelement """
    ret = s
    if sid == std.EID_TFS_SUBELEMENT_TFS:
        # there are one or more tclas elements folled by an option tclas
        # processing element
        ret = {}
        while s:
            eid,tlen = struct.unpack_from('=2B',s)
            if eid == std.EID_TCLAS:
                if not 'tclas' in ret: ret['tclas'] = []
                ret['tclas'].append(_parseie_(std.EID_TCLAS,s[:tlen]))
                s = s[2+tlen:]
            elif eid == std.EID_TCLAS_PRO:
                s['tclas-pro'] = _parseie_(std.EID_TCLAS_PRO,ret)
                # could use a break here but want to make sure
                # there are not hanging elements
                s = s[3:]
    elif sid == std.EID_TFS_SUBELEMENT_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Pilot subelements Std Table 8-117
def _iesubelmsmtpilot_(s,sid):
    """ :returns: parsed msmt pilot subelement"""
    ret = s
    # ATT only vendor specific is defined
    if sid == std.EID_VEND_SPEC: ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelements for type Channel load Std Table 8-60 and figures below
def _iesubelmsmtreqcl_(s,sid):
    """ :returns: parsed subelement of type channel load in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_CL_RPT:
        # Std fig. 8-110
        c,r = struct.unpack_from('=2B',s)
        ret = {'rpt-condition':c,'ch-load-ref-val':r}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_CL_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelements for type Noise Histogram Std Table 8-62 and figures below
def _iesubelmsmtreqnh_(s,sid):
    """ :returns: parsed subelement of type channel load in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_NH_RPT:
        # Std fig. 8-112
        c,a = struct.unpack_from('=2B',s)
        ret = {'rpt-condition':c,'anpi-ref-val':a}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_NH_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelements for type Beaon Std Table 8-65 and figures below
def _iesubelmsmtreqbeacon_(s,sid):
    """ :returns: parsed subelement of type beacon in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_BEACON_SSID:
        ret = {'ssid':_iesubelssid_(s)}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_BEACON_BRI:
        # Std Fig. 8-114
        r,t = struct.unpack_from('=2B',s)
        ret = {'rpt-condition':r,'threshold':t}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_BEACON_RPT:
        # Std Table 8-67
        ret = {'rpt-detail':struct.unpack_from('=B',s)}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_BEACON_REQ:
        # same as Std 8.4.2.13
        ret = _parseie_(std.EID_REQUEST,s)
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_BEACON_AP_CH_RPT:
        # same as Std 8.4.2.38
        ret = _parseie_(std.EID_AP_CH_RPT,s)
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_BEACON_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

#### NOTE: next three could probably be combined

# MSMT Request subelements for type Frame Request Std Table 8-68 and figures below
def _iesubelmsmtreqframe_(s,sid):
    """ :returns: parsed subelement of type frame request in msmt request """
    ret = s
    # For now, not going to bother with defining the element ids in Table 8-68
    # since the only subelement is a vend specific
    if sid == std.EID_VEND_SPEC: ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelements for type STA Request Sta counters Std Table 8-70 and figures below
def _iesubelmsmtreqstasta_(s,sid):
    """ :returns: parsed subelement of type sta request for sta counters in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_STA_RPT:
        # Std Fig. 8-117
        cnt,to,t = struct.unpack_from('=I2H',s)
        ts = s[8:]
        ret = {'msmt-cnt':cnt,
               'trigger-timeout':to,
               'sta-cntr-trigger-cond':_stacntrtriggerconds_(t),
               'thresholds':{}}

        # optional count fields are 4-bytes assuming they are appending in order
        for thresh in ['fail','fcs-error','mult-retry','dup','rts-fail','ack-fail','retry-cnt']:
            if ret['sta-cntr-trigger-cond'][thresh]:
                ret['thresholds'][thresh] = struct.unpack_from('=I',ts)[0]
                ts = ts[4:]
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_STA_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# STA Counter Trigger Conditions Std Fig. 8-118
_STA_COUNTER_TRIGGER_CONDITIONS_ = {
    'fail':(1<<0),
    'fcs-error':(1<<1),
    'mult-retry':(1<<2),
    'dup':(1<<3),
    'rts-fail':(1<<4),
    'ack-fail':(1<<5),
    'retry-cnt':(1<<6)
}
_STA_COUNTER_TRIGGER_CONDITIONS_RSRV_START_ = 7
def _stacntrtriggerconds_(v):
    """ :returns: parsed sta counter tigger conditions """
    s = bits.bitmask_list(_STA_COUNTER_TRIGGER_CONDITIONS_,v)
    s['rsrv'] = bits.mostx(_STA_COUNTER_TRIGGER_CONDITIONS_RSRV_START_,v)

# MSMT Request subelements for type STA Request QoS counters Std Table 8-70 and figures below
def _iesubelmsmtreqstaqos_(s,sid):
    """ :returns: parsed subelement of type sta request for qos counters in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_STA_RPT:
        # Std Fig. 8-119
        cnt,to,t = struct.unpack_from('=I2H',s)
        ts = s[8:]
        ret = {'msmt-cnt':cnt,
               'trigger-timeout':to,
               'qos-cntr-trigger-cond':_qoscntrtriggerconds_(t),
               'thresholds':{}}

        # optional count fields are 4-bytes assuming they are appending in order
        for thresh in ['fail','retry-cnt','mult-retry','dup','rts-fail','ack-fail','discarded']:
            if ret['sta-cntr-trigger-cond'][thresh]:
                ret['thresholds'][thresh] = struct.unpack_from('=I',ts)[0]
                ts = ts[4:]
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_STA_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# QOS Counter Trigger Conditions Std Fig. 8-120
_QOS_COUNTER_TRIGGER_CONDITIONS_ = {
    'fail':(1<<0),
    'retry-cnt':(1<<1),
    'mult-retry':(1<<2),
    'dup':(1<<3),
    'rts-fail':(1<<4),
    'ack-fail':(1<<5),
    'discarded':(1<<6)
}
_QOS_COUNTER_TRIGGER_CONDITIONS_RSRV_START_ = 7
def _qoscntrtriggerconds_(v):
    """ :returns: parsed sta counter tigger conditions """
    s = bits.bitmask_list(_QOS_COUNTER_TRIGGER_CONDITIONS_,v)
    s['rsrv'] = bits.mostx(_QOS_COUNTER_TRIGGER_CONDITIONS_RSRV_START_,v)

# MSMT Request subelements for type STA Request RSNA counters Std Table 8-70 and figures below
def _iesubelmsmtreqstarsna_(s,sid):
    """ :returns: parsed subelement of type sta request for qos counters in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_STA_RPT:
        # Std Fig. 8-121
        cnt,to,t = struct.unpack_from('=I2H',s)
        ts = s[8:]
        ret = {'msmt-cnt':cnt,
               'trigger-timeout':to,
               'rsna-cntr-trigger-cond':_rsnacntrtriggerconds_(t),
               'thresholds':{}}

        # optional count fields are 4-bytes assuming they are appending in order
        for thresh in ['cmacicv-err','cmarc-replay','robust-ccmp-replay','tkipicv-err','tkip-replay','ccmp-decrypt','ccmp-replay']:
            if ret['sta-cntr-trigger-cond'][thresh]:
                ret['thresholds'][thresh] = struct.unpack_from('=I',ts)[0]
                ts = ts[4:]
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_STA_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# RSNA Counter Trigger Conditions Std Fig. 8-122
_RSNA_COUNTER_TRIGGER_CONDITIONS_ = {
    'cmacicv-err':(1<<0),
    'cmarc-replay':(1<<1),
    'robust-ccmp-replay':(1<<2),
    'tkipicv-err':(1<<3),
    'tkip-replay':(1<<4),
    'ccmp-decrypt':(1<<5),
    'ccmp-replay':(1<<6)
}
_RSNA_COUNTER_TRIGGER_CONDITIONS_RSRV_START_ = 7
def _rsnacntrtriggerconds_(v):
    """ :returns: parsed sta counter tigger conditions """
    s = bits.bitmask_list(_RSNA_COUNTER_TRIGGER_CONDITIONS_,v)
    s['rsrv'] = bits.mostx(_RSNA_COUNTER_TRIGGER_CONDITIONS_RSRV_START_,v)

# MSMT REQUEST->Type LCI optional subfields Std Table 8-72 & figures below
def _iesubelmsmtreqlci_(s,sid):
    """ :returns: parsed lci optional subfield """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_LCI_AZIMUTH: # std Fig. 8-124
        ret = {'azimuth-req':_eidmsmtreqlciazimuth_(struct.unpack_from('=B',s)[0])}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LCI_REQUESTING:
        ret = {'originator-mac':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LCI_TARGET:
        ret = {'target-mac':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LCI_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# LCI AZIMUTH REQUEST AZIMUTH REQUST FIELD Std Fig. 8-125
_LCI_AZIMUTH_REQ_ = {'azimuth-type':(1<<4)}
_LCI_AZIMUTH_REQ_RES_DIVIDER_    = 4
_LCI_AZIMUTH_REQ_RES_RSRV_START_ = 5
def _eidmsmtreqlciazimuth_(v):
    """ :returns: parsed azimuth request subelement of MSMT req """
    az = bits.bitmask_list(_LCI_AZIMUTH_REQ_,v)
    az['azimuth-resolution'] = bits.leastx(_LCI_AZIMUTH_REQ_RES_DIVIDER_,v)
    az['rsrv'] = bits.mostx(_LCI_AZIMUTH_REQ_RES_RSRV_START_,v)
    return az

# MSMT REQUEST->Type TX optional subfields Std Table 8-73 & figures below
def _iesubelmsmtreqtx_(s,sid):
    """ :returns: parsed tx optional subfield """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_TX_RPT:
        c,ae,ce,d,m,to = struct.unpack_from('=6B',s)
        ret = {'trigger-cond':_eidmsmtreqtxtrigger_(c),
               'avg-err-thresh':ae,
               'cons-err-thresh':ce,
               'delay-thresh':_eidmsmtreqtxdelay_(d),
               'msmt-cnt':m,
               'trigger-timeout':to}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_TX_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# TX TRIGGER CONDITION Std Fig. 8-132
_TX_TRIGGER_COND_ = {'avg':(1<<0),'consecutive':(1<<1),'delay':(1<<2)}
_TX_TRIGGER_COND_RSRV_START_ = 3
def _eidmsmtreqtxtrigger_(v):
    """ :returns: parsed trigger reporting for TX """
    tc = bits.bitmask_list(_TX_TRIGGER_COND_,v)
    tc['rsrv'] = bits.mostx(_TX_TRIGGER_COND_RSRV_START_,v)
    return tc

# TX DELAYED MSDU Std Fig. 8-133
_TX_DELAYED_DIVIDER_ = 2
def _eidmsmtreqtxdelay_(v):
    """ :returns: parsed tx delay """
    d = {'delayed-msdu-range':bits.leastx(_TX_DELAYED_DIVIDER_,v),
         'delayed-msdu-cnt':bits.mostx(_TX_DELAYED_DIVIDER_,v)}
    return d

# MSMT Request subelements for type Pause Std Table 8-75
def _iesubelmsmtreqpause_(s,sid):
    """ :returns: parsed subelement of type frame request in msmt request """
    ret = s
    # For now, not going to bother with defining the element ids in Table 8-75
    # since the only subelement is a vend specific
    if sid == std.EID_VEND_SPEC: ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelement for type MCAST Diag Std Table 8-76
def _iesubelmsmtreqmcastdiag_(s,sid):
    """ :returns: parsed subelement of type mcast diag """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_MCAST_TRIGGER:
        c,t,d = struct.unpack_from('=3B',s)
        ret = {'mcast-trigger-rpt':{'trigger-condition': c,
                                    'inactivity-timeout': t,
                                    'reactivation-delay': d}}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_MCAST_VEND:
        ret =  _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelements for type Location civic request Std Table 8-79
def _iesubelmsmtreqloccivic_(s,sid):
    """ :returns: parsed subelement of type location civic in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_CIVIC_ORIGIN:
        ret = {'originator':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_CIVIC_TARGET:
        ret = {'target':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_CIVIC_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelements for Type Location Id Std Table 8-80
def _iesubelmsmtreqlid_(s,sid):
    """ :returns: parsed subelement of type location civic in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_ID_ORIGIN:
        ret = {'originator':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_ID_TARGET:
        ret = {'target':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_ID_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Report subelements for:
# Type Channel Load Std Table 8-83
# Type Noise Histogram Std Table 8-85
# Type Tx Stream/Category Std Table 8-92
# Type Mcast Diag Std Table 8-93
def _iesubelmsmtrptvend_(s,sid):
    """ :returns: parsed ch load subelement """
    ret = s
    # only vend is currently defined
    if sid == std.EID_VEND_SPEC: ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Report subelements for Type Beacon Std Table 8-86
def _iesubelmsmtrptbeacon_(s,sid):
    """ :returns: parsed beacon subelement """
    ret = s
    # we leave the reported frame body as is for now
    #if sid == std.EID_MSMT_RPT_BEACON_FRAME_BODY:
    if sid == std.EID_MSMT_RPT_BEACON_VEND: ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Report subelements for Type Frame Std Table 8-87
def _iesubelmsmtrptframe_(s,sid):
    """ :returns: parsed frame subelement """
    ret = s
    if sid == std.EID_MSMT_RPT_FRAME_CNT_RPT:
        # Fig 8-151, 8-152
        ret = []
        n = len(s)/19
        for i in xrange(n):
            vs = struct.unpack_from('=17BH',s,i*19)
            ent = {'tx-addr':_hwaddr_(vs[0:6]),
                   'bssid':_hwaddr_(vs[6:12]),
                   'phy-type':vs[12],
                   'avg-rcpi':vs[13],
                   'last-rsni':vs[14],
                   'last-rcpi':vs[15],
                   'antenna-id':vs[16],
                   'frmae-cnt':vs[17]}
            ret.append(ent)
    elif sid == std.EID_MSMT_RPT_FRAME_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Report subelements for Type STA statistics Std Table 8-89
def _iesubelmsmtrptsta_(s,sid):
    """ :returns: parsed STA optional subelement """
    ret = s
    if sid == std.EID_MSMT_RPT_STA_STAT_REASON:
        ret = {'reason':struct.unpack_from('=B',s)[0]}
    elif sid == std.EID_MSMT_RPT_STA_STAT_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Report subelements for Type LCI Std Table 8-90
def _iesubelmsmtrptlci_(s,sid):
    """ :returns: parsed LCI optional subelement """
    ret = s
    if sid == std.EID_MSMT_RPT_LCI_AZIMUTH:
        ret = {
            'azimuth-rpt':_iesubelmsmtrptlicazimuth_(struct.unpack_from('=H',s)[0])
        }
    elif sid == std.EID_MSMT_RPT_LCI_ORIGIN:
        ret = {'originator':_hwaddr_(struct.unpack('=6B',s))}
    elif sid == std.EID_MSMT_RPT_LCI_TARGET:
        ret = {'target':_hwaddr_(struct.unpack('=6B',s))}
    elif sid == std.EID_MSMT_RPT_LCI_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Report->Azimuth Report fields Std Fig. 8-164
_EID_MSMT_RPT_LCI_AZIMUTH_TYPE_START_       = 2
_EID_MSMT_RPT_LCI_AZIMUTH_TYPE_LEN_         = 1
_EID_MSMT_RPT_LCI_AZIMUTH_RESOLUTION_START_ = 3
_EID_MSMT_RPT_LCI_AZIMUTH_RESOLUTION_LEN_   = 4
_EID_MSMT_RPT_LCI_AZIMUTH_AZIMUTH_START_    = 7
def _iesubelmsmtrptlicazimuth_(v):
    """ :returns: parsed azimuth report """
    a = {}
    a['rsrv'] = bits.leastx(_EID_MSMT_RPT_LCI_AZIMUTH_TYPE_START_,v)
    a['type'] = bits.midx(_EID_MSMT_RPT_LCI_AZIMUTH_TYPE_START_,
                          _EID_MSMT_RPT_LCI_AZIMUTH_TYPE_LEN_,
                          v)
    a['resolution'] = bits.midx(_EID_MSMT_RPT_LCI_AZIMUTH_RESOLUTION_START_,
                                _EID_MSMT_RPT_LCI_AZIMUTH_RESOLUTION_LEN_,
                                v)
    a['azimuth'] = bits.mostx(_EID_MSMT_RPT_LCI_AZIMUTH_AZIMUTH_START_,v)
    return a

# MSMT Report->TX Stream/Category MSMT report reporting reason Std Fig.8-166
_EID_MSMT_RPT_TX_RPT_REASON_ = {
    'avg-trigger':(1<<0),
    'cons-trigger':(1<<1),
    'delay-trigger':(1<<2)
}
_EID_MSMT_RPT_TX_RPT_REASON_RSRV_START_ = 3
def _eidmsmtrpttxrptreason_(v):
    """ :returns: parsed report reason of msmt rpt """
    r = bits.bitmask_list(_EID_MSMT_RPT_TX_RPT_REASON_,v)
    r['rsrv'] = bits.mostx(_EID_MSMT_RPT_TX_RPT_REASON_RSRV_START_,v)
    return r

# MSMT Report->Location Civic Report subelements Std Table 8-95
def _iesubelmsmtrptloccivic_(s,sid):
    """ :returns: parsed optional subelements for location civic report """
    ret = s
    if sid == std.EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_ORIGIN:
        ret = {'originator':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_TARGET:
        ret = {'target': _hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_LOC_REF:
        # Std Fig. 8-170. loc reference is an ASCII string
        ret = {'loc-ref':s}
    elif sid == std.EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_LOC_SHAPE:
        # Std Fig. 8-171
        ret = {'loc-shape-id':struct.unpack_from('=B',s)[0]}
        if ret['loc-shape-id'] == std.LOC_SHAPE_2D_PT: # Std Fig. 8-172
            x,y = struct.unpack_from('=2f',s,1)
            ret['shape'] = {'x':x,'y':y}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_3D_PT: # Std Fig. 8-173
            x,y,z = struct.unpack_from('=3f',s,1)
            ret['shape'] = {'x':x,'y':y,'z':z}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_CIRCLE: # Std Fig. 8-174
            x,y,r = struct.unpack_from('=3f',s,1)
            ret['shape'] = {'x':x,'y':y,'radius':r}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_SPHERE: # Std Fig 8-175
            x,y,z,r = struct.unpack_from('=4f',s,1)
            ret['shape'] = {'x':x,'y':y,'z':z,'radius':r}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_POLYGON: # Std Fig 8-176
            n = struct.unpack_from('=B',s,1)[0]
            pts = []
            for i in xrange(n):
                x,y = struct.unpack_from('=2f',s,2+(i*struct.calcsize('=2f')))
                pts.append({'x':x,'y':y})
            ret['shape'] = {'num-pts':n,'points':pts}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_PRISM: # Std fig. 8-177
            n = struct.unpack_from('=B',s,1)[0]
            pts = []
            for i in xrange(n):
                x,y,z = struct.unpack_from('=3f',s,2+(i*struct.calcsize('=3f')))
                pts.append({'x':x,'y':y,'z':z})
            ret['shape'] = {'num-pts': n, 'points': pts}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_ELLIPSE: # Std Fig 8-178
            x,y,a,ax1,ax2 = struct.unpack_from('=2fH2f',s,1)
            ret['shape'] = {'x':x,'y':y,'angle':a,'major-axis':ax1,'minor-axis':ax2}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_ELLIPSOID: # Std fig 8-179
            x,y,z,a,ax1,ax2,ax3 = struct.unpack_from('=3fH3f',s,1)
            ret['shape'] = {'x':x,'y':y,'z':z,'angle':a,
                            'major-axis':ax1,
                            'minor-axis':ax2,
                            'vertical-axis':ax3}
        elif ret['loc-shape-id'] == std.LOC_SHAPE_ARCBAND: # Std Fig. 8-180
            x,y,ri,ro,s,o = struct.unpack_from('=4f,2H',s,1)
            ret['shape'] = {'x':x,'y':y,
                            'inner-radius':ri,
                            'outer-radius':ro,
                            'start-angle':s,
                            'opening-angle':o}
    elif sid == std.EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_MAP_IMAGE:
        # Std Fig 8-181
        ret = {'map-type':struct.unpack_from('=B',s)[0]}
        ret['map-url'] = s[1:]
    elif sid == std.EID_MSMT_RPT_LOC_CIVIC_SUBELEMENT_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# MSMT Request subelements for Type Location Id Report Std Table 8-98
def _iesubelmsmtrptlocid_(s,sid):
    """ :returns: parsed subelement of type location civic in msmt request """
    ret = s
    if sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_ID_ORIGIN:
        ret = {'originator':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_ID_TARGET:
        ret = {'target':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EID_MSMT_REQ_SUBELEMENT_LOC_ID_VEND:
        ret = _parseie_(std.EID_VEND_SPEC,s)
    return ret

# EVENT REQUEST sublements for Type transition Std 8.4.2.69.2
def _iesubelevreqtransistion_(s,sid):
    """ :returns: parsed subelements of type transistion in event request """
    ret = s
    if sid == std.EVENT_REQUEST_TYPE_TRANSITION_TARGET:
        ret = {'tgt-bssid':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EVENT_REQUEST_TYPE_TRANSITION_SOURCE:
        ret = {'src-bssid':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EVENT_REQUEST_TYPE_TRANSITION_TIME_TH:
        ret = {'trans-time-threshold':struct.unpack_from('=H',s)[0]}
    elif sid == std.EVENT_REQUEST_TYPE_TRANSITION_RESULT:
        v = struct.unpack_from('=B',s)[0]
        ret = {'match-val':_eidevreqsubelmatchval_(v)}
    elif sid == std.EVENT_REQUEST_TYPE_TRANSITION_FREQUENT:
        ft,t = struct.unpack_from('=BH',s)
        ret = {'freq-transistion-cnt-threahold':ft,'time-intv':t}
    return ret

# EVENT REQUEST match value for Type transition Std Fig 8-272
_EID_EVENT_REQ_TRANSITION_MATCH_VALUE_ = {
    'include-success':(1<<0),
    'include-failed':(1<<1)
}
_EID_EVENT_REQ_TRANSITION_MATCH_VALUE_RSRV_START_ = 2
def _eidevreqsubelmatchval_(v):
    """ :returns: parsed match value of transistion type in event request """
    mv = bits.bitmask_list(_EID_EVENT_REQ_TRANSITION_MATCH_VALUE_,v)
    mv['rsrv'] = bits.mostx(_EID_EVENT_REQ_TRANSITION_MATCH_VALUE_RSRV_START_,v)
    return mv

# EVENT REQUEST sublements for Type RSNA Std 8.4.2.69.3
def _iesubelevreqrsna_(s,sid):
    """ :returns: parsed subelements of type RSNA in event request """
    ret = s
    if sid == std.EVENT_REQUEST_TYPE_RSNA_TARGET:
        ret = {'tgt-bssid':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EVENT_REQUEST_TYPE_AUTH_TYPE:
        ret = {'auth-type':_parsesuitesel_(s)}
    elif sid == std.EVENT_REQUEST_TYPE_EAP_METHOD:
        ret = {'eap-type':struct.unpack_from('=B',s)[0]}
        if ret['eap-type'] == 254:
            # include eap vendor id
            # TODO: combine the below into a function as it appears more than
            # once in the code
            ret['eap-vend-id'] = _hwaddr_(struct.unpack_from('=3B',s,1))
            ret['eap-vend-type'] = struct.unpack_from('=I',s,4)[0]
    elif sid == std.EVENT_REQUEST_TYPE_RSNA_RESULT:
        v = struct.unpack_from('=B',s)[0]
        ret = {'match-val':_eidevreqsubelmatchval_(v)}
    return ret

# EVENT REQUEST sublements for Type Peer-to-Peer link Std 8.4.2.69.4
def _iesubelevreqp2p_(s,sid):
    """ :returns: parsed sublements of type P2P link in event request """
    ret = s
    if sid == std.EVENT_REQUEST_TYPE_P2P_PEER:
        ret = {'peer-addr':_hwaddr_(struct.unpack_from('=6B',s))}
    elif sid == std.EVENT_REQUEST_TYPE_P2P_CH_NUM:
        # TODO: make this a single function -> it appears multiple times
        o,c = struct.unpack_from('=2B',s)
        ret = {'op-class':o,'ch-num':c}
    return ret

# EVENT REQUEST sublements for Type Vend Std 8.4.2.69.5
def _iesubelevreqvend_(s,sid):
    """ :returns: parsed sublements of type vend in event request """
    ret = s
    if sid == std.EID_VEND_SPEC: ret = {'vend':_parseie_(std.EID_VEND_SPEC,s)}
    return ret

# SUPPORTED RATES/EXTENDED RATES Std 8.4.2.3 and 8.4.2.15
# Std 6.5.5.2 table of rates not contained in the BSSBasicRateSet
# Reading 8.4.2.3 directs to the table in 6.5.5.2 which (see below) relates
# the number in bits 0-6 to 0.5 * times that number which is the same thing
# that happens if MSB is set to 1 ????
_RATE_DIVIDER_ = 7
def _eidrates_(val): return bits.leastx(_RATE_DIVIDER_,val) * 0.5

# ERP Parameters
# Std 8.4.2.14
# NonERP_Present|Use_Protection|Barker_Preamble|Reserved
#             B0|            B1|             B2|  B3-B5
_EID_ERPPRM_ = {'non-erp':(1<<0),'use-protect':(1<<1),'barker':(1<<2)}
_EID_ERPPRM_RSRV_START_ = 3
def _eiderp_(v):
    """parse ERP Parameters """
    ee = bits.bitmask_list(_EID_ERPPRM_,v)
    ee['rsrv'] = bits.mostx(_EID_ERPPRM_RSRV_START_,v)
    return ee

# constants for Secondary Channel Offset Field Std Table 8-57
_EID_SEC_CH_OFFSET_SCN_ = 0
_EID_SEC_CH_OFFSET_SCA_ = 1
_EID_SEC_CH_OFFSET_SCB_ = 3
# NOTE: 2, & 4-255 are reserved
def _edisecchoffset_(v):
    """ :returns: human readable secondary channel offset value """
    if v == _EID_SEC_CH_OFFSET_SCN_: return 'scn'
    elif v == _EID_SEC_CH_OFFSET_SCA_: return 'sca'
    elif v == _EID_SEC_CH_OFFSET_SCB_: return 'scb'
    else: return "rsrv-{0}".format(v)

# MSMT Report subelement Type Basic map field Std Fig. 8-143
_EID_MSMT_RPT_BASIC_MAP_ = {
    'bss':(1<<0),
    'ofdm':(1<<1),
    'unident':(1<<2),
    'radar':(1<<3),
    'unmeas':(1<<4)
}
_EID_MSMT_RPT_BASIC_MAP_RSRV_START_ = 5
def _eidmsmtrptbasicmap_(v):
    """ :returns: parsed map subfield of msmt report basic report """
    m = bits.bitmask_list(_EID_MSMT_RPT_BASIC_MAP_,v)
    m['rsrv'] = bits.mostx(_EID_MSMT_RPT_BASIC_MAP_RSRV_START_,v)
    return m

# Reporting reason subelement definitions
# STA Counters: Fig. 8-159
_EID_MSMT_RPT_REASON_STA_ = {
    'dot11Failed':(1<<0),
    'dot11FCSError':(1<<1),
    'dot11MultipleRetry':(1<<2),
    'dot11FrameDuplicate':(1<<3),
    'dot11RTSFailure':(1<<4),
    'dot11ACKFailure':(1<<5),
    'dot11Retry':(1<<6),
    'rsrv':(1<<7)
}
# QoS Counters: Fig. 8-160
_EID_MSMT_RPT_REASON_QOS_ = {
    'dot11QoSFailed':(1<<0),
    'dot11QoSRetry':(1<<1),
    'dot11QoSMultipleRetry':(1<<2),
    'dot11QoSFrameDuplicate':(1<<3),
    'dot11QoSRTSFailure':(1<<4),
    'dot11QoSACKFailure':(1<<5),
    'dot11QoSDiscarded':(1<<6),
    'rsrv':(1<<7)
}
# RSNA Counters: Fig. 8-161
_EID_MSMT_RPT_REASON_RSNA_ = {
    'dot11RSNAStatsCMACICVErrors':(1<<0),
    'dot11RSNAStatsCMACReplays':(1<<1),
    'dot11RSNAStatsRobustMgmtCCMPReplays':(1<<2),
    'dot11RSNAStatsTKIPICVErrors':(1<<3),
    'dot11RSNAStatsTKIPReplays':(1<<4),
    'dot11RSNAStatsTKIP2Replays':(1<<5), # this is in Std but not sure if it is right
    'dot11RSNAStatsCCMPReplays':(1<<6),
    'rsrv':(1<<7)
}
def _eidmsmtrptstareason_(v,g):
    """ :returns: parsed reason based on grp-id g """
    if g <= 1: return bits.bitmask_list(_EID_MSMT_RPT_REASON_STA_,v)
    elif 2 <= g <= 9: return bits.bitmask_list(_EID_MSMT_RPT_REASON_QOS_,v)
    elif g == 16: return bits.bitmask_list(_EID_MSMT_RPT_REASON_RSNA_,v)
    else: return v

# MSMT Reprot LCI format Std Fig. 8-162
# NOTE: same as DSE location fields upto and including datum We define the fields
# as a list of tuples (Name,Start Bit,Length,Num Nulls,Format)
_EID_MSMT_RPT_LCI_FIELDS_ = [
    ('lat-res',0,6,2,'=B'),
    ('lat-frac',6,25,7,'=I'),
    ('lat-int',31,9,7,'=H'),
    ('lon-res',40,6,2,'=B'),
    ('lon-frac',46,25,7,'=I'),
    ('lon-int',71,9,7,'=H'),
    ('alt-type',80,4,4,'=B'),
    ('alt-res',84,6,2,'=B'),
    ('alt-frac',90,8,0,'=B'),
    ('alt-int',98,22,10,'=I'),
    ('datum',120,3,5,'=B')
]
def _parselcirpt_(s):
    """ :returns: parsed lci location elements """
    lci = {}
    for n,i,l,x,f in _EID_MSMT_RPT_LCI_FIELDS_:
        lci[n] = struct.unpack_from(f,s[i:i+l]+'\x00'*x)
    return lci

# MSMT Report->MCast Diagn report reason field Std Fig. 8-188
_EID_MSMT_RPT_MCAST_REASON_ = {'inactivity-to-trigger':(1<<0),'msmt-rpt':(1<<1)}
_EID_MSMT_RPT_MCAST_REASON_RSRV_START_ = 2
def _eidmsmtrptmcastreason_(v):
    """ :returns: parsed mcast reason """
    r = bits.bitmask_list(_EID_MSMT_RPT_MCAST_REASON_,v)
    r['rsrv'] = bits.mostx(_EID_MSMT_RPT_MCAST_REASON_RSRV_START_,v)
    return r

# Schedule element->Schedule Info field Std Table 8-212
# Std 8.4.2.36
# Aggregation| TSID |Direction|Reserved
#          B0| B1-B4| B5,B6   |B7-B15
_EID_SCHED_ = {'aggregation':(1<<0)}
_EID_SCHED_TSID_START_ = 1
_EID_SCHED_TSID_LEN_   = 4
_EID_SCHED_DIR_START_  = 5
_EID_SCHED_DIR_LEN_    = 2
_EID_SCHED_RSRV_START_ = 7
def _eidsched_(v):
    """ :returns: parsed schedule info field of the schedule info element """
    sc = bits.bitmask_list(_EID_SCHED_,v)
    sc['tsid'] = bits.midx(_EID_SCHED_TSID_START_,_EID_SCHED_TSID_LEN_,v)
    sc['direction'] = bits.midx(_EID_SCHED_DIR_START_,_EID_SCHED_DIR_LEN_,v)
    sc['rsrv'] = bits.mostx(_EID_SCHED_RSRV_START_,v)
    return sc

# Mobility Domain element FT Capability and Policy Field Std Figure 8-233
_EID_MDE_FT_ = {'fast-bss':(1<<0),'res-req':(1<<1)}
_EID_MDE_FT_RSRV_START_ = 2
def _eidftcappol_(v):
    """ :returns parsed FT capacity and policy field """
    ft = bits.bitmask_list(_EID_MDE_FT_,v)
    ft['rsrv'] = bits.mostx(_EID_MDE_FT_RSRV_START_,v)
    return ft

# 20/40 Coexistence information field Std Figure 8-260
# Info Re1|40 Intolerant|20 Request|Exempt Request|Exempt Grant|Reserved
#       B0|           B1|        B2|            B3|          B4|B5-B7
_EID_20_40_COEXIST_ = {
    'info-req':(1<<0),
    '40-intol':(1<<1),
    '20-req':(1<<2),
    'exempt-req':(1<<3),
    'exempt-grant':(1<<4)
}
_EID_20_40_COEXIST_RSRV_START_ = 5
def _eid2040coexist_(v):
    """ :returns: parsed 20/40 coexistence Info. field """
    co = bits.bitmask_list(_EID_20_40_COEXIST_,v)
    co['rsrv'] = bits.mostx(_EID_20_40_COEXIST_RSRV_START_,v)
    return co

# TPU Buffer Status Std Figure 8-266
# AC_BK Traf|AC_BE Traf|AC_VI Traf|AC_VO_Traf|Reserved
#         B0|        B1|        B2|        B3| B4-B7
_EID_TPU_BUFF_STATUS_ = {
    'ac-bk':(1<<0),
    'ac-be':(1<<1),
    'ac-vi':(1<<2),
    'ac-vo':(1<<3)
}
_EID_TPU_BUFF_STATUS_RSRV_START_ = 4
def _eidtpubuffstat_(v):
    """ :returns: parsed TPU buffer status """
    bs = bits.bitmask_list(_EID_TPU_BUFF_STATUS_,v)
    bs['rsrv'] = bits.mostx(_EID_TPU_BUFF_STATUS_RSRV_START_,v)
    return bs

# BSS Max Idle Period -> Idle Options Std Fig 8-333
_EID_BSS_MAX_IDLE_PRO_ = 1
def _eidbssmaxidle_(v):
    """ :returns: parsed idle options field """
    return {'pro-keep-alive':bits.leastx(_EID_BSS_MAX_IDLE_PRO_,v),
            'rsrv':bits.mostx(_EID_BSS_MAX_IDLE_PRO_,v)}

# Advertisement Protocol -> Query Response Info Std Fig 8-354
EID_ADV_PROTOCOL_QRI_DIVIDER_ = 7
def _eidadvprotoqryrep_(v):
    """ :returns: parsed query response info """
    return {'qry-res-len-limit':bits.leastx(EID_ADV_PROTOCOL_QRI_DIVIDER_,v),
            'PAME-BI':bits.mostx(EID_ADV_PROTOCOL_QRI_DIVIDER_,v)}

# Mesh formation info Std Figure 8-364
# Conneected Mesh|Peerings|Connected AS
#              BO|  B1-B6 |B7
_EID_MESH_CONFIG_FORM_ = {'mesh-connect':(1<<0),'as-connect':(1<<7)}
_EID_MESH_CONFIG_FORM_NUM_START_ = 1
_EID_MESH_CONFIG_FORM_NUM_LEN_   = 6
def _eidmeshconfigform_(v):
    """ :returns: parsed mesh formation info s"""
    mf = bits.bitmask_list(_EID_MESH_CONFIG_FORM_,v)
    mf['num-peerings'] = bits.midx(_EID_MESH_CONFIG_FORM_NUM_START_,
                                   _EID_MESH_CONFIG_FORM_NUM_LEN_,v)
    return mf

# Mesh capability Std Figure 8-365
_EID_MESH_CONFIG_CAP_ = {
    'accept':(1<<0),
    'mcca-support':(1<<1),
    'mcca-enable':(1<<2),
    'forwarding':(1<<3),
    'mbca':(1<<4),
    'tbtt':(1<<5),
    'pwr-save':(1<<6),
    'rsrv':(1<<7)
}
def _eidmeshconfigcap_(v):
    """ :returns: parsed mesh capability field """
    return bits.bitmask_list(_EID_MESH_CONFIG_CAP_,v)

# Mesh Channel Switch Parameters flags field definition Std Fig 8-372
# Transmit Restrict|Initiator|Reason|Reserved
#                B0|       B!|    B2|B3-B7
_EID_MESH_CH_SWITCH_FLAGS_ = {
    'tx-restrict':(1<<0),
    'initiator':(1<<1),
    'reason':(1<<2)
}
_EID_MESH_CH_SWITCH_FLAGS_RSRV_START_ = 3
def _eidmeshchswitch_(v):
    """ :returns: parsed mesh channel switch flags field """
    cs = bits.bitmask_list(_EID_MESH_CH_SWITCH_FLAGS_,v)
    cs['rsrv'] = bits.mostx(_EID_MESH_CH_SWITCH_FLAGS_RSRV_START_,v)
    return cs

# EDCA Parameter Set -> ACI/AIFSN definition Std Fig 8-193
_EID_EDCA_ACI_ = {'acm':(1<<4),'rsrv':(1<<7)}
_EID_EDCA_ACM_START_ = 4
_EID_EDCA_ACI_START_ = 5
_EID_EDCA_ACI_LEN_   = 2
def _eidedcaaci_(v):
    """ :returns: parsed aci/aifsn field """
    aa = bits.bitmask_list(_EID_EDCA_ACI_,v)
    aa['aifsn'] = bits.leastx(_EID_EDCA_ACM_START_,v)
    aa['aci'] = bits.midx(_EID_EDCA_ACI_START_,_EID_EDCA_ACI_LEN_,2)
    return aa

# EDCA Parameter Set -> ECW Min/Max Std Fig 8-195
_EID_EDCA_ECW_SPLIT_ = 4
def _eidedcaecw_(v):
    """ :returns: parsed ECWMin/ECWMax field """
    return {'min':bits.leastx(_EID_EDCA_ECW_SPLIT_,v),
            'max':bits.mostx(_EID_EDCA_ECW_SPLIT_,v)}

# ts info of the TSPEC element Std Fig 8-197
# NOTE: ts info is a 3-octet field
_EID_TSPEC_TSINFO_ = {
    'traffic-type':(1<<0),
    'aggregation':(1<<9),
    'apsd':(1<<10),
    'schedule':(1<<16)
}
_EID_TSPEC_TSINFO_TSID_START_   =  1
_EID_TSPEC_TSINFO_TSID_LEN_     =  4
_EID_TSPEC_TSINFO_DIR_START_    =  5
_EID_TSPEC_TSINFO_DIR_LEN_      =  2
_EID_TSPEC_TSINFO_APOL_START_   =  7
_EID_TSPEC_TSINFO_APOL_LEN_     =  2
_EID_TSPEC_TSINFO_UPRI_START_   = 11
_EID_TSPEC_TSINFO_UPRI_LEN_     =  3
_EID_TSPEC_TSINFO_ACKPOL_START_ = 14
_EID_TSPEC_TSINFO_ACKPOL_LEN_   =  2
_EID_TSPEC_TSINFO_RSRV_START_   = 17
def _eidtspectsinfo_(v):
    """ :returns: parsed ts-info field """
    tsi = bits.bitmask_list(_EID_TSPEC_TSINFO_,v)
    tsi['tsid'] = bits.midx(_EID_TSPEC_TSINFO_TSID_START_,
                            _EID_TSPEC_TSINFO_TSID_LEN_,
                            v)
    tsi['dir'] = bits.midx(_EID_TSPEC_TSINFO_DIR_START_,
                           _EID_TSPEC_TSINFO_DIR_LEN_,
                           v)
    tsi['access-pol'] = bits.midx(_EID_TSPEC_TSINFO_APOL_START_,
                                  _EID_TSPEC_TSINFO_APOL_LEN_,
                                  v)
    tsi['user-pri'] = bits.midx(_EID_TSPEC_TSINFO_UPRI_START_,
                                _EID_TSPEC_TSINFO_UPRI_LEN_,
                                v)
    tsi['ack-pol'] = bits.midx(_EID_TSPEC_TSINFO_ACKPOL_START_,
                               _EID_TSPEC_TSINFO_ACKPOL_LEN_,
                               v)
    tsi['rsrv'] = bits.mostx(_EID_TSPEC_TSINFO_RSRV_START_,v)
    return tsi

# DES Registered location element subfields Std Fig 8-244
# unlike others, DSE is not a byte oriented field. We define the fields as
# a list of tuples (Name,Start Bit,Length,Num Nulls,Format)
# NOTE: while we could treat datum,reg-loc-agree,reg-loc-dse,depend-sta &
# reserved sa single 1-byte field, we decided to leave in the same format
_EID_DSE_FIELDS_ = [
    ('lat-res',0,6,2,'=B'),
    ('lat-frac',6,25,7,'=I'),
    ('lat-int',31,9,7,'=H'),
    ('lon-res',40,6,2,'=B'),
    ('lon-frac',46,25,7,'=I'),
    ('lon-int',71,9,7,'=H'),
    ('alt-type',80,4,4,'=B'),
    ('alt-res',84,6,2,'=B'),
    ('alt-frac',90,8,0,'=B'),
    ('alt-int',98,22,10,'=I'),
    ('datum',120,3,5,'=B'),
    ('reg-loc-agree',123,1,7,'=B'),
    ('reg-loc-dse',124,1,7,'=B'),
    ('depend-sta',125,1,7,'=B'),
    ('rsrv',126,2,6,'=B')
]
def _parseinfoeldse_(s):
    """ :returns: parsed dse location from packed string s """
    dse = {}
    for n,i,l,x,f in _EID_DSE_FIELDS_:
        dse[n] = struct.unpack_from(f,s[i:i+l]+'\x00'*x)

    # last three fields are byte centric
    dei,op,chn = struct.unpack_from('=H2B',s,len(s)-4)
    dse['depend-enable-id'] = dei
    dse['op-class'] = op
    dse['ch-num'] = chn
    return dse

# HT Capabilities Info field Std Fig 8-249
# octest are defined as 1|1|2|1|1|1|1|2|1|1|1|1|1|1 see Fig 8-249 for names
# See also Std Table 8-124 for definition of sub fields
_EID_HT_CAP_HTI_ = {
    'ldpc-cap':(1<<0),
    'ch-width-set':(1<<1),
    'ht-greenfield':(1<<4),
    'short-gi-20':(1<<5),
    'short-gi-40':(1<<6),
    'tx-stbc':(1<<7),
    'ht-delay-back':(1<<10),
    'max-amsdu':(1<<11),
    'dsss-cck-mod':(1<<12),
    'rsrv':(1<<13),
    '40-intolerant':(1<<14),
    'lsig-txop-pro':(1<<15)
}
_EID_HT_CAP_HTI_SM_PWR_START_  = 2
_EID_HT_CAP_HTI_SM_PWR_LEN_    = 2
_EID_HT_CAP_HTI_RX_STBC_START_ = 8
_EID_HT_CAP_HTI_RX_STBC_LEN_   = 2
def _eidhtcaphti_(v):
    """ :returns: parse ht capabilities info field """
    hti = bits.bitmask_list(_EID_HT_CAP_HTI_,v)
    hti['sm-pwr-save'] = bits.midx(_EID_HT_CAP_HTI_SM_PWR_START_,
                                   _EID_HT_CAP_HTI_SM_PWR_LEN_,
                                   v)
    hti['rx-stbc'] = bits.midx(_EID_HT_CAP_HTI_RX_STBC_START_,
                               _EID_HT_CAP_HTI_RX_STBC_LEN_,
                               v)
    return hti

# A-MPDU Parameters field Std Fig 8-250
# Max Length|Min Start Spacing|Reserved
#      BO-B1|            B2-B4|   B5-B7
_EID_HT_CAP_AMPDU_MIN_START_  = 2
_EID_HT_CAP_AMPDU_MIN_LEN_    = 3
_EID_HT_CAP_AMPDU_RSRV_START_ = 5
def _eidhtcapampdu_(v):
    """ :returns: parsed ampdu parameters field """
    return {'max-length':bits.leastx(_EID_HT_CAP_AMPDU_MIN_START_,v),
            'min-spacing':bits.midx(_EID_HT_CAP_AMPDU_MIN_START_,
                                    _EID_HT_CAP_AMPDU_MIN_LEN_,
                                    v),
            'rsrv':bits.mostx(_EID_HT_CAP_AMPDU_RSRV_START_,v)}

# HT Extended Capabilities Field Std Fig 8-252
# PCO|PCO Transit|Reserved|MCS Feedback|+HTC Supp|RD Resond|Reseved
#  B0|      B1-B2|   B3-B7|       B8-B9|      B10|      B11|B12-B15
_EID_HT_CAP_HTE_ = {'pco':(1<<0),'+htc':(1<<10),'rd-resp':(1<<11)}
_EID_HT_CAP_PCO_START_   =  1
_EID_HT_CAP_PCO_LEN_     =  2
_EID_HT_CAP_RSRV1_START_ =  3
_EID_HT_CAP_RSRV1_LEN_   =  7
_EID_HT_CAP_MCS_START_   =  8
_EID_HT_CAP_MCS_LEN_     =  2
_EID_HT_CAP_RSRV2_START_ = 12
def _eidhtcaphte_(v):
    """ :returns parsed ht extended capabilities """
    hte = bits.bitmask_list(_EID_HT_CAP_HTE_,v)
    hte['pco-transit'] = bits.midx(_EID_HT_CAP_PCO_START_,_EID_HT_CAP_PCO_LEN_,v)
    hte['rsrv-1'] = bits.midx(_EID_HT_CAP_RSRV1_START_,_EID_HT_CAP_RSRV1_LEN_,v)
    hte['mcs-feedback'] = bits.midx(_EID_HT_CAP_MCS_START_,_EID_HT_CAP_MCS_LEN_,v)
    hte['rsrv-2'] = bits.mostx(_EID_HT_CAP_RSRV2_START_,v)
    return hte

# Transmit Beamforming Capabilities Std Fig 8-253
_EID_HT_CAP_TX_BF_ = {
    'rx-cap':(1<<0),        # implicit tx beamforming receiving capable
    'rx-stag-sound':(1<<1), # rx staggered sounding capable
    'tx-stag-sound':(1<<2), # tx staggered sounding capable
    'rx-ndp':(1<<3),        # rx ndp capable
    'tx-ndp':(1<<4),        # tx ndp capable
    'tx-bf-cap':(1<<5),     # implicit tx beamforming capable
    'csi-tx':(1<<8),        # explicit tx beamforming capable
    'noncompressed':(1<<9), # non-compressed steering capable
    'compressed':(1<<10)    # compressed steering capable
}
_EID_HT_CAP_SUB_LEN_ = 2 # all but reserved are of len 2
_EID_HT_CAP_TX_BF_CALIB_START_       =  6
_EID_HT_CAP_TX_BF_CSI_FEED_START_    = 11
_EID_HT_CAP_TX_BF_NONCOMP_START_     = 13
_EID_HT_CAP_TX_BF_COMP_START_        = 15
_EID_HT_CAP_TX_BF_MIN_GRP_START_     = 17
_EID_HT_CAP_TX_BF_CSI_ANT_START_     = 19
_EID_HT_CAP_TX_BF_NONCOMP_ANT_START_ = 21
_EID_HT_CAP_TX_BF_COMP_ANT_START_    = 23
_EID_HT_CAP_TX_BF_CSI_MAX_NUM_START_ = 25
_EID_HT_CAP_TX_BF_CH_EST_CAP_START_  = 27
_EID_HT_CAP_TX_BF_RSRV_START_        = 29
def _eidhtcaptxbf_(v):
    """ :returns: parsed tx beamforming capabilities field """
    txbf = bits.bitmask_list(_EID_HT_CAP_TX_BF_,v)
    txbf['calibration'] = bits.midx(_EID_HT_CAP_TX_BF_CALIB_START_,
                                    _EID_HT_CAP_SUB_LEN_,
                                    v)
    txbf['tx-csi-feedback'] = bits.midx(_EID_HT_CAP_TX_BF_CSI_FEED_START_,
                                        _EID_HT_CAP_SUB_LEN_,
                                        v)
    txbf['noncompressed-feedback'] = bits.midx(_EID_HT_CAP_TX_BF_NONCOMP_START_,
                                               _EID_HT_CAP_SUB_LEN_,
                                                v)
    txbf['compressed-feedback'] = bits.midx(_EID_HT_CAP_TX_BF_COMP_START_,
                                            _EID_HT_CAP_SUB_LEN_,
                                            v)
    txbf['min-grouping'] = bits.midx(_EID_HT_CAP_TX_BF_MIN_GRP_START_,
                                     _EID_HT_CAP_SUB_LEN_,
                                     v)
    txbf['csi-antenna'] = bits.midx(_EID_HT_CAP_TX_BF_CSI_ANT_START_,
                                     _EID_HT_CAP_SUB_LEN_,
                                     v)
    txbf['noncomp-antenna'] = bits.midx(_EID_HT_CAP_TX_BF_NONCOMP_ANT_START_,
                                        _EID_HT_CAP_SUB_LEN_,
                                        v)
    txbf['comp-antenna'] = bits.midx(_EID_HT_CAP_TX_BF_COMP_ANT_START_,
                                     _EID_HT_CAP_SUB_LEN_,
                                     v)
    txbf['csi-max-rows'] = bits.midx(_EID_HT_CAP_TX_BF_CSI_MAX_NUM_START_,
                                      _EID_HT_CAP_SUB_LEN_,
                                      v)
    txbf['ch-est-cap'] = bits.midx(_EID_HT_CAP_TX_BF_CH_EST_CAP_START_,
                                   _EID_HT_CAP_SUB_LEN_,
                                   v)
    txbf['rsrv'] = bits.mostx(_EID_HT_CAP_TX_BF_RSRV_START_,v)
    return txbf

# Transmit Beamforming Capabilities Std Fig 8-254
_EID_HT_CAP_ASEL_ = {
    'ant-sel':(1<<0),       # antenna selection capable
    'csi-asel-cap':(1<<1),  # explicit cs feedback based tx ASEL capable
    'ant-asel-cap':(1<<2),  # antenna indices feedback based tx ASEL capable
    'csi-cap':(1<<3),       # explicit csi feedback capable
    'ant-cap':(1<<4),       # antenna indices feedback capable
    'recv-asel-cap':(1<<5), # receive ASEL capable
    'tx-ppdu-cap':(1<<6),   # tx sounding PPDUs capable
    'rsrv':(1<<7)
}
def _eidhtcapasel_(v):
    """ :returns: parsed ASEL capability field """
    return bits.bitmask_list(_EID_HT_CAP_ASEL_,v)

# QoS Capability Std 8.4.1.17
# two meanings dependent on if AP transmitted frame or non-Ap transmitted frame
# Sent by AP Std Fig 8-51
_EID_QOS_CAP_AP_ = {'q-ack':(1<<4),'q-req':(1<<5),'txop-req':(1<<6),'rsrv':(1<<7)}
_EID_QOS_CAP_AP_DIVIDER_ = 4
# Sent by non-AP
_EID_QOS_CAP_NON_AP_ = {
    'ac-vo':(1<<0),
    'ac-vi':(1<<1),
    'ac-bk':(1<<2),
    'ac-be':(1<<3),
    'q-ack':(1<<4),
    'more-data':(1<<7)
}
_EID_QOS_CAP_NON_AP_MAX_SP_START_ = 5
_EID_QOS_CAP_NON_AP_MAX_SP_LEN_   = 2
def _eidqoscap_(v,ap=True):
    """ :returns: parsed qos capability info field based on traffic is from ap """
    if ap:
        qc = bits.bitmask_list(_EID_QOS_CAP_AP_,v)
        qc['edca-update-cnt'] = bits.leastx(_EID_QOS_CAP_AP_DIVIDER_,v)
    else:
        qc = bits.bitmask_list(_EID_QOS_CAP_NON_AP_,v)
        qc['max-sp-len'] = bits.midx(_EID_QOS_CAP_NON_AP_MAX_SP_START_,
                                     _EID_QOS_CAP_NON_AP_MAX_SP_LEN_,
                                     v)
    return qc

# Extended capabilities bitmask field Std Table 8-103
_EID_EXT_CAP_ = {
    '20/40':(1<<0),
    'rsrv-1':(1<<1),
    'ext-ch-switch':(1<<2),
    'rsrv-2':(1<<3),
    'psmp-cap':(1<<4),
    'rsrv-3':(1<<5),
    's-psmp-support':(1<<6),
    'event:':(1<<7),
    'diag':(1<<8),
    'mcast-diag':(1<<9),
    'loc-tracking':(1<<10),
    'fms':(1<<11),
    'proxy-arp-ser':(1<<12),
    'collocated-interference-rpt':(1<<13),
    'civic-loc':(1<<14),
    'geo-loc':(1<<15),
    'tfs':(1<<16),
    'wnm-sleep-mode':(1<<17),
    'tim-bcast':(1<<18),
    'bss-transistion':(1<<19),
    'qos-traff-cap':(1<<20),
    'ac-sta-cnt':(1<<21),
    'mult-bssid':(1<<22),
    'timing-msmt':(1<<23),
    'ch-usage':(1<<24),
    'ssid-list':(1<<25),
    'dms':(1<<26),
    'utc-tsf-offset':(1<<27),
    'tdls-peer-uapsd':(1<<28),
    'tdls-peer-psm':(1<<29),
    'tdls-ch-switch':(1<<30),
    'interworking':(1<<31),
    'qos-map':(1<<32),
    'ebr':(1<<33),
    'sspn-interface':(1<<34),
    'rsrv-4':(1<<35),
    'msgcf-cap':(1<<36),
    'tdls-spt':(1<<37),
    'tdls-prohibited':(1<<38),
    'tdls-ch-switch-prohibited':(1<<39),
    'reject-unadmitted':(1<<40),
    'id-loc':(1<<44),
    'uapsd-coexist':(1<<45),
    'wnm-notify':(1<<46),
    'rsrv-5':(1<<47),
    'utf8-ssid':(1<<49)
}
_EID_EXT_CAP_SIG_START_ = 41
_EID_EXT_CAP_SIG_LEN_   =  2
def _eidextcap_(v):
    """ :returns: parsed extended capabilities field """
    ec = bits.bitmask_list(_EID_EXT_CAP_,v)
    ec['ser-intv-granularity'] = bits.midx(_EID_EXT_CAP_SIG_START_,
                                           _EID_EXT_CAP_SIG_LEN_,
                                           v)
    return ec

# Measurement Request Mode of the Measurement request element Std Fig 8-105
_EID_MSMT_REQ_MODE_ = {
    'parallel':(1<<0),
    'enable':(1<<1),
    'request':(1<<2),
    'report':(1<<3),
    'dur-mandatory':(1<<4)
}
_EID_MSMT_REQ_MODE_RSRV_START_ = 5
def _eidmsmtreqmode_(v):
    """ :returns: parsed msmt request mode field """
    rm = bits.bitmask_list(_EID_MSMT_REQ_MODE_,v)
    rm['rsrv'] = bits.mostx(_EID_MSMT_REQ_MODE_RSRV_START_,v)
    return rm

# Suite selector Std Figure 8-187, Table 8-99
def _parsesuitesel_(s):
    """ :returns: parse suite selector from packed string s """
    vs = struct.unpack_from('=4B',s)
    return {'oui':_hwaddr_(vs[0:3]).replace(':','-'),'suite-type':vs[-1]}

# RSN capabilities of the RSNE Std Fig 8-188
_EID_RSNE_CAP_ = {
    'preauth':(1<<0),
    'no-pairwise':(1<<1),
    'mfpr':(1<<6),
    'mfpc':(1<<7),
    'rsrv-1':(1<<8),
    'peerkey-enabled':(1<<9),
    'spp-amsdu-cap':(1<<10),
    'spp-amsdu-req':(1<<11),
    'pbac':(1<<12),
    'ext-key-id':(1<<13)
}
_EID_RSNE_CAP_PTKSA_START_ =  2
_EID_RSNE_CAP_PTKSA_LEN_   =  2
_EID_RSNE_CAP_GTKSA_START_ =  4
_EID_RSNE_CAP_GTKSA_LEN_   =  2
_EID_RSNE_CAP_RSRV2_START_ = 14
def _eidrsnecap_(v):
    """ :returns: parsed rsn capabilities field """
    rc = bits.bitmask_list(_EID_RSNE_CAP_,v)
    rc['ptksa-replay-cntr'] = bits.midx(_EID_RSNE_CAP_PTKSA_START_,
                                        _EID_RSNE_CAP_PTKSA_LEN_,
                                        v)
    rc['gtksa-replay-cntr'] = bits.midx(_EID_RSNE_CAP_GTKSA_START_,
                                        _EID_RSNE_CAP_GTKSA_LEN_,
                                        v)
    rc['rsrv-2'] = bits.mostx(_EID_RSNE_CAP_RSRV2_START_,v)
    return rc

# Mesaurment Report Mode of the Measurement report element Std Fig 8-141
_EID_MSMT_RPT_MODE_ = {'late':(1<<0),'incapable':(1<<1),'refused':(1<<2)}
_EID_MSMT_RPT_MODE_RSRV_START_ = 3
def _eidmstrptmode_(v):
    """ :returns: parsed msmt rpt mode """
    rm = bits.bitmask_list(_EID_MSMT_RPT_MODE_,v)
    rm['rsrv'] = bits.mostx(_EID_MSMT_RPT_MODE_RSRV_START_,v)
    return rm

# Channel Map Std Fig 8-143 (Used by multiple info elements)
_EID_MULT_CH_MAP_ = {
    'bss':(1<<0),
    'ofdm-pre':(1<<1),
    'unidentified':(1<<2),
    'radar':(1<<3),
    'unmeasured':(1<<4)
}
_EID_MULT_CH_MAP_RSRV_START_ = 5
def _eidmultchmap_(v):
    """ :returns: parsed channel map """
    cm = bits.bitmask_list(_EID_MULT_CH_MAP_,v)
    cm['rsrv'] = bits.mostx(_EID_MULT_CH_MAP_RSRV_START_,v)

# Neighbor Report BSSID Info subfield Std Fig 8-216
# AP Reachability|Security|Key Scope|Capabilities|Mobility Dom| HT|Reserved
#           BO-B1|      B2|       B3|       B4-B9|         B10|B11|B12-B31
# where capabilties is defined as Std Fig 8-127
# Spec MGMT|QoS|APSD|RDO MSMT|DEL Block ACK|Immediate Block Ack
#         1|  2|   3|       4|            5|                  6
_EID_NEIGHBOR_REPORT_BSSID_INFO_ = {
    'security':(1<<2),
    'key-scope':(1<<3),
    'spec-mgmt':(1<<4),
    'qos':(1<<5),
    'apsd':(1<<6),
    'rdo-msmt':(1<<7),
    'del-back':(1<<8),
    'imm-back':(1<<9),
    'mob-dom':(1<<10),
    'ht':(1<<11)
}
_EID_NEIGHBOR_REPORT_BSSID_INFO_REACH_DIVIDER_    =  2
_EID_NEIGHBOR_REPORT_BSSID_INFO_CAPS_START_       =  4
_EID_NEIGHBOR_REPORT_BSSID_INFO_CAPS_LEN_         =  6
_EID_NEIGHBOR_REPORT_BSSID_INFO_RSRV_START_       = 12
def _eidneighrptinfo_(v):
    """ :returns: parsed bssid info subelement """
    bi = bits.bitmask_list(_EID_NEIGHBOR_REPORT_BSSID_INFO_,v)
    bi['ap-reach'] = bits.leastx(_EID_NEIGHBOR_REPORT_BSSID_INFO_REACH_DIVIDER_,v)
    bi['rsrv'] = bits.mostx(_EID_NEIGHBOR_REPORT_BSSID_INFO_RSRV_START_,v)
    return bi

# HT OP element HT OP Info subelement Std Fig 8-256
# This is a 5 octet subelement that we break down into 1,2,2 octets
# HT OP Info One: 1 octet
# Secondary Channel offset|Sta Ch Width|RIFS Mode|Reserved
#                    B0-B1|          B2|       B3|   B4-B7
_EID_HT_OP_HT_OP1_ = {'sta-ch-width':(1<<2),'rifs':(1<<3)}
_EID_HT_OP_HT_OP1_DIVIDER_    = 2
_EID_HT_OP_HT_OP1_RSRV_START_ = 4
# HT OP Info Two: 2 octets
# HT Protection|Nongreendfield Present|Reserved|OBSS Non-Ht Present|Reserved
#         B8-B9|                   B10|     B11|                B12|B13-B23
#       <B0-B1>|                  <B2>|    <B3>|               <B4>|<B5>-<B15>
_EID_HT_OP_HT_OP2_ = {'non-greenfield':(1<<2),'rsrv-2':(1<<3),'obss-non-ht':(1<<4)}
_EID_HT_OP_HT_OP2_DIVIDER_    = 2
_EID_HT_OP_HT_OP2_RSRV_START_ = 5
# HT OP Info Three: 2 octets
# Reserved|Dual Beacon|Dual CTS|STBC Beacon|L-SIX TXOP|PCO Active|PCO Phase|Reserved
#  B24-B29|        B30|     B31|        B32|       B33|       B34|      B35|B36-B39
#  <B0-B5>|       <B6>|    <B7>|       <B8>|      <B9>|     <B10>|    <B11>|<B12>-<B15>
_EID_HT_OP_HT_OP3_ = {
    'dual-beacon':(1<<6),
    'dual-cts':(1<<7),
    'stbc-beacon':(1<<8),
    'lsig-txop-pro':(1<<9),
    'pco-active':(1<<10),
    'pco-phase':(1<<11)
}
_EID_HT_OP_HT_OP3_DIVIDER_    =  6
_EID_HT_OP_HT_OP3_RSRV_START_ = 12
def _eidhtopinfo_(h1,h2,h3):
    """ :returns: parsed HT OP Info subelement"""
    htop = {}
    ht1 = bits.bitmask_list(_EID_HT_OP_HT_OP1_,h1)
    ht1['sec-ch-off'] = bits.leastx(_EID_HT_OP_HT_OP1_DIVIDER_,h1)
    ht1['rsrv-1'] = bits.mostx(_EID_HT_OP_HT_OP1_RSRV_START_,h1)
    ht2 = bits.bitmask_list(_EID_HT_OP_HT_OP2_,h2)
    ht2['ht-pro'] = bits.leastx(_EID_HT_OP_HT_OP2_DIVIDER_,h2)
    ht2['rsrv-3'] = bits.mostx(_EID_HT_OP_HT_OP2_RSRV_START_,h2)
    ht3 = bits.bitmask_list(_EID_HT_OP_HT_OP3_,h3)
    ht3['rsrv-4'] = bits.leastx(_EID_HT_OP_HT_OP3_DIVIDER_,h3)
    ht3['rsrv-5'] = bits.mostx(_EID_HT_OP_HT_OP3_RSRV_START_,h3)
    for ht in ht1: htop[ht] = ht1[ht]
    for ht in ht2: htop[ht] = ht2[ht]
    for ht in ht3: htop[ht] = ht3[ht]
    return htop

# Available Admission Capacity Bitmask Std Table 8-118
_EID_BSS_AVAIL_CAP_ = 12
def _edibssavailadmin_(v):
    bm = [0] * _EID_BSS_AVAIL_CAP_
    for i in xrange(_EID_BSS_AVAIL_CAP_):
        if (1<<i) & v: bm[i] = 1
    return {'reported':bm,'rsrv':bits.mostx(_EID_BSS_AVAIL_CAP_,v)}

# RM Enabled Capabilities Std Table 8-119
_EID_RM_ENABLED_ = [{
    'link-msmt':(1<<0),
    'neighbor-rpt':(1<<1),
    'parallel-msmt':(1<<2),
    'repeated-msmt':(1<<3),
    'beacon-pass-msmt':(1<<4),
    'beacon-act-msmt':(1<<5),
    'beacon-tab-msmt':(1<<6),
    'beacon-msmt':(1<<7)
},{
    'frame-msmt':(1<<0),
    'ch-load-msmt':(1<<1),
    'noise-hist-msmt':(1<<2),
    'stat-msmt':(1<<3),
    'lci-msmt':(1<<4),
    'lci-azimuth':(1<<5),
    'tx-stream-cat-msmt':(1<<6),
    'triggered-tx-stream-cat':(1<<7)
},{
    'ap-ch-rpt':(1<<0),
    'rm-mib':(1<<1)
},{
    'msmt-pilot-tx':(1<<3),
    'neighbor-rpt-tsf-offset':(1<<4),
    'rcpi-msmt':(1<<5),
    'rsni-msmt':(1<<6),
    'bss-avg-access-delay':(1<<7)
},{
    'bss-avail-admission':(1<<0),
    'ant-cap':(1<<1)
}]
# 3rd octet
_EID_BSS_AVAIL_CAP_OP_CHAN_START_    = 3
_EID_BSS_AVAIL_CAP_OP_CHAN_LEN_      = 2
_EID_BSS_AVAIL_CAP_NONOP_CHAN_START_ = 5
# 4th octet
_EID_BSS_AVAIL_CAP_MSMT_PILOT_DIVIDER_ = 3
# 5th octet
_EID_BSS_AVAIL_CAP_RSRV_START_ = 2
def _eidrmenable_(vs):
    """ :returns: parsed RM enabled capabilities definitions """
    rme = {}
    for i in xrange(vs):
        temp = bits.bitmask_list(_EID_RM_ENABLED_[i],vs[i])
        for t in temp: rme[t] = temp[t]
    rme['op-ch-max-msmt'] = bits.midx(_EID_BSS_AVAIL_CAP_OP_CHAN_START_,
                                      _EID_BSS_AVAIL_CAP_OP_CHAN_LEN_,
                                      vs[2])
    rme['non-op-ch-max-msmt'] = bits.mostx(_EID_BSS_AVAIL_CAP_NONOP_CHAN_START_,vs[2])
    rme['msmt-pilot'] = bits.leastx(_EID_BSS_AVAIL_CAP_MSMT_PILOT_DIVIDER_,vs[3])
    rme['rsrv'] = bits.mostx(_EID_BSS_AVAIL_CAP_RSRV_START_,vs[4])
    return rme

# QoS Traffic Capability Bitmask Std Table 8-161
_EID_QOS_TRAFFIC_CAP_ = {'ac-vo':(1<<0),'ac-vi':(1<<1),'rsrv-1':(1<<2),
                         'rsrv-2':(1<<3),'up4':(1<<4),'up5':(1<<5),
                         'up6':(1<<6),'rsrv-3':(1<<7)}
def _eidqostrafficcap_(v):
    """ :returns: parsed qos traffic capability bitmask """
    return bits.bitmask_list(_EID_QOS_TRAFFIC_CAP_,v)

# Access Network Options subfield of nterworking Std Fig 8-352
_EID_INTERWORKING_ANO_ = {'internet':(1<<4),'asra':(1<<5),'esr':(1<<6),'uesa':(1<<7)}
_EID_INTERWORKING_ANO_ANT_DIVIDER_ = 4
def _eidinterworkingano_(v):
    """ :returns: parsed access network options """
    ano = bits.bitmask_list(_EID_INTERWORKING_ANO_,v)
    ano['access-net-type'] = bits.leastx(_EID_INTERWORKING_ANO_ANT_DIVIDER_,v)
    return ano

# Std Fig 8-375 Report Control subfield of Beacon Timing element
_EID_BEACON_TIMING_RPT_EL_NUM_START_ = 4
_EID_BEACON_TIMING_RPT_EL_NUM_LEN_   = 3
_EID_BEACON_TIMING_RPT_MORE_START_   = 7
def _eidbeacontimingrpt_(v):
    """ :returns: parsed beacon timing report control field"""
    rpt = {}
    rpt['stat-num'] = bits.leastx(_EID_BEACON_TIMING_RPT_EL_NUM_START_,v)
    rpt['el-num'] = bits.midx(_EID_BEACON_TIMING_RPT_EL_NUM_START_,
                              _EID_BEACON_TIMING_RPT_EL_NUM_LEN_,
                              v)
    rpt['more'] = bits.mostx(_EID_BEACON_TIMING_RPT_MORE_START_,v)

# Std Fig 8-378 MCCAOP Reservation field
def _parsemccaopresfield_(v):
    """ :returns: parsed mccaop reservation field """
    # MCCAOP Reservation field is a 5-octet subfiled further broken into 1, 1, 3
    # MCCAOP Dur|MCCAOP Period|MCCAOP Offset|
    #          1|            1|            3|
    # to get the 3-byte mccaop offset, we add 1 null byte to the end of of v,
    # (end of offset subfield) and unpack using the 4 byte unsigned int
    dur,per,off = struct.unpack('=2BI',v+'\x00')
    return {'duration':dur,'period':per,'offset': off}

# Std Fig 8-383 MCCAOP Advertisement Element Information Field
_EID_MCCAOP_ADV_INFO_ = {'tx-rx':(1<<4),'bcast':(1<<5),
                         'interference':(1<<6),'rsrv':(1<<7)}
_EID_MCCAOP_ADV_INFO_IDX_DIVIDER_ = 4
def _eidmccaopadvinfo_(v):
    """ :returns: parsed advertisement element information """
    adv = bits.bitmask_list(_EID_MCCAOP_ADV_INFO_,v)
    adv['adv-idx'] = bits.leastx(_EID_MCCAOP_ADV_INFO_IDX_DIVIDER_,v)
    return adv

# Std Fig 8-390 flags field of the PREQ element
_EID_PREQ_FLAGS_ = {'gate-annouce':(1<<0),'address-mode':(1<<1),
                    'proactive-preo':(1<<2),'ae':(1<<6),'rsrv-2':(1<<7)}
_EID_PREQ_FLAGS_RSRV1_START_ = 3
_EID_PREQ_FLAGS_RSRV1_LEN_   = 3
def _eidpreqflags_(v):
    """ :returns: parsed flags field of PREQ element """
    fs = bits.bitmask_list(_EID_PREQ_FLAGS_,v)
    fs['rsrv-1'] = bits.midx(_EID_PREQ_FLAGS_RSRV1_START_,
                             _EID_PREQ_FLAGS_RSRV1_LEN_,
                             v)
    return fs

# Std Fig 8-391 per target flags field of the PREQ element
_EID_PREQ_TGT_FLAGS_ = {'to':(1<<0),'rsrv-1':(1<<1),'usn':(1<<2)}
_EID_PREQ_TGT_FLAGS_RSRV2_START_ = 3
def _eidpreqtgtflags_(v):
    """ :returns: parsed target flags of the PREQ element """
    tf = bits.bitmask_list(_EID_PREQ_TGT_FLAGS_,v)
    tf['rsrv-2'] = bits.mostx(_EID_PREQ_TGT_FLAGS_RSRV2_START_,v)
    return tf

# Std Fig 8-393 flags field of the PREP element
_EID_PREP_FLAGS_ = {'ae':(1<<6),'rsrv-2':(1<<7)}
_EID_PREP_FLAGS_RSRV1_DIVIDER_ = 6
def _eidprepflags_(v):
    """ :returns: parsed flags of the PREP element """
    fs = bits.bitmask_list(_EID_PREP_FLAGS_,v)
    fs['rsrv-1'] = bits.leastx(_EID_PREP_FLAGS_RSRV1_DIVIDER_,v)
    return fs

# Std Fig 8-395 flags field of the PERR element
_EID_PERR_FLAGS_ = {'ae':(1<<6)}
_EID_PERR_FLAGS_DIVIDER1_ = 6
_EID_PERR_FLAGS_DIVIDER2_ = 7
def _eidperrflags_(v):
    """ :returns: parsed flags of the PERR element """
    fs = bits.bitmask_list(_EID_PERR_FLAGS_,v)
    fs['rsrv-1'] = bits.leastx(_EID_PERR_FLAGS_DIVIDER1_,v)
    fs['rsrv-2'] = bits.mostx(_EID_PERR_FLAGS_DIVIDER2_,v)
    return fs

# Std Fig 8-398 Flags subfield of a PXU Proxy Information field
_EID_PXU_INFO_FLAGS_ = {'del':(1<<0),'org-is-proxy':(1<<1),'lifetime':(1<<2)}
_EID_PXU_INFO_FLAGS_DIVIDER_ = 3
def _eidpxuinfoflags_(v):
    """ :returns: parsed flags field of a PXU proxy information """
    fs = bits.bitmask_list(_EID_PXU_INFO_FLAGS_,v)
    fs['rsrv'] = bits.mostx(_EID_PXU_INFO_FLAGS_DIVIDER_,v)
    return fs

# Std Fig 8-251 MCS set
# Rx MCS Bitmask|Rsrv|Rx Highest|Rsrv|Tx MCS Set|TX/RX MCS !=|TX Max|TX !=|Rsrv
#             77|   3|        10|   6|         1|           1|     2|    1|27
# |<--    8,2     -->|<--    2    -->|<--                4                 -->|
_MCS_SET_RX_MCS_BM_RSRV_START_ = 13
_MCS_SET_TX_HIGHEST_DIVIDER_ = 10
_MCS_SET_LAST_ = {
    'tx-ms-set-defined':(1<<0),
    'tx/rx-mcs-set-unequal':(1<<1),
    'tx-unequal-mod':(1<<4)
}
_MCS_SET_LAST_TX_MAX_START_ = 2
_MCS_SET_LAST_TX_MAX_LEN_   = 2
_MCS_SET_LAST_RSRV_START_   = 5
def _parsemcsset_(s):
    """ :returns: parsed mcs set """
    # mcs set is a 16 bit number. We break it down into the above 8-byte,2-byte
    # 2-byte, and 4-byte
    vs = struct.unpack('=Q2HI',s)
    # do last 4-byte first
    m = bits.bitmask_list(_MCS_SET_LAST_,vs[3])
    m['tx-max-num-spatial'] = bits.midx(_MCS_SET_LAST_TX_MAX_START_,
                                        _MCS_SET_LAST_TX_MAX_LEN_,
                                        vs[3])
    m['rsrv-3'] = bits.mostx(_MCS_SET_LAST_RSRV_START_,vs[3])

    # then middle 2-byte
    m['tx-highest-sup-data-rate'] = bits.leastx(_MCS_SET_TX_HIGHEST_DIVIDER_,vs[2])
    m['rsrv-2'] = bits.mostx(_MCS_SET_TX_HIGHEST_DIVIDER_,vs[2])

    # and first 10-byte. Note for this, we'll use a list where B_i corresponds
    # to MCS_i. Because the rx mcs bitmask is 77 bits, it is unpacked as a
    # 8-byte integer and 2-byte integer. Each of these ints is processed in
    # turn
    #m['rx-mcs-bitmask'] = [0]*_MCS_SET_RX_MCS_BM_LEN_
    #for i in xrange(struct.calcsize('=Q')):
    #    if (1<<i) & vs[0]: m['rx-mcs-bitmask'][i] = 1
    # first 64 bits from '=Q'
    m['rx-mcs-bitmask'] = [0]*64 # initial 8-bytes
    for i in xrange(len(m['rx-mcs-bitmask'])):
        if (1<<i) & vs[0]: m['rx-mcs-bitmask'][i] = 1
    # next 13 bits from '=H'
    for i in xrange(_MCS_SET_LAST_RSRV_START_):
        if (1<<i) & vs[1]: m['rx-mcs-bitmask'].append(1)
        else: m['rx-mcs-bitmask'].append(0)
    # last 3 bits are reserved
    m['rsrv-1'] = bits.mostx(_MCS_SET_RX_MCS_BM_RSRV_START_,vs[1])
    return m

# Std Table 8-132 Time Value (10-byte element H5BHB
def _parsetimeval_(s):
    """ :returns: a parsed time value from packed string s """
    tval = struct.unpack_from('=H5BHB',s)
    return {'year':tval[0],
            'month':tval[1],
            'day':tval[2],
            'hours':tval[3],
            'minutes':tval[4],
            'seconds':tval[5],
            'milliseconds':tval[6],
            'rsrv':tval[7]}

################################################################################
#### CTRL Frames Std 8.3.1
################################################################################

def _parsectrl_(f,m):
    """
     parse the control frame f into the mac dict
     :param f: frame
     :param m: mpdu dict
     NOTE: the mpdu dict is modified in place
    """
    if m.subtype == std.ST_CTRL_CTS or m.subtype == std.ST_CTRL_ACK: pass # do nothing
    elif m.subtype in [std.ST_CTRL_RTS,std.ST_CTRL_PSPOLL,std.ST_CTRL_CFEND,std.ST_CTRL_CFEND_CFACK]:
        try:
            # append addr2 and process macaddress
            v,m['offset'] = _unpack_from_(_S2F_['addr'],f,m['offset'])
            m['addr2'] = _hwaddr_(v)
            m['present'].append('addr2')
        except Exception as e:
            m['err'].append(('ctrl.{0}'.format(std.ST_CTRL_TYPES[m.subtype]),
                             "unpacking {0}".format(e)))
    elif m.subtype == std.ST_CTRL_BLOCK_ACK_REQ:
        # append addr2 & bar control
        try:
            v,m['offset'] = _unpack_from_(_S2F_['addr'],f,m['offset'])
            m['addr2'] = _hwaddr_(v)
            m['present'].append('addr2')
        except Exception as e:
            m['err'].append(('ctrl.ctrl-block-ack-req.addr2',
                             "unpacking {0}".format(e)))

        try:
            v,m['offset'] = _unpack_from_(_S2F_['barctrl'],f,m['offset'])
            m['barctrl'] = _bactrl_(v)
            m['present'].append('barctrl')
        except Exception as e:
            m['err'].append(('ctrl.ctrl-block-ack-req.barctrl',
                             "unpacking {0}".format(e)))

        # & bar info field
        try:
            if not m['barctrl']['multi-tid']:
                # for 0 0 Basic BlockAckReq and 0 1 Compressed BlockAckReq the
                # bar info field appears to be the same 8.3.1.8.2 and 8.3.1.8.3, a
                # sequence control
                if not m['barctrl']['compressed-bm']: m['barctrl']['type'] = 'basic'
                else: m['barctrl']['type'] = 'compressed'
                v,m['offset'] = _unpack_from_(_S2F_['seqctrl'],f,m['offset'])
                m['barinfo'] = _seqctrl_(v)
            else:
                if not m['barctrl']['compressed-bm']:
                    # 1 0 -> Reserved
                    m['barctrl']['type'] = 'reserved'
                    m['barinfo'] = {'unparsed':f[m['offset']:]}
                    m['offset'] += len(f[m['offset']:])
                else:
                    # 1 1 -> Multi-tid BlockAckReq Std 8.3.1.8.4 See Figures Std 8-22, 8-23
                    m['barctrl']['type'] = 'multi-tid'
                    m['barinfo'] = {'tids':[]}
                    try:
                        for i in xrange(m['barctrl']['tid-info'] + 1):
                            v,m['offset'] = _unpack_from_("HH",f,m['offset'])
                            m['barinfo']['tids'].append(_pertid_(v))
                    except Exception as e:
                        m['err'].append(('ctrl.ctrl-block-ack-req.barinfo.tids',
                                         "unpacking {0}".format(e)))
        except Exception as e:
            m['err'].append(('ctrl.ctrl-block-ack-req.barinfo',
                             "unpacking {0}".format(e)))
    elif m.subtype == std.ST_CTRL_BLOCK_ACK:
        # add addr2 & ba control
        try:
            v,m['offset'] = _unpack_from_(_S2F_['addr'],f,m['offset'])
            m['addr2'] = _hwaddr_(v)
            m['present'].append('addr2')
        except Exception as e:
            m['err'].append(('ctrl.ctrl-block-ack.addr2',
                             "unpacking {0}".format(e)))

        try:
            v,m['offset'] = _unpack_from_(_S2F_['bactrl'],f,m['offset'])
            m['bactrl'] = _bactrl_(v)
            m['present'].append('bactrl')
        except Exception as e:
            m['err'].append(('ctrl.ctrl-block-ack.bactrl',"unpacking {0}".format(e)))

        # & ba info field
        try:
            if not m['bactrl']['multi-tid']:
                v,m['offset'] = _unpack_from_(_S2F_['seqctrl'],f,m['offset'])
                m['bainfo'] = _seqctrl_(v)
                if not m['bactrl']['compressed-bm']:
                    # 0 0 -> Basic BlockAck 8.3.1.9.2
                    m['bactrl']['type'] = 'basic'
                    m['bainfo']['babitmap'] = f[m['offset']:m['offset']+128]
                    m['offset'] += 128
                else:
                    # 0 1 -> Compressed BlockAck Std 8.3.1.9.3
                    m['bactrl']['type'] = 'compressed'
                    m['bainfo']['babitmap'] = f[m['offset']:m['offset']+8]
                    m['offset'] += 8
            else:
                if not m['bactrl']['compressed-bm']:
                    # 1 0 -> Reserved
                    m['bactrl']['type'] = 'reserved'
                    m['bainfo'] = {'unparsed':f[m['offset']:]}
                else:
                    # 1 1 -> Multi-tid BlockAck Std 8.3.1.9.4 see Std Figure 8-28, 8-23
                    m['bactrl']['type'] = 'multi-tid'
                    m['bainfo'] = {'tids':[]}
                    try:
                        for i in xrange(m['bactrl']['tid-info'] + 1):
                            v,m['offset'] = _unpack_from_("HH",f,m['offset'])
                            pt = _pertid_(v)
                            pt['babitmap'] = f[m['offset']:m['offset']+8]
                            m['bainfo']['tids'].append(pt)
                            m['offset'] += 8
                    except Exception as e:
                        m['err'].append(('ctrl.ctrl-block-ack.bainfo.tids',
                                         "unpacking {0}".format(e)))
        except Exception as e:
            m['err'].append(('ctrl.ctrl-block-ack.bainfo',"unpacking {0}".format(e)))
    elif m.subtype == std.ST_CTRL_WRAPPER:
        # Std 8.3.1.10, carriedframectrl is a Frame Control
        try:
            v,m['offset'] = _unpack_from_(_S2F_['framectrl'],f,m['offset'])
            m['carriedframectrl'] = v
            m['present'].append('carriedframectrl')
        except Exception as e:
            m['err'].append(('ctrl.ctrl-wrapper.carriedframectrl',
                             "unpacking {0}".format(e)))

        # ht control
        try:
            v,m['offset'] = _unpack_from_(_S2F_['htc'],f,m['offset'])
            m['htc'] = v
            m['present'].append('htc')
        except Exception as e:
            m['err'].append(('ctrl.ctrl-wrapper.htc',"unpacking {0}".format(e)))

        # carried frame
        try:
            m['carriedframe'] = f[m['offset']:]
            m['offset'] += len(f[m['offset']:])
            m['present'].extend(['htc','carriedframe'])
        except Exception as e:
            m['err'].append(('ctrl.ctrl-wrapper.carriedframe',
                             "unpacking {0}".format(e)))
    else:
        m['err'].append(('ctrl',
                         "invalid subtype {0}".format(std.ST_CTRL_TYPES[m.subtype])))

#### Control Frame subfields

#--> Block Ack request Std 8.3.1.8
# BA and BAR Ack Policy|Multi-TID|Compressed BM|Reserved|TID_INFO
#                    B0|       B1|           B2|  B3-B11| B12-B15
# for the ba nad bar information see Std Table 8.16
_BACTRL_ = {'ackpolicy':(1<<0),'multi-tid':(1<<1),'compressed-bm':(1<<2)}
_BACTRL_RSRV_START_     =  3
_BACTRL_RSRV_LEN_       =  9
_BACTRL_TID_INFO_START_ = 12
def _bactrl_(v):
    """ parses the ba/bar control """
    bc = bits.bitmask_list(_BACTRL_,v)
    bc['rsrv'] = bits.midx(_BACTRL_RSRV_START_,_BACTRL_RSRV_LEN_,v)
    bc['tid-info'] = bits.mostx(_BACTRL_TID_INFO_START_,v)
    return bc

#--> Per TID info subfield Std Fig 8-22 and 8-23
_BACTRL_PERTID_DIVIDER_ = 12
_BACTRL_MULTITID_DIVIDER_ = 12
def _pertid_(v):
    """
     parses the per tid info and seq control
     :param v: unpacked value
     :returns: per-tid info
    """
    pti = _seqctrl_(v[1])
    pti['pertid-rsrv'] = bits.leastx(_BACTRL_PERTID_DIVIDER_,v[0])
    pti['pertid-tid'] = bits.mostx(_BACTRL_PERTID_DIVIDER_,v[0])
    return pti

################################################################################
#### DATA Frames Std 8.3.2
################################################################################

def _parsedata_(f,m):
    """
     parse the data frame f
     :param f: frame
     :param m: mpdu dict
    """
    # addr2, addr3 & seqctrl are always present in data Std Figure 8-30
    try:
        fmt = _S2F_['addr'] + _S2F_['addr'] + _S2F_['seqctrl']
        v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
        m['addr2'] = _hwaddr_(v[0:6])
        m['addr3'] = _hwaddr_(v[6:12])
        m['seqctrl'] = _seqctrl_(v[-1])
        m['present'].extend(['addr2','addr3','seqctrl'])
    except Exception as e:
        m['err'].append(('data',"unpacking addr2,addr3,seqctrl {0}".format(e)))

    # fourth address?
    if m.flags['td'] and m.flags['fd']:
        try:
            v,m['offset'] = _unpack_from_(_S2F_['addr'],f,m['offset'])
            m['addr4'] = _hwaddr_(v)
            m['present'].append('addr4')
        except Exception as e:
            m['err'].append(('data.addr4',"unpacking {0}".format(e)))

    # QoS field?
    if std.ST_DATA_QOS_DATA <= m.subtype <= std.ST_DATA_QOS_CFACK_CFPOLL:
        try:
            v,m['offset'] = _unpack_from_(_S2F_['qos'],f,m['offset'])
            m['qos'] = _qosctrl_(v)
            m['present'].append('qos')
        except Exception as e:
            m['err'].append(('data.qos',"unpacking {0}".format(e)))

        # HTC fields?
        #if mac.flags['o']:
        #    v,mac['offset'] = _unpack_from_(_S2F_['htc'],f,mac['offset'])
        #    mac['htc'] = _htctrl_(v)
        #    mac['present'].append('htc')

#### ENCRYPTION (see Chapter 11 Std)

#### WEP Std 11.2.2.2
# <MAC HDR>|IV|DATA|ICV|FCS
# bytes var| 4| >=1|  4|  4
# where the IV is defined:
# Init Vector|  Pad | Key ID
# bits     24| 6bits| 2 bits
_WEP_IV_LEN_  = 4
_WEP_ICV_LEN_ = 4
_WEP_IV_KEY_START_ = 6
def _wep_(f,m):
    """
     parse wep data from frame
     :param f: frame
     :param m: mpdu dict
    """
    try:
        keyid = struct.unpack_from('='+_S2F_['wep-keyid'],f,
                                   m['offset']+_WEP_IV_LEN_-1)[0]
        m['l3-crypt'] = {'type':'wep',
                         'iv':f[m['offset']:m['offset']+_WEP_IV_LEN_],
                         'key-id':bits.mostx(_WEP_IV_KEY_START_,keyid),
                         'icv':f[-_WEP_ICV_LEN_:]}
        m['offset'] += _WEP_IV_LEN_
        m['stripped'] += _WEP_ICV_LEN_
    except Exception as e:
        m['err'].append(('l3-crypt.wep',"parsing {0}".format(e)))

#### TKIP Std 11.4.2.1
# <MAC HDR>|IV|ExtIV|DATA|MIC|ICV|FCS
# bytes var| 4|    4| >=1|  8|  4|  4
# where the IV is defined
#   TSC1|WEPSeed|TSC0|RSRV|EXT IV|KeyID
# bits 8|      8|   8|   4|     1|    3
# and the extended iv is defined as
#   TSC2|TSC3|TSC4|TSC5
# bits 8|   8|   8|   8
_TKIP_TSC1_BYTE_      = 0
_TKIP_WEPSEED_BYTE_   = 1
_TKIP_TSC0_BYTE_      = 2
_TKIP_KEY_BYTE_       = 3
_TKIP_EXT_IV_         = 5
_TKIP_EXT_IV_LEN_     = 1
_TKIP_TSC2_BYTE_      = 4
_TKIP_TSC3_BYTE_      = 5
_TKIP_TSC4_BYTE_      = 6
_TKIP_TSC5_BYTE_      = 7
_TKIP_IV_LEN_         = 8
_TKIP_MIC_LEN_        = 8
_TKIP_ICV_LEN_        = 4
def _tkip_(f,m):
    """
     parse tkip data from frame f into mac dict
     :param f: frame
     :param m: mpdu dict
    """
    try:
        keyid = struct.unpack_from('=B',f,m['offset']+_TKIP_KEY_BYTE_)[0]
        m['l3-crypt'] = {'type':'tkip',
                         'iv':{'tsc1':f[m['offset']+_TKIP_TSC1_BYTE_],
                               'wep-seed':f[m['offset']+_TKIP_WEPSEED_BYTE_],
                               'tsc0':f[m['offset']+_TKIP_TSC0_BYTE_],
                               'key-id':{'rsrv':bits.leastx(_TKIP_EXT_IV_,keyid),
                                         'ext-iv':bits.midx(_TKIP_EXT_IV_,_TKIP_EXT_IV_LEN_,keyid),
                                         'key-id':bits.mostx(_TKIP_EXT_IV_+_TKIP_EXT_IV_LEN_,keyid)}},
                         'ext-iv':{'tsc2':f[m['offset']+_TKIP_TSC2_BYTE_],
                                   'tsc3':f[m['offset']+_TKIP_TSC3_BYTE_],
                                   'tsc4':f[m['offset']+_TKIP_TSC4_BYTE_],
                                   'tsc5':f[m['offset']+_TKIP_TSC5_BYTE_]},
                         'mic':f[-(_TKIP_MIC_LEN_ + _TKIP_ICV_LEN_):-_TKIP_ICV_LEN_],
                         'icv':f[-_TKIP_ICV_LEN_:]}
        m['offset'] += _TKIP_IV_LEN_
        m['stripped'] += _TKIP_MIC_LEN_ + _TKIP_ICV_LEN_
    except Exception as e:
        m['err'].append(('l3-crypt.tkip',"parsing {0}".format(e)))

#### CCMP Std 11.4.3.2
# <MAC HDR>|CCMP HDR|DATA|MIC|FCS
# bytes var|       8| >=1|  8|  4
# where the CCMP Header is defined
#    PN0|PN1|RSRV|RSRV|EXT IV|KeyID|PN2|PN3|PN4|PN5
# bits 8|  8|   8|   5|     1|    2|  8|  8|  8|  8
_CCMP_PN0_BYTE_   = 0
_CCMP_PN1_BYTE_   = 1
_CCMP_RSRV_BYTE_  = 2
_CCMP_KEY_BYTE_   = 3
_CCMP_EXT_IV_     = 5
_CCMP_EXT_IV_LEN_ = 1
_CCMP_PN2_BYTE_   = 4
_CCMP_PN3_BYTE_   = 5
_CCMP_PN4_BYTE_   = 6
_CCMP_PN5_BYTE_   = 7
_CCMP_IV_LEN_     = 8
_CCMP_MIC_LEN_    = 8
def _ccmp_(f,m):
    """
     parse tkip data from frame f into mac dict
     :param f: frame
     :param m: mpdu dict
    """
    try:
        keyid = struct.unpack_from('=B',f,m['offset']+_CCMP_KEY_BYTE_)[0]
        m['l3-crypt'] = {'type':'ccmp',
                       'pn0':f[m['offset']+_CCMP_PN0_BYTE_],
                       'pn1':f[m['offset']+_CCMP_PN1_BYTE_],
                       'rsrv':f[m['offset']+_CCMP_RSRV_BYTE_],
                       'key-id':{'rsrv':bits.leastx(_CCMP_EXT_IV_,keyid),
                                 'ext-iv':bits.midx(_CCMP_EXT_IV_,_CCMP_EXT_IV_LEN_,keyid),
                                 'key-id':bits.mostx(_CCMP_EXT_IV_+_CCMP_EXT_IV_LEN_,keyid)},
                       'pn2':f[m['offset']+_CCMP_PN2_BYTE_],
                       'pn3':f[m['offset']+_CCMP_PN3_BYTE_],
                       'pn4':f[m['offset']+_CCMP_PN4_BYTE_],
                       'pn5':f[m['offset']+_CCMP_PN0_BYTE_],
                       'mic':f[-_CCMP_MIC_LEN_:]}
        m['offset'] += _CCMP_IV_LEN_
        m['stripped'] += _CCMP_MIC_LEN_
    except Exception as e:
        m['err'].append(('l3-crypt.ccmp',"parsing {0}".format(e)))


#### GENERAL HELPERS

def _unpack_from_(fmt,b,o):
    """
     unpack data from the buffer b given the format specifier fmt starting at o &
     returns the unpacked data and the new offset
     :param fmt: unpack format string
     :param b: buffer
     :param o: offset to unpack from
     :returns: new offset after unpacking
    """
    vs = struct.unpack_from('='+fmt,b,o)
    if len(vs) == 1: vs = vs[0]
    return vs,o+struct.calcsize(fmt)