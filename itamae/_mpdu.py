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
__version__ = '0.0.1'
__date__ = 'September 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

import struct
from binascii import hexlify
import itamae.bits as bits
import itamae.ieee80211 as std

#### FRAME FIELDS Std 8.2.3

# FRAMECTRL|DUR/ID|ADDR1|ADDR2|ADDR3|SEQCTRL|ADDR4|QOS|HTC|BODY|FCS
# BYTES   2      2     6     6     6       2     6   2   4  var   4

# unpack formats
_S2F_ = {'framectrl':'BB',
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
         'fcs':'I'}

# Frame Control Flags Std 8.2.4.1.1
# td -> to ds fd -> from ds mf -> more fragments r  -> retry pm -> power mgmt
# md -> more data pf -> protected frame o  -> order
# index of frame types and string titles
_FC_FLAGS_NAME_ = ['td','fd','mf','r','pm','md','pf','o']
_FC_FLAGS_ = {'td':(1<<0),'fd':(1<<1),'mf':(1<<2),'r':(1<<3),
               'pm':(1<<4),'md':(1<<5),'pf':(1<<6),'o':(1<<7)}
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
     converts list of unpacked ints to hw address (lower case)
     :params l: tuple of 6 bytes
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
_QOS_INFO_STA_ = {'vo':(1<<0),'vi':(1<<1),'bk':(1<<2),
                  'be':(1<<3),'q-ack':(1<<4),'more':(1<<7)}
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
_HTC_FIELDS_ = {'lac-rsrv':(1<<0),
                'lac-trq':(1<<1),
                'lac-mai-mrq':(1<<2),
                'ndp-annoucement':(1<<24),
                'ac-constraint':(1<<30),
                'rdg-more-ppdu':(1<<31)}
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
    htc['rsrv2'] = bits.midx(_HTC_RSRV2_START_,_HTC_RSRV2_LEN_,v)
    return htc

#### FRAME TYPE PARSING

#### MGMT Frames Std 8.3.3

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
                               'beacon-int':v[1]*1024,    # return in microseconds
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
        #else: # std.ST_MGMT_ATIM, RSRV_7, RSRV_8 or RSRV_15
    except Exception as e:
        m['err'].append(('mgmt.{0}'.format(std.ST_MGMT_TYPES[m.subtype]),
                         "unpacking/parsing {0}".format(e)))

    # get information elements if any
    if m['offset'] < len(f):
        m['info-elements'] = [] # use a list of tuples to handle multiple tags
        m['present'].append('info-elements')
        while m['offset'] < len(f):
            try:
                # info elements have the structure (see Std 8.4.2.1)
                # Element ID|Length|Information
                #          1      1    variable

                # pull out info element id and info element len
                # before calc the new offse, pull out the info element
                v,m['offset'] = _unpack_from_("BB",f,m['offset'])
                ie = f[m['offset']:m['offset']+v[1]]
                m['offset'] += v[1]

                # parse the info element
                ie = _parseie_(v[0],ie)
                m['info-elements'].append(ie)
            except EnvironmentError as e:
                # error in _parseie_
                m['err'].append(('mgmt.info-elements.eid-{0}'.format(e[0]),
                                 "parsing {0}".format(e[1])))
            except Exception as e:
                m['err'].append(('mgmt.info-elements',"generic {0}".format(e)))

#### MGMT Frame subfields

# CAPABILITY INFO Std 8.4.1.4

_CAP_INFO_ = {'ess':(1<<0),
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
              'immediate-ba':(1<<15)}
def _parsecapinfo_(mn):
    """ :returns: parsed cap info field"""
    return bits.bitmask_list(_CAP_INFO_,mn)

# INFORMATION ELEMENTS Std 8.2.4.6

def _parseie_(eid,info):
    """
     parse information elements (exluding vendor specific)
    :param eid: element id
    :param info: packed string of the information field
    :returns: a tuple (element id,parsed info field)
    """
    try:
        if eid == std.EID_SSID: # Std 8.4.2.2
            try:
                info = info.decode('utf8')
            except UnicodeDecodeError:
                pass
        elif eid == std.EID_SUPPORTED_RATES or eid == std.EID_EXTENDED_RATES: # Std 8.4.2.3, .15
            # split listofrates where each rate is Mbps. list is 1 to 8 octets,
            # each octect describes a single rate or BSS membership selector
            info = [_getrate_(struct.unpack('=B',r)[0]) for r in info]
        elif eid == std.EID_FH: # Std 8.4.2.4
            # ttl length is 5 octets w/ 4 elements
            dtime,hset,hpattern,hidx = struct.unpack_from('=HBBB',info)
            info = {'dwell-time':dtime,
                    'hop-set':hset,
                    'hop-patterin':hpattern,
                    'hop-index':hidx}
        elif eid == std.EID_DSSS: # Std 8.4.2.5
            # contains the dot11Currentchannel (1-14)
            info = struct.unpack('=B',info)[0]
        elif eid == std.EID_CF: # 8.4.2.6
            # ttl lenght is 6 octets w/ 4 elements
            cnt,per,mx,rem = struct.unpack_from('=BBHH',info)
            info = {'cfp-cnt':cnt,
                    'cfp-per':per,
                    'max-dur':mx,
                    'dur-remaining':rem}
        elif eid == std.EID_TIM: # Std 8.4.2.7
            # variable 4 element
            cnt,per,ctrl = struct.unpack_from('=BBB',info)
            rem = info[3:]
            info = {'dtim-cnt':cnt,
                    'dtim-per':per,
                    'bm-ctrl':{'tib':bits.leastx(1,ctrl),
                               'offset':bits.mostx(1,ctrl)},
                               'vir-bm':rem}
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
            for i in range(0,len(info),3):
                try:
                    trips.append(struct.unpack_from('=3B',info,i))
                except struct.error:
                    pad = struct.unpack_from('=B',info,i)
            info = {'country':cstr,'op-tuples':trips}
            if pad: info['pad'] = pad
        elif eid == std.EID_HOP_PARAMS: # Std 8.4.2.11
            # 2 elements
            rad,num = struct.unpack_from('=BB',info)
            info = {'prime-rad':rad,'num-channels':num}
        elif eid == std.EID_HOP_TABLE: # Std 8.4.2.12
            # 4 1-bte elements & 1 variable list of 1 octet
            flag,num,mod,off = struct.unpack_from('=BBBB',info)
            rtab = info[4:]
            info = {'flag':flag,
                    'num-sets':num,
                    'modulus':mod,
                    'offset':off,
                    'rtab':[struct.unpack('=B',r)[0] for r in rtab]}
        elif eid == std.EID_REQUEST: # Std 8.4.2.13
            # variable length see Std 10.1.4.3.2 for more info
            pass
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
            vs = struct.unpack_from('=2B2BH2BH2BH2BH',info)
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
            pass
        elif eid == std.EID_TCLAS: # Std 8.4.2.33
            pass
        elif eid == std.EID_SCHED: # Std 8.4.2.36
            # 12 bytes, 4 element
            sinfo,start,ser_int,spec_int = struct.unpack_from('=HIII',info)
            info = {'sched-info':_eidsched_(sinfo),
                    'ser-start':start,
                    'ser-int':ser_int,
                    'spec-int':spec_int}
        elif eid == std.EID_CHALLENGE: pass # Std 8.4.2.9
        elif eid == std.EID_PWR_CONSTRAINT: # Std 8.4.2.16
            info = struct.unpack_from('=B',info)[0] # in dBm
        elif eid == std.EID_PWR_CAPABILITY: # Std 8.4.2.17
            mn,mx = struct.unpack_from('=BB',info)
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
            for i in range(0,len(info),2):
                try:
                    chs.append(struct.unpack_from('=2B',info,i))
                except struct.error:
                    break
            info = chs
        elif eid == std.EID_CH_SWITCH: # Std 8.4.2.21
            # 3 element
            mode,new,cnt = struct.unpack_from('=BBB',info)
            info = {'mode':mode,'new-ch':new,'cnt':cnt}
        elif eid == std.EID_MEAS_REQ: # Std 8.4.2.23
            pass
        elif eid == std.EID_MEAS_RPT: # Std 8.4.2.24
            pass
        elif eid == std.EID_QUIET: # Std 8.4.2.25
            # 4 element
            cnt,per,dur,off = struct.unpack_from('=BBHH',info)
            info = {'cnt':cnt,'per':per,'dur':dur,'offset':off}
        elif eid == std.EID_IBSS_DFS: # Std 8.4.2.26
            pass
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
                    'mcs-set':mcs, # see Std Fig 8-251
                    'ht-ext-cap':_eidhtcaphte_(hte),
                    'tx-beamform':_eidhtcaptxbf_(bf),
                    'asel-cap':_eidhtcapasel_(asel)}
        elif eid == std.EID_QOS_CAP: # Std 8.4.2.37, 8.4.1.17
            # 1 byte 1 element. Requires further parsing to get subfields
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_RSN: # Std 8.4.2.27
            pass
        elif eid == std.EID_AP_CH_RPT: # Std 8.4.2.38
            # min 1 octet followed by variable list of channels
            opclass = struct.unpack_from('=B',info)[0]
            info = {'op-class':opclass,
                    'ch-list':[struct.unpack('=B',ch)[0] for ch in info[1:]]}
        elif eid == std.EID_NEIGHBOR_RPT: # Std 8.4.2.39
            # BSSID|BSSID INFO|OP CLASS|CH NUM|PHY TYPE|SUB ELS
            #     6|         4|       1|     1|       1| var
            binfo,op,ch,phy, = struct.unpack_from('=I3B',info,6)
            var = info[struct.calcsize('=6BI3B'):]
            info = {'bssid':_hwaddr_(struct.unpack_from('=6B',info)),
                    'bssid-info':_eidneighrptinfo_(binfo),
                    'op-class':op,
                    'ch-num':ch,
                    'phy':phy}
            if var:
                opt = []
                while len(var):
                    sid,slen,el = _parseinfoelsubel_(var)
                    var = var[2+slen] # adjust 2 octets for sid, slen and var for data
                    opt.append((sid,slen,el))
                info['opt'] = opt
        elif eid == std.EID_RCPI: # Std 8.4.2.40
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_MDE: # Std 84.2.49
            mdid,ft = struct.unpack_from('=HB',info)
            info = {'mdid':mdid,'ft-cap-pol':_eidftcappol_(ft)}
        elif eid == std.EID_FTE: # Std 8.4.2.50
            pass
        elif eid == std.EID_TIE: # Std 8.4.2.51
            typ,val = struct.unpack_from('=BI',info)
            info = {'int-type':typ,'int-val':val}
        elif eid == std.EID_RDE: # Std 8.4.2.52
            # 4 byte 3 element (See 8.4.1.9 for values of stat)
            rid,cnt,stat = struct.unpack_from('=2BH',info)
            info = {'rde-id':rid,'rd-cnt':cnt,'status':stat}
        elif eid == std.EID_DSE_REG_LOC: # Std 8.4.2.54
            pass
        elif eid == std.EID_OP_CLASSES:
            # 2 elements, 1 byte, & 1 2 to 253
            # see 10.10.1 and 10.11.9.1 for use of op-classes element
            opclass = struct.unpack_from('=B',info)
            info = {'op-class':opclass,'op-classes':info[1:]}
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
            pri,htop1,htop2,htop3 = struct.unpack_from('=BBHH',info)
            mcs = info[-16:]
            info = {'pri-ch':pri,
                    'ht-op-info':_eidhtopinfo_(htop1,htop2,htop3),
                    'mcs-set':mcs}
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
        elif eid == std.EID_MEAS_PILOT: # Std 8.4.2.44
            pass
        elif eid == std.EID_BSS_AVAIL: # Std 8.4.2.45
            pass
        elif eid == std.EID_BSS_AC_DELAY: # Std 8.4.2.46
            # four 1 byte elements, each is a scalar indicator as in BSS Average
            # Access delay
            be,bk,vi,vo = struct.unpack_from('=4B',info)
            info = {'ac-be':be, # best effort avg access delay
                    'ac-bk':bk, # background avg access delay
                    'ac-vi':vi, # video avg access delay
                    'ac-vo':vo} # voice avg access delay
        elif eid == std.EID_TIME_ADV: # Std 8.4.2.63
            pass
        elif eid == std.EID_RM_ENABLED: # Std 8.4.2.47
            pass
        elif eid == std.EID_MUL_BSSID: # Std 8.4.2.48
            pass
        elif eid == std.EID_20_40_COEXIST: # Std 8.4.2.62
            # 1 element, 1 byte
            info = _eid2040coexist_(struct.unpack_from('=B',info)[0])
        elif eid == std.EID_20_40_INTOLERANT: # Std 8.4.2.60
            pass
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
            pass
        elif eid == std.EID_MGMT_MIC: # Std 8.4.2.57
            # lengths are 2, 6, 8
            pass
        elif eid == std.EID_EVENT_REQ: # Std 8.4.2.69
            pass
        elif eid == std.EID_EVENT_RPT: # Std 8.4.2.70
            pass
        elif eid == std.EID_DIAG_REQ: # Std 8.3.2.71
            pass
        elif eid == std.EID_DIAG_RPT: # Std 8.3.2.72
            pass
        elif eid == std.EID_LOCATION: # Std 8.3.2.73
            pass
        elif eid == std.EID_NONTRANS_BSS: # Std 8.4.2.74
            info = struct.unpack_from('=H',info)[0]
        elif eid == std.EID_SSID_LIST: # Std 8.4.2.75
            pass
        elif eid == std.EID_MULT_BSSID_INDEX: # Std 8.4.2.76
            pass
        elif eid == std.EID_FMS_DESC: # Std 8.4.2.77
            pass
        elif eid == std.EID_FMS_REQ: # Std 8.4.2.78
            pass
        elif eid == std.EID_FMS_RESP: # Std 8.4.2.79
            pass
        elif eid == std.EID_QOS_TRAFFIC_CAP: # Std 8.4.2.80
            pass
        elif eid == std.EID_BSS_MAX_IDLE: # Std 8.4.2.81
            # 2 elements
            per,opts = struct.unpack_from('=HB',info)
            info = {'max-idle-per':per,'idle-ops':_eidbssmaxidle_(opts)}
        elif eid == std.EID_TFS_REQ: # Std 8.4.2.82
            pass
        elif eid == std.EID_TFS_RESP: # Std 8.4.2.83
            pass
        elif eid == std.EID_WNM_SLEEP: # Std 8.4.2.84
            # 3 elements, 1,1 and 2 octets
            act,stat,intv = struct.unpack_from('=2BH',info)
            info = {'act-type':act,'resp-status':stat,'interval':intv}
        elif eid == std.EID_TIM_REQ: # Std 8.4.2.85
            # 1 octet element (TIM BCAST Interval
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_TIM_RESP: # Std 8.4.2.86
            pass
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
            pass
        elif eid == std.EID_TIME_ZONE: # Std 8.4.2.89
            pass
        elif eid == std.EID_DMS_REQ: # Std 8.4.2.90
            pass
        elif eid == std.EID_DMS_RESP: # Std 8.4.2.91
            pass
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
            pass
        elif eid == std.EID_ADV_PROTOCOL: # Std 8.4.2.95
            pass
        elif eid == std.EID_EXPEDITED_BW_REQ: # Std 8.4.2.96
            # 1 element (precedence level)
            info = struct.unpack_from('=B',info)[0]
        elif eid == std.EID_QOS_MAP_SET: # Std 8.4.2.97
            pass
        elif eid == std.EID_ROAMING_CONS: # Std 8.4.2.98
            pass
        elif eid == std.EID_EMERGENCY_ALERT_ID: # Std 8.4.2.99
            # info is an 8-octet hash value
            info = hexlify(info)
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
            pass
        elif eid == std.EID_MESH_LINK_METRIC_RPT: # Std 8.4.2.102
            pass
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
            pass
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
            pass
        elif eid == std.EID_MCCAOP_SETUP_REQ: # Std 8.4.2.108
            pass
        elif eid == std.EID_MCCOAP_SETUP_REP: # Std 8.4.2.109
            pass
        elif eid == std.EID_MCCAOP_ADV: # Std 8.4.2.111
            pass
        elif eid == std.EID_MCCAOP_TEARDOWN: # Std 8.4.2.112
            pass
        elif eid == std.EID_GANN: # Std 8.4.2.113
            # 1|1|1|6|4|2
            fs,hop,ttl = struct.unpack_from('=3B',info)
            mesh = struct.unpack_from('=6B',info,3)
            seqn,intv = struct.unpack_from('=IH',info,9)
            info = {'flags':fs,
                    'hop-cnt':hop,
                    'element-ttl':ttl,
                    'mesh-gate':_hwaddr_(mesh),
                    'gann-seq-num':seqn,
                    'interval':intv}
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
            pass
        elif eid == std.EID_PREQ: # Std 8.4.2.115
            pass
        elif eid == std.EID_PREP: # Std 8.4.2.116
            pass
        elif eid == std.EID_PERR: # Std 8.4.2.117
            pass
        elif eid == std.EID_PXU: # Std 8.4.2.118
            pass
        elif eid == std.EID_PXUC: # Std 8.4.2.119
            # 1|6
            vs = struct.unpack_from('=7B',info)
            info = {'pxu-id':vs[0],'pxu-recipient':_hwaddr_(vs[1:])}
        elif eid == std.EID_AUTH_MESH_PEER_EXC: # Std 8.4.2.120
            pass
        elif eid == std.EID_MIC: # Std 8.4.2.121
            pass
        elif eid == std.EID_DEST_URI: # Std 8.4.2.92
            ess = struct.unpack_from('=B',info)[0]
            info = {'ess-intv':ess,'uri':info[1:]}
        elif eid == std.EID_UAPSD_COEXIST: # Std 8.4.2.93
            pass
        elif eid == std.EID_MCCAOP_ADV_OVERVIEW: # Std 8.4.2.119
            # 1|1|1|1|2
            seqn, fs, frac, lim, bm = struct.unpack_from('=4BH', info)
            info = {'adv-seq-num': seqn,
                    'flags': {'accept': bits.leastx(1, fs),
                              'rsrv': bits.mostx(1, fs)},
                    'mcca-access-frac': frac,
                    'maf-lim': lim,
                    'adv-els-bm': bm}
        elif eid == std.EID_VEND_SPEC:
            # split into tuple (tag,(oui,value))
            vs = struct.unpack_from('=3B',info)
            info = {'oui':":".join(['{0:02X}'.format(v) for v in vs]),
                    'content':info[3:]}
        else:
            info = {'rsrv':info}
    except (struct.error,IndexError) as e:
        raise EnvironmentError(eid,e)
    return eid,info

# INFORMATION ELEMENT SUBELEMENT Std Fig 8-402
# Subelement ID|Length|Data
#             1|     1| var
def _parseinfoelsubel_(info):
    """
     parse a variable length info element sub element
     :param info: packed string, next element starts at index 0
    """
    sid,slen = struct.unpack_from('=2B',info)
    return sid,slen,info[struct.calcsize('=2b')+slen:]

# SUPPORTED RATES/EXTENDED RATES Std 8.4.2.3 and 8.4.2.15
# Std 6.5.5.2 table of rates not contained in the BSSBasicRateSet
# Reading 8.4.2.3 directs to the table in 6.5.5.2 which (see below) relates
# the number in bits 0-6 to 0.5 * times that number which is the same thing
# that happens if MSB is set to 1 ????
_RATE_DIVIDER_ = 7
def _getrate_(val): return bits.leastx(_RATE_DIVIDER_,val) * 0.5

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
def _secchoffset_(v):
    """ :returns: human readable secondary channel offset value """
    if v == _EID_SEC_CH_OFFSET_SCN_: return 'scn'
    elif v == _EID_SEC_CH_OFFSET_SCA_: return 'sca'
    elif v == _EID_SEC_CH_OFFSET_SCB_: return 'scb'
    else: return "rsrv-{0}".format(v)

# constants for TCLAS Processing Std Table 8-113
# ???? move to ieee80211 ???? 
_EID_TCLAS_PRO_ALL_  = 0
_EID_TCLAS_PRO_ONE_  = 1
_EID_TCLAS_PRO_NONE_ = 2
# NOTE: 3-255 are reserved

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

# TIE interval type field values Std Table 8-122
std.EID_TIE_TYPE_REASSOC  = 1
std.EID_TIE_TYPE_KET_LIFE = 2
std.EID_TIE_TYPE_COMEBACK = 3
# NOTE 0, 4=255 are reserved

# 20/40 Coexistence information field Std Figure 8-260
# Info Re1|40 Intolerant|20 Request|Exempt Request|Exempt Grant|Reserved
#       B0|           B1|        B2|            B3|          B4|B5-B7
_EID_20_40_COEXIST_ = {'info-req':(1<<0),'40-intol':(1<<1),'20-req':(1<<2),
                       'exempt-req':(1<<3),'exempt-grant':(1<<4)}
_EID_20_40_COEXIST_RSRV_START_ = 5
def _eid2040coexist_(v):
    """ :returns: parsed 20/40 coexistence Info. field """
    co = bits.bitmask_list(_EID_20_40_COEXIST_,v)
    co['rsrv'] = bits.mostx(_EID_20_40_COEXIST_RSRV_START_,v)
    return co

# TPU Buffer Status Std Figure 8-266
# AC_BK Traf|AC_BE Traf|AC_VI Traf|AC_VO_Traf|Reserved
#         B0|        B1|        B2|        B3| B4-B7
_EID_TPU_BUFF_STATUS_ = {'ac-bk':(1<<0),'ac-be':(1<<1),'ac-vi':(1<<2),'ac-vo':(1<<3)}
_EID_TPU_BUFF_STATUS_RSRV_START_ = 4
def _eidtpubuffstat_(v):
    """ :returns: parsed TPU buffer status """
    bs = bits.bitmask_list(_EID_TPU_BUFF_STATUS_,v)
    bs['rsrv'] = bits.mostx(_EID_TPU_BUFF_STATUS_RSRV_START_,v)
    return bs

# BSS Max Idle Period -> Idle Options # Std Figure 8-333
_EID_BSS_MAX_IDLE_PRO_ = 1
def _eidbssmaxidle_(v):
    """ :returns: parsed idle options field """
    return {'pro-keep-alive':bits.leastx(_EID_BSS_MAX_IDLE_PRO_,v),
            'rsrv':bits.mostx(_EID_BSS_MAX_IDLE_PRO_,v)}

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
_EID_MESH_CONFIG_CAP_ = {'accept':(1<<0),'mcca-support':(1<<1),
                         'mcca-enable':(1<<2),'forwarding':(1<<3),'mbca':(1<<4),
                         'tbtt':(1<<5),'pwr-save':(1<<6),'rsrv':(1<<7)}
def _eidmeshconfigcap_(v):
    """ :returns: parsed mesh capability field """
    return bits.bitmask_list(_EID_MESH_CONFIG_CAP_,v)

# Mesh Channel Switch Parameters flags field definition Std Fig 8-372
# Transmit Restrict|Initiator|Reason|Reserved
#                B0|       B!|    B2|B3-B7
_EID_MESH_CH_SWITCH_FLAGS_ = {'tx-restrict':(1<<0),'initiator':(1<<1),'reason':(1<<2)}
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

#### HT CAPABILITIES Std 8.4.2.58

# HT Capabilities Info field Std Fig 8-249
# octest are defined as 1|1|2|1|1|1|1|2|1|1|1|1|1|1 see Fig 8-249 for names
# See also Std Table 8-124 for definition of sub fields
_EID_HT_CAP_HTI_ = {'ldpc-cap':(1<<0),'ch-width-set':(1<<1),'ht-greenfield':(1<<4),
                    'short-gi-20':(1<<5),'short-gi-40':(1<<6),'tx-stbc':(1<<7),
                    'ht-delay-back':(1<<10),'max-amsdu':(1<<11),'dsss-cck-mod':(1<<12),
                    'rsrv':(1<<13),'40-intolerant':(1<<14),'lsig-txop-pro':(1<<15)}
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
_EID_HT_CAP_ASEL_ = {'ant-sel':(1<<0),       # antenna selection capable
                     'csi-asel-cap':(1<<1),  # explicit cs feedback based tx ASEL capable
                     'ant-asel-cap':(1<<2),  # antenna indices feedback based tx ASEL capable
                     'csi-cap':(1<<3),       # explicit csi feedback capable
                     'ant-cap':(1<<4),       # antenna indices feedback capable
                     'recv-asel-cap':(1<<5), # receive ASEL capable
                     'tx-ppdu-cap':(1<<6),   # tx sounding PPDUs capable
                     'rsrv':(1<<7)}
def _eidhtcapasel_(v):
    """ :returns: parsed ASEL capability field """
    return bits.bitmask_list(_EID_HT_CAP_ASEL_,v)

# QoS Capability Std 8.4.1.17
# two meanings dependent on if AP transmitted frame or non-Ap transmitted frame
# Sent by AP Std Fig 8-51
_EID_QOS_CAP_AP_ = {'q-ack':(1<<4),'q-req':(1<<5),'txop-req':(1<<6),'rsrv':(1<<7)}
_EID_QOS_CAP_AP_DIVIDER_ = 4
# Sent by non-AP
_EID_QOS_CAP_NON_AP_ = {'ac-vo':(1<<0),'ac-vi':(1<<1),'ac-bk':(1<<2),'ac-be':(1<<3),
                        'q-ack':(1<<4),'more-data':(1<<7)}
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

# Neighbor Report BSSID Info subfield Std Fig 8-216
# AP Reachability|Security|Key Scope|Capabilities|Mobility Dom| HT|Reserved
#           BO-B1|      B2|       B3|       B4-B9|         B10|B11|B12-B31
# where capabilties is defined as Std Fig 8-127
# Spec MGMT|QoS|APSD|RDO MSMT|DEL Block ACK|Immediate Block Ack
#         1|  2|   3|       4|            5|                  6
_EID_NEIGHBOR_REPORT_BSSID_INFO_ = {'security':(1<<2),'key-scope':(1<<3),
                                    'spec-mgmt':(1<<4),'qos':(1<<5),
                                    'apsd':(1<<6),'rdo-msmt':(1<<7),
                                    'del-back':(1<<8),'imm-back':(1<<9),
                                    'mob-dom':(1<<10),'ht':(1<<11)}
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
_EID_HT_OP_HT_OP2_ = {'non-greenfield':(1<<2),'rsrv2':(1<<3),'obss-non-ht':(1<<4)}
_EID_HT_OP_HT_OP2_DIVIDER_    = 2
_EID_HT_OP_HT_OP2_RSRV_START_ = 5
# HT OP Info Three: 2 octets
# Reserved|Dual Beacon|Dual CTS|STBC Beacon|L-SIX TXOP|PCO Active|PCO Phase|Reserved
#  B24-B29|        B30|     B31|        B32|       B33|       B34|      B35|B36-B39
#  <B0-B5>|       <B6>|    <B7>|       <B8>|      <B9>|     <B10>|    <B11>|<B12>-<B15>
_EID_HT_OP_HT_OP3_ = {'dual-beacon':(1<<6),'dual-cts':(1<<7),'stbc-beacon':(1<<8),
                      'lsig-txop-pro':(1<<9),'pco-active':(1<<10),'pco-phase':(1<<11)}
_EID_HT_OP_HT_OP3_DIVIDER_    =  6
_EID_HT_OP_HT_OP3_RSRV_START_ = 12
def _eidhtopinfo_(h1,h2,h3):
    """ :returns: parsed HT OP Info subelement"""
    htop = {}
    ht1 = bits.bitmask_list(_EID_HT_OP_HT_OP1_,h1)
    ht1['sec-ch-off'] = bits.leastx(_EID_HT_OP_HT_OP1_DIVIDER_,h1)
    ht1['rsrv1'] = bits.mostx(_EID_HT_OP_HT_OP1_RSRV_START_,h1)
    ht2 = bits.bitmask_list(_EID_HT_OP_HT_OP2_,h2)
    ht2['ht-pro'] = bits.leastx(_EID_HT_OP_HT_OP2_DIVIDER_,h2)
    ht2['rsrv3'] = bits.mostx(_EID_HT_OP_HT_OP2_RSRV_START_,h2)
    ht3 = bits.bitmask_list(_EID_HT_OP_HT_OP3_,h3)
    ht3['rsrv4'] = bits.leastx(_EID_HT_OP_HT_OP3_DIVIDER_,h3)
    ht3['rsrv5'] = bits.mostx(_EID_HT_OP_HT_OP3_RSRV_START_,h3)
    for ht in ht1: htop[ht] = ht1[ht]
    for ht in ht2: htop[ht] = ht2[ht]
    for ht in ht3: htop[ht] = ht3[ht]
    return htop

#### CTRL Frames Std 8.3.1

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

#### DATA Frames Std 8.3.2

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
