#!/usr/bin/env python

""" mpdu.py: Mac Protocol Data Unit (MPDU) parsing.

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

Parses the 802.11 MAC Protocol Data Unit (MPDU) IAW IEE 802.11-2012 (Std).

NOTE:
 It is recommended not to import * as it may cause conflicts with other modules

"""

__name__ = 'mpdu'
__license__ = 'GPL v3.0'
__version__ = '0.1.2'
__date__ = 'November 2015'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

import struct
from binascii import hexlify
import itamae.bits as bits

class error(EnvironmentError): pass

# SOME CONSTANTS
BROADCAST = "ff:ff:ff:ff:ff:ff" # broadcast address
MAX_MPDU = 7991                 # maximum mpdu size in bytes
FMT_BO = "="                    # struct format byte order specifier

class MPDU(dict):
    """
     A wrapper for the underlying mpdu dict with the following mandatory
     key/value pairs:
      FRAMECTRL|DURATION|ADDR1 (and fcs if not stripped by firmware) see Std 8.3.1.3]
      present: an ordered list of mpdu fields
      offset: the number of bytes read from the first byte of frame upto the msdu
       (including any encryption)
      stripped: the number of bytes read from the last byte of the frame upto
       the end of the msdu (including any encryption)
     a MPDU object will also contain key/value pairs for fields present in the
     mpdu as dictated by the structure of the mac header

     the MPDU object will expose 'toplevel' mac layer fields so that users can call
     for example dictMPDU.framectrl rather than dictMPDU['framectrl']. These are
     listed below:
      framectrl,
      duration,
      addr1, ..., addr4 (as present),
      seqctrl,
      qosctrl
      htc, (not currently supported)
      crypt,
      fcs

     it will also expose certain sublevel fields:
     vers, type, subtype, flags,

     as well as additional members:
     offset (bytes read from 'front' of frame),
     stripped (bytes read from 'end' of frame),
     size (total bytes read),
     present (ordered list of fields present in the MPDU)
     error: list of tuples t = (location,message) where location is a '.'
     separated list of locations/sublocations and message describes the error
    """
    def __new__(cls,d=None):
        return super(MPDU,cls).__new__(cls,dict({} if d is None else d))

    #### PROPERTIES

    # the following are 'added fields' of an mpdu they will return a default
    # 'empty' value if the mpdu is not instantiated

    @property
    def error(self):
        """ returns error message(s) """
        try:
            return self['err']
        except KeyError:
            return []

    @property
    def offset(self):
        """ :returns: number of bytes read from byte 0 """
        try:
            return self['offset']
        except KeyError:
            return 0

    @property
    def stripped(self):
        """ :returns: # of bytes read from the last byte of the frame """
        try:
            return self['stripped']
        except KeyError:
            return 0

    @property
    def size(self):
        """ :returns: ttl # of bytes read (includes fcs and any icv, etc) """
        try:
            return self['offset'] + self['stripped']
        except KeyError:
            return 0

    @property
    def present(self):
        """ :returns: list of fields that are present """
        try:
            return self['present']
        except KeyError:
            return []

    @property
    def isempty(self):
        """ :returns: True if mpdu is 'uninstantiated' """
        return self.present == []

    # The following are the minimum required fields of a mpdu frame
    # and will raise an unistantiated error if not present

    @property
    def framectrl(self):
        """ :returns: mpdu frame control """
        try:
            return self['framectrl']
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def vers(self):
        """ :returns: version as specified in frame control """
        try:
            return self['framectrl']['vers']
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def type(self):
        """ :returns: type as specified in frame control """
        try:
            return self['framectrl']['type']
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def type_desc(self):
        """ :returns: string repr of type """
        try:
            return FT_TYPES[self.type]
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def subtype(self):
        """ :returns: subtype as specified in frame control """
        try:
            return self['framectrl']['subtype']
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def subtype_desc(self):
        """ :returns: string repr of type as specified in frame control """
        try:
            if self.type == FT_MGMT: return ST_MGMT_TYPES[self.subtype]
            elif self.type == FT_CTRL: return ST_CTRL_TYPES[self.subtype]
            elif self.type == FT_DATA: return ST_DATA_TYPES[self.subtype]
            else: return 'rsrv'
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def flags(self):
        """ :returns: flags as specified in frame control """
        try:
            return self['framectrl']['flags']
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def duration(self):
        """ :returns: durtion of mpdu """
        try:
            return self['duration']
        except KeyError:
            raise error('MPDU is uninstantiated')

    @property
    def addr1(self):
        """ :returns: addr1 of mpdu """
        try:
            return self['addr1']
        except KeyError:
            raise error('MPDU is uninstantiated')

    # the following may or may not be present. returns  None if not present
    @property
    def addr2(self): return self['addr2'] if 'addr2' in self else None
    @property
    def addr3(self): return self['addr3'] if 'addr3' in self else None
    @property
    def seqctrl(self): return self['seqctrl'] if 'seqctrl' in self else None
    @property
    def addr4(self): return self['addr4'] if 'addr4' in self else None
    @property
    def qosctrl(self): return self['qos'] if 'qos' in self else None
    @property
    def htc(self): return self['htc'] if 'htc' in self else None
    @property
    def fcs(self): return self['fcs'] if 'fcs' in self else None
    @property
    def crypt(self): return self['l3-crypt'] if 'l3-crypt' in self else None
    @property
    def fixed_params(self):
        return self['fixed-params'] if 'fixed-params' in self else []
    @property
    def info_els(self):
        return self['info-elements'] if 'info-elements' in self else []

    def geties(self,ies):
        """
        :param ies: desired list of info elements
        :returns: list of lists of info elements found
        """
        ret = [[] for _ in ies]
        for ie in self.info_els:
            try:
                ix = ies.index(ie[0])
                ret[ix].append(ie[1])
            except (ValueError,IndexError):
                pass
        return ret

def parse(f,hasFCS=False):
    """
     parse the mpdu in frame (where frame is stripped of any layer 1 header)
      :param f: the frame to parse
      :param hasFCS: fcs is present in frame
      :returns: an mpdu object
       vers -> mpdu version (always 0)
       sz -> offset of last bytes read from mpdu (not including fcs).
       present -> an ordered list of fields present in the frame
       and key->value pairs for each field in present
     NOTE: will throw an exception if the minimum frame cannot be parsed
    """
    # at a minimum, frames will be FRAMECTRL|DURATION|ADDR1 (and fcs if not
    # stripped by the firmware) see Std 8.3.1.3
    try:
        vs,offset = _unpack_from_(_S2F_['framectrl'],f,0)
        m = MPDU({'framectrl':{'vers':bits.leastx(2,vs[0]),
                               'type':bits.midx(2,2,vs[0]),
                               'subtype':bits.mostx(4,vs[0]),
                               'flags':_fcflags_(vs[1])},
                  'present':['framectrl'],
                  'offset':offset,
                  'stripped':0,
                  'err':[]})
        vs,m['offset'] = _unpack_from_(_S2F_['duration'] + _S2F_['addr'],f,m['offset'])
        m['duration'] = _duration_(vs[0])
        m['addr1'] = _hwaddr_(vs[1:])
        m['present'].extend(['duration','addr1'])
        if hasFCS:
            m['fcs'] = struct.unpack('=L',f[-4:])[0]
            f = f[:-4]
            m['stripped'] += 4
    except (struct.error,ValueError) as e:
        if len(f) <= 0: return {'offset':0}
        raise error("Failed to unpack: {0}".format(e))
    else:
        # handle frame types separately (return on FT_RSRV
        if m.type == FT_MGMT: _parsemgmt_(f,m)
        elif m.type == FT_CTRL: _parsectrl_(f,m)
        elif m.type == FT_DATA: _parsedata_(f,m)
        else:
            m['err'].append(('framectrl.type','invalid type RSRV'))

        # process encryption
        if m.flags['pf']:
            # get 1st four bytes of the msdu & run encryption test
            # if 5th (ExtIV) bit set on the 4th octet then WPA/WPA2
            # if 5th (ExtIV) bit is not set then WEP
            # see http://www.xirrus.com/cdn/pdf/wifi-demystified/documents_posters_encryption_plotter.pdf
            try:
                bs = struct.unpack_from('=4B',f,m['offset'])
                if bs[3] & 0x20:
                    # check wep seed (the 2nd byte) via (TSC1 | 0x20) & 0x7f
                    # if set we have tkip otherwise ccmp
                    if (bs[0] | 0x20) & 0x7f == bs[1]: _tkip_(f,m)
                    else: _ccmp_(f,m)
                else: _wep_(f,m)
                if 'l3-crypt' in m: m['present'].append('l3-crypt')
            except struct.error as e:
                m['err'].append(('l3-crypt',"unpacking encryption {0}".format(e)))
            except Exception as e:
                m['err'].append(('l3-crypt',"testing for encryption {0}".format(e)))

    # append the fcs to present if necessary and return the mpdu dict
    if hasFCS: m['present'].append('fcs')
    return m

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

# Frame Control Flags Std 8.2.4.1.1
# td -> to ds fd -> from ds mf -> more fragments r  -> retry pm -> power mgmt
# md -> more data pf -> protected frame o  -> order
# index of frame types and string titles
_FC_FLAGS_NAME_ = ['td','fd','mf','r','pm','md','pf','o']
_FC_FLAGS_ = {'td':(1<<0),'fd':(1<<1),'mf':(1<<2),'r':(1<<3),
               'pm':(1<<4),'md':(1<<5),'pf':(1<<6),'o':(1<<7)}
def _fcflags_(mn): return bits.bitmask_list(_FC_FLAGS_,mn)

# Std 8.2.4.1.3
# each subtype field bit pos indicates a specfic modification of the base data frame
_DATA_SUBTYPE_FIELDS_ = {'cf-ack':(1<<0),'cf-poll':(1<<1),
                         'no-body':(1<<2),'qos':(1<<3)}
def datasubtype(mn): return bits.bitmask(_DATA_SUBTYPE_FIELDS_,mn)
def datasubtype_all(mn): return bits.bitmask_list(_DATA_SUBTYPE_FIELDS_,mn)
def datasubtype_get(mn,f):
    try:
        return bits.bitmask_get(_DATA_SUBTYPE_FIELDS_,mn,f)
    except KeyError:
        raise error("Invalid data subtype flag {0}".format(f))

def subtypes(ft,st):
    if ft == FT_MGMT: return ST_MGMT_TYPES[st]
    elif ft == FT_CTRL: return ST_CTRL_TYPES[st]
    elif ft == FT_DATA: return ST_DATA_TYPES[st]
    else: return 'rsrv'

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

# ACCESS CATEGORY CONSTANTS
QOS_AC_BE_BE = 0
QOS_AC_BK_BK = 1
QOS_AC_BK_NN = 2
QOS_AC_BE_EE = 3
QOS_AC_VI_CL = 4
QOS_AC_VI_VI = 5
QOS_AC_VO_VO = 6
QOS_AC_VO_NC = 7

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
# ST_DATA_QOS_CFPOLL              |TXOP Limit          |                   |
# ST_DATA_QOS_CFACK_CFPOLL        |TXOP Limit          |                   |
# ST_DATA_QOS_DATA_CFACK          |TXOP Limit          |                   |
# ST_DATA_QOS_DATA_CFACK_CFPOLL   |TXOP Limit          |                   |
# ST_DATA_QOS_DATA                |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# ST_DATA_QOS_DATA_CFACK          |AP PS Buffer State  |TXOP Duration Req  |Queue Size
# ST_DATA_QOS_NULL                |AP PS Buffer State  |TXOP Duration Req  |Queue Size
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

## FRAME TYPE PARSING

#--> MGMT Frames Std 8.3.3
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
        if m.subtype == ST_MGMT_ASSOC_REQ:
            # cability info, listen interval
            fmt = _S2F_['capability'] + _S2F_['listen-int']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'capability':capinfo_all(v[0]),'listen-int':v[1]}
            m['present'].append('fixed-params')
        elif m.subtype == ST_MGMT_ASSOC_RESP or m.subtype == ST_MGMT_REASSOC_RESP:
            # capability info, status code and association id (only uses 14 lsb)
            fmt = _S2F_['capability'] + _S2F_['status-code'] + _S2F_['aid']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'capability':capinfo_all(v[0]),
                                 'status-code':v[1],
                                 'aid':bits.leastx(14,v[2])}
            m['present'].append('fixed-params')
        elif m.subtype == ST_MGMT_REASSOC_REQ:
            fmt = _S2F_['capability'] + _S2F_['listen-int'] + _S2F_['addr']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'capability':capinfo_all(v[0]),
                                 'listen-int':v[1],
                                 'current-ap':_hwaddr_(v[2:])}
            m['present'].append('fixed-params')
        elif m.subtype == ST_MGMT_PROBE_REQ: pass # all fields are info-elements
        elif m.subtype == ST_MGMT_TIMING_ADV:
            fmt = _S2F_['timestamp'] + _S2F_['capability']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'timestamp':v[0],
                                 'capability':capinfo_all(v[1])}
            m['present'].append('fixed-params')
        elif m.subtype == ST_MGMT_PROBE_RESP or m.subtype == ST_MGMT_BEACON:
            fmt = _S2F_['timestamp'] + _S2F_['beacon-int'] + _S2F_['capability']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'timestamp':v[0],
                               'beacon-int':v[1]*1024,    # return in microseconds
                               'capability':capinfo_all(v[2])}
            m['present'].append('fixed-params')
        elif m.subtype == ST_MGMT_DISASSOC or m.subtype == ST_MGMT_DEAUTH:
            v,m['offset'] = _unpack_from_(_S2F_['reason-code'],f,m['offset'])
            m['fixed-params'] = {'reason-code':v}
            m['present'].append('fixed-params')
        elif m.subtype == ST_MGMT_AUTH:
            fmt = _S2F_['algorithm-no'] + _S2F_['auth-seq'] + _S2F_['status-code']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'algorithm-no':v[0],
                               'auth-seq':v[1],
                               'status-code':v[2]}
            m['present'].append('fixed-params')
        elif m.subtype == ST_MGMT_ACTION or m.subtype == ST_MGMT_ACTION_NOACK:
            fmt = _S2F_['category'] + _S2F_['action']
            v,m['offset'] = _unpack_from_(fmt,f,m['offset'])
            m['fixed-params'] = {'category':v[0],'action':v[1]}
            m['present'].append('fixed-params')

            # store the action element(s)
            if m['offset'] < len(f):
                m['action-el'] = f[m['offset']:]
                m['present'].append('action-els')
                m['offset'] = len(f)
        #else: # ST_MGMT_ATIM, RSRV_7, RSRV_8 or RSRV_15
    except Exception as e:
        m['err'].append(('mgmt.{0}'.format(ST_MGMT_TYPES[m.subtype]),
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
            except error as e:
                # error in _parseie_
                m['err'].append(('mgmt.info-elements.eid-{0}'.format(e[0]),
                                 "parsing {0}".format(e[1])))
            except Exception as e:
                m['err'].append(('mgmt.info-elements',"generic {0}".format(e)))

#### MGMT Frame subfields
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
def capinfo(mn): return bits.bitmask(_CAP_INFO_,mn)
def capinfo_all(mn): return bits.bitmask_list(_CAP_INFO_,mn)
def capinfo_get(mn,f):
    try:
        return bits.bitmask_get(_CAP_INFO_,mn,f)
    except KeyError:
        raise error("Invalid data subtype flag {0}".format(f))

# CONSTANTS for action frames Std 8.5.1
SPEC_MGMT_MEAS_REQ  = 0
SPEC_MGMT_MEAS_REP  = 1
SPEC_MGMT_TPC_REQ   = 2
SPEC_MGMT_TPC_REP   = 3
SPEC_MGMT_CH_SWITCH = 4

#### INFORMATION ELEMENTS Std 8.2.4.6

def _parseie_(eid,info):
    """
     parse information elements (exluding vendor specific)
    :param eid: element id
    :param info: packed string of the information field
    :returns: a tuple (element id,parse info field)
    """
    try:
        if eid == EID_SSID: # Std 8.4.2.2
            try:
                info = info.decode('utf8')
            except UnicodeDecodeError:
                pass
        elif eid == EID_SUPPORTED_RATES or eid == EID_EXTENDED_RATES: # Std 8.4.2.3, .15
            # split listofrates where each rate is Mbps. list is 1 to 8 octets,
            # each octect describes a single rate or BSS membership selector
            info = [_getrate_(struct.unpack('=B',r)[0]) for r in info]
        elif eid == EID_FH: # Std 8.4.2.4
            # ttl length is 5 octets w/ 4 elements
            dtime,hset,hpattern,hidx = struct.unpack_from('=HBBB',info)
            info = {'dwell-time':dtime,
                    'hop-set':hset,
                    'hop-patterin':hpattern,
                    'hop-index':hidx}
        elif eid == EID_DSSS: # Std 8.4.2.5
            # contains the dot11Currentchannel (1-14)
            info = struct.unpack('=B',info)[0]
        elif eid == EID_CF: # 8.4.2.6
            # ttl lenght is 6 octets w/ 4 elements
            cnt,per,mx,rem = struct.unpack_from('=BBHH',info)
            info = {'cfp-cnt':cnt,
                    'cfp-per':per,
                    'max-dur':mx,
                    'dur-remaining':rem}
        elif eid == EID_TIM: # Std 8.4.2.7
            # variable 4 element
            cnt,per,ctrl = struct.unpack_from('=BBB',info)
            rem = info[3:]
            info = {'dtim-cnt':cnt,
                    'dtim-per':per,
                    'bm-ctrl':{'tib':bits.leastx(1,ctrl),
                               'offset':bits.mostx(1,ctrl)},
                               'vir-bm':rem}
        elif eid == EID_IBSS: # Std 8.4.2.8
            # single element ATIM Window
            info = struct.unpack_from('=H',info)[0]
        elif eid == EID_COUNTRY: pass # Std 8.4.2.10
        elif eid == EID_HOP_PARAMS: # Std 8.4.2.11
            # 2 elements
            rad,num = struct.unpack_from('=BB',info)
            info = {'prime-rad':rad,'num-channels':num}
        elif eid == EID_HOP_TABLE: # Std 8.4.2.12
            # 4 1-bte elements & 1 variable list of 1 octet
            flag,num,mod,off = struct.unpack_from('=BBBB',info)
            rtab = info[4:]
            info = {'flag':flag,
                    'num-sets':num,
                    'modulus':mod,
                    'offset':off,
                    'rtab':[struct.unpack('=B',r)[0] for r in rtab]}
        elif eid == EID_REQUEST: # Std 8.4.2.13
            # variable length see Std 10.1.4.3.2 for more info
            pass
        elif eid == EID_BSS_LOAD: # Std 8.4.2.30
            # 3 element
            cnt,util,cap = struct.unpack_from('=HBH',info)
            info = {'sta-cnt':cnt,'ch-util':util,'avail-cap':cap}
        elif eid == EID_EDCA: # Std 8.4.2.31
            # 18 byte, 6 elements
            #qos,rsrv,be,bk,vi,vo = struct.unpack_from('=BB',info)
            pass
        elif eid == EID_TSPEC: # Std 8.4.2.32
            pass
        elif eid == EID_TCLAS: # Std 8.4.2.33
            pass
        elif eid == EID_SCHED: # Std 8,4,2,36
            # 12 bytes, 4 element
            sinfo,start,ser_int,spec_int = struct.unpack_from('=HIII',info)
            info = {'sched-info':_eidsched_(sinfo),
                    'ser-start':start,
                    'ser-int':ser_int,
                    'spec-int':spec_int}
        elif eid == EID_CHALLENGE: pass # Std 8.4.2.9
        elif eid == EID_PWR_CONSTRAINT: # Std 8.4.2.16
            # in dBm
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_PWR_CAPABILITY: # Std 8.4.2.17
            # in dBm
            mn,mx = struct.unpack_from('=BB',info)
            info = {'min':mn,'max':mx}
        elif eid == EID_TPC_REQ: pass # Std 8.4.2.18 (a flag w/ no info
        elif eid == EID_TPC_RPT: # Std 8.4.2.19
            # 2 element, tx pwr in dBm & twos-complement dBm
            # see also 8,3,3,2, 8.3.3.10 8.5.2.5 & 19.8.6
            pwr,link = struct.unpack_from('=Bb',info)
            info = {'tx-power':pwr,'link-margin':link}
        elif eid == EID_CHANNELS: pass # Std 8.4.2.20
        elif eid == EID_CH_SWITCH: # Std 8.4.2.21
            # 3 element
            mode,new,cnt = struct.unpack_from('=BBB',info)
            info = {'mode':mode,'new-ch':new,'cnt':cnt}
        elif eid == EID_MEAS_REQ: # Std 8.4.2.23
            pass
        elif eid == EID_MEAS_RPT: # Std 8.4.2.24
            pass
        elif eid == EID_QUIET: # Std 8.4.2.25
            # 4 element
            cnt,per,dur,off = struct.unpack_from('=BBHH',info)
            info = {'cnt':cnt,'per':per,'dur':dur,'offset':off}
        elif eid == EID_IBSS_DFS: # Std 8.4.2.26
            pass
        elif eid == EID_ERP: # Std 8.4.2.14
            # Caution: element length is flexible, may change
            info = _eiderp_(struct.unpack_from('=B',info)[0])
        elif eid == EID_TS_DELAY: # Std 8.4.2.34
            # 1 element, 4 bytes
            info = struct.unpack_from('=I',info)[0]
        elif eid == EID_TCLAS_PRO: # Std 8.4.2.35
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_HT_CAP: # Std 8.4.2.58
            pass
        elif eid == EID_QOS_CAP: # Std 8.4.2.37, 8.4.1.17
            # 1 byte 1 element. Requires further parsing to get subfields
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_RSN: # Std 8.4.2.27
            pass
        elif eid == EID_AP_CH_RPT: # Std 8.4.2.38
            pass
        elif eid == EID_NEIGHBOR_RPT: # Std 8.4.2.39
            pass
        elif eid == EID_RCPI: # Std 8.4.2.40
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_MDE: # Std 84.2.49
            mdid,ft = struct.unpack_from('=HB',info)
            info = {'mdid':mdid,
                    'ft-cap-pol':_eidftcappol_(ft)}
        elif eid == EID_FTE: # Std 8.4.2.50
            pass
        elif eid == EID_TIE: # Std 8.4.2.51
            typ,val = struct.unpack_from('=BI',info)
            info = {'int-type':typ,'int-val':val}
        elif eid == EID_RDE: # Std 8.4.2.52
            # 4 byte 3 element (See 8.4.1.9 for values of stat)
            rid,cnt,stat = struct.unpack_from('=2BH',info)
            info = {'rde-id':rid,'rd-cnt':cnt,'status':stat}
        elif eid == EID_DSE_REG_LOC: # Std 8.4.2.54
            pass
        elif eid == EID_OP_CLASSES:
            # 2 elements, 1 byte, & 1 2 to 253
            # see 10.10.1 and 10.11.9.1 for use of op-classes element
            opclass = struct.unpack_from('=B',info)
            info = {'op-class':opclass,'op-classes':info[1:]}
        elif eid == EID_EXT_CH_SWITCH: # Std 8.4.2.55
            # 4 octect, 4 element
            mode,opclass,ch,cnt = struct.unpack_from('=4B',info)
            info = {
                'switch-mode':mode,'op-class':opclass,'new-ch':ch,'switch-cnt':cnt
            }
        elif eid == EID_HT_OP: # Std 8.4.2.59
            pass
        elif eid == EID_SEC_CH_OFFSET: # 8.4.2.22
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_BSS_AVG_DELAY: # Std 8.4.2.41
            # a scalar indication of relative loading level
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_ANTENNA: # Std 8.4.2.42
            # 0: antenna id is uknown, 255: multiple antenneas &
            # 1-254: unique antenna or antenna configuration.
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_RSNI: # Std 8.4.2.43
            # 255: RSNI is unavailable
            # RSNI = (10 * log10((RCPI_power - ANPI_power / ANPI_power) + 10) * 2
            # where RCPI_power & ANPI_power indicate power domain values & not dB domain
            # values. RSNI in dB is scaled in steps of 0.5 dB to obtain 8-bit RSNI values,
            # which cover the range from -10 dB to +117 dB
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_MEAS_PILOT: # Std 8.4.2.44
            pass
        elif eid == EID_BSS_AVAIL: # Std 8.4.2.45
            pass
        elif eid == EID_BSS_AC_DELAY: # Std 8.4.2.46
            # four 1 byte elements, each is a scalar indicator as in BSS Average
            # Access delay
            be,bk,vi,vo = struct.unpack_from('=4B',info)
            info = {'ac-be':be, # best effort avg access delay
                    'ac-bk':bk, # background avg access delay
                    'ac-vi':vi, # video avg access delay
                    'ac-vo':vo} # voice avg access delay
        elif eid == EID_TIME_ADV: # Std 8.4.2.63
            pass
        elif eid == EID_RM_ENABLED: # Std 8.4.2.47
            pass
        elif eid == EID_MUL_BSSID: # Std 8.4.2.48
            pass
        elif eid == EID_20_40_COEXIST: # Std 8.4.2.62
            # 1 element, 1 byte
            info = _eid2040coexist_(struct.unpack_from('=B',info)[0])
        elif eid == EID_20_40_INTOLERANT: # Std 8.4.2.60
            pass
        elif eid == EID_OVERLAPPING_BSS: # Std 8.4.2.61
            # 7 elements each 2 octets
            vs = struct.unpack_from('=7H',info)
            info = {'pass-dwell':vs[0],
                    'act-dwell':vs[1],
                    'trigger-scan-int':vs[2],
                    'pass-per-ch':vs[3],
                    'act-per-ch':vs[4],
                    'delay-factor':vs[5],
                    'threshold':vs[6]}
        elif eid == EID_RIC_DESC: # Std 8.4.2.53
            pass
        elif eid == EID_MGMT_MIC: # Std 8.4.2.57
            # lengths are 2, 6, 8
            pass
        elif eid == EID_EVENT_REQ: # Std 8.4.2.69
            pass
        elif eid == EID_EVENT_RPT: # Std 8.4.2.70
            pass
        elif eid == EID_DIAG_REQ: # Std 8.3.2.71
            pass
        elif eid == EID_DIAG_RPT: # Std 8.3.2.72
            pass
        elif eid == EID_LOCATION: # Std 8.3.2.73
            pass
        elif eid == EID_NONTRANS_BSS: # Std 8.4.2.74
            info = struct.unpack_from('=H',info)[0]
        elif eid == EID_SSID_LIST: # Std 8.4.2.75
            pass
        elif eid == EID_MULT_BSSID_INDEX: # Std 8.4.2.76
            pass
        elif eid == EID_FMS_DESC: # Std 8.4.2.77
            pass
        elif eid == EID_FMS_REQ: # Std 8.4.2.78
            pass
        elif eid == EID_FMS_RESP: # Std 8.4.2.79
            pass
        elif eid == EID_QOS_TRAFFIC_CAP: # Std 8.4.2.80
            pass
        elif eid == EID_BSS_MAX_IDLE: # Std 8.4.2.81
            # 2 elements
            per,opts = struct.unpack_from('=HB',info)
            info = {'max-idle-per':per,'idle-ops':_eidbssmaxidle_(opts)}
        elif eid == EID_TFS_REQ: # Std 8.4.2.82
            pass
        elif eid == EID_TFS_RESP: # Std 8.4.2.83
            pass
        elif eid == EID_WNM_SLEEP: # Std 8.4.2.84
            # 3 elements, 1,1 and 2 octets
            act,stat,intv = struct.unpack_from('=2BH',info)
            info = {'act-type':act,'resp-status':stat,'interval':intv}
        elif eid == EID_TIM_REQ: # Std 8.4.2.85
            # 1 octet element (TIM BCAST Interval
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_TIM_RESP: # Std 8.4.2.86
            pass
        elif eid == EID_COLLOCATED_INTERFERENCE: # Std 8.4.2.87
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
        elif eid == EID_CH_USAGE: # Std 8.4.2.88
            pass
        elif eid == EID_TIME_ZONE: # Std 8.4.2.89
            pass
        elif eid == EID_DMS_REQ: # Std 8.4.2.90
            pass
        elif eid == EID_DMS_RESP: # Std 8.4.2.91
            pass
        elif eid == EID_LINK_ID: # Std 8.4.2.64
            # 3 elements, each is a mac address
            info = {'bssid':_hwaddr_(struct.unpack_from('=6B',info)),
                    'initiator':_hwaddr_(struct.unpack_from('=6B',info,6)),
                    'responder':_hwaddr_(struct.unpack_from('=6B',info,12))}
        elif eid == EID_WAKEUP_SCHED: # Std 8.4.2.65
            # 5 elements, 4 4 byte & 1 2 byte
            off,intv,slots,dur,cnt = struct.unpack_from('=4IH',info)
            info = {'offset':off,
                    'interval':intv,
                    'win-slots':slots,
                    'max-awake-dur':dur,
                    'idle-cnt':cnt}
        elif eid == EID_CH_SWITCH_TIMING: # Std 8.4.2.66 = 104
            # 2 element, each 2 byte
            swtime,swto = struct.unpack_from('=2H',info)
            info = {'switch-time':swtime,'switch-timeout':swto}
        elif eid == EID_PTI_CTRL: # Std 8.4.2.67
            # 2 elements 1 1 byte & 1 2 byte
            tid,seqctrl = struct.unpack_from('=BH',info)
            info = {'tid':tid,'seq-ctrl':seqctrl}
        elif eid == EID_TPU_BUFF_STATUS: # Std 8.4.2.68
            info = _eidtpubuffstat_(struct.unpack_from('=B',info)[0])
        elif eid == EID_INTERWORKING: # Std 8.4.2.94
            pass
        elif eid == EID_ADV_PROTOCOL: # Std 8.4.2.95
            pass
        elif eid == EID_EXPEDITED_BW_REQ: # Std 8.4.2.96
            # 1 element (precedence level)
            info = struct.unpack_from('=B',info)[0]
        elif eid == EID_QOS_MAP_SET: # Std 8.4.2.97
            pass
        elif eid == EID_ROAMING_CONS: # Std 8.4.2.98
            pass
        elif eid == EID_EMERGENCY_ALERT_ID: # Std 8.4.2.99
            # info is an 8-octet hash value
            info = hexlify(info)
        elif eid == EID_MESH_CONFIG: # Std 8.4.2.100
            # 7 1 octet elements
            vs = struct.unpack_from('=7B',info)
            info = {'path-proto-id':vs[0],
                    'path-metric-id':vs[1],
                    'congest-mode-id':vs[2],
                    'sync-id':vs[3],
                    'auth-proto-id':vs[4],
                    'mesh-form-id':_eidmeshconfigform_(vs[5]),
                    'mesh-cap':_eidmeshconfigcap_(vs[6])}
        elif eid == EID_MESH_ID: # Std 8.4.2.101
            pass
        elif eid == EID_MESH_LINK_METRIC_RPT: # Std 8.4.2.102
            pass
        elif eid == EID_CONGESTION: # Std 8.4.2.103
            # 5 elements 6|2|2|2|2
            sta = _hwaddr_(struct.unpack_from('=6B',info)),
            bk,be,vi,vo = struct.unpack_from('=4H',info,6)
            info = {'mesh-sta':sta, # dest-sta address
                    'ac-be':be,     # best effort avg access delay
                    'ac-bk':bk,     # background avg access delay
                    'ac-vi':vi,     # video avg access delay
                    'ac-vo':vo}     # voice avg access delay
        elif eid == EID_MESH_PEERING_MGMT: # Std 8.4.2.104
            pass
        elif eid == EID_MESH_CH_SWITCH_PARAM: # Std 8.4.2.105
            # 4 elements 1|1|1|2|2
            ttl,fs,res,pre = struct.unpack_from('=3B2H',info)
            info = {'ttl':ttl,
                    'flags':_eidmeshchswitch_(fs),
                    'reason':res,
                    'precedence':pre}
        elif eid == EID_MESH_AWAKE_WIN: # Std 8.4.2.106
            # 1 2-octect element
            info = struct.unpack_from('=H',info)[0]
        elif eid == EID_BEACON_TIMING: # Std 8.4.2.107
            pass
        elif eid == EID_MCCAOP_SETUP_REQ: # Std 8.4.2.108
            pass
        elif eid == EID_MCCOAP_SETUP_REP: # Std 8.4.2.109
            pass
        elif eid == EID_MCCAOP_ADV: # Std 8.4.2.111
            pass
        elif eid == EID_MCCAOP_TEARDOWN: # Std 8.4.2.112
            pass
        elif eid == EID_GANN: # Std 8.4.2.113
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
        elif eid == EID_RANN: # Std 8.4.2.114
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
        elif eid == EID_EXT_CAP: # Std 8.4.2.29
            pass
        elif eid == EID_PREQ: # Std 8.4.2.115
            pass
        elif eid == EID_PREP: # Std 8.4.2.116
            pass
        elif eid == EID_PERR: # Std 8.4.2.117
            pass
        elif eid == EID_PXU: # Std 8.4.2.118
            pass
        elif eid == EID_PXUC: # Std 8.4.2.119
            # 1|6
            vs = struct.unpack_from('=7B',info)
            info = {'pxu-id':vs[0],'pxu-recipient':_hwaddr_(vs[1:])}
        elif eid == EID_AUTH_MESH_PEER_EXC: # Std 8.4.2.120
            pass
        elif eid == EID_MIC: # Std 8.4.2.121
            pass
        elif eid == EID_DEST_URI: # Std 8.4.2.92
            ess = struct.unpack_from('=B',info)[0]
            info = {'ess-intv':ess,'uri':info[1:]}
        elif eid == EID_UAPSD_COEXIST: # Std 8.4.2.93
            pass
        elif eid == EID_MCCAOP_ADV_OVERVIEW: # Std 8.4.2.119
            # 1|1|1|1|2
            seqn, fs, frac, lim, bm = struct.unpack_from('=4BH', info)
            info = {'adv-seq-num': seqn,
                    'flags': {'accept': bits.leastx(1, fs),
                              'rsrv': bits.mostx(1, fs)},
                    'mcca-access-frac': frac,
                    'maf-lim': lim,
                    'adv-els-bm': bm}
        elif eid == EID_VEND_SPEC:
            # split into tuple (tag,(oui,value))
            vs = struct.unpack_from('=3B',info)
            info = {'oui':":".join(['{0:02X}'.format(v) for v in vs]),
                    'content':info[3:]}
        else:
            info = {'rsrv':info}
    except (struct.error,IndexError) as e:
        raise error(eid,e)
    return eid,info

# CONSTANTS for element ids Std 8.4.2.1
# reserved 17 to 31, 47, 49, 128, 129, 133-136, 143-173, 175-220, 222-255
# undefined 77,103
EID_SSID                    =   0
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
EID_MEAS_REQ                =  38
EID_MEAS_RPT                =  39
EID_QUIET                   =  40
EID_IBSS_DFS                =  41
EID_ERP                     =  42
EID_TS_DELAY                =  43
EID_TCLAS_PRO               =  44
EID_HT_CAP                  =  45
EID_QOS_CAP                 =  46
EID_RSN                     =  48
EID_EXTENDED_RATES          =  50
EID_AP_CH_RPT               =  51
EID_NEIGHBOR_RPT            =  52
EID_RCPI                    =  53
EID_MDE                     =  54
EID_FTE                     =  55
EID_TIE                     =  56
EID_RDE                     =  57
EID_DSE_REG_LOC             =  58
EID_OP_CLASSES              =  59
EID_EXT_CH_SWITCH           =  60
EID_HT_OP                   =  61
EID_SEC_CH_OFFSET           =  62
EID_BSS_AVG_DELAY           =  63
EID_ANTENNA                 =  64
EID_RSNI                    =  65
EID_MEAS_PILOT              =  66
EID_BSS_AVAIL               =  67
EID_BSS_AC_DELAY            =  68
EID_TIME_ADV                =  69
EID_RM_ENABLED              =  70
EID_MUL_BSSID               =  71
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
EID_MCCOAP_SETUP_REP        = 122
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
EID_VEND_SPEC               = 221

# SUUPORTED RATES/EXTENDED RATES Std 8.4.2.3 and 8.4.2.15
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
EID_SEC_CH_OFFSET_SCN = 0
EID_SEC_CH_OFFSET_SCA = 1
EID_SEC_CH_OFFSET_SCB = 3
# NOTE: 2, & 4-255 are reserved
def secchoffset(v):
    """ :returns: human readable secondary channel offset value """
    if v == EID_SEC_CH_OFFSET_SCN: return 'scn'
    elif v == EID_SEC_CH_OFFSET_SCA: return 'sca'
    elif v == EID_SEC_CH_OFFSET_SCB: return 'scb'
    else: return "rsrv-{0}".format(v)

# constants for TCLAS Processing Std Table 8-113
EID_TCLAS_PRO_ALL  = 0
EID_TCLAS_PRO_ONE  = 1
EID_TCLAS_PRO_NONE = 2
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
EID_TIE_TYPE_REASSOC  = 1
EID_TIE_TYPE_KET_LIFE = 2
EID_TIE_TYPE_COMEBACK = 3
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
STATUS_INVALID_RSNe_CAP                       =  45
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

###--> CTRL Frames Std 8.3.1
def _parsectrl_(f,m):
    """
     parse the control frame f into the mac dict
     :param f: frame
     :param m: mpdu dict
     NOTE: the mpdu dict is modified in place
    """
    if m.subtype == ST_CTRL_CTS or m.subtype == ST_CTRL_ACK: pass # do nothing
    elif m.subtype in [ST_CTRL_RTS,ST_CTRL_PSPOLL,ST_CTRL_CFEND,ST_CTRL_CFEND_CFACK]:
        try:
            # append addr2 and process macaddress
            v,m['offset'] = _unpack_from_(_S2F_['addr'],f,m['offset'])
            m['addr2'] = _hwaddr_(v)
            m['present'].append('addr2')
        except Exception as e:
            m['err'].append(('ctrl.{0}'.format(ST_CTRL_TYPES[m.subtype]),
                             "unpacking {0}".format(e)))
    elif m.subtype == ST_CTRL_BLOCK_ACK_REQ:
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
    elif m.subtype == ST_CTRL_BLOCK_ACK:
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
    elif m.subtype == ST_CTRL_WRAPPER:
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
                         "invalid subtype {0}".format(ST_CTRL_TYPES[m.subtype])))

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

#--> DATA Frames Std 8.3.2
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
    if ST_DATA_QOS_DATA <= m.subtype <= ST_DATA_QOS_CFACK_CFPOLL:
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
        keyid = struct.unpack_from(FMT_BO+_S2F_['wep-keyid'],f,
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

#### HELPERS

def validssid(s):
    """
     determines if ssid is valid
     :param s: ssid
     :returns True if ssid is 32 characters and utf-8, False otherwise:
    """
    if len(s) > 32: return False
    else:
        try:
            s.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False

def _unpack_from_(fmt,b,o):
    """
     unpack data from the buffer b given the format specifier fmt starting at o &
     returns the unpacked data and the new offset
     :param fmt: unpack format string
     :param b: buffer
     :param o: offset to unpack from
     :returns: new offset after unpacking
    """
    vs = struct.unpack_from(FMT_BO+fmt,b,o)
    if len(vs) == 1: vs = vs[0]
    return vs,o+struct.calcsize(fmt)