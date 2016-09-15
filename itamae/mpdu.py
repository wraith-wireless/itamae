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

Parses the 802.11 MAC Protocol Data Unit (MPDU) IAW IEEE 802.11-2012 (Std).

NOTE:
 It is recommended not to import * as it may cause conflicts with other modules

"""

__name__ = 'mpdu'
__license__ = 'GPL v3.0'
__version__ = '0.1.3'
__date__ = 'September 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

import struct
import itamae.bits as bits
import itamae.ieee80211 as std
import itamae._mpdu as _mpdu

class error(EnvironmentError): pass

# SOME CONSTANTS
BROADCAST = "ff:ff:ff:ff:ff:ff" # broadcast address
MAX_MPDU = 7991                 # maximum mpdu size in bytes

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
            return std.FT_TYPES[self.type]
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
            if self.type == std.FT_MGMT: return std.ST_MGMT_TYPES[self.subtype]
            elif self.type == std.FT_CTRL: return std.ST_CTRL_TYPES[self.subtype]
            elif self.type == std.FT_DATA: return std.ST_DATA_TYPES[self.subtype]
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

    def getie(self,ie):
        """
         returns value of specified ie (if present)
         :param ie:
         :returns: value for info element field ie if present else None
        """
        for eid,val in self.info_els:
            if eid == ie: return val
        return None

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
        vs,offset = _mpdu._unpack_from_(_mpdu._S2F_['framectrl'],f,0)
        m = MPDU({'framectrl':{'vers':bits.leastx(2,vs[0]),
                               'type':bits.midx(2,2,vs[0]),
                               'subtype':bits.mostx(4,vs[0]),
                               'flags':_mpdu._fcflags_(vs[1])},
                  'present':['framectrl'],
                  'offset':offset,
                  'stripped':0,
                  'err':[]})
        vs,m['offset'] = _mpdu._unpack_from_(_mpdu._S2F_['duration'] + _mpdu._S2F_['addr'],f,m['offset'])
        m['duration'] = _mpdu._duration_(vs[0])
        m['addr1'] = _mpdu._hwaddr_(vs[1:])
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
        if m.type == std.FT_MGMT: _mpdu._parsemgmt_(f,m)
        elif m.type == std.FT_CTRL: _mpdu._parsectrl_(f,m)
        elif m.type == std.FT_DATA: _mpdu._parsedata_(f,m)
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
                    if (bs[0] | 0x20) & 0x7f == bs[1]: _mpdu._tkip_(f,m)
                    else: _mpdu._ccmp_(f,m)
                else: _mpdu._wep_(f,m)
                if 'l3-crypt' in m: m['present'].append('l3-crypt')
            except struct.error as e:
                m['err'].append(('l3-crypt',"unpacking encryption {0}".format(e)))
            except Exception as e:
                m['err'].append(('l3-crypt',"testing for encryption {0}".format(e)))

    # append the fcs to present if necessary and return the mpdu dict
    if hasFCS: m['present'].append('fcs')
    return m

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
    if ft == std.FT_MGMT: return std.ST_MGMT_TYPES[st]
    elif ft == std.FT_CTRL: return std.ST_CTRL_TYPES[st]
    elif ft == std.FT_DATA: return std.ST_DATA_TYPES[st]
    else: return 'rsrv'

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

