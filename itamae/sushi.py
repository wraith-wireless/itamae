#!/usr/bin/env python
""" sushi: parse Radiotap and MPDU

Copyright (C) 2016  Dale V. Patterson (wraith.wireless@yandex.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

Redistribution and use in source and binary forms, with or without modifications,
are permitted provided that the following conditions are met:
 o Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 o Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 o Neither the name of the orginal author Dale V. Patterson nor the names of any
   contributors may be used to endorse or promote products derived from this
   software without specific prior written permission.

Parses raw 802.11 captures i.e. packed bytes. Raw bytes can be in the form of 
a string or memoryview

"""
__name__ = 'sushi'
__license__ = 'GPL v3.0'
__version__ = '0.0.1'
__date__ = 'September 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

import itamae.radiotap as rtap
import itamae.mpdu as mpdu

def bento(f):
    """
     parses raw frame 
     :param f: raw bytes (string or memoryview) of the frame
     :returns: tuple t = (Radiotap dict, MPDU dict, remaining bytes,error)
      where error is None if no non-recoverable error(s) occurred or a string
      describing the error
    """
    dR = rtap.RTAP() # make an empty rtap dict
    dM = mpdu.MPDU() # & an empty mpdu dict
    err = None
    try:
        dR = rtap.parse(f)
        dM = mpdu.parse(f[dR.size:],'fcs' in dR.flags)
    except (rtap.error,mpdu.error) as e:
        err = e
    
    return dR,dM,f[dR.size+dM.offset:-dM.stripped],err
