#!/usr/bin/env python
""" itamae: 802.11 parsing

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

Defines functions to parse raw 802.11 captures i.e. packed bytes.


Also defines constansts for PyPI packaging.
Partial support of 802.11-2012
Currently Supported
802.11a\b\g

Partially Supported
802.11n

Not Supported
802.11s\y\ac\ad\af

Requires:
 linux (3.x or 4.x kernel)
 Not tested on Windows or Mac OS
 Python 2.7

 pyric 0.1.5 through 0.1.6
  desc: provides tools to parse raw wireless traffic
  includes: dotllu 0.0.1, mcs 0.0.2, radiotap 0.0.5, mpdu 0.1.2
  changes:
   See CHANGES in top-level directory


WARNING: Be careful if importing * (all)

"""
__name__ = 'itamae'
__license__ = 'GPL v3.0'
__version__ = '0.1.1'
__date__ = 'August 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

# for out setup.py
version = __version__

long_desc = """
Itamae is a simple yet robust raw 802.11 frame parser. It is designed to be easy
and fast to use providing all 802.11 MPDU fields/values and radiotap fields/values.

Itamae is not designed to replace Scapy but is meant to be used when speed of
parsing is important.
"""