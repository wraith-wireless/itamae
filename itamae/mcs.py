#!/usr/bin/env python

""" mcs.py: mcs index functions 

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

provides mcs index, modulation and coding functions

NOTE: does not support VHT/802.11ac

"""
__name__ = 'mcs'
__license__ = 'GPL v3.0'
__version__ = '0.0.2'
__date__ = 'July 2016'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Production'

# modulation and coding rate Table 20-30 thru 20-35 Std (these repeat 0-7, 8-15 etc)
MCS_HT_INDEX = ["BPSK 1/2",
                "QPSK 1/2",
                "QPSK 3/4",
                "16-QAM 1/2",
                "16-QAM 3/4",
                "64-QAM 2/3",
                "64-QAM 3/4",
                "64-QAM 5/6"]

# mcs rates see tables 20-30 thru 20-37 of Std
# TODO: add up table 20-44
MCS_HT_RATES = [{20:{1:7.2,0:6.5},40:{1:15,0:13.5}},     # mcs index 0
                {20:{1:14.4,0:13},40:{1:30,0:27}},       # mcs index 1
                {20:{1:21.7,0:19.5},40:{1:45,0:40.5}},   # mcs index 2
                {20:{1:28.9,0:26},40:{1:60,0:54}},       # mcs index 3
                {20:{1:43.3,0:39},40:{1:90,0:81}},       # mcs index 4
                {20:{1:57.8,0:52},40:{1:120,0:108}},     # mcs index 5
                {20:{1:65,0:58.5},40:{1:135,0:121.5}},   # mcs index 6
                {20:{1:72.2,0:65},40:{1:150,0:135}},     # mcs index 7
                {20:{1:14.4,0:13},40:{1:30,0:27}},       # mcs index 8
                {20:{1:28.9,0:26},40:{1:60,0:54}},       # mcs index 9
                {20:{1:43.3,0:39},40:{1:90,0:81}},       # mcs index 10
                {20:{1:57.8,0:52},40:{1:120,0:108}},     # mcs index 11
                {20:{1:86.7,0:78},40:{1:180,0:162}},     # mcs index 12
                {20:{1:115.6,0:104},40:{1:240,0:216}},   # mcs index 13
                {20:{1:130.3,0:117},40:{1:270,0:243}},   # mcs index 14
                {20:{1:144.4,0:130},40:{1:300,0:270}},   # mcs index 15
                {20:{1:21.7,0:19.5},40:{1:45,0:40.5}},   # mcs index 16
                {20:{1:43.3,0:39},40:{1:90,0:81}},       # mcs index 17
                {20:{1:65,0:58.5},40:{1:135,0:121.5}},   # mcs index 18
                {20:{1:86.7,0:78},40:{1:180,0:162}},     # mcs index 19
                {20:{1:130,0:117},40:{1:270,0:243}},     # mcs index 20
                {20:{1:173.3,0:156},40:{1:360,0:324}},   # mcs index 21
                {20:{1:195,0:175.5},40:{1:405,0:364.5}}, # mcs index 22
                {20:{1:216.7,0:195},40:{1:450,0:405}},   # mcs index 23
                {20:{1:28.9,0:26},40:{1:60,0:54}},       # mcs index 24
                {20:{1:57.8,0:52},40:{1:120,0:108}},     # mcs index 25
                {20:{1:86.7,0:78},40:{1:180,0:162}},     # mcs index 26
                {20:{1:115.6,0:104},40:{1:240,0:216}},   # mcs index 27
                {20:{1:173.3,0:156},40:{1:360,0:324}},   # mcs index 28
                {20:{1:231.1,0:208},40:{1:480,0:432}},   # mcs index 29
                {20:{1:260,0:234},40:{1:540,0:486}},     # mcs index 30
                {20:{1:288.9,0:260},40:{1:600,0:540}}]   # mcs index 31

def mcs_coding(i):
    """
     given the mcs index i, returns a tuple (m=modulation & coding rate,s= # of
     spatial streams)

     :param i: mcs index
     :returns: tuple t = (modulation & coding rate,number of spatial streams)
    """
    if i < 0 or i > 31:
        raise ValueError("mcs index {0} must be 0 <= i <= 32".format(i))
    (m,n) = divmod(i,8)
    return MCS_HT_INDEX[n],m+1

def mcs_rate(i,w,gi):
    """
     given the mcs index i, channel width w and guard interval returns the data rate

     :param i: mcs index
     :param w: channel width
     :param gi: guard interval (0 for short, 1 for long)
     :returns: data rate
    """
    if i < 0 or i > 31: raise ValueError("mcs index {0} must be 0 <= i <= 32".format(i))
    if not(w == 20 or w == 40): raise ValueError("mcs width {0} must be 20 or 40".format(w))
    if gi < 0 or gi > 1: raise ValueError("mcs guard interval {0} must be 0:short or 1:long".format(gi))
    return MCS_HT_RATES[i][w][gi]

def mcs_width(i,dr):
    """
     given mcs index i & data rate dr, returns channel width and guard interval

     :param i: mcs index
     :param dr: data rate
     :returns: tuple t = (channel width,guard interval)
    """
    if i < 0 or i > 31: raise ValueError("mcs index {0} must be 0 <= i <= 32".format(i))
    for w in MCS_HT_RATES[i]:
        for gi in MCS_HT_RATES[i][w]:
            if MCS_HT_RATES[i][w][gi] == dr:
                return w,gi
    return None
