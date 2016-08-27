# itamae 0.1.1: 802.11 parser
![](logo/itamae.png?raw=true)

[![License: GPLv3](https://img.shields.io/pypi/l/itamae.svg)](https://github.com/wraith-wireless/itamae/blob/master/LICENSE)
[![PyPI Version](https://img.shields.io/pypi/v/itamae.svg)](https://pypi.python.org/pypi/itamae)
![Supported Python Versions](https://img.shields.io/pypi/pyversions/itamae.svg)
![Software status](https://img.shields.io/pypi/status/itamae.svg)

## 1 DESCRIPTION:
Itamae is a raw (packed binary data) 802.11 parser. Consider the OSI model:
```
 +-------------+
 | Application |
 +-------------+
 | Presentation|
 +-------------+
 | Session     |
 +-------------+     
 | Transport   |  
 +-------------+ 
 | Network     | /+-----------+   
 +-------------+/ | MSDU (LLC)|   
 | Data-Link   |  +-----------+
 +-------------+\ | MPDU (MAC)|
 | Physical    | \+-----------+
 +-------------+ 
```
Layer 2, the Data-Link layer can be subdivided into the MAC Service Data Unit 
(MSDU) or IEEE 802.2 Logical Link Control and the MAC Protocol Data Unit (MPDU).
Itamae is concerned with parsing the MPDU or 802.11 frame and parsing meta-data
about the Layer 1, Physical layer as found in <a href="http://www.radiotap.org">Radiotap</a>. 
ATT, itamae does not support Prism or AVS at Layer 1 and it does not parse 
anything at the LLC sublayer or above. In the future, I plan on extending it 
into the Network layer and include 802.1X parsing.
 
Itamae is not intended to be a substitute for Scapy. Use Scapy if you
 
 * need to parse TCP/IP, 
 * need to craft packets, or
 * need to inject packets.

Itamae is intended to meet a niche set of goals and is ideal if 

 * speed and efficiency is a requirement,
 * you only need 802.11 support, and
 * you are only parsing, not building packets.
 
When parsing raw data, Itamae is six times faster than Scapy and has a reduced 
overhead in terms of object size because it uses minimal classes. However, unlike 
Scapy, Itamae does not offer socket support (you'll have to bind and sniff your 
own sockets) and it is not layered. See Section 3: Using for an explanation.

## 2. INSTALLING:

### a. Requirements
Itamae requires Python 2.7. I have no plans on supported Python 3.x as doing so 
makes the code ugly. If at such a time as Python 3 becomes the defacto standard, 
I will move it to Python 3. Itamae has been tested on Linux but, as of yet, has
not been tested on Windows or MAC OS.

### b. Install from Package Manager
Install itamae through PyPI:

    sudo pip install itamae

### c. Install from Source
Itamae can also be installed from source. Download from http://wraith-wireless.github.io/itamae 
or https://github.com/wraith-wireless/itamae. Once downloaded, extract the files 
and from the itamae directory run:

    sudo python setup.py install

## 3. USING

Before using Itamae, you'll need a wireless card in monitor mode and a raw socket. 
You can use iw (or, shameless plug follows <a href="https://github.com/wraith-wireless/PyRIC">PyRIC</a>) 
to create a virtual interface and use the Python socket module to bind the raw 
socket. Before showing Itamae examples, let's set up our card and socket. You'll
need to be root to do so.

```python
>>> import pyric.pyw as pyw
>>> import socket

>>> card = pyw.getcard('wlan0')
>>> pyw.phyadd(card,'mon0','monitor')
>>> sock = socket.socket(socket.AF_PACKET,
...                      socket.SOCK_RAW,
...                      socket.htons(0x0003))
>>> sock.bind((card.dev,0x0003))
```

With the raw socket ready, we can read the raw frames and parse them with Itamae.
 
```python
>>> from itamae.mpdu import MAX_MPDU
>>> raw = sock.recv(MAX_MPDU)
```

Before showing how to parse with Itamae, it is best to describe how the RTAP 
object and MPDU object are handled. Each is a wrapper around a dict that exposes 
certain fields using the '.' operator. And for each, the respective parse 
function takes a byte stream and returns the appropriate layer dict. Unlike Scapy 
and other protocol parsers, Itamae does not parse and/or treat RTAP and MPDU as 
a layered hierarchy. That is, the parsed MPDU is not an object contained within 
the radiotap object.

For the following examples we will be parsing three frames as shown below:

```python
>>> len(raw1), raw1
(171, "\x00\x00\x12\x00.H\x00\x00\x00$l\t\xc0\x00\xb5\x01\x00\x00\x88A0\x00
\x04\xa1Q\xd0\xdc\x0f\xb04\x95n0\x02\x04\xa1Q\xd0\xdc\x0f\x00<\x00\x00\x07\x08
\x00 \n\x00\x00\x00\xa9\xe6\xfc\x98  T\xe4\xed\xf5\x01w`\xe76\x18@D.'\xaf:;\xa3
\xff\xf2\xb8\x88J\xe8\xeeL\x84\xaf\x08$\x1e\x87\xbc\x8e\xa0\x8e\x86\xd1\xce\xa26
\x84\xa4.\xf5#\xff\xc07`\xd4\xb2\xe4\xaf\n\x01\xcby\x9e4\xb5\xac:0a]\x9d\xfb
\xbf5X\xb3\xc5-f\xca0\xb77~4\xd5\xbf9\x8d\xf3oZ\xcb\xe6>t\xd35\x01\x1c%\x19
\x8cD+\xd6\xc7W\x81\xcb\xd6\x97O.\xde\x07\x11")
>>>
>>> len(raw2), raw2
(153, "\x00\x00\x15\x00*H\x08\x00\x00\x00\x9e\t\x80\x04\xc3\x01\x00\x00\x07
\x00\x05\x88\xc1,\x00\x08\x86;C\xf2h\x949\xe5i\xcf\x0b\xff\xff\xff\xff\xff
\xff\x90\x1a\x00\x00\xc0\xff\x00\xc0RM\x00 \x0b\x00\x00\x00!\xd0M$6\x15\x8f5;
\xaf\xc1\xee_\xae\x84 >\xc72\xdaJ-\xb6\xb61\x85+\xa1\xe4\xd1ys\xe9B\xe4\x8b%
\xaa\xe0j\xdf\x86\x04\xe6\x88\x89g\x11\x85\xb4\x0f\xbcI'Df\xcd\xbf\x83\xf5
\x10\xec\x1b\xa1FMD\x81\xcb\xbe\xa9qO\xc3\xb8\xecL\xb6[:\xe2h\xd5\x13\xbd
\xdd\x94\xd6\xe2\xa6)\xd8\x9b\xab")
>>>
>>> len(raw3), raw3
(38, '\x00\x00\x12\x00.H\x00\x00\x100l\t\xc0\x00\xbe\x03\x00\x00\xb4\x00\x80
\x00\xac\xb5}\x8d;0<F\xd8~\x0e\xdd\xc2U0\xde')
```

As can be seen from above the sizes of the frames are 171 bytes, 153 bytes and 38 
bytes respectively.

Let us begin parsing with radiotap, radiotap.parse() returns a RTAP object. RTAP 
always exposes three fields: the version, the size and the present list. RTAP will
also expose certain other commonly found fields via the '.' operator and for all
others, the bracket(s) operator will work. Parsing raw1 we get:

```python
>>> import itamae.radiotap as rtap
>>> dR1 = rtap.parse(raw1)
>>> dR1
{'sz': 18, 'vers': 0, 'antenna': 1, 'rx-flags': 0, 'antsignal': -75, 'rate': 36, 
'flags': 0, 'channel': [2412, 192], 'present': ['flags', 'rate', 'channel', 
'antsignal', 'antenna', 'rx-flags']}
>>> dR1.vers,dR1.sz,dR1.present
(0, 18, ['flags', 'rate', 'channel', 'antsignal', 'antenna', 'rx-flags'])
>>> 
```

So far, we have read a raw frame of 171 bytes (which as we will see later is 
a data frame) off our monitor interface and parsed the radiotap "layer". We can 
print the version (0), size, in bytes, (18) and the list of present fields (flags, 
rate, channel, antsignal, antenna and rx-flags). Let us continue with the present 
fields (see http://www.radiotap.org/defined-fields for a listing
of all defined fields):
 
 * flags: frame properties. see http://www.radiotap.org/defined-fields/Flags
 * rate: TX/RX data rate (in 500Kbps)
 * channel: a set (list) where the first item is the frequency and the second
  is the channel flags
 * antsignal: received signal power in dBM
 * antenna: the antenna index starting at 0. 
 * rx-flags: received frame properties. see http://www.radiotap.org/defined-fields/RX%20flags
 
We could get the field values using the bracket operator on the returned RTAP 
object or as mentioned above use the '.' operator. Below, we show both methods.

```python
>>> print "Antenna: via '[]' = {0} & '.' = {1}".format(dR1['antenna'],dR1.antenna)
Antenna: via '[]' = 1 & '.' = 1
>>> 
>>> print "Signal Strength: via '[]' = {0} & '.' = {1}".format(dR1['antsignal'],dR1.rss)
Signal Strength: via '[]' = -75 & '.' = -75
>>> 
>>> print "Flags: via '[]' = {0} & '.' = {1}".format(radiotap.flags(dR1['flags']),dR1.flags)
Flags: via '[]' = [] & '.' = []
>>>
>>> print "Data rate: via '[]' = {0} & '.' = {1}".format(dR1['rate'],dR1.rate)
Data rate: via '[]' = 36 & '.' = 18.0
```

Antenna (the index 0-based of the antenna that read the signal) and Signal strength 
(strength of the received signal in dBm) are straightforward. Regardless of which 
method you use, you will get the same result. Looking at flags, notice that by
using the brackets, additional manipulation was required to get the same result
as using the '.' operator. This is because dR['flags'] returns the value of 
the flags field whereas dR.flags returns a list of flags present in the flags
field. Finally, looking at the data rate, we get two different results. Once
again this is because the '.' will execute additional parsing for you. Using the
brackets, dR['rate'] returns the rate in 500kbps IAW the radiotap definition but
the '.' operator, dR.rate returns the rate in Mbps. As we will see in a later 
example, dR.rate also handles cases where the data rate is not defined in the 
rate field but is calculated via the mcs field. 

```python
>>> dR1['channel']
[2412, 192]
>>> dR1['channel'][0], radiotap.chflags(dR1['channel'][1])
(2462, ['ism', 'ofdm'])
>>>
>>> dR1.channel, dR1.chflags
```

Some radiotap fields like channel are multipart. RTAP treats these as a list. In
the case of the channel (see http://www.radiotap.org/defined-fields/Channel) 
the first 'subfield' is the frequency in MHz and the second subfield is bitmap.
You can manually parse this as above or use the '.' operator and let RTAP do the 
hard work for you. In this example, the frame is transmitted on 2 GHz ('ism') and 
it's a CCK channel (see http://www.radiotap.org/defined-fields/Channel for a full 
listing of all channel flags). 

Parsing the frame raw 2, the first thing to note is that there is no rate field 
defined. That is because we have an 'HT', 802.11n frame as can be seen by the 
presence of an mcs field. Secondly, instead of a CCK channel, we have a Dyanamic 
CCK-OFDM channel.  

```python
>>> import itamae.mcs as mcs
>>> dR2 = rtap.parse(raw2)
>>> dR2
{'sz': 21, 'vers': 0, 'antenna': 1, 'rx-flags': 0, 'antsignal': -61, 'flags': 0, 
'present': ['flags', 'channel', 'antsignal', 'antenna', 'rx-flags', 'mcs'], 
'mcs': [7, 0, 5], 'channel': [2462, 1152]}
>>>
>>> dR2.chflags
['ism', 'dcck']
```

To get the rate, we could do some additional parsing. The mcs field is a triple 
(known, flags, index) see http://www.radiotap.org/defined-fields/MCS. Using the 
mcsflags_param function with known and flags, returns 'bw' (bandwidth) with a 
value of 0 and 'gi' (guard interval) with a value of 0. The bandwidth of this 
signal is 20MHz (0 = 20, 1 = 40, 2 = 20L and 3 = 20U), and the guard interval is 
long (800ns). Passing these along with our mcs index to the mcs_rate we get a 
rate of 57.8Mbps. Or we could simply just use the rate property of the RTAP
object which does the work for us.

```python
>>> mcsflags = rtap.mcsflags_params(dR2['mcs'][0],dR2['mcs'][1])
>>> mcsflags
{'bw': 0, 'gi': 0}
>>> if mcsflags['bw'] == rtap.MCS_BW_20: bw = '20'
... elif mcsflags['bw'] == rtap.MCS_BW_40: bw = '40'
... elif mcsflags['bw'] == rtap.MCS_BW_20L: bw = '20L'
... else: bw = '20U'
... 
>>> gi = 1 if 'gi' in mcsflags and mcsflags['gi'] > 0 else 0
>>> index = dR2['mcs'][2]
>>> gi, ht, index
(0, 0, 5)
>>> width = int(bw[:2])
>>> rate = mcs.mcs_rate(index,width,gi)
>>> rate
57.8
>>>
>> dR2.rate
>>> 57.8
```

So far we have covered the fields you will most likely encounter and shown how
RTAP does the heavy lifting. There are cases where you may come across additional 
fields which will require 'manual' parsing. Radiotap provides the functions to do 
so and can review http://www.radiotap.org or the radiotap source code for help 
along the way.

To parse the MPDU layer, we need to pass the raw frame at the beginning 
of layer two. For that, we need to refer back to the size of the radiotap
frame. Additionally, depending on your interface's firmware the raw frame
may include the MPDU's FCS. If it is included, it will be set in the radiotap's
flags field. The MPDU dict exposes the toplevel MPDU fields via the '.' operator. 
They are framectrl, duration, addr1 ... addr4 (as present), seqctrl, qosctrl,
crypt and fcs. For convience it also exposes some sublevel fields:
vers, type (framectrl->type), subtype (framectrl->subtype) and flags
(framectrl->flags) as well as non-MPDU fields, offset, stripped, size, 
present and error.

```python
>>> import itamae.mpdu as mpdu
>>> hasFCS = 'fcs' in dR1.flags
>>> hasFCS 
0
>>> dM = mpdu.parse(raw1[dR1.sz:],hasFCS)
>>> dM.error
[]
>>> dM.size, dM.offset, dM.stripped
(42, 34, 8)
>>>
>>> for field in dM.present: print "{0}: {1}".format(field, dM[field])
... 
framectrl: {'subtype': 8, 'vers': 0, 'type': 2, 
            'flags': {'md': 0, 'mf': 0, 'o': 0, 'r': 0, 'fd': 0, 'pf': 1, 
            'td': 1, 'pm': 0}}
duration: {'dur': 48, 'type': 'vcs'}
addr1: 04:a1:51:d0:dc:0f
addr2: b0:34:95:6e:30:02
addr3: 04:a1:51:d0:dc:0f
seqctrl: {'seqno': 960, 'fragno': 0}
qos: {'tid': 0, 'a-msdu': 0, 'ack-policy': 0, 'eosp': 0, 'txop': 0}
l3-crypt: {'mic': '\xcb\xd6\x97O.\xde\x07\x11', 'rsrv': '\x00', 'pn5': '\x07', 
           'pn1': '\x08', 'pn0': '\x07', 'pn3': '\x00', 'pn2': '\n', 
           'type': 'ccmp', 'pn4': '\x00', 'key-id': {'ext-iv': 1, 'rsrv': 0, 
                                                     'key-id': 0}}
```

The fields size, offset, stripped and error are not included in the present list 
as they are not official components of a MPDU. They define, in order, the total 
size in bytes of the MPDU frame, the bytes read from the front, the bytes read 
from the end (in this case the 8 bytes of the MIC of the CCMP encryption but it 
would also include FCS if present) and any errors encountered during parsing. 
mpdu parse will attempt to continue parsing in the event of errors, appending 
errors to the error list.

Keeping in mind that mpdu.parse begins at the first byte of the MPDU, the total 
bytes parsed (including the radiotap) would be 60 (18 + 34 + 8). If you wanted 
to look at the unparsed bytes i.e. the LLC sub layer, Layer 3 etc you would 
slice as follows:
 
```python [dR.sz+dM.offset:-dM.stripped]``` 

Examining the frame control field we see that the type is 2 (Data) and the 
subtype is 8 (QoS) and that the protected frame flag and to ds flag are set.
Remember these are also exposed via the '.' operator. If you need to get 
a "human-readable" version try:

```python
>>> mpdu.type_desc
'data'
>>> mpdu.subtype_desc
'qos-data'
```

Moving on, we see that the duration field is another dict duration: {'dur': 48, 
'type': 'vcs'}. Defining the duration field is outside the scope of this 
document. For further information see the 802.11-2012 or CWAP Certified
Analysis or search on google. This frame has three address which are self
explanatory. Next is the sequence control field which is also another dict 
containing the fragment number and sequence number. However, l3-crypt does
relay the type of encryption used in the 'type' field. In this case, it is
CCMP.

The last two fields are the QoS control field and the layer 3 encryption 
field. Again, it is outside the scope of this document to define each of 
these. 

Finally, let us parse a frame where the FCS was not stripped by the firmware.
We'll also show using the '.' operator vice bracket(s) operator.

```python
>>> dR3 = radiotap.parse(dR3)
>>> dR3.flags
['fcs']
>>>
>>> dM3 = mpdu.parse(raw3[dR3.sz:],'fcs' in dR3.flags)
>>> dM3.size, dM3.offset, dM3.stripped
(20, 16, 4)
>>> dM3.fcs
3727709634
>>>
>>> dM3.type_desc, dM3.subtype_desc
('ctrl', 'rts')
>>> dM3.flags
{'md': 0, 'mf': 0, 'o': 0, 'r': 0, 'fd': 0, 'pf': 0, 'td': 0, 'pm': 0}
>>> dM3.addr1, dM3.addr2
('ac:b5:7d:8d:3b:30', '3c:46:d8:7e:0e:dd')
>>>
>>> dR3.sz + dM3.size == len(raw3)
True
```

The raw frame dM3 is an RTS frame with FCS present. Because control frames
have no layer 3 content (in reality, no MSDU - LLC either) Itamae has 
parsed the entire frame: this is verified by comparing the total bytes
parsed with the length of the raw frame.

### Moving Foward
ATT, there are still some further steps to take. Radiotap needs to be tested
against Atheros card to ensure that the data padding is handled correctly. 
For MPDU, control wrappers and a-msdu are not parsed. I have not found
any test frames to use with a HT control field to test against.
 
To improve, I also want to parse more info-elements including RSN, TIM
and vendor-related as well as provide for 802.1X parsing and possibly 
parsing of layer 3 if not encrypted.

Finally, I would also like to look into using a buffer instead of a string
to minimize the number of string copies.

## 4. ARCHITECTURE/HEIRARCHY:
Brief Overview of the project file structure. Directories and/or files annotated
with (-) are not included in pip installs or PyPI downloads

* itamae                  root Distribution directory
  - \_\_init\_\_.py       initialize distrubution module
  - logo (-)              logo directory
    + itamae.png (-)      image for README
  - setup.py              install file
  - setup.cfg             used by setup.py
  - MANIFEST.in           used by setup.py
  - README.md             this file
  - LICENSE               GPLv3 License
  - CHANGES               revision file
  - TODO                  todos for itamae
  - itamae                package directory
    + \_\_init\_\_.py     initialize itamae module
    + radiotap.py         parse radiotap
    + mpdu.py             parse the MPDU of layer 2
    + dot11u.py           constants for 802.11u
    + mcs.py              mcs index, modulation and coding
    + bits.py            bitmask related functions