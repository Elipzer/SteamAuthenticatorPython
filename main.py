'''

The MIT License (MIT)

Copyright (c) 2015 Michael Peters

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

'''


import hmac
import hashlib
import struct
import time
import sys
import base64
import urllib
import urllib2
import json
from datetime import datetime
from binascii import unhexlify

def get_confirmation_key(time, secret, tag):
    # ---- NOT WORKING, but someone may know how to fix it?
    #
    # time - The Unix time for which you are generating this secret. Generally should be the current time.
    # secret - The identity_secret that you received when enabling two-factor authentication
    # tag - The tag which identifies what this request (and therefore key) will be for. "conf" to load the confirmations page, "details" to load details about a trade, "allow" to confirm a trade, "cancel" to cancel it.
    # returns key to confirm trades, 
    v = long_to_bytes(long(time))
    if tag:
        v += tag
    print 'value: ' + v.encode('hex')

    h = hmac.new(base64.b64decode(secret), v, hashlib.sha1)
    return h.hexdigest()

def long_to_bytes(val, endianness='big'):
    width = 64#force 64 bit long

    fmt = '%%0%dx' % (width // 4)

    s = unhexlify(fmt % val)

    if (endianness == 'little'):
        s = s[::-1]

    return s

def get_server_time():
    SYNC_URL = 'https://api.steampowered.com:443/ITwoFactorService/QueryTime/v0001'
    values = {}
    data = urllib.urlencode(values)
    req = urllib2.Request(SYNC_URL, data)
    resp = urllib2.urlopen(req)
    resp_text = resp.read()
    print resp_text
    json_resp = json.loads(resp_text)
    return json_resp['response']['server_time']

STEAM_CHARS = ['2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y']

toLong = lambda x: long(x.encode('hex'), 16)


local = lambda: long(round(time.mktime(time.localtime(time.time())) * 1000))
timediff = local() - (long(get_server_time()) * 1000)
codeinterval = lambda: long((local() + timediff) / 30000)

print 'Local: ' + str(local())
print 'timediff: ' + str(timediff)
print 'codeinterval: ' + str(codeinterval())

v = long_to_bytes(codeinterval())#for some reason, this does not need to be little endian even on my little-endian machine

print 'value: ' + v.encode('hex')

h = hmac.new(base64.b32decode('<secretkey>'), v, hashlib.sha1)

digest = h.digest()

print 'digest: ' + digest.encode('hex')

start = toLong(digest[19]) & 0x0f

print 'start: ' + str(start)

b = digest[start:start + 4]

print 'bytes: ' + b.encode('hex')

#for some reason, this does not need to be little endian even on my little-endian machine
#if (sys.byteorder == 'little'):
#    b = b[::-1]

fullcode = toLong(b) & 0x7fffffff

print 'fullcode: ' + long_to_bytes(fullcode).encode('hex')

CODE_LENGTH = 5
code = ''
for i in range(CODE_LENGTH):
    code += STEAM_CHARS[fullcode % len(STEAM_CHARS)]
    fullcode /= len(STEAM_CHARS)
print code
