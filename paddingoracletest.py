#!/usr/bin/python
# paddingoracletext.py - implementation of a padding oracle and an
# padding oracle attack which decrypts a given crypt text with usage
# of the oracle. This was implemented for learning myself about such
# lind of attacks.
#
# Copyright 2012 Thomas Skora <thomas@skora.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import binascii
from Crypto.Cipher import AES

### Parameters ###
key = binascii.unhexlify('0123456789ABCDEF0123456789ABCDEF')
iv = key
plaintext = "This is a test for a padding oracle attack."
blocksize = AES.block_size
##################

def binprint(bin):
    hex = binascii.hexlify(bin)
    spaced = str()
    for i in range(0, len(hex), blocksize * 2):
        spaced = spaced + " " + hex[i:i + blocksize * 2]
    
    return spaced

# Encrypts plain text with given key and iv. Adds pkcs#7 padding.
def encryptor(key, iv, pt):
    padlen = (blocksize - (len(pt) % blocksize))
    padchar = chr(padlen)
    pt = pt + padlen * padchar
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pt)
    
# decrypts and returns the state of the padding (good or broken)
def padding_oracle(msg):
#    print "Padding Oracle Input: " + binprint(msg)
    miv = msg[:blocksize]
    mct = msg[blocksize:]
    cipher = AES.new(key, AES.MODE_CBC, miv)
    pt = cipher.decrypt(mct)
    pad = pt[-1]
    padlen = ord(pad)
#    print "Padding Oracle Padding length: " + str(padlen)
    if padlen > len(pt) or padlen == 0:
        return False
    for i in range(len(pt) - padlen, len(pt)):
        if (pt[i] != pad):
            return False
    return True

### Main ###
ct = encryptor(key, iv, plaintext);

if (padding_oracle(ct)):
    print "Padding of crypt text is ok."
else:
    print "Padding of crypt text is broken."

# decomposite ciphertext into blocks
ctb = []
blocks = len(ct) / blocksize
print str(blocks) + " blocks"
for i in range(0, len(ct), blocksize):
    ctb.append(ct[i:i + blocksize])

ptb = [""]
for i in range(1, blocks):              # iterate over blocks from first one
    print "Block " + str(i) + ": "
    iv = blocksize * list("\x00");      # this is the calculated iv to get a valid padding
    block = ctb[i]                      # current cipher text block
    ptb.append(16 * list("\x00"))       # append nulled plain text block
    j = blocksize - 1                   # current position in block, starting at the end
    pad = "\x01"                        # current padding character, starting at 0x01
    while j >= 0:                       # iterate over iv from end (iv[j])
        print "- IV byte " + str(j + 1)
            
        print "Trying bytes...",
        for k in range(0, 256):         # brute force until an iv[j] is found, which causes a valid padding
            print str(k),
            iv[j] = chr(k)
            if padding_oracle("".join(iv) + block): # found it!
                print
                l = 1
                while j - l >= 0:     # but first verify, if we hit a bigger padding block as expected
                    print "Verifying if byte " + str(j - l + 1) + " is also padding...",
                    iv[j - l] = chr(ord(iv[j - l]) + 1 % 255)
                    if padding_oracle("".join(iv) + block): # iv[j-l] was not relevant for the valid padding - restore iv and cancel scan
                        print "no"
                        iv[j - l] = chr(ord(iv[j - l]) - 1 % 255)
                        l = l - 1
                        break
                    print "yes"
                    pad = chr(ord(pad) + 1)
                    iv[j - l] = chr(ord(iv[j - l]) - 1 % 255)
                    l = l + 1
                    
                for m in range(j - l, j + 1): # iterate over padding to decrypt
                    #print "pad=0x" + binascii.hexlify(pad) + " calculated iv=0x" + binascii.hexlify(iv[m]) + " previous iv=0x" + binascii.hexlify(ctb[i - 1][m])
                    pt = chr(ord(pad) ^ ord(iv[m]) ^ ord(ctb[i - 1][m])) # ...and retrieve plain text bytes
                    ptb[i][m] = pt
                    if ord(pt) >= 32:
                        print "Got plain text byte " + str(m + 1) + " from block " + str(i) + ": " + pt + " (0x" + binascii.hexlify(pt) + ")"
                    else:
                        print "Got plain text byte " + str(m + 1) + " from block " + str(i) + ": 0x" + binascii.hexlify(pt) + ")"
                j = j - l - 1           # move pointer up to next byte which must be decrypted

                pad = chr(ord(pad) + 1)
                print "New padding byte is 0x" + binascii.hexlify(pad) + ", calculating iv bytes..."
                for m in range(j + 1, blocksize): # recalculate iv to new expected padding bytes
                    # for each byte of the iv we need a x, where (according to CBC encryption mode) the following condition applies:
                    # iv ^ d(ct) ^ x = p
                    # p is the incremented padding
                    # solving this to x gives:
                    # x = p ^ iv ^ d(ct)
                    # Since pt is d(ct) ^ iv[i-1] and we don't need iv[i-1], the value must be xored again.
                    x = ord(pad) ^ ord(iv[m]) ^ ord(ptb[i][m]) ^ ord(ctb[i - 1][m])
                    # This x is now used to calculate the new iv which results in the wanted padding
                    iv[m] = chr(ord(iv[m]) ^ x)
                    print "IV Byte " + str(m + 1) + " ^= 0x" + binascii.hexlify(chr(x)) + " = 0x" + binascii.hexlify(iv[m])
                print
                break
    print "Retrieved plain text block " + str(i) + ": " + "".join(ptb[i])
ptb = ptb[1:]
print "Retrieved plain text: " + "".join(map("".join, ptb))
