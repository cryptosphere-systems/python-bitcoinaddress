"""Validate bitcoin/altcoin addresses

Copied from:
http://rosettacode.org/wiki/Bitcoin/address_validation#Python
"""

import string
from hashlib import sha256

digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l" # BECH32 charset


def _bytes_to_long(bytestring, byteorder):
    """Convert a bytestring to a long

    For use in python version prior to 3.2
    """
    result = []
    if byteorder == 'little':
        result = (v << i * 8 for (i, v) in enumerate(bytestring))
    else:
        result = (v << i * 8 for (i, v) in enumerate(reversed(bytestring)))
    return sum(result)

def _long_to_bytes(n, length, byteorder):
    """Convert a long to a bytestring

    For use in python version prior to 3.2
    Source:
    http://bugs.python.org/issue16580#msg177208
    """
    if byteorder == 'little':
        indexes = range(length)
    else:
        indexes = reversed(range(length))
    return bytearray((n >> i * 8) & 0xff for i in indexes)

def decode_base58(bitcoin_address, length):
    """Decode a base58 encoded address

    This form of base58 decoding is bitcoind specific. Be careful outside of
    bitcoind context.
    """
    n = 0
    for char in bitcoin_address:
        try:
            n = n * 58 + digits58.index(char)
        except:
            msg = u"Character not part of Bitcoin's base58: '%s'"
            raise ValueError(msg % (char,))
    try:
        return n.to_bytes(length, 'big')
    except AttributeError:
        # Python version < 3.2
        return _long_to_bytes(n, length, 'big')

def encode_base58(bytestring):
    """Encode a bytestring to a base58 encoded string
    """
    # Count zero's
    zeros = 0
    for i in range(len(bytestring)):
        if bytestring[i] == 0:
            zeros += 1
        else:
            break
    try:
        n = int.from_bytes(bytestring, 'big')
    except AttributeError:
        # Python version < 3.2
        n = _bytes_to_long(bytestring, 'big')
    result = ''
    (n, rest) = divmod(n, 58)
    while n or rest:
        result += digits58[rest]
        (n, rest) = divmod(n, 58)
    return zeros * '1' + result[::-1]  # reverse string

def validate(bitcoin_address, testnet=False):
    """Check the integrity of a bitcoin address

    Returns False if the address is invalid.
    >>> validate('1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i')
    True
    >>> validate('')
    False
    """
    if testnet:
        magicbyte=(111,196)
        bech32_hrp = "tb"
    else:
        magicbyte=(0, 5)
        bech32_hrp = "bc"

    if (bitcoin_address[:2]).lower() == bech32_hrp:
        return validate_bech32(bitcoin_address, bech32_hrp)
    else:
        return validate_base58(bitcoin_address, magicbyte)

def validate_base58(bitcoin_address, magicbyte):
    clen = len(bitcoin_address)
    if clen < 27 or clen > 35:
        return False
    try:
        bcbytes = decode_base58(bitcoin_address, 25)
    except ValueError:
        return False
    # Check magic byte (for other altcoins, fix by Frederico Reiven)
    for mb in magicbyte:
        if bcbytes.startswith(chr(int(mb))):
            break
    else:
        return False
    # Compare checksum
    checksum = sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
    if bcbytes[-4:] != checksum:
        return False
    # Encoded bytestring should be equal to the original address,
    # for example '14oLvT2' has a valid checksum, but is not a valid btc
    # address
    return bitcoin_address == encode_base58(bcbytes)


# All BECH32 code below is from Pieter Wuille's reference implementation associated with BIP173
# See https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
# and https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Reference_implementations
def validate_bech32(bitcoin_address, hrp):
    return (decode(hrp, bitcoin_address)[0] is not None)

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(bech):
    """Validate a Bech32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    return (data[0], decoded)
