"""Spot elliptic-curve public keys whose private key is a tiny integer.

The October 2026 eMudhra keys were of this kind: the public key is d*G for a very small d, so anyone can
find d by adding the curve's generator G to itself and comparing. This checks a certificate's key against
d*G for every d up to BOUND, independent of any published list. Standard library only.
"""
from collections import namedtuple
from functools import lru_cache

from .der import _tlv, parse_cert

BOUND = 1 << 12  # the incident's keys were below 256; 4096 keeps a full scan under a second per curve

Curve = namedtuple("Curve", "name p b gx gy n")
CURVES = {
    "1.2.840.10045.3.1.7": Curve(
        "secp256r1", 2**256 - 2**224 + 2**192 + 2**96 - 1,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    "1.3.132.0.34": Curve(
        "secp384r1", 2**384 - 2**128 - 2**96 + 2**32 - 1,
        0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973),
    "1.3.132.0.35": Curve(
        "secp521r1", 2**521 - 1,
        0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409),
}
_EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"


def _oid(buf, start, end):
    first = buf[start]
    parts = [first // 40, first % 40]
    value = 0
    for byte in buf[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


def parse_ec_spki(spki):
    """Return (curve, x, y) for a named-curve EC SubjectPublicKeyInfo, else None."""
    try:
        tag, s, e = _tlv(spki, 0)
        if tag != 0x30:
            return None
        tag, a_s, a_e = _tlv(spki, s)           # AlgorithmIdentifier
        if tag != 0x30:
            return None
        tag, o_s, o_e = _tlv(spki, a_s)
        if tag != 0x06 or _oid(spki, o_s, o_e) != _EC_PUBLIC_KEY_OID:
            return None
        tag, c_s, c_e = _tlv(spki, o_e)
        if tag != 0x06:
            return None
        curve = CURVES.get(_oid(spki, c_s, c_e))
        tag, b_s, b_e = _tlv(spki, a_e)         # BIT STRING
    except (ValueError, IndexError):
        return None
    if curve is None or tag != 0x03:
        return None
    point = spki[b_s + 1:b_e]                   # skip the unused-bits byte
    size = (curve.p.bit_length() + 7) // 8
    if len(point) != 1 + 2 * size or point[0] != 4:
        return None
    x = int.from_bytes(point[1:1 + size], "big")
    y = int.from_bytes(point[1 + size:], "big")
    if (y * y - (x * x * x - 3 * x + curve.b)) % curve.p:
        return None                             # not on the curve
    return curve, x, y


@lru_cache(maxsize=None)
def _small_multiples(oid):
    """{x: (k, y)} for k*G, k = 1..BOUND, on the curve with this OID. Built once per curve."""
    c = CURVES[oid]
    p = c.p
    table = {c.gx: (1, c.gy)}
    x, y = c.gx, c.gy
    for k in range(2, BOUND + 1):
        if k == 2:  # G + G is a doubling; every later step adds G to (k-1)*G
            lam = (3 * x * x - 3) * pow(2 * y, -1, p) % p
        else:
            lam = (y - c.gy) * pow(x - c.gx, -1, p) % p
        nx = (lam * lam - x - c.gx) % p
        x, y = nx, (lam * (x - nx) - y) % p
        table[x] = (k, y)
    return table


def tiny_private_key(der):
    """Return k if this certificate's EC key is +-k*G for some k <= BOUND, else None."""
    try:
        parsed = parse_ec_spki(parse_cert(der)["spki"])
    except ValueError:
        return None
    if parsed is None:
        return None
    curve, x, y = parsed
    oid = next(o for o, c in CURVES.items() if c is curve)
    hit = _small_multiples(oid).get(x)
    return hit[0] if hit else None
