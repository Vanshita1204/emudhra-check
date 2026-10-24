"""Tiny DER reader: just enough X.509 to hash a certificate's SubjectPublicKeyInfo.

Standard library only, so the tool has no dependencies. Certificates are untrusted
input, so every length is bounds-checked and anything odd raises ValueError.
"""
import base64
import hashlib
import re

_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def pem_to_ders(text):
    out = []
    for block in _PEM_RE.findall(text):
        try:
            out.append(base64.b64decode("".join(block.split()), validate=True))
        except ValueError:
            continue
    return out


def _tlv(buf, pos):
    if pos + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[pos]
    first = buf[pos + 1]
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + 2 + n > len(buf):
            raise ValueError("bad DER length")
        length = int.from_bytes(buf[pos + 2:pos + 2 + n], "big")
        header = 2 + n
    else:
        length, header = first, 2
    end = pos + header + length
    if end > len(buf):
        raise ValueError("DER length exceeds buffer")
    return tag, pos + header, end


def parse_cert(der):
    """Return dict with raw TLV bytes for 'issuer', 'subject', 'spki'."""
    tag, start, end = _tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a certificate")
    tag, tbs_start, tbs_end = _tlv(der, start)
    if tag != 0x30:
        raise ValueError("bad tbsCertificate")
    pos = tbs_start
    fields = []
    while pos < tbs_end and len(fields) < 8:
        t, s, e = _tlv(der, pos)
        fields.append((t, pos, e))
        pos = e
    if fields and fields[0][0] == 0xA0:  # explicit [0] version
        fields = fields[1:]
    # serial, signature alg, issuer, validity, subject, spki
    if len(fields) < 6:
        raise ValueError("incomplete tbsCertificate")
    raw = lambda f: der[f[1]:f[2]]
    return {"issuer": raw(fields[2]), "subject": raw(fields[4]), "spki": raw(fields[5])}


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest().upper()


def cert_fingerprint(der):
    return sha256_hex(der)


def spki_fingerprint(der):
    return sha256_hex(parse_cert(der)["spki"])
