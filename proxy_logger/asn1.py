"""
Pure Python ASN.1 / X.509 certificate builder with ECDSA P-256.

No external dependencies - uses only Python stdlib.
Generates self-signed CA certificates and host certificates for MITM proxying.
"""

import base64
import hashlib
import hmac
import os
import struct
import time
from datetime import datetime, timezone, timedelta


# ============================================================
# ASN.1 DER encoding primitives
# ============================================================

def _tag(number: int, constructed: bool = False, cls: int = 0) -> bytes:
    t = (cls << 6) | (0x20 if constructed else 0) | number
    return bytes([t])


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    length_bytes = []
    tmp = n
    while tmp > 0:
        length_bytes.insert(0, tmp & 0xFF)
        tmp >>= 8
    return bytes([0x80 | len(length_bytes)] + length_bytes)


def _encode(tag_byte: int, value: bytes, constructed: bool = False, cls: int = 0) -> bytes:
    t = _tag(tag_byte, constructed, cls)
    return t + _length(len(value)) + value


def der_integer(n: int) -> bytes:
    if n == 0:
        return _encode(0x02, b'\x00')
    negative = n < 0
    if negative:
        # Two's complement for negative
        byte_len = (n.bit_length() + 8) // 8
        n = (1 << (byte_len * 8)) + n
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if not negative and b[0] & 0x80:
        b = b'\x00' + b
    return _encode(0x02, b)


def der_sequence(*items: bytes) -> bytes:
    return _encode(0x10, b''.join(items), constructed=True)


def der_set(*items: bytes) -> bytes:
    return _encode(0x11, b''.join(items), constructed=True)


def der_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split('.')]
    result = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        if p < 128:
            result.append(p)
        else:
            enc = []
            while p > 0:
                enc.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(enc) - 1):
                enc[i] |= 0x80
            result.extend(enc)
    return _encode(0x06, bytes(result))


def der_utf8string(s: str) -> bytes:
    return _encode(0x0C, s.encode('utf-8'))


def der_printablestring(s: str) -> bytes:
    return _encode(0x13, s.encode('ascii'))


def der_bitstring(data: bytes, unused_bits: int = 0) -> bytes:
    return _encode(0x03, bytes([unused_bits]) + data)


def der_octetstring(data: bytes) -> bytes:
    return _encode(0x04, data)


def der_null() -> bytes:
    return _encode(0x05, b'')


def der_boolean(val: bool) -> bytes:
    return _encode(0x01, b'\xff' if val else b'\x00')


def der_utctime(dt: datetime) -> bytes:
    s = dt.strftime('%y%m%d%H%M%SZ')
    return _encode(0x17, s.encode('ascii'))


def der_generalizedtime(dt: datetime) -> bytes:
    s = dt.strftime('%Y%m%d%H%M%SZ')
    return _encode(0x18, s.encode('ascii'))


def der_context(tag_number: int, value: bytes, constructed: bool = True) -> bytes:
    """Context-specific tagged value [tag_number]."""
    t = (0x80 | (0x20 if constructed else 0) | tag_number)
    return bytes([t]) + _length(len(value)) + value


# ============================================================
# OIDs
# ============================================================

OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_PRIME256V1 = "1.2.840.10045.3.1.7"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_CN = "2.5.4.3"
OID_ORG = "2.5.4.10"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_SUBJECT_KEY_ID = "2.5.29.14"
OID_AUTHORITY_KEY_ID = "2.5.29.35"
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


# ============================================================
# ECDSA P-256 (secp256r1) key generation & signing
# ============================================================

# P-256 curve parameters
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _modinv(a: int, m: int) -> int:
    """Modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _point_add(p1, p2):
    """Add two points on the P-256 curve."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 == y2:
        # Point doubling
        lam = (3 * x1 * x1 + A) * _modinv(2 * y1, P) % P
    elif x1 == x2:
        return None  # Point at infinity
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _point_multiply(k: int, point):
    """Scalar multiplication on the P-256 curve."""
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def generate_ec_key() -> int:
    """Generate a random ECDSA P-256 private key."""
    while True:
        key = int.from_bytes(os.urandom(32), 'big')
        if 1 <= key < N:
            return key


def public_key_from_private(private_key: int) -> tuple[int, int]:
    """Derive the public key point from a private key."""
    return _point_multiply(private_key, (GX, GY))


def _encode_public_key(pub: tuple[int, int]) -> bytes:
    """Encode public key as uncompressed point (0x04 || x || y)."""
    x, y = pub
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def _sign_ecdsa(private_key: int, message: bytes) -> bytes:
    """Sign a message with ECDSA P-256 SHA-256. Returns DER-encoded signature."""
    z = int.from_bytes(hashlib.sha256(message).digest(), 'big')

    while True:
        k = int.from_bytes(os.urandom(32), 'big') % N
        if k == 0:
            continue

        point = _point_multiply(k, (GX, GY))
        r = point[0] % N
        if r == 0:
            continue

        k_inv = _modinv(k, N)
        s = (k_inv * (z + r * private_key)) % N
        if s == 0:
            continue

        # Use low-S normalization
        if s > N // 2:
            s = N - s

        return der_sequence(der_integer(r), der_integer(s))


def private_key_to_pem(private_key: int) -> str:
    """Convert EC private key to PEM format (SEC1 / RFC 5915)."""
    priv_bytes = private_key.to_bytes(32, 'big')
    pub = public_key_from_private(private_key)
    pub_bytes = _encode_public_key(pub)

    # ECPrivateKey ::= SEQUENCE {
    #   version INTEGER (1),
    #   privateKey OCTET STRING,
    #   parameters [0] EXPLICIT OID,
    #   publicKey [1] EXPLICIT BIT STRING
    # }
    ec_key = der_sequence(
        der_integer(1),
        der_octetstring(priv_bytes),
        der_context(0, der_oid(OID_PRIME256V1)),
        der_context(1, der_bitstring(pub_bytes)),
    )

    b64 = base64.b64encode(ec_key).decode('ascii')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN EC PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END EC PRIVATE KEY-----\n"


def load_ec_private_key(pem: str) -> int:
    """Load EC private key from PEM."""
    lines = [l for l in pem.strip().split('\n') if not l.startswith('-----')]
    der = base64.b64decode(''.join(lines))

    # Parse outer SEQUENCE to get its content, then parse inside
    _, seq_content = _parse_tlv(der, 0)
    pos = 0
    # version INTEGER
    pos, _ = _parse_tlv(seq_content, pos)
    # privateKey OCTET STRING
    pos, priv_data = _parse_tlv(seq_content, pos)

    return int.from_bytes(priv_data, 'big')


def load_certificate_der(pem: str) -> bytes:
    """Extract DER bytes from a PEM certificate."""
    lines = [l for l in pem.strip().split('\n') if not l.startswith('-----')]
    return base64.b64decode(''.join(lines))


def _parse_tlv(data: bytes, offset: int) -> tuple[int, bytes]:
    """Parse a single TLV and return (new_offset, value_bytes)."""
    tag = data[offset]
    offset += 1

    length = data[offset]
    offset += 1

    if length & 0x80:
        num_bytes = length & 0x7F
        length = int.from_bytes(data[offset:offset + num_bytes], 'big')
        offset += num_bytes

    value = data[offset:offset + length]
    return offset + length, value


# ============================================================
# X.509 Certificate builder
# ============================================================

def _build_name(org: str, cn: str) -> bytes:
    """Build X.509 Name (RDNSequence)."""
    rdn_org = der_set(der_sequence(der_oid(OID_ORG), der_utf8string(org)))
    rdn_cn = der_set(der_sequence(der_oid(OID_CN), der_utf8string(cn)))
    return der_sequence(rdn_org, rdn_cn)


def _build_validity(not_before: datetime, not_after: datetime) -> bytes:
    return der_sequence(der_utctime(not_before), der_utctime(not_after))


def _build_spki(public_key: tuple[int, int]) -> bytes:
    """Build SubjectPublicKeyInfo for EC P-256."""
    algo = der_sequence(der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1))
    pub_bytes = _encode_public_key(public_key)
    return der_sequence(algo, der_bitstring(pub_bytes))


def _build_extension(oid: str, critical: bool, value: bytes) -> bytes:
    parts = [der_oid(oid)]
    if critical:
        parts.append(der_boolean(True))
    parts.append(der_octetstring(value))
    return der_sequence(*parts)


def _key_identifier(public_key: tuple[int, int]) -> bytes:
    """SHA-1 hash of the public key for Subject/Authority Key Identifier."""
    pub_bytes = _encode_public_key(public_key)
    return hashlib.sha1(pub_bytes).digest()


def build_ca_certificate(private_key: int, public_key: tuple[int, int]) -> bytes:
    """Build a self-signed CA certificate."""
    now = datetime.now(timezone.utc)
    serial = int.from_bytes(os.urandom(16), 'big')
    subject = _build_name("HTTP Proxy Logger", "HTTP Proxy Logger CA")
    validity = _build_validity(now - timedelta(hours=1), now + timedelta(days=3650))
    spki = _build_spki(public_key)

    # Extensions
    key_id = _key_identifier(public_key)

    extensions = der_sequence(
        # Basic Constraints: CA=TRUE
        _build_extension(OID_BASIC_CONSTRAINTS, True,
                         der_sequence(der_boolean(True), der_integer(0))),
        # Key Usage: keyCertSign, cRLSign
        _build_extension(OID_KEY_USAGE, True,
                         der_bitstring(b'\x06', unused_bits=1)),
        # Subject Key Identifier
        _build_extension(OID_SUBJECT_KEY_ID, False,
                         der_octetstring(key_id)),
    )

    # TBSCertificate
    tbs = der_sequence(
        der_context(0, der_integer(2)),   # version v3
        der_integer(serial),
        der_sequence(der_oid(OID_ECDSA_SHA256)),  # signature algorithm
        subject,     # issuer = subject (self-signed)
        validity,
        subject,
        spki,
        der_context(3, extensions),
    )

    # Sign
    signature = _sign_ecdsa(private_key, tbs)
    sig_algo = der_sequence(der_oid(OID_ECDSA_SHA256))

    return der_sequence(tbs, sig_algo, der_bitstring(signature))


def build_host_certificate(
    hostname: str,
    host_public_key: tuple[int, int],
    ca_private_key: int,
    ca_cert_der: bytes,
) -> bytes:
    """Build a host certificate signed by the CA."""
    now = datetime.now(timezone.utc)
    serial = int.from_bytes(os.urandom(16), 'big')

    # Extract issuer Name from CA cert
    issuer_name = _extract_subject_from_cert(ca_cert_der)

    subject = _build_name("HTTP Proxy Logger", hostname)
    validity = _build_validity(now - timedelta(hours=1), now + timedelta(hours=24))
    spki = _build_spki(host_public_key)

    # CA public key for authority key identifier
    ca_pub = public_key_from_private(ca_private_key)

    # Subject Alternative Name: DNS:hostname
    san_value = der_sequence(
        # DNSName is context tag [2] implicit
        der_context(2, hostname.encode('ascii'), constructed=False)
    )

    extensions = der_sequence(
        # Basic Constraints: CA=FALSE
        _build_extension(OID_BASIC_CONSTRAINTS, True, der_sequence()),
        # Key Usage: digitalSignature, keyEncipherment
        _build_extension(OID_KEY_USAGE, True,
                         der_bitstring(b'\xa0', unused_bits=5)),
        # Extended Key Usage: serverAuth
        _build_extension(OID_EXT_KEY_USAGE, False,
                         der_sequence(der_oid(OID_SERVER_AUTH))),
        # Subject Alternative Name
        _build_extension(OID_SUBJECT_ALT_NAME, False, san_value),
        # Authority Key Identifier
        _build_extension(OID_AUTHORITY_KEY_ID, False,
                         der_sequence(der_context(0, _key_identifier(ca_pub), constructed=False))),
        # Subject Key Identifier
        _build_extension(OID_SUBJECT_KEY_ID, False,
                         der_octetstring(_key_identifier(host_public_key))),
    )

    tbs = der_sequence(
        der_context(0, der_integer(2)),   # version v3
        der_integer(serial),
        der_sequence(der_oid(OID_ECDSA_SHA256)),
        issuer_name,
        validity,
        subject,
        spki,
        der_context(3, extensions),
    )

    signature = _sign_ecdsa(ca_private_key, tbs)
    sig_algo = der_sequence(der_oid(OID_ECDSA_SHA256))

    return der_sequence(tbs, sig_algo, der_bitstring(signature))


def _extract_subject_from_cert(cert_der: bytes) -> bytes:
    """Extract the Subject (issuer) field from a DER-encoded X.509 certificate."""
    # Certificate -> SEQUENCE { TBSCertificate, sigAlgo, sig }
    _, cert_content = _parse_tlv(cert_der, 0)

    # TBSCertificate -> SEQUENCE { version[0], serial, sigAlgo, issuer, validity, subject, ... }
    _, tbs_content = _parse_tlv(cert_content, 0)

    p = 0
    # version [0] EXPLICIT (optional, but always present for v3)
    if tbs_content[p] == 0xA0:
        p, _ = _parse_tlv(tbs_content, p)

    # serial INTEGER
    p, _ = _parse_tlv(tbs_content, p)

    # signatureAlgorithm SEQUENCE
    p, _ = _parse_tlv(tbs_content, p)

    # issuer Name - return the full TLV
    issuer_start = p
    p, _ = _parse_tlv(tbs_content, p)
    return tbs_content[issuer_start:p]
