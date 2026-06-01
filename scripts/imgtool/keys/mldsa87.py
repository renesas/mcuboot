"""
MLDSA87 key management using FIPS 204 specification.

Private key storage uses PKCS#8 (RFC 5958) PEM format.
The canonical private key is the 32-byte seed xi (ξ) per FIPS 204;
the expanded 4896-byte secret key is derived on demand via key_derive().

"""

# SPDX-License-Identifier: Apache-2.0

import base64
import os

from dilithium_py.ml_dsa import ML_DSA_87
from cryptography.exceptions import InvalidSignature

from .general import KeyClass

# ML-DSA-87 seed size per FIPS 204
MLDSA87_SEED_BYTES    = 32
MLDSA87_PUBKEY_BYTES  = 2592
MLDSA87_SIG_BYTES     = 4627

# DER-encoded OID 2.16.840.1.101.3.4.3.19 (ML-DSA-87, NIST FIPS 204)
_OID_ML_DSA_87 = bytes([0x06, 0x09,
                         0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13])


def _der_len(n):
    """Encode DER length."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, n >> 8, n & 0xff])


def _der_seq(*items):
    body = b''.join(items)
    return b'\x30' + _der_len(len(body)) + body


def _der_octet(data):
    return b'\x04' + _der_len(len(data)) + data


def _seed_to_pkcs8_der(seed):
    """
    Encode a 32-byte ML-DSA-87 seed as PKCS#8 OneAsymmetricKey DER (RFC 5958).

    OneAsymmetricKey ::= SEQUENCE {
        version           INTEGER (0),
        algorithm         AlgorithmIdentifier { OID },
        privateKey        OCTET STRING { OCTET STRING { seed } }
    }
    """
    version    = b'\x02\x01\x00'
    alg_id     = _der_seq(_OID_ML_DSA_87)
    # RFC 5958: privateKey is an OCTET STRING wrapping the key encoding.
    # For ML-DSA the key encoding is itself an OCTET STRING of the seed.
    priv_key   = _der_octet(_der_octet(seed))
    return _der_seq(version, alg_id, priv_key)


def _pkcs8_der_to_seed(der):
    """
    Extract the 32-byte seed from a PKCS#8 OneAsymmetricKey DER buffer.
    Raises ValueError on malformed input.
    """
    def _parse_tlv(buf, offset):
        tag  = buf[offset]
        b1   = buf[offset + 1]
        if b1 < 0x80:
            length, offset = b1, offset + 2
        elif b1 == 0x81:
            length, offset = buf[offset + 2], offset + 3
        elif b1 == 0x82:
            length = (buf[offset + 2] << 8) | buf[offset + 3]
            offset = offset + 4
        else:
            raise ValueError("Unsupported DER length encoding")
        return tag, length, offset

    # SEQUENCE (outer)
    tag, _, off = _parse_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("Expected SEQUENCE")
    # version INTEGER
    tag, ln, off = _parse_tlv(der, off)
    if tag != 0x02 or ln != 1 or der[off] != 0:
        raise ValueError("Expected version 0")
    off += ln
    # AlgorithmIdentifier SEQUENCE
    tag, ln, off = _parse_tlv(der, off)
    if tag != 0x30:
        raise ValueError("Expected AlgorithmIdentifier")
    off += ln  # skip OID contents
    # privateKey OCTET STRING (outer)
    tag, ln, off = _parse_tlv(der, off)
    if tag != 0x04:
        raise ValueError("Expected OCTET STRING (outer)")
    # privateKey OCTET STRING (inner seed)
    tag, ln, off = _parse_tlv(der, off)
    if tag != 0x04:
        raise ValueError("Expected OCTET STRING (inner seed)")
    if ln != MLDSA87_SEED_BYTES:
        raise ValueError(f"Expected seed of {MLDSA87_SEED_BYTES} bytes, got {ln}")
    return der[off:off + ln]


def _pem_wrap(der, label="PRIVATE KEY"):
    b64    = base64.b64encode(der).decode()
    lines  = '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f'-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n'


def _pem_unwrap(pem_text, label="PRIVATE KEY"):
    lines = pem_text.strip().splitlines()
    if lines[0] != f'-----BEGIN {label}-----':
        raise ValueError(f"Missing PEM header '-----BEGIN {label}-----'")
    if lines[-1] != f'-----END {label}-----':
        raise ValueError(f"Missing PEM footer '-----END {label}-----'")
    return base64.b64decode(''.join(lines[1:-1]))


class Mldsa87UsageError(Exception):
    pass

class Mldsa87Public(KeyClass):
    """ML-DSA-87 public key (2592 bytes raw, FIPS 204)."""

    def __init__(self, public_key_bytes):
        if not isinstance(public_key_bytes, bytes):
            raise Mldsa87UsageError("Public key must be bytes")
        if len(public_key_bytes) != MLDSA87_PUBKEY_BYTES:
            raise Mldsa87UsageError(
                f"Invalid public key size: {len(public_key_bytes)} bytes, "
                f"expected {MLDSA87_PUBKEY_BYTES}")
        self.public_key_bytes = public_key_bytes

    def shortname(self):
        return "mldsa87"

    def _unsupported(self, name):
        raise Mldsa87UsageError(f"Operation {name} requires private key")

    def _get_public(self):
        return self.public_key_bytes

    def get_public_bytes(self):
        return self.public_key_bytes

    def get_private_bytes(self, minimal, format):
        self._unsupported('get_private_bytes')

    def export_private(self, path, passwd=None):
        self._unsupported('export_private')

    def export_public(self, path):
        """Write the raw 2592-byte public key to file."""
        try:
            with open(path, 'wb') as f:
                f.write(self.public_key_bytes)
        except OSError as e:
            raise Mldsa87UsageError(f"Failed to write public key to {path}: {e}")

    def sig_type(self):
        return "MLDSA87"

    def sig_tlv(self):
        return "MLDSA87"

    def sig_len(self):
        return MLDSA87_SIG_BYTES

    def verify(self, signature, message):
        """Verify ML-DSA-87 pure-mode signature over raw message."""
        try:
            result = ML_DSA_87.verify(self.public_key_bytes, message, signature)
        except Exception as e:
            raise InvalidSignature("ML-DSA-87 verification failed") from e
        if not result:
            raise InvalidSignature("ML-DSA-87 verification failed")

    def verify_digest(self, signature, digest):
        self.verify(signature, digest)


class Mldsa87(Mldsa87Public):
    """
    ML-DSA-87 key pair.

    Stores the canonical 32-byte seed (ξ per FIPS 204).
    The expanded 4896-byte secret key is derived via ML_DSA_87.key_derive(seed)
    and cached after the first use.

    Key file format: PKCS#8 PEM (RFC 5958) with OID 2.16.840.1.101.3.4.3.19.
    """

    def __init__(self, seed, public_key_bytes):
        if not isinstance(seed, bytes) or len(seed) != MLDSA87_SEED_BYTES:
            raise Mldsa87UsageError(
                f"Seed must be {MLDSA87_SEED_BYTES} bytes, got {len(seed) if isinstance(seed, bytes) else type(seed)}")
        super().__init__(public_key_bytes)
        self._seed = seed
        self._sk   = None  # expanded SK, derived lazily

    @staticmethod
    def generate():
        """Generate a new ML-DSA-87 key pair from a random 32-byte seed."""
        seed = os.urandom(MLDSA87_SEED_BYTES)
        pk, _sk = ML_DSA_87.key_derive(seed)
        return Mldsa87(seed, pk)

    def _expanded_sk(self):
        """Return the 4896-byte expanded secret key, deriving it if needed."""
        if self._sk is None:
            _pk, self._sk = ML_DSA_87.key_derive(self._seed)
        return self._sk

    def get_private_bytes(self, minimal, format):
        if format == 'raw':
            return self._seed
        raise Mldsa87UsageError(
            f"get_private_bytes format '{format}' not supported for mldsa87")

    def export_private(self, path, passwd=None):
        """
        Write the private key as PKCS#8 PEM (seed only, 32 bytes).
        Password protection is not supported.
        """
        if passwd is not None:
            raise Mldsa87UsageError("Password protection is not supported for ML-DSA-87 keys")
        pem = _pem_wrap(_seed_to_pkcs8_der(self._seed))
        try:
            with open(path, 'w') as f:
                f.write(pem)
        except OSError as e:
            raise Mldsa87UsageError(f"Failed to write private key to {path}: {e}")

    def sign(self, payload):
        """Sign raw payload (pure mode) using FIPS 204 ML-DSA-87."""
        return ML_DSA_87.sign(self._expanded_sk(), payload)

    def sign_digest(self, digest):
        """Sign bytes using ML-DSA-87; kept for API compatibility."""
        return self.sign(digest)


def load_mldsa87_pem(pem_text):
    """Load an ML-DSA-87 private key from PKCS#8 PEM text."""
    try:
        der  = _pem_unwrap(pem_text)
        seed = _pkcs8_der_to_seed(der)
    except (ValueError, IndexError, KeyError) as e:
        raise Mldsa87UsageError(f"Invalid ML-DSA-87 PEM key: {e}") from e
    pk, _sk = ML_DSA_87.key_derive(seed)
    return Mldsa87(seed, pk)
