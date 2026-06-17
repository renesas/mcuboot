# Copyright 2017 Linaro Limited
# Copyright 2023 Arm Limited
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Cryptographic key management for imgtool.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .ecdsa import ECDSA256P1, ECDSA384P1, ECDSA256P1Public, ECDSA384P1Public, ECDSAUsageError
from .ed25519 import Ed25519, Ed25519Public, Ed25519UsageError
from .rsa import RSA, RSA_KEY_SIZES, RSAPublic, RSAUsageError
from .x25519 import X25519, X25519Public, X25519UsageError
from .mldsa44 import Mldsa44, Mldsa44Public, Mldsa44UsageError
from .mldsa65 import Mldsa65, Mldsa65Public, Mldsa65UsageError
from .mldsa87 import Mldsa87, Mldsa87Public, Mldsa87UsageError

__all__ = [
    "ECDSA256P1",
    "ECDSA384P1",
    "ECDSA256P1Public",
    "ECDSA384P1Public",
    "ECDSAUsageError",
    "Ed25519",
    "Ed25519Public",
    "Ed25519UsageError",
    "RSA",
    "RSA_KEY_SIZES",
    "RSAPublic",
    "RSAUsageError",
    "X25519",
    "X25519Public",
    "X25519UsageError",
]


class PasswordRequired(Exception):
    """Raised to indicate that the key is password protected, but a
    password was not specified."""


def load(path, passwd=None):
    """Try loading a key from the given path.
      Returns None if the password wasn't specified."""
    with open(path, 'rb') as f:
        raw_pem = f.read()
    
    try:
        # Check for MLDSA44 format (FIPS 204): 4 + 2560 + 1312 = 3876 bytes
        if len(raw_pem) == 3876:
            return load_mldsa44_key(raw_pem)

        # Check for MLDSA65 format (FIPS 204): 4 + 4032 + 1952 = 5988 bytes
        if len(raw_pem) == 5988:
            return load_mldsa65_key(raw_pem)

        # Check for MLDSA87 format (FIPS 204): 4 + 4896 + 2592 = 7492 bytes
        if len(raw_pem) == 7492:
            return load_mldsa87_key(raw_pem)
            
        # Continue with existing PEM/DER loading for other key types
        pk = serialization.load_pem_private_key(
                raw_pem,
                password=passwd,
                backend=default_backend())
    # Unfortunately, the crypto library raises unhelpful exceptions,
    # so we have to look at the text.
    except TypeError as e:
        msg = str(e)
        if "private key is encrypted" in msg:
            return None
        raise e
    except ValueError as e:
        # Check if it's an MLDSA44 error or a cryptography error
        if "MLDSA44" in str(e):
            raise e
        if "MLDSA65" in str(e):
            raise e
        if "MLDSA87" in str(e):
            raise e
        # This seems to happen if the key is a public key, let's try
        # loading it as a public key.
        pk = serialization.load_pem_public_key(
                raw_pem,
                backend=default_backend())

    if isinstance(pk, RSAPrivateKey):
        if pk.key_size not in RSA_KEY_SIZES:
            raise Exception("Unsupported RSA key size: " + pk.key_size)
        return RSA(pk)
    elif isinstance(pk, RSAPublicKey):
        if pk.key_size not in RSA_KEY_SIZES:
            raise Exception("Unsupported RSA key size: " + pk.key_size)
        return RSAPublic(pk)
    elif isinstance(pk, EllipticCurvePrivateKey):
        if pk.curve.name not in ('secp256r1', 'secp384r1'):
            raise Exception("Unsupported EC curve: " + pk.curve.name)
        if pk.key_size not in (256, 384):
            raise Exception("Unsupported EC size: " + pk.key_size)
        if pk.curve.name == 'secp256r1':
            return ECDSA256P1(pk)
        elif pk.curve.name == 'secp384r1':
            return ECDSA384P1(pk)
    elif isinstance(pk, EllipticCurvePublicKey):
        if pk.curve.name not in ('secp256r1', 'secp384r1'):
            raise Exception("Unsupported EC curve: " + pk.curve.name)
        if pk.key_size not in (256, 384):
            raise Exception("Unsupported EC size: " + pk.key_size)
        if pk.curve.name == 'secp256r1':
            return ECDSA256P1Public(pk)
        elif pk.curve.name == 'secp384r1':
            return ECDSA384P1Public(pk)
    elif isinstance(pk, Ed25519PrivateKey):
        return Ed25519(pk)
    elif isinstance(pk, Ed25519PublicKey):
        return Ed25519Public(pk)
    elif isinstance(pk, X25519PrivateKey):
        return X25519(pk)
    elif isinstance(pk, X25519PublicKey):
        return X25519Public(pk)
    else:
        raise Exception("Unknown key type: " + str(type(pk)))



# Key size reference for FIPS 204 ML-DSA implementations:
# MLDSA44 (ML-DSA-44): Private=2560, Public=1312, Signature=2420, File=3876
# MLDSA65 (ML-DSA-65): Private=4032, Public=1952, Signature=3309, File=5988
# MLDSA87 (ML-DSA-87): Private=4896, Public=2592, Signature=4627, File=7492

def load_mldsa44_key(key_data):
    """Load MLDSA44 key from custom format: 4-byte length + private_key + public_key (FIPS 204)"""
    import struct

    # Validate minimum size
    if len(key_data) < 4:
        raise ValueError("Invalid MLDSA44 key file: too short")

    # Read the private key length from first 4 bytes
    priv_len = struct.unpack('<I', key_data[:4])[0]

    # Validate expected lengths (FIPS 204 sizes)
    expected_total = 4 + priv_len + 1312  # header + private + public
    if len(key_data) != expected_total:
        raise ValueError(f"Invalid MLDSA44 key file: expected {expected_total} bytes, got {len(key_data)}")

    # Validate private key length (FIPS 204: 2560 bytes)
    if priv_len != 2560:
        raise ValueError(f"Invalid MLDSA44 private key length: expected 2560, got {priv_len}")

    # Extract keys
    private_key_bytes = key_data[4:4+priv_len]
    public_key_bytes = key_data[4+priv_len:]

    # Validate public key length
    if len(public_key_bytes) != 1312:
        raise ValueError(f"Invalid MLDSA44 public key length: expected 1312, got {len(public_key_bytes)}")

    from .mldsa44 import Mldsa44
    return Mldsa44(private_key_bytes, public_key_bytes)

def load_mldsa65_key(key_data):
    """Load MLDSA65 key from custom format: 4-byte length + private_key + public_key (FIPS 204)"""
    import struct

    # Validate minimum size
    if len(key_data) < 4:
        raise ValueError("Invalid MLDSA65 key file: too short")

    # Read the private key length from first 4 bytes
    priv_len = struct.unpack('<I', key_data[:4])[0]

    # Validate expected lengths (FIPS 204 sizes)
    expected_total = 4 + priv_len + 1952  # header + private + public
    if len(key_data) != expected_total:
        raise ValueError(f"Invalid MLDSA65 key file: expected {expected_total} bytes, got {len(key_data)}")

    # Validate private key length (FIPS 204: 4032 bytes)
    if priv_len != 4032:
        raise ValueError(f"Invalid MLDSA65 private key length: expected 4032, got {priv_len}")

    # Extract keys
    private_key_bytes = key_data[4:4+priv_len]
    public_key_bytes = key_data[4+priv_len:]

    # Validate public key length
    if len(public_key_bytes) != 1952:
        raise ValueError(f"Invalid MLDSA65 public key length: expected 1952, got {len(public_key_bytes)}")

    from .mldsa65 import Mldsa65
    return Mldsa65(private_key_bytes, public_key_bytes)

def load_mldsa87_key(key_data):
    """Load MLDSA87 key from custom format: 4-byte length + private_key + public_key (FIPS 204)"""
    import struct

    # Validate minimum size
    if len(key_data) < 4:
        raise ValueError("Invalid MLDSA87 key file: too short")

    # Read the private key length from first 4 bytes
    priv_len = struct.unpack('<I', key_data[:4])[0]

    # Validate expected lengths (FIPS 204 sizes)
    expected_total = 4 + priv_len + 2592  # header + private + public
    if len(key_data) != expected_total:
        raise ValueError(f"Invalid MLDSA87 key file: expected {expected_total} bytes, got {len(key_data)}")

    # Validate private key length (FIPS 204: 4896 bytes)
    if priv_len != 4896:
        raise ValueError(f"Invalid MLDSA87 private key length: expected 4896, got {priv_len}")

    # Extract keys
    private_key_bytes = key_data[4:4+priv_len]
    public_key_bytes = key_data[4+priv_len:]

    # Validate public key length
    if len(public_key_bytes) != 2592:
        raise ValueError(f"Invalid MLDSA87 public key length: expected 2592, got {len(public_key_bytes)}")

    from .mldsa87 import Mldsa87
    return Mldsa87(private_key_bytes, public_key_bytes)