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
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

from .rsa import RSA, RSAPublic, RSAUsageError, RSA_KEY_SIZES
from .ecdsa import (ECDSA256P1, ECDSA256P1Public,
                    ECDSA384P1, ECDSA384P1Public, ECDSAUsageError)
from .ed25519 import Ed25519, Ed25519Public, Ed25519UsageError
from .x25519 import X25519, X25519Public, X25519UsageError
from .mldsa44 import Mldsa44, Mldsa44Public, Mldsa44UsageError
from .mldsa67 import Mldsa67, Mldsa67Public, Mldsa67UsageError


class PasswordRequired(Exception):
    """Raised to indicate that the key is password protected, but a
    password was not specified."""
    pass


def load(path, passwd=None):
    """Try loading a key from the given path.
      Returns None if the password wasn't specified."""
    with open(path, 'rb') as f:
        raw_pem = f.read()
    
    try:
        # Check for MLDSA44 format: 4 + 2528 + 1312 = 3844 bytes
        if len(raw_pem) == 3844:
            return load_mldsa44_key(raw_pem)
        
        # Check for MLDSA67 format: 4 + 4000 + 1952 = 5956 bytes
        if len(raw_pem) == 5956:
            return load_mldsa67_key(raw_pem)
            
        # Continue with existing PEM/DER loading for other key types
        pk = serialization.load_pem_private_key(
                raw_pem,
                password=passwd,
                backend=default_backend())
    except TypeError as e:
        msg = str(e)
        if "private key is encrypted" in msg:
            return None
        raise e
    except ValueError as e:
        # Check if it's our MLDSA44 error or a cryptography error
        if "MLDSA44" in str(e):
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



#This is WIP!!
# Key size reference for MLDSA implementations:
# MLDSA44 (Dilithium2): Private=2528, Public=1312, Signature=2420, File=3844
# MLDSA67 (Dilithium3): Private=4000, Public=1952, Signature=3293, File=5956
# MLDSA87 (Dilithium5): Private=4864, Public=2592, Signature=4595, File=7460

def load_mldsa44_key(key_data):
    """Load MLDSA44 key from custom format: 4-byte length + private_key + public_key"""
    import struct
    
    # Validate minimum size
    if len(key_data) < 4:
        raise ValueError("Invalid MLDSA44 key file: too short")
    
    # Read the private key length from first 4 bytes
    priv_len = struct.unpack('<I', key_data[:4])[0]
    
    # Validate expected lengths
    expected_total = 4 + priv_len + 1312  # header + private + public
    if len(key_data) != expected_total:
        raise ValueError(f"Invalid MLDSA44 key file: expected {expected_total} bytes, got {len(key_data)}")
    
    # Validate private key length
    if priv_len != 2528:
        raise ValueError(f"Invalid MLDSA44 private key length: expected 2528, got {priv_len}")
    
    # Extract keys
    private_key_bytes = key_data[4:4+priv_len]
    public_key_bytes = key_data[4+priv_len:]
    
    # Validate public key length
    if len(public_key_bytes) != 1312:
        raise ValueError(f"Invalid MLDSA44 public key length: expected 1312, got {len(public_key_bytes)}")
    
    from .mldsa44 import Mldsa44
    return Mldsa44(private_key_bytes, public_key_bytes)

def load_mldsa67_key(key_data):
    """Load MLDSA67 key from custom format: 4-byte length + private_key + public_key"""
    import struct
    
    # Validate minimum size
    if len(key_data) < 4:
        raise ValueError("Invalid MLDSA67 key file: too short")
    
    # Read the private key length from first 4 bytes
    priv_len = struct.unpack('<I', key_data[:4])[0]
    
    # Validate expected lengths
    expected_total = 4 + priv_len + 1952  # header + private + public
    if len(key_data) != expected_total:
        raise ValueError(f"Invalid MLDSA67 key file: expected {expected_total} bytes, got {len(key_data)}")
    
    # Validate private key length
    if priv_len != 4000:
        raise ValueError(f"Invalid MLDSA67 private key length: expected 4000, got {priv_len}")
    
    # Extract keys
    private_key_bytes = key_data[4:4+priv_len]
    public_key_bytes = key_data[4+priv_len:]
    
    # Validate public key length
    if len(public_key_bytes) != 1952:
        raise ValueError(f"Invalid MLDSA67 public key length: expected 1952, got {len(public_key_bytes)}")
    
    from .mldsa67 import Mldsa67
    return Mldsa67(private_key_bytes, public_key_bytes)