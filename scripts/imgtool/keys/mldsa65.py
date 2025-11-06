"""
MLDSA65 key management using FIPS 204 specification
"""

# SPDX-License-Identifier: Apache-2.0

import os
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .general import KeyClass


class Mldsa65UsageError(Exception):
    pass


class Mldsa65Public(KeyClass):
    def __init__(self, public_key_bytes):
        """Initialize with raw public key bytes from FIPS 204 ML-DSA-65"""
        if not isinstance(public_key_bytes, bytes):
            raise Mldsa65UsageError("Public key must be bytes")
        if len(public_key_bytes) != 1952:  # FIPS 204 ML-DSA-65 public key size
            raise Mldsa65UsageError(f"Invalid public key size: {len(public_key_bytes)} bytes, expected 1952")
        self.public_key_bytes = public_key_bytes

    def shortname(self):
        return "mldsa65"

    def _unsupported(self, name):
        raise Mldsa65UsageError(f"Operation {name} requires private key")

    def _get_public(self):
        return self.public_key_bytes

    def get_public_bytes(self):
        """Return raw public key bytes"""
        return self.public_key_bytes

    def get_private_bytes(self, minimal, format):
        self._unsupported('get_private_bytes')

    def export_private(self, path, passwd=None):
        self._unsupported('export_private')

    def export_public(self, path):
        """Write the public key to the given file as raw bytes."""
        try:
            with open(path, 'wb') as f:
                f.write(self.public_key_bytes)
        except OSError as e:
            raise Mldsa65UsageError(f"Failed to write public key to {path}: {e}")

    def sig_type(self):
        return "MLDSA65"

    def sig_tlv(self):
        return "MLDSA65"

    def sig_len(self):
        return 3309  # FIPS 204 ML-DSA-65 signature length

    def verify_digest(self, signature, digest):
        """Verify that signature is valid for given digest using FIPS 204 ML-DSA"""
        try:
            # Use FIPS 204 ML-DSA-65 for verification
            return ML_DSA_65.verify(self.public_key_bytes, digest, signature)
        except Exception:
            return False


class Mldsa65(Mldsa65Public):
    """
    Wrapper around an MLDSA65 private key using FIPS 204 specification.

    Provides methods for key generation, signing, and exporting both
    private and public keys in various formats for post-quantum cryptography.
    Uses ML-DSA-65 parameter set for higher security than MLDSA44.
    """

    def __init__(self, private_key_bytes, public_key_bytes):
        """Initialize with raw private and public key bytes from FIPS 204 ML-DSA-65"""
        if not isinstance(private_key_bytes, bytes):
            raise Mldsa65UsageError("Private key must be bytes")
        if len(private_key_bytes) != 4032:  # FIPS 204 ML-DSA-65 private key size
            raise Mldsa65UsageError(f"Invalid private key size: {len(private_key_bytes)} bytes, expected 4032")

        super().__init__(public_key_bytes)
        self.private_key_bytes = private_key_bytes

    @staticmethod
    def generate():
        """Generate a new MLDSA65 key pair using FIPS 204 ML-DSA specification"""
        # Use FIPS 204 ML-DSA-65 for key generation
        public_key, private_key = ML_DSA_65.keygen()

        return Mldsa65(private_key, public_key)

    def _get_public(self):
        return self.public_key_bytes

    def get_private_bytes(self, minimal, format):
        """Return raw private key bytes"""
        if format == 'raw':
            return self.private_key_bytes
        else:
            raise Mldsa65UsageError(f"get_private_bytes not supported with format {format} for {self.shortname()} keys")

    def export_private(self, path, passwd=None):
        """
        Write the private key to the given file with both private and public key data.
        Format: 4 bytes length + private key + public key
        Total size: 4 + 4032 + 1952 = 5988 bytes
        """
        if passwd is not None:
            raise Mldsa65UsageError("Password protection not supported for raw dilithium keys")
        
        try:
            with open(path, 'wb') as f:
                import struct
                # Write header: private_key_length (4 bytes little-endian)
                f.write(struct.pack('<I', len(self.private_key_bytes)))
                # Write private key bytes
                f.write(self.private_key_bytes)
                # Write public key bytes
                f.write(self.public_key_bytes)
        except OSError as e:
            raise Mldsa65UsageError(f"Failed to write private key to {path}: {e}")

    def sign_digest(self, digest):
        """Return the actual signature using FIPS 204 ML-DSA"""
        # Use FIPS 204 ML-DSA-65 for signing
        signature = ML_DSA_65.sign(self.private_key_bytes, digest)

        return signature





# Debugging Code
        """
# Remove old keys
rm mykey.pem

# Generate new key with enhanced format (usese 16-byte seed from os.random())
python imgtool.py keygen -t mldsa-65 -k mykey.pem

# Check file size (should be 5956 bytes now since both public and private keys are present)
ls -la mykey.pem

# Test public key extraction 
python imgtool.py getpub -k mykey.pem -e raw -o pubkey.bin

# Check public key size (should be 1952 bytes)
ls -la pubkey.bin

# Test signing (2420-byte packed signatures)
python imgtool.py sign -k mykey.pem --version 2.0.0+0 --header-size 0x80 --align 128 --max-align 128 --slot-size 0x8000 --max-sectors 1 --overwrite-only --pad-header input.bin output.bin

# Test verification. Not sure if we should change this to accept public key... that may be not necessary since that happens on the MCU
python imgtool.py verify -k mykey.pem output.bin
"""