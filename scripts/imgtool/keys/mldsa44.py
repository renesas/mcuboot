"""
MLDSA44 key management using FIPS 204 specification
"""

# SPDX-License-Identifier: Apache-2.0

import os
from dilithium_py.ml_dsa import ML_DSA_44
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .general import KeyClass


class Mldsa44UsageError(Exception):
    pass


class Mldsa44Public(KeyClass):
    def __init__(self, public_key_bytes):
        """Initialize with raw public key bytes from FIPS 204 ML-DSA-44"""
        if not isinstance(public_key_bytes, bytes):
            raise Mldsa44UsageError("Public key must be bytes")
        if len(public_key_bytes) != 1312:  # FIPS 204 ML-DSA-44 public key size
            raise Mldsa44UsageError(f"Invalid public key size: {len(public_key_bytes)} bytes, expected 1312")
        self.public_key_bytes = public_key_bytes

    def shortname(self):
        return "mldsa44"

    def _unsupported(self, name):
        raise Mldsa44UsageError(f"Operation {name} requires private key")

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
            raise Mldsa44UsageError(f"Failed to write public key to {path}: {e}")

    def sig_type(self):
        return "MLDSA44"

    def sig_tlv(self):
        return "MLDSA44"

    def sig_len(self):
        return 2420  # FIPS 204 ML-DSA-44 signature length

    def verify_digest(self, signature, digest):
        """Verify that signature is valid for given digest using FIPS 204 ML-DSA"""
        try:
            # Use FIPS 204 ML-DSA-44 for verification
            return ML_DSA_44.verify(self.public_key_bytes, digest, signature)
        except Exception:
            return False


class Mldsa44(Mldsa44Public):
    """
    Wrapper around an MLDSA44 private key using FIPS 204 specification.

    Provides methods for key generation, signing, and exporting both
    private and public keys in various formats for post-quantum cryptography.
    """

    def __init__(self, private_key_bytes, public_key_bytes):
        """Initialize with raw private and public key bytes from FIPS 204 ML-DSA-44"""
        if not isinstance(private_key_bytes, bytes):
            raise Mldsa44UsageError("Private key must be bytes")
        if len(private_key_bytes) != 2560:  # FIPS 204 ML-DSA-44 private key size
            raise Mldsa44UsageError(f"Invalid private key size: {len(private_key_bytes)} bytes, expected 2560")

        super().__init__(public_key_bytes)
        self.private_key_bytes = private_key_bytes

    @staticmethod
    def generate():
        """Generate a new MLDSA44 key pair using FIPS 204 ML-DSA specification"""
        seed = os.urandom(32)

        # Use FIPS 204 ML-DSA-44 for key generation
        public_key, private_key = ML_DSA_44.key_derive(seed)
        return Mldsa44(private_key, public_key)

    def _get_public(self):
        return self.public_key_bytes

    def get_private_bytes(self, minimal, format):
        """Return raw private key bytes"""
        if format == 'raw':
            return self.private_key_bytes
        else:
            raise Mldsa44UsageError(f"get_private_bytes not supported with format {format} for {self.shortname()} keys")

    def export_private(self, path, passwd=None):

        """ Write the private key to the given file with both private and public key data.
        Format: 4 bytes length + private key + public key
        Total size: 4 + 2560 + 1312 = 3876 bytes
        """
        if passwd is not None:
            raise Mldsa44UsageError("Password protection not supported for raw dilithium keys")
        
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
            raise Mldsa44UsageError(f"Failed to write private key to {path}: {e}")

    def sign_digest(self, digest):
        """Return the actual signature using FIPS 204 ML-DSA"""
        # Use FIPS 204 ML-DSA-44 for signing
        signature = ML_DSA_44.sign(self.private_key_bytes, digest)

        return signature





# Debugging Code
"""
# Remove old keys
rm mykey.pem

# Generate new key with enhanced format (usese 16-byte seed from os.random())
python imgtool.py keygen -t mldsa-44 -k mykey.pem

# Check file size (should be 3844 bytes now since both public and private keys are present)
ls -la mykey.pem

# Test public key extraction 
python imgtool.py getpub -k mykey.pem -e raw -o pubkey.bin

# Check public key size (should be 1312 bytes)
ls -la pubkey.bin

# Test signing (2420-byte packed signatures)
python imgtool.py sign -k mykey.pem --version 2.0.0+0 --header-size 0x80 --align 128 --max-align 128 --slot-size 0x8000 --max-sectors 1 --overwrite-only --pad-header input.bin output.bin

# Test verification. Not sure if we should change this to accept public key... that may be not necessary since that happens on the MCU
python imgtool.py verify -k mykey.pem output.bin

# Test public key extraction to a C array
python imgtool.py getpub -k mykey.pem

# Test private key extraction to a C array (this does not work, but that may be ok since MCUboot firmware does not neet it? It works for other key types so maybe needs to be fixed)
python imgtool.py getpriv -k mykey.pem
"""