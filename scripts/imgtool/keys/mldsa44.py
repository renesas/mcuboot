"""
MLDSA44 key management
"""

# SPDX-License-Identifier: Apache-2.0

import dilithium
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .general import KeyClass


class Mldsa44UsageError(Exception):
    pass


class Mldsa44Public(KeyClass):
    def __init__(self, public_key_bytes):
        """Initialize with raw public key bytes from dilithium"""
        if not isinstance(public_key_bytes, bytes):
            raise Mldsa44UsageError("Public key must be bytes")
        if len(public_key_bytes) != 1312:  # MLDSA44 public key size
            raise Mldsa44UsageError(f"Invalid public key size: {len(public_key_bytes)} bytes")
        self.public_key_bytes = public_key_bytes

    def shortname(self):
        return "mldsa44"

    def _unsupported(self, name):
        raise Mldsa44UsageError(f"Operation {name} requires private key")

    def _get_public(self):
        return self.public_key_bytes

    def get_public_bytes(self):
        """Return raw public key bytes (dilithium doesn't use DER/PEM by default)"""
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
        return 2420  # MLDSA44 signature length

    def verify_digest(self, signature, digest):
        """Verify that signature is valid for given digest"""
        try:
            # dilithium.verify returns True/False
            return dilithium.verify(signature, digest, self.public_key_bytes)
        except Exception:
            return False


class Mldsa44(Mldsa44Public):
    """
    Wrapper around an MLDSA44 private key.
    
    Provides methods for key generation, signing, and exporting both
    private and public keys in various formats for post-quantum cryptography.
    """

    def __init__(self, private_key_bytes, public_key_bytes):
        """Initialize with raw private and public key bytes from dilithium"""
        if not isinstance(private_key_bytes, bytes):
            raise Mldsa44UsageError("Private key must be bytes")
        if len(private_key_bytes) != 2560:  # MLDSA44 private key size
            raise Mldsa44UsageError(f"Invalid private key size: {len(private_key_bytes)} bytes")
        
        super().__init__(public_key_bytes)
        self.private_key_bytes = private_key_bytes

    @staticmethod
    def generate():
        """Generate a new MLDSA44 key pair"""
        public_key, private_key = dilithium.keypair()
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
        """
        Write the private key to the given file as raw bytes.
        Note: Password protection not supported with raw dilithium keys.
        """
        if passwd is not None:
            raise Mldsa44UsageError("Password protection not supported for raw dilithium keys")
        
        try:
            with open(path, 'wb') as f:
                f.write(self.private_key_bytes)
        except OSError as e:
            raise Mldsa44UsageError(f"Failed to write private key to {path}: {e}")

    def sign_digest(self, digest):
        """Return the actual signature"""
        return dilithium.sign(digest, self.private_key_bytes)