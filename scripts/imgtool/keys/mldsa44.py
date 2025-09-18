"""
MLDSA44 key management
"""

# SPDX-License-Identifier: Apache-2.0

from dilithium import Dilithium  # Use the correct import
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
        if len(public_key_bytes) != 1312:  # Actual Dilithium2 public key size
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
        return 2420  # Actual Dilithium2/MLDSA44 signature length

    def verify_digest(self, signature, digest):
        """Verify that signature is valid for given digest"""
        try:
            # Use Dilithium2 parameter set for MLDSA44
            from dilithium import DEFAULT_PARAMETERS
            dilithium_instance = Dilithium(DEFAULT_PARAMETERS['dilithium2'])
            
            # Unpack the signature for verification
            z, h = dilithium_instance._unpack_sig(signature)
            
            # Verify with unpacked signature and packed public key
            # Check parameter order - might be (pk, message, z, h) or similar
            return dilithium_instance.verify(self.public_key_bytes, digest, z, h)
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
        if len(private_key_bytes) != 2528:  # Actual Dilithium2 private key size
            raise Mldsa44UsageError(f"Invalid private key size: {len(private_key_bytes)} bytes, expected 2528")
        
        super().__init__(public_key_bytes)
        self.private_key_bytes = private_key_bytes

    @staticmethod
    def generate():
        """Generate a new MLDSA44 key pair using Dilithium2 parameter set"""
        import os
        from dilithium import DEFAULT_PARAMETERS
        
        # MLDSA44 corresponds to Dilithium2
        dilithium_instance = Dilithium(DEFAULT_PARAMETERS['dilithium2'])
        
        # Generate 16-byte random seed for key generation
        key_seed = os.urandom(16)
        
        # Generate key pair with seed
        public_key, private_key = dilithium_instance.keygen(key_seed)
        
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
        from dilithium import DEFAULT_PARAMETERS
        # MLDSA44 corresponds to Dilithium2
        dilithium_instance = Dilithium(DEFAULT_PARAMETERS['dilithium2'])
        
        # Use sign_with_input which returns a packed signature directly
        packed_signature = dilithium_instance.sign_with_input(self.private_key_bytes, digest)
        
        return packed_signature