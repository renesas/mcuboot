"""
ML-DSA-44 key management
"""

# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Using a specialized library for ML-DSA, as pyca/cryptography doesn't support it yet
from dilithium_py.ml_dsa import ML_DSA_44  #

from .general import KeyClass


class MLDSA44UsageError(Exception):
    pass


class MLDSA44Public(KeyClass):
    def __init__(self, key):
        # Key is raw public key bytes from ML_DSA_44.keygen()
        self.key = key

    def shortname(self):
        return "mldsa-44"

    def _unsupported(self, name):
        raise MLDSA44UsageError("Operation {} requires private key".format(name))

    def _get_public(self):
        return self.key

    def get_public_bytes(self):
        # dilithium-py uses raw bytes, but we'll adapt to DER for MBUboot format
        # Note: This is an example, and the target system (MBUboot) must support ML-DSA SubjectPublicKeyInfo
        # This implementation requires custom handling for PKIX SubjectPublicKeyInfo encoding.
        # Since standard Python cryptography doesn't support this, we return the raw key for now.
        return self._get_public()

    def get_private_bytes(self, minimal, format):
        self._unsupported('get_private_bytes')

    def export_private(self, path, passwd=None):
        self._unsupported('export_private')

    def export_public(self, path):
        """
        Write the public key to the given file.
        Note: Writing the raw public key bytes, not PEM formatted.
        """
        public_bytes = self.get_public_bytes()
        with open(path, 'wb') as f:
            f.write(public_bytes)

    def sig_type(self):
        return "ML-DSA-44"

    def sig_tlv(self):
        return "ML-DSA-44"

    def sig_len(self):
        # The ML-DSA-44 signature is 2420 bytes long
        return 2420

    def verify_digest(self, signature, digest):
        """Verify that signature is valid for given digest"""
        # ML-DSA-44's verification expects the full message, not a digest.
        # If the input `digest` is actually the pre-hashed message, this works.
        # This implementation assumes the input `digest` is the full message.
        return ML_DSA_44.verify(self.key, digest, signature)


class MLDSA44(MLDSA44Public):
    """
    Wrapper around an ML-DSA-44 private key.
    """
    def __init__(self, key):
        """
        key should be the raw private key bytes from dilithium_py.ml_dsa.ML_DSA_44.keygen()
        """
        self.key = key

    @staticmethod
    def generate():
        pk, sk = ML_DSA_44.keygen()
        return MLDSA44(sk)

    def _get_public(self):
        # Public key is derived from the private key
        return ML_DSA_44.public_key(self.key)

    def get_private_bytes(self, minimal, format):
        # dilithium-py returns raw bytes; `minimal` and `format` are not used
        return self.key

    def export_private(self, path, passwd=None):
        """
        Write the private key to the given file.
        Note: Does not support password protection, as dilithium-py handles raw bytes.
        """
        private_bytes = self.key
        with open(path, 'wb') as f:
            f.write(private_bytes)

    def sign_digest(self, digest):
        """Return the actual signature"""
        # ML-DSA-44's signing expects the full message, not a digest.
        # This implementation assumes the input `digest` is the full message.
        return ML_DSA_44.sign(self.key, digest)

