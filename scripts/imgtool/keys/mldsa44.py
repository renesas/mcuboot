"""
MLDSA44 key management
"""

# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ml_dsa

from .general import KeyClass


class Mldsa44UsageError(Exception):
    pass


class Mldsa44Public(KeyClass):
    def __init__(self, key):
        if not isinstance(key, (ml_dsa.MLDSAPrivateKey, ml_dsa.MLDSAPublicKey)):
            raise Mldsa44UsageError("Key must be an MLDSA key instance")
        self.key = key

    def shortname(self):
        return "mldsa44"

    def _unsupported(self, name):
        raise Mldsa44UsageError(f"Operation {name} requires private key")

    def _get_public(self):
        return self.key

    def get_public_bytes(self):
        # The key is embedded into MBUboot in "SubjectPublicKeyInfo" format
        return self._get_public().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def get_private_bytes(self, minimal, format):
        self._unsupported('get_private_bytes')

    def export_private(self, path, passwd=None):
        self._unsupported('export_private')

    def export_public(self, path):
        """Write the public key to the given file."""
        try:
            pem = self._get_public().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
            with open(path, 'wb') as f:
                f.write(pem)
        except OSError as e:
            raise Mldsa44UsageError(f"Failed to write public key to {path}: {e}")

    def sig_type(self):
        return "MLDSA44"

    def sig_tlv(self):
        return "MLDSA44"

    def sig_len(self):
        return 2420  # ML-DSA-44 signature length

    def verify_digest(self, signature, digest):
        """Verify that signature is valid for given digest"""
        k = self.key
        if isinstance(self.key, ml_dsa.MLDSAPrivateKey):
            k = self.key.public_key()
        
        try:
            k.verify(signature=signature, data=digest)
            return True
        except Exception:
            return False


class Mldsa44(Mldsa44Public):
    """
    Wrapper around an MLDSA44 private key.
    
    Provides methods for key generation, signing, and exporting both
    private and public keys in various formats for post-quantum cryptography.
    """

    def __init__(self, key):
        """key should be an instance of MLDSAPrivateKey"""
        if not isinstance(key, ml_dsa.MLDSAPrivateKey):
            raise Mldsa44UsageError("Key must be an MLDSA private key instance")
        self.key = key

    @staticmethod
    def generate():
        # Generate ML-DSA-44 private key (security level 2)
        pk = ml_dsa.MLDSAPrivateKey.generate(ml_dsa.MLDSAParameterSet.ML_DSA_44)
        return Mldsa44(pk)

    def _get_public(self):
        return self.key.public_key()

    def get_private_bytes(self, minimal, format):
        raise Mldsa44UsageError(f"get_private_bytes not supported with {self.shortname()} keys")

    def export_private(self, path, passwd=None):
        """
        Write the private key to the given file, protecting it with the
        optional password.
        """
        try:
            if passwd is None:
                enc = serialization.NoEncryption()
            else:
                enc = serialization.BestAvailableEncryption(passwd)
            
            pem = self.key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=enc)
            
            with open(path, 'wb') as f:
                f.write(pem)
        except OSError as e:
            raise Mldsa44UsageError(f"Failed to write private key to {path}: {e}")

    def sign_digest(self, digest):
        """Return the actual signature"""
        return self.key.sign(data=digest)