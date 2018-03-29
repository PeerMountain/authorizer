import logging
import base64

from Cryptodome import Random
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA as Key
from Cryptodome.Util.number import bytes_to_long, long_to_bytes


logger = logging.getLogger(__name__)


class RSA():

    @staticmethod
    def from_b64(encoded):
        return RSA(base64.b64decode(encoded))

    def __init__(self, key):
        if isinstance(key, (str, bytes)):
            self.key = Key.importKey(key)
        elif isinstance(key, Key.RsaKey):
            self.key = key
        else:
            raise Exception('Invalid key format.')

    def encrypt(self, content):
        cyphred_content = PKCS1_OAEP.new(self.key).encrypt(content)
        return base64.b64encode(cyphred_content)

    def decrypt(self, b64_ciphred_content):
        ciphred_content = base64.b64decode(b64_ciphred_content)
        return PKCS1_OAEP.new(self.key).decrypt(ciphred_content)

    def sign(self, content):
        content_hash = SHA256.new(content)
        signature = pkcs1_15.new(self.key).sign(content_hash)
        return base64.b64encode(signature)

    def verify(self, content, b64_bytes_signature):
        content_hash = SHA256.new(content)
        bytes_signature = base64.b64decode(b64_bytes_signature)
        try:
            pkcs1_15.new(self.key).verify(content_hash, bytes_signature)
            return True
        except ValueError as exc:
            # Signature validation did not pass
            logger.error(str(exc))
            return False
