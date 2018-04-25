import base64
from collections import OrderedDict

import base58
from Cryptodome import Random
from Cryptodome.Hash import RIPEMD, SHA256
from Cryptodome.PublicKey import RSA as Key

from .RSA import RSA

ADDRESS_PREFIX = [1, 0]

class Identity():
    """Identity

    Class used for handling identity related tasks such as
    RSA encryption/decryption and calculation of addresses
    """

    def __init__(self, key=None):
        """__init__

        Initialize an Identity instance using a public or private key.
        If none is supplied, generates a fresh key pair.

        :param key: String containing an RSA public or private key.
        """
        if key is None:
            rng = Random.new().read
            self.key = Key.generate(4096, rng)
        else:
            if isinstance(key, (str, bytes)):
                self.key = Key.import_key(key.strip())
            elif isinstance(key, Key.RsaKey):
                self.key = key
            else:
                raise Exception('Invalid key format.')
        self.rsa = RSA(self.key)

    @property
    def address(self):
        """address

        Calculate this Identity's address.
        """
        # The public key of the pair is hashed SHA-256.
        step_1 = SHA256.new(self.key.publickey().exportKey()).digest()
        # The resulting Hash is further hashed with RIPEMD-160.
        step_2 = RIPEMD.new(step_1).digest()
        # Two bytes are prefixed to the resulting RIPEMD-160 hash in order to
        # identify the deployment system.
        step_3 = bytes(ADDRESS_PREFIX) + step_2
        # A checksum is calculated by SHA-256 hashing the extended RIPEMD-160 hash, then hashing
        # the resulting hash once more.
        step_4_checksum = SHA256.new(SHA256.new(step_3).digest()).digest()
        # The last 4 bytes of the final hash are added as the
        # trailing 4 bytes of the extended RIPEMD-160 hash. This is the
        # checksum
        step_4 = step_3 + step_4_checksum[-4:]
        # The resulting object is Base58 encoded
        return base58.b58encode(step_4)

    @property
    def pubkey(self):
        return self.key.publickey().exportKey("PEM")

    @property
    def privkey(self):
        if self.key.has_private:
            return self.key.exportKey("PEM")
        else:
            return False

    def export_private(self, passphrase):
        if self.key.has_private:
            return self.key.exportKey(passphrase=passphrase, pkcs=8)
        else:
            return False

    def sign(self, content):
        if self.key.has_private:
            return self.rsa.sign(content)
        else:
            return False

    def verify(self, content, signature):
        return self.rsa.verify(content, signature)

    def encrypt(self, content):
        return self.rsa.encrypt(content)

    def decrypt(self, content):
        if self.key.has_private:
            return self.rsa.decrypt(content)
        else:
            return False
