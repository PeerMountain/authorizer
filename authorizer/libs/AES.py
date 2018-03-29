import logging
import random
import base64
from typing import Union

from Cryptodome.Cipher import AES as Base_AES


logger = logging.getLogger(__name__)


class AES:
    """AES

    Helper class for AES, using GCM mode.
    """

    def __init__(self, key: bytes, nonce: Union[bytes, None]=None):
        """__init__
        Initialize the cipher.
        :param key: Encryption or decryption key.
        :type key: bytes
        :param nonce: Nonce to be used in encryption or decryption.
            If no nonce is supplied, a random one WILL be generated.
        :type nonce: Union[bytes, None]
        """
        self.nonce = (
            nonce if nonce
            else bytes(random.randint(1, 255) for _ in range(16))
        )
        self.key = key
        self.cipher = Base_AES.new(key, Base_AES.MODE_GCM, nonce=self.nonce)

    def decrypt(self, ciphertext: bytes, tag: Union[bytes, None]=None) -> bytes:  # NOQA
        """decrypt
        Decrypt a piece of ciphertext.
        :param ciphertext: Base64 encoded ciphertext to decrypt.
        :type ciphertext: bytes
        :param tag: Base64 encoded tag to be used for message authentication.
            If no tag is supplied, authentication WILL NOT be performed.
        :type tag: Union[bytes, None]
        :rtype: bytes
        """
        decoded_ciphertext = base64.b64decode(ciphertext)
        plaintext = self.cipher.decrypt(decoded_ciphertext)
        if not tag:
            logger.warning("Tag not supplied, skipping message authentication.")  # NOQA
            return plaintext
        try:
            self.cipher.verify(
                base64.b64decode(tag)
            )
            logger.debug("AES tag verified successfully!")
            return plaintext
        except ValueError:
            logger.error(
                "AES tag could not be verfied."
                " Key incorrect or message corrupted."
            )
            return None

    def encrypt(self, data: bytes) -> bytes:
        """encrypt
        Encrypt a piece of data.
        :param data: Data to be encrypted.
        :type data: bytes
        :rtype: bytes
        """
        ciphertext, _ = self.cipher.encrypt_and_digest(data)
        return base64.b64encode(ciphertext)
