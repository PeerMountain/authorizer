import time
import os

from collections import OrderedDict

from ..libs import Identity

KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__name__)), 'authorizer', 'keys')

TELEFERIC_PUBLIC_KEY = open(os.path.join(KEY_PATH, '4096_teleferic.public')).read()
TELEFERIC_KEY = open(os.path.join(KEY_PATH, '4096_teleferic.private')).read()

TelefericIdentity = Identity(TELEFERIC_KEY)


def sign_current_timestamp():
    timestamp = str(time.time()).encode()
    signature = TelefericIdentity.sign(timestamp)
    result = OrderedDict()
    result['signature'] = signature
    result['timestamp'] = timestamp
    return result


def decrypt_content(content):
    return TelefericIdentity.decrypt(content)


def verify_signature(content, sign):
    return TelefericIdentity.verify(content, sign)
