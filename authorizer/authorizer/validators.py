from collections import OrderedDict
from umsgpack import packb
import base64
import datetime
import dateutil.parser

from Cryptodome.Hash import SHA256

from libs import Identity
from .exceptions import ValidationError


def verify_sha256(content, providen_hash: bytes):
    """verify_sha256

    Helper function for SHA256 hash verification

    :param content: Any object
    :param providen_hash: hash digest bytestring
    """

    if type(content) == str:
        content = content.encode()
    elif isinstance(content, dict):
        # Sometimes content is wrongfullty decoded beforehand
        content = packb(content)
    return providen_hash == SHA256.new(content).digest()


def validate_timestamped_signature(pubkey: str, _hash: bytes, signature: dict):
    """validate_timestamped_signature

    Validates a timestamped signature.

    :param pubkey: User's public Key
    :param _hash: Provided hash.
    :param signature: Signature to verify, decoded msgpack object
    """

    identity = Identity(pubkey)

    sign = signature['signature']
    timestamp = signature['timestamp']

    validator_map = OrderedDict()
    validator_map['timestamp'] = timestamp
    validator_map['messageHash'] = base64.b64encode(hash)

    validator = packb(validator_map)

    if not identity.verify(validator, sign):
        raise ValidationError('Invalid sign')


def validate_objects(sender_pubkey, objects=[]):
    """validate_objects

    Validates all the objects received with a message

    :param sender_pubkey: User's public key
    :param objects: Object list
    """
    # For each container
    for _object in objects:

        # if objectContainer be present
        container = _object.get('objectContainer')
        container_hash = _object.get('objectHash')
        if container:
            # Validate container hash
            verify_sha256(container, container_hash)

            # Validate container signature
            validate_timestamped_signature(
                sender_pubkey, container_hash, _object.get('containerSig'))
