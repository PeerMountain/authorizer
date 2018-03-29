from mock import reader as Reader
from libs import Identity
from Cryptodome.Hash import SHA256
from collections import OrderedDict
import msgpack
import base64
import datetime
import dateutil.parser

from . import identity as Teleferic_Identity


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
        content = msgpack.packb(content)
    return providen_hash == SHA256.new(content).digest()


def validate_timestamped_signature(pubkey: str, _hash: bytes, signature: dict):
    """validate_timestamped_signature

    Validates a timestamped signature.

    :param pubkey: User's public Key
    :param _hash: Provided hash.
    :param signature: Signature to verify, decoded msgpack object
    """
    identity = Identity(pubkey)

    sign = signature[b'signature']
    timestamp = signature[b'timestamp']

    validator_map = OrderedDict()
    validator_map['timestamp'] = timestamp
    validator_map['messageHash'] = base64.b64encode(hash)

    validator = msgpack.packb(validator_map)

    if not identity.verify(validator, sign):
        raise ValidationError("Invalid sign")


def validate_objects(sender_pubkey, objects=[]):
    """validate_objects

    Validates all the objects received with a message

    Stub function

    :param sender_pubkey: User's public key
    :param objects: Object list
    """
    # FIXME validate all objects.
    # FIXME integrate in message validation.
    # For each container
    for _object in objects:
        object_hash = _object.get('objectHash')

        # if objectContainer be present
        objectContainer = _object.get('objectContainer')
        if not objectContainer is None:
            container_object = _object.get('objectContainer')
            container_hash = _object.get('containerHash')
            # Validate container hash
            verify_sha256(_object.get('objectContainer'),
                        _object.get('containerHash'))

            # Validate container signature
            validate_timestamped_signature(
                sender_pubkey, container_hash, _object.get('containerSig'))
        # else:
        #     if not Reader.object_existnce(object_hash):
        #         raise Exception('Object %s not exist.' % object_hash)
