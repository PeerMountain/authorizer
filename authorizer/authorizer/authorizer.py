import base64
import logging
import time
from collections import OrderedDict

import msgpack
from Cryptodome.Hash import HMAC, SHA256

from libs import AES, Identity
from mock import reader as Reader

from . import identity as Teleferic_Identity, ValidationError
from .constants import PUBLIC_AES_KEY, BodyTypes, MessageTypes, Parameters
from .validators import validate_objects, verify_sha256


logger = logging.getLogger(__name__)


def authorize_message(envelope: dict):
    """authorize_message

    Main validation function.
    Performs all necessary validations on received messages.
    If a validation does not pass, an exception will be raised.

    :param envelope: message received from the user.
    """
    logger.debug(f"Authorizing message with hash {envelope.get('messageHash')}")
    try:
        Reader.get_message(envelope.get('messageHash'))
    except Reader.NotFound:
        pass
    else:
        raise ValidationError('Message already registred')
    logger.debug(f'Message does not exist. Continuing.')
    if envelope.get('messageType') == MessageTypes.REGISTRATION:
        sender_pubkey = validate_message_registration(envelope.get('message'))
    else:
        sender_pubkey = None

    if not sender_pubkey:
        # Validate Sender
        sender = envelope.get('sender')
        try:
            sender_pubkey = Reader.get_persona(address=sender).get('pubkey')
        except Reader.NotFound:
            raise ValidationError(f'Sender address {sender} does not exist.')

    # Validate MessageHash
    verify_sha256(
        envelope.get('message'),
        base64.b64decode(envelope.get('messageHash'))
    )

    # Validate Sign
    signature = envelope.get('messageSign')
    validate_timestamped_signature(
        sender_pubkey,
        envelope.get('messageHash'),
        signature
    )

    if envelope.get('messageType') != MessageTypes.REGISTRATION:
        validate_access_control_list(envelope.get('ACL'))
        validate_objects(sender_pubkey, envelope.get('objects'))
    else:
        validate_public_message(envelope)
    return True


def validate_timestamped_signature(sender_pubkey: str, message_hash: str, signature: str):
    """validate_timestamped_signature

    Validate if the timestamped signature received is correct.
    If a validation does not pass, an exception will be raised.

    :param sender_pubkey: Sender user's public key
    :param message_hash: base64 encoded SHA-256 of the received message
    :param signature:
        Message signature as received in the envelope.
        Actually a base64 encoded msgpacked dictionary.
    """
    identity = Identity(sender_pubkey)

    signature = msgpack.unpackb(
        base64.b64decode(signature)
    )

    sign = signature[b'signature']
    timestamp = signature[b'timestamp']

    teleferic_signature = msgpack.unpackb(base64.b64decode(timestamp))
    teleferic_time = teleferic_signature[b'timestamp']
    teleferic_sign = teleferic_signature[b'signature']

    logger.debug(f"Included signature timestamp is from {teleferic_time}")

    # Validate if timestamp is signed by Teleferic
    if not Teleferic_Identity.verify_signature(
            teleferic_time,
            teleferic_sign):
        raise ValidationError("Teleferic timestamped signature is invalid.")

    # Validate tolerance
    timedelta = time.time()//1 - float(teleferic_time)
    logger.debug(f"Timedelta between present and sign time is {timedelta}")
    if timedelta > Parameters.TOLERABLE_TIME_DIFFERENCE_IN_SECONDS:
        raise ValidationError("Timestamped signature time tolerance exceeded.")

    validator_map = OrderedDict()
    validator_map['messageHash'] = message_hash
    validator_map['timestamp'] = timestamp

    validator = msgpack.packb(validator_map)

    if not identity.verify(validator, sign):
        raise ValidationError("User message signature invalid.")
    logger.debug("User message signature is valid")


def validate_message_registration(message: str):
    """validate_message_registration

    Validates the message if it is a registration message.
    If the validation succeeds, returns the sender's public key
    as received in the message.
    Else, returns none.

    :param message: message part of the envelope.
    """
    sender_pubkey = None
    try:
        message_content_raw = base64.b64decode(message)
        logger.debug("Successfully decoded message")

        # Parse message
        message_content = msgpack.unpackb(message_content_raw)
        if message_content[b'bodyType'] == BodyTypes.Registration.REGISTRATION:
            message_body = msgpack.unpackb(
                base64.b64decode(message_content[b'messageBody']))
            sender_pubkey = message_body[b'publicKey'].decode()
            logger.debug("Successfully retrieved user pubkey from message")
    except Exception:
        raise ValidationError(
            "Message could not be decoded."
            " Are you sure that it is Base64 encoded?"
        )

    return sender_pubkey


def validate_access_control_list(ACL: list):
    """validate_access_control_list

    Validates that all readers mentioned in the access control list
    are registered with us.
    If a validation does not pass, an exception will be raised.

    :param ACL: List of dictionaries containing ACL rules.
    """
    if ACL:
        logger.debug(f"Message has ACL, with {len(ACL)} readers")
        for ACL_rule in ACL:
            reader = ACL_rule.get('reader')
            # Raise an exception if some address be not registred
            try:
                Reader.get_persona(address=reader)
                logger.debug(f"Reader with address {reader} exists.")
            except ValidationError:
                raise ValidationError('Reader address %s not exist.' % reader)
    else:
        raise ValidationError('Invalid ACL')


def decrypt_message(message):
    """Try to decrypt the message as a public one.
    If decryption fails, an exception is raised

    :param encrypted_message: Base64 encoded messagepacked message.
    :return: tuple (dict, bytes), message content, parsed and msgpack raw data
    """
    try:
        message_content_raw = base64.b64decode(message)
    except Exception as e:
        logging.warning("Message is not base64 encoded.")
    try:
        # Parse message
        message_content = msgpack.unpackb(message_content_raw)
        return message_content, message_content_raw
    except Exception as e:
        raise ValidationError('Invalid public message content.')


def validate_message_body(envelope, message_content):
    """validate_message_body

    Verify that the hash of the body matches what we expect.
    If verification fails an exception is raised.

    :param envelope: dictionary, envelope as received for the user
    :param message_content: message content decrypted from the envelope
    """
    body_hash = base64.b64decode(envelope.get('bodyHash'))
    message_body_raw = message_content.get(b'messageBody')
    if not verify_sha256(message_body_raw, body_hash):
        raise ValidationError('Invalid bodyHash.')
    logger.debug("Body hash matches expected value.")


def validate_dossier_salt(message_content):
    dossier_salt = base64.b64decode(message_content.get(b'dossierSalt'))
    if len(dossier_salt) != 40:
        raise ValidationError('Invalid dossierSalt.')
    logger.debug("Dossier Salt is the correct length")


def validate_dossier_hash(dossier_hash, dossier_salt, message_body_raw):
    if dossier_hash != HMAC.new(dossier_salt, message_body_raw, SHA256).digest():
        raise ValidationError('Invalid dossierHash.')
    logger.debug("Dossier Hash matches expected value.")


def parse_message_body(message_body_raw):
    """parse_message_body

    Try to parse the message body.
    If parsing fails, an exception is raised.

    :param message_body_raw: Raw base64 encoded msgpack data
    :return: dict with contents of the message itself.
    """
    if isinstance(message_body_raw, dict):
        return message_body_raw
    try:
        decoded_message_body = base64.b64decode(message_body_raw)
        message_body = msgpack.unpackb(decoded_message_body)
        logger.debug("Successfully extracted message body.")
        return message_body
    except Exception as e:
        raise ValidationError('Invalid messageBody.')


def validate_public_message(envelope):
    """validate_public_message

    Performs validations for all public messages
    If a validation does not pass, an exception will be raised.

    :param encrypted_message: encrypted message content
    """
    logger.debug('Message is public, running validations.')

    message_content_raw = base64.b64decode(envelope.get('message'))

    # Validate Pulic Message
    message_content = msgpack.unpackb(message_content_raw)

    # Validate Body
    validate_message_body(envelope, message_content)

    # Validate dossierSalt
    validate_dossier_salt(message_content)

    # Validate dossierHash
    dossier_salt = base64.b64decode(message_content.get(b'dossierSalt'))
    dossier_hash = base64.b64decode(envelope.get('dossierHash'))
    validate_dossier_hash(dossier_hash, dossier_salt, message_content_raw)

    # Parse message body
    message_body_raw = message_content.get(b'messageBody')
    message_body = parse_message_body(message_body_raw)

    if message_content.get(b'bodyType') == MessageTypes.INVITE:
        validate_invite(message_body)
    elif message_content.get(b'bodyType') == MessageTypes.REGISTRATION:
        validate_registration(message_body)


def validate_registration(message_body: dict):
    """validate_registration

    Performs necessary validations on REGISTRATION messages

    :param message_body: decrypted and unpacked message body
        Notice that the keys are all bytestrings since
        msgpack#unpackb returns dicts in that fashion.
    """
    logger.debug("Body type is registration, running registration verifications")
    # Validate bootstrap node
    invite_message_hash = message_body.get(b'inviteMsgID')
    if not invite_message_hash:
        raise ValidationError('Invalid invite message hash.')
    logger.debug(f"Registration references valid invite {invite_message_hash}")

    nickname = message_body.get(b'publicNickname')
    if not nickname:
        raise ValidationError('Invalid nickname.')

    # Try deciphering the message using the public aes key.
    invite_message = Reader.get_message(invite_message_hash)
    logger.debug("Successfully retrieved referenced invite message")
    try:
        invite_message_content_raw = base64.b64decode(invite_message['message'])
        # Parse message
        invite_message_content = msgpack.unpackb(
            invite_message_content_raw
        )
        invite_message_body_content = msgpack.unpackb(base64.b64decode(
            invite_message_content.get(b'messageBody')
        ))
    except Exception as e:
        raise ValidationError('Invalid invite message content.')

    # Extract the keyProof from the registration message
    logger.debug("Verifying proofs.")
    key_proof_raw = message_body.get(b'keyProof')
    try:
        invite_proof = msgpack.unpackb(
            Teleferic_Identity.decrypt_content(key_proof_raw)
        )
        key_proof = invite_proof.get(b'key')
        nonce_proof = invite_proof.get(b'nonce')
    except Exception as e:
        raise ValidationError('Invalid Key Proof')
    if not key_proof:
        raise ValidationError('Invalid Key Proof')
    logger.debug("Key Proof is valid.")

    # Try decoding the original inviteName from the invite message.
    decoder = AES(key_proof, nonce=nonce_proof)

    original_invite_name_raw = invite_message_body_content.get(b'inviteName')
    original_invite_name = decoder.decrypt(original_invite_name_raw)

    logger.debug("Successfully decrypted invite message using key proof.")

    given_invite_name_raw = message_body.get(b'inviteName')
    given_invite_name = Teleferic_Identity.decrypt_content(
        given_invite_name_raw)

    # Check the registration invite name against the original invite name.
    if original_invite_name != given_invite_name:
        raise ValidationError('Invalid Invite Key.')
    logger.debug('Invite key is valid.')

    # If these validations pass, register the persona into our database.
    logger.debug("Validations successful, registering new user.")
    public_key = message_body.get(b'publicKey')

    if not Reader.persona_exists(nickname, public_key):
        logger.debug("New user has address {new_identity.address}")
    else:
        raise ValidationError('Persona already exists.')


def validate_invite(message_body: dict):
    """validate_invite

    Performs necessary validations on INVITE messages.

    :param message_body: decrypted and unpacked message body
        Notice that the keys are all bytestrings since
        msgpack#unpackb returns dicts in that fashion.
    """
    # Validate bootstrap node
    bootstrap_node = message_body.get(b'bootstrapNode')
    if not bootstrap_node:
        raise ValidationError('Invalid bootstrapNode.')

    # Validate bootstrap address
    bootstrap_address = message_body.get(b'bootstrapAddr')
    if not bootstrap_address:
        raise ValidationError('Invalid bootstrapAddr.')

    # Validate offering address
    offering_address = message_body.get(b'offeringAddr')
    if not offering_address:
        raise ValidationError('Invalid offeringAddr.')

    # Validate service announcement message
    service_announcement_message = message_body.get(
        b'serviceAnnouncementMessage')
    if not service_announcement_message:
        raise ValidationError('Invalid serviceAnnouncementMessage.')

    # Validate service offering id
    service_offering_id = message_body.get(b'serviceOfferingID')
    if not service_offering_id:
        raise ValidationError('Invalid serviceOfferingID.')

    # Validate invite name
    invite_name_raw = message_body.get(b'inviteName')
    if not invite_name_raw:
        raise ValidationError('Invalid inviteName.')
