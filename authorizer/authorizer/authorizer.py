import base64
import logging
import time
from collections import OrderedDict

import msgpack  # used to validate the message sign
from umsgpack import packb, unpackb
from Cryptodome.Hash import HMAC, SHA256

from libs import AES, Identity
from reader.reader import reader
from . import identity as Teleferic_Identity
from .exceptions import ValidationError
from .constants import  BodyTypes, MessageTypes, Parameters
from .validators import validate_objects, verify_sha256


logger = logging.getLogger(__name__)


def authorize_message(envelope: dict):
    """authorize_message

    Main validation function.
    Performs all necessary validations on received messages.
    If a validation does not pass, an exception will be raised.

    :param envelope: message received from the user.
    """

    message_hash = envelope.get('messageHash')
    message_type = envelope.get('messageType')
    message = envelope.get('message')
    sender = envelope.get('sender')
    signature = envelope.get('messageSign')
    acl = envelope.get('ACL')
    objects = envelope.get('objects')

    logger.debug(f'Authorizing message with hash {message_hash}')

    response = reader.message(hash=message_hash)
    if response.get('response') and response.get('status') == 200:
        raise ValidationError('Message already registred')

    logger.debug(f'Message does not exist. Continuing')

    sender_pubkey = None
    if message_type in [MessageTypes.REGISTRATION]:
        sender_pubkey = validate_message_registration(message)

    if not sender_pubkey:
        persona = reader.persona(address=sender)

        if persona.get('error') or persona.get('status') == 404:
            error_message = response.get('error').get('data').get('message')
            raise ValidationError(f'Persona with address {sender} not found')

        sender_pubkey = persona.get('response').get('pubkey')

    # Validate MessageHash
    verify_sha256(
        message,
        base64.b64decode(message_hash),
    )

    # Validate Sign
    validate_timestamped_signature(
        sender_pubkey,
        message_hash,
        signature,
    )

    if message_type not in [MessageTypes.REGISTRATION]:
        validate_access_control_list(acl)
        validate_objects(sender_pubkey, objects)
    else:
        validate_public_message(envelope)


def validate_timestamped_signature(
    sender_pubkey: str,
    message_hash: str,
    signature: str
):
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

    logger.debug(f'Included signature timestamp is from {teleferic_time}')

    # Validate if timestamp is signed by Teleferic
    if not Teleferic_Identity.verify_signature(
        teleferic_time,
        teleferic_sign,
    ):
        raise ValidationError('Teleferic timestamped signature is invalid')

    # Validate tolerance
    timedelta = time.time()//1 - float(teleferic_time)
    logger.debug(f'Timedelta between present and sign time is {timedelta}')
    if timedelta > Parameters.TOLERABLE_TIME_DIFFERENCE_IN_SECONDS:
        raise ValidationError('Timestamped signature time tolerance exceeded')

    validator_map = OrderedDict()
    validator_map['messageHash'] = message_hash
    validator_map['timestamp'] = timestamp

    validator = msgpack.packb(validator_map)

    if not identity.verify(validator, sign):
        raise ValidationError('User message signature invalid')

    logger.debug('User message signature is valid')


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
        message_content = unpackb(message_content_raw)
        if message_content['bodyType'] == BodyTypes.Registration.REGISTRATION:
            message_body = unpackb(
                base64.b64decode(message_content['messageBody']))
            sender_pubkey = message_body['publicKey']
            logger.debug("Successfully retrieved user pubkey from message")
    except Exception:
        raise ValidationError(
            'Message could not be decoded.'
            ' Are you sure that it is Base64 encoded?'
        )

    return sender_pubkey


def validate_access_control_list(ACL: list):
    """validate_access_control_list

    Validates that all readers mentioned in the access control list
    are registered with us.
    If a validation does not pass, an exception will be raised.

    :param ACL: List of dictionaries containing ACL rules.
    """

    logger.debug(f'Message has ACL, with {len(ACL)} readers')

    for rule in ACL:
        acl_reader = rule.get('reader')
        persona = reader.persona(address=acl_reader)

        if not persona.get('response') and persona.get('status') == 404:
            log_message = f'Reader with address {reader} exists'
            logger.debug(log_message)
            raise ValidationError(log_message)


def decrypt_message(message):
    """Try to decrypt the message as a public one.
    If decryption fails, an exception is raised

    :param encrypted_message: Base64 encoded messagepacked message.
    :return: tuple (dict, bytes), message content, parsed and msgpack raw data
    """

    try:
        message_content_raw = base64.b64decode(message)
    except Exception as e:
        logging.warning('Message is not base64 encoded')

    try:
        # Parse message
        message_content = unpackb(message_content_raw)
        return message_content, message_content_raw
    except Exception as e:
        raise ValidationError('Invalid public message content')


def validate_message_body(envelope, message_content):
    """validate_message_body

    Verify that the hash of the body matches what we expect.
    If verification fails an exception is raised.

    :param envelope: dictionary, envelope as received for the user
    :param message_content: message content decrypted from the envelope
    """

    body_hash = base64.b64decode(envelope.get('bodyHash'))
    message_body_raw = message_content.get('messageBody')

    if not verify_sha256(message_body_raw, body_hash):
        raise ValidationError('Invalid bodyHash.')
    logger.debug('Body hash matches expected value')


def validate_dossier_salt(message_content):
    """

    """

    dossier_salt = base64.b64decode(message_content.get('dossierSalt'))
    if len(dossier_salt) != 40:
        raise ValidationError('Invalid dossierSalt')
    logger.debug('Dossier Salt is the correct length')


def validate_dossier_hash(dossier_hash, dossier_salt, message_body_raw):
    """
    
    """

    hmac = HMAC.new(dossier_salt, message_body_raw, SHA256).digest()
    if dossier_hash != hmac:
        raise ValidationError('Invalid dossierHash')
    logger.debug('Dossier Hash matches expected value')


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
        message_body = unpackb(decoded_message_body)
        logger.debug('Successfully extracted message body')
        return message_body
    except Exception as e:
        raise ValidationError('Invalid messageBody')


def validate_public_message(envelope):
    """validate_public_message

    Performs validations for all public messages
    If a validation does not pass, an exception will be raised.

    :param encrypted_message: encrypted message content
    """

    logger.debug('Message is public, running validations.')

    message_content_raw = base64.b64decode(envelope.get('message'))

    # Validate Pulic Message
    message_content = unpackb(message_content_raw)

    # Validate Body
    validate_message_body(envelope, message_content)

    # Validate dossierSalt
    validate_dossier_salt(message_content)

    # Validate dossierHash
    dossier_salt = base64.b64decode(message_content.get('dossierSalt'))
    dossier_hash = base64.b64decode(envelope.get('dossierHash'))
    validate_dossier_hash(dossier_hash, dossier_salt, message_content_raw)

    # Parse message body
    message_body_raw = message_content.get('messageBody')
    message_body = parse_message_body(message_body_raw)

    if message_content.get('bodyType') == MessageTypes.INVITE:
        validate_invite(message_body)
    elif message_content.get('bodyType') == MessageTypes.REGISTRATION:
        validate_registration(message_body)


def validate_registration(message_body: dict):
    """validate_registration

    Performs necessary validations on REGISTRATION messages

    :param message_body: decrypted and unpacked message body
        Notice that the keys are all bytestrings since
        msgpack#unpackb returns dicts in that fashion.
    """

    logger.debug('Body type is registration, running registration verifications')

    # Validate bootstrap node
    invite_message_hash = message_body.get('inviteMsgID')
    if not invite_message_hash:
        raise ValidationError('Invalid invite message hash.')
    logger.debug(f'Registration references valid invite {invite_message_hash}')

    nickname = message_body.get('publicNickname')
    if not nickname:
        raise ValidationError('Invalid nickname.')

    # Try deciphering the message using the public aes key.
    invite_message = reader.message(hash=invite_message_hash)
    # verify if reader really gets the message
    try:
        logger.debug('Successfully retrieved referenced invite message')
        invite_message_content_raw = invite_message.get('response').get('message')
        invite_message_content = unpackb(
            base64.b64decode(invite_message_content_raw)
        )
        invite_message_body_content = unpackb(
            base64.b64decode(invite_message_content.get('messageBody'))
        )
    except Exception as e:
        raise ValidationError(e)

    # Extract the keyProof from the registration message
    try:
        key_proof_raw = message_body.get('keyProof')
        key_proof_decrypted = Teleferic_Identity.decrypt_content(key_proof_raw)
        invite_proof = unpackb(key_proof_decrypted)
        key_proof = invite_proof.get('key').encode()
        nonce_proof = invite_proof.get('nonce').encode()
    except Exception as e:
        raise ValidationError(e)
    logger.debug('Key Proof is valid')


    # Try decoding the original inviteName from the invite message.
    decoder = AES(key_proof, nonce=nonce_proof)

    original_invite_name_raw = invite_message_body_content.get('inviteName')
    original_invite_name = decoder.decrypt(original_invite_name_raw)

    logger.debug('Successfully decrypted invite message using key proof')

    given_invite_name_raw = message_body.get('inviteName')
    given_invite_name = Teleferic_Identity.decrypt_content(
        given_invite_name_raw
    )

    # Check the registration invite name against the original invite name.
    if original_invite_name != given_invite_name:
        raise ValidationError('Invalid Invite Key')
    logger.debug('Invite key is valid')

    # If these validations pass, register the persona into our database.
    logger.debug('Validations successful, registering new user')
    public_key = message_body.get('publicKey')

    persona = reader.persona(pubkey=public_key)
    if persona.get('response') and persona.get('status') == 200:
        logger.debug('New user has address {new_identity.address}')
    else:
        raise ValidationError('Persona already exists')


def validate_invite(message_body: dict):
    """validate_invite

    Performs necessary validations on INVITE messages.

    :param message_body: decrypted and unpacked message body
        Notice that the keys are all bytestrings since
        msgpack#unpackb returns dicts in that fashion.
    """

    # Validate bootstrap node
    bootstrap_node = message_body.get('bootstrapNode')
    if not bootstrap_node:
        raise ValidationError('Invalid bootstrapNode')

    # Validate bootstrap address
    bootstrap_address = message_body.get('bootstrapAddr')
    if not bootstrap_address:
        raise ValidationError('Invalid bootstrapAddr')

    # Validate offering address
    offering_address = message_body.get('offeringAddr')
    if not offering_address:
        raise ValidationError('Invalid offeringAddr')

    # Validate service announcement message
    service_announcement_message = message_body.get(
        'serviceAnnouncementMessage'
    )
    if not service_announcement_message:
        raise ValidationError('Invalid serviceAnnouncementMessage')

    # Validate service offering id
    service_offering_id = message_body.get('serviceOfferingID')
    if not service_offering_id:
        raise ValidationError('Invalid serviceOfferingID')

    # Validate invite name
    invite_name_raw = message_body.get('inviteName')
    if not invite_name_raw:
        raise ValidationError('Invalid inviteName')
