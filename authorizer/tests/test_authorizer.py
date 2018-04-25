import base64
import pytest
from freezegun import freeze_time

from authorizer import authorizer, validators
from .fixtures import (
    sender_pubkey
)
from .authorizer_test_parameters import (
    EXPECTED_HASHES,
    SIGNATURES,
    REGISTRATION_MESSAGES,
    ACCESS_CONTROL_LISTS,
    PUBLIC_MESSAGE_ENVELOPES,
    INVITE_MESSAGE_BODIES,
    INVITE_MESSAGE_EXAMPLE,
    REGISTRATION_MESSAGE_BODIES,
)

@pytest.mark.parametrize("content, expected_hash", EXPECTED_HASHES)
def test_verify_sha256(content, expected_hash):
    assert validators.verify_sha256(content, expected_hash)


@pytest.mark.parametrize("signature, message_hash", SIGNATURES)
@freeze_time("2018-03-07 15:08:00 UTC-3")
def test_validate_timestamped_signature(signature, message_hash, sender_pubkey):  # flake8: noqa
    authorizer.validate_timestamped_signature(sender_pubkey, message_hash, signature)


@pytest.mark.parametrize("envelope", REGISTRATION_MESSAGES)
def test_validate_message_registration(envelope):
    authorizer.validate_message_registration(envelope)


@pytest.mark.parametrize("ACL", ACCESS_CONTROL_LISTS)
def test_validate_access_control_list(ACL, mocker):
    def mock_get_persona(address):
        if address == 'validAddress':
            return {'pubkey': 'OK'}
        else:
            raise Exception()
    mocker.patch(
        'authorizer.authorizer.reader.persona',
        mock_get_persona
    )
    authorizer.validate_access_control_list(ACL)


@pytest.mark.parametrize("envelope", PUBLIC_MESSAGE_ENVELOPES)
def test_validate_public_message(envelope, mocker):
    mocker.patch('authorizer.authorizer.validate_invite', lambda *args, **kwargs: None)
    mocker.patch('authorizer.authorizer.validate_registration', lambda *args, **kwargs: None)
    authorizer.validate_public_message(envelope)


@pytest.mark.parametrize("message_body", INVITE_MESSAGE_BODIES)
def test_validate_invite_message(message_body):
    authorizer.validate_invite(message_body)


@pytest.mark.parametrize("message_body", REGISTRATION_MESSAGE_BODIES)
def test_verify_registration_message_data(message_body, mocker):
    mocker.patch(
        'authorizer.authorizer.reader.message',
        lambda hash: {'response': INVITE_MESSAGE_EXAMPLE, 'status': 200}
    )
    mocker.patch(
        'authorizer.authorizer.reader.persona',
        lambda pubkey: {
            'response': REGISTRATION_MESSAGE_BODIES[0].get('publicKey'),
            'status': 200
        }
    )
    authorizer.validate_registration(message_body)
