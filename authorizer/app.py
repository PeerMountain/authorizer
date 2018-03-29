import base64
import datetime
import json
import logging

import msgpack
from apistar import Include, Route, http, typesystem
from apistar.frameworks.wsgi import WSGIApp as App
from apistar.handlers import docs_urls, static_urls

from authorizer import authorizer, ValidationError
from authorizer.identity import TelefericIdentity, sign_current_timestamp
from authorizer.producer import send_message_to_writer
from mock import reader
import settings


settings.configure_logging()
logger = logging.getLogger(__name__)


class Date(typesystem.String):
    format = 'date'


def send_message(data: http.RequestData) -> http.Response:
    logger.debug("Received new message.")
    envelope = data['envelope']
    try:
        authorizer.authorize_message(envelope)
        send_message_to_writer(envelope)
        logger.info("Database insert queued.")
    except ValidationError as exc:
        logger.error(exc.message)
        return http.Response(
            content={'error': exc.message},
            status=400
        )
    else:
        return http.Response(
            content=envelope,
            status=201
        )


def persona(address: str=None, pubkey: str=None, nickname: str=None) -> dict:
    logger.info(f"Persona lookup, address {address} //  nickname {nickname}")
    try:
        return reader.get_persona(address, nickname, pubkey)
    except reader.NotFound:
        return http.Response(
            content={'error': 'Persona not found.'},
            status=404
        )


def teleferic() -> dict:
    return {
        'persona': {
            'address': TelefericIdentity.address,
            'pubkey': base64.b64encode(TelefericIdentity.pubkey).decode(),
            'nickname': 'Teleferic'
        },
        'signedTimestamp': base64.b64encode(
            msgpack.packb(sign_current_timestamp())
        ).decode()
    }


def messages(message_hash: str=None, date: Date=None, reader_address: str=None):
    logger.debug("Received message query")
    if message_hash:
        try:
            return reader.get_message(message_hash)
        except reader.NotFound as exc:
            return http.Response(
                content={'error': exc.message},
                status=404
            )
    elif date:
        return reader.get_messages(message_date=date)
    elif reader_address:
        return reader.get_messages(message_reader=reader_address)
    return http.Response(
        content={'error': 'You must specify at least one filter'},
        status=400
    )


routes = [
    Route('/send_message', 'POST', send_message),
    Route('/persona', 'GET', persona),
    Route('/teleferic', 'GET', teleferic),
    Route('/messages', 'GET', messages),
    Include('/docs', docs_urls),
    Include('/static', static_urls)
]


app = App(routes=routes)


if __name__ == '__main__':
    app.main()
