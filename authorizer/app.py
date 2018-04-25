import base64
import logging
import logging.config

from umsgpack import packb
from apistar import Include, Route, http, typesystem
from apistar.frameworks.wsgi import WSGIApp as App
from apistar.handlers import docs_urls, static_urls

from authorizer.authorizer import authorize_message
from authorizer.exceptions import ValidationError
from authorizer.identity import TelefericIdentity, sign_current_timestamp
from authorizer.producer import send_message_to_writer
from reader.reader import reader


logging.config.fileConfig('logging_config.cfg', disable_existing_loggers=False)
logger = logging.getLogger('root')


class Date(typesystem.String):
    format = 'date'


def send_message(data: http.RequestData) -> http.Response:
    """

    """

    envelope = data.get('envelope')
    message_hash = envelope.get('messageHash')

    try:
        authorize_message(envelope)
        send_message_to_writer(envelope)
        logger.info(f'Message {message_hash} sent to Writer queue')
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
    """

    """

    if address:
        logger.info(f'Persona lookup address {address}')
        response = reader.persona(address=address)
    elif pubkey:
        response = reader.persona(pubkey=pubkey)
        logger.info(f'Persona lookup pubkey {pubkey}')
    elif nickname:
        response = reader.persona(nickname=nickname)
        logger.info(f'Persona lookup nickname {nickname}')

    if not response.get('response') and response.get('status') == 404:
        return http.Response(
            content={'error': exc.message},
            status=404,
        )

    return response.get('response')


def teleferic() -> dict:
    """

    """

    response =  {
        'persona': {
            'address': TelefericIdentity.address.decode(),
            'pubkey': base64.b64encode(TelefericIdentity.pubkey).decode(),
            'nickname': 'Teleferic'
        },
        'signedTimestamp': base64.b64encode(
            packb(sign_current_timestamp())
        ).decode()
    }

    return response


def messages(message_hash: str=None, date: Date=None, reader_address: str=None):
    """

    """

    if not message_hash and not date and not reader_address:
        return http.Response(
            content={'error': 'You must specify at least one filter'},
            status=400
        )

    if message_hash:
        logger.info(f'Message lookup hash {message_hash}')
        response = reader.message(hash=message_hash)
    elif date:
        logger.info(f'Message lookup date {date}')
        response = reader.message(created_at=date)
    elif reader_address:
        logger.info(f'Message lookup reader_address {reader_address}')
        response = reader.message(persona_sender=reader_address)

    if not response.get('response') and response.get('status') == 404:
        return http.Response(
            content={'error': exc.message},
            status=404,
        )

    return response.get('response')


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
