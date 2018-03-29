import base64
import logging

from kombu import Connection
from msgpack import packb

from .queues import writer_exchange, writer_queue
from .settings import BROKER_URL
from libs import Identity


# gets instanciated every time this module is loaded
# which hopefully is enough for the connection not to die
BROKER_CONNECTION = Connection(BROKER_URL)


def send_message_to_writer(envelope: dict):
    """send_message_to_writer

    :param envelope: Envelope as received by Authorizer from the user.
    :type envelope: dict
    """
    message = packb(envelope)
    producer = BROKER_CONNECTION.Producer(serializer='msgpack')
    producer.publish(
        message,
        exchange=writer_exchange,
        routing_key='writer',
        declare=[writer_queue],
    )
