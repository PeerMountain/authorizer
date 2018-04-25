from kombu import Connection
from umsgpack import packb

from .queues import writer_exchange, writer_queue
from settings import BROKER_URL


BROKER_CONNECTION = Connection(BROKER_URL)


def send_message_to_writer(envelope: dict):
    """send_message_to_writer

    :param envelope: Envelope as received by Authorizer from the user.
    :type envelope: dict
    """

    message = packb(envelope)
    producer = BROKER_CONNECTION.Producer()
    producer.publish(
        message,
        exchange=writer_exchange,
        routing_key='writer',
        declare=[writer_queue],
    )
