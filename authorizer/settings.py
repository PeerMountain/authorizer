from os import getenv
import logging
import logging.config


BROKER_URL = getenv('BROKER_URL')
if not BROKER_URL:
    raise NotImplementedError('BROKER_URL must be configured.')


READER_HOSTNAME = getenv('READER_HOSTNAME')
if not READER_HOSTNAME:
    raise NotImplementedError('READER_HOSTNAME must be configured.')


READER_PORT = getenv('READER_PORT')
if not READER_PORT:
    raise NotImplementedError('READER_PORT must be configured.')


def configure_logging():
    logging.config.fileConfig('logging_config.cfg')
