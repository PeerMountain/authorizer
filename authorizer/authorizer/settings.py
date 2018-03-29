from os import getenv

BROKER_URL = getenv('BROKER_URL')

if not BROKER_URL:
    raise NotImplementedError('BROKER_URL must be configured.')

