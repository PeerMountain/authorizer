from jsonrpc_requests import Server
from settings import READER_HOSTNAME, READER_PORT


READER_URL = f'http://{READER_HOSTNAME}:{READER_PORT}'
reader = Server(READER_URL)
