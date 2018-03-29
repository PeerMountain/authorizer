import logging
import base64
import tinydb

from .db import get_db
from libs import Identity


def add_persona(pubkey, nickname):
    DB, Personas, Messages, Objects = get_db()
    identity = Identity(pubkey)
    Personas.insert({
        'address': identity.address,
        'pubkey': pubkey.decode(),
        'nickname': nickname.decode()
    })

def write_message(envelope):
    DB, Personas, Messages, Objects = get_db()
    Messages.insert(envelope)
    for o in envelope['objects']:
        Objects.insert(o)
