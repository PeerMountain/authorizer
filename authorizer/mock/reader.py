import logging
import tinydb

from .db import get_db


def get_persona(address=None, nickname=None, pubkey=None):
    DB, Personas, Messages, Objects = get_db()
    Persona = tinydb.Query()
    personas = Personas.search((
        (Persona.address==address)
        | (Persona.nickname==nickname)
        | (Persona.pubkey==pubkey)
    ))
    if len(personas) > 2:
        raise MultipleObjectsReturned("Multiple personas returned")
    if len(personas) < 1:
        raise NotFound("Persona not found")
    return personas[0]


def get_message(message_hash=None, message_date=None, message_reader=None):
    DB, Personas, Messages, Objects = get_db()
    if isinstance(message_hash, bytes):
        message_hash = message_hash.decode()
    Message = tinydb.Query()
    messages = Messages.search((
       (Message.messageHash==message_hash)
    ))
    if len(messages) > 2:
        raise MultipleObjectsReturned("Multiple messages returned")
    if len(messages) < 1:
        raise NotFound("Message not found")
    message = messages[0]
    if isinstance(message['sender'], dict):
        message['sender'] = message['sender']['address']
    sender = get_persona(message['sender'])
    message['sender'] = sender
    acl_rules = []
    for rule in message['ACL']:
        reader = rule['reader']
        if isinstance(reader, dict):
            continue
        acl_rules.append({
            'reader': get_persona(reader),
            'key': rule['key']
        })
    message['ACL'] = acl_rules

    return message


def get_messages(message_date=None, message_reader=None):
    DB, Personas, Messages, Objects = get_db()
    Message = tinydb.Query()
    messages = Messages.search((
       (Message.messageDate==message_date)
       | (Message.ACL.reader==message_reader)
    ))
    return messages


def persona_exists(nickname, pubkey):
    DB, Personas, Messages, Objects = get_db()
    if isinstance(nickname, bytes):
        nickname = nickname.decode()
    if isinstance(pubkey, bytes):
        pubkey = pubkey.decode()
    Persona = tinydb.Query()
    return Personas.contains(
        (Persona.nickname == nickname)
        | (Persona.pubkey == pubkey)
    )


def object_exists(object_hash):
    DB, Personas, Messages, Objects = get_db()
    Object = tinydb.Query()
    return Objects.contains(
        (Object.objectHash == object_hash)
    )




class NotFound(Exception):
    def __init__(self, msg):
        self.message = msg


class MultipleObjectsReturned(Exception):
    def __init__(self, msg):
        self.message = msg
    pass
