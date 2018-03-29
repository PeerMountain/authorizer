import tinydb

def get_db():
    DB = tinydb.TinyDB('db.json')

    Personas = DB.table('persona')
    Messages = DB.table('message')
    Objects = DB.table('object')

    return DB, Personas, Messages, Objects
