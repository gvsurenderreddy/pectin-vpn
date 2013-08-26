
import sqlite3
import os

import scrypt
from flask import g

import pki

DATABASE = 'users.db'

def get_db():
    return sqlite3.connect(DATABASE)

class Config(object):

    def __init__(self):
        self._cache = {}
        c = g.db.cursor()
        for row in c.execute("SELECT * FROM config"):
            self._cache[row[0]] = row[1]

    def __contains__(self, key):
        return key in self._cache

    def __getitem__(self, key):
        return self._cache[key]

    def __setitem__(self, key, value):
        c = g.db.cursor()
        c.execute("INSERT INTO config (key, value) VALUES (?, ?)", (key, value))
        g.db.commit()
        self._cache[key] = value

    def __delitem__(self, key):
        if key not in self._cache:
            raise KeyError, key
        c = g.db.cursor()
        c.execute("DELETE FROM config WHERE key=?", (key,))
        g.db.commit()
        del self._cache[key]

    def __iter__(self):
        return iter(self._cache)

class User(object):
    
    def __init__(self, username, pass_hash, pass_salt, private_key, certificate):
        self.username = username
        self.pass_hash = pass_hash
        self.pass_salt = pass_salt
        self.private_key = private_key
        self.certificate = certificate

    @property
    def status(self):
        # one of 'revoked', 'inactive', 'active'
        return 'inactive'

    @property
    def vpn_ip(self):
        return 'N/A'

    def check_login(self, password):
        c = g.db.cursor()
        c.execute("SELECT pass_hash, pass_salt FROM users WHERE username=?", (self.username,))
        for row in c:
            pass_hash, pass_salt = row
            return (str(pass_hash) == scrypt.hash(password.encode('utf-8'), str(pass_salt)))
        return False

    def revoke_keys(self):
        # TODO
        pass

    def generate_keys(self, password):
        c = g.db.cursor()

class Users(object):
    
    def __init__(self):
        self._user_list = []
        c = g.db.cursor()
        for row in c.execute("SELECT username FROM users"):
            self._user_list.append(row[0])

    def __contains__(self, username):
        return username in self._user_list

    def __getitem__(self, username):
        c = g.db.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        for row in c:
            return User(*row)
        raise KeyError, username

    def __delitem__(self, username):
        c = g.db.cursor()
        c.execute("DELETE FROM users WHERE username=?", (username,))
        g.db.commit()

    def __iter__(self):
        for username in self._user_list:
            yield self[username]

    def create(self, username, password):
        if 'ca_key' not in g.config:
            # CA not configured
            return False
        pass_salt = os.urandom(8)
        pass_hash = scrypt.hash(password.encode('utf-8'), pass_salt)
        user_key = pki.make_key(password=password)
        c = g.db.cursor()
        c.execute('''
        INSERT INTO users (username, pass_hash, pass_salt, private_key)
        VALUES (?, ?, ?, ?)
        ''', (username, buffer(pass_hash), buffer(pass_salt), user_key)
        )
        g.db.commit()
        self._user_list.append(username)
        return True

def init():
    c = g.db.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value BLOB
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        pass_hash BLOB, pass_salt BLOB,
        key BLOB, cert BLOB
    )
    ''')
    g.db.commit()

def configure(host, port, name):
    g.config['vpn_host'] = host
    g.config['vpn_port'] = port
    g.config['vpn_name'] = name
    
def init_ca():
    return
    if 'ca_key' in g.config and 'ca_cert' in g.config:
        return
    g.config['ca_key'], g.config['ca_cert'] = pki.make_ca(g.config['vpn_name'])
