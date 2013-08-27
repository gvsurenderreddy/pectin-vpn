
import sqlite3
import os

import scrypt
from flask import g

import pki

DATABASE = 'users.db'

def get_db():
    return sqlite3.connect(DATABASE)

if not os.path.isfile(DATABASE):
    db = get_db()
    c = db.cursor()
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
    db.commit()

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
        if key in self._cache:
            c.execute("UPDATE config SET value=? WHERE key=?", (value, key))
        else:
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
        user_cert = pki.make_cert(user_key, username+'.'+g.config['vpn_name'],
                                  g.config['ca_key'], g.config['ca_cert'], 
                                  key_password=password)
        c = g.db.cursor()
        c.execute('''
        INSERT INTO users (username, pass_hash, pass_salt, key, cert)
        VALUES (?, ?, ?, ?, ?)
        ''', (username, buffer(pass_hash), buffer(pass_salt), user_key, user_cert)
        )
        g.db.commit()
        self._user_list.append(username)
        return True

def destroy_users():
    c = g.db.cursor()
    c.execute("DROP TABLE users")
    c.execute('''
    CREATE TABLE users (
        username TEXT PRIMARY KEY,
        pass_hash BLOB, pass_salt BLOB,
        key BLOB, cert BLOB
    )
    ''')
    g.db.commit()

def configure_vpn(host, proto, port):
    if 'vpn_state' in g.config and g.config['vpn_state'] == 'running':
        raise ValueError, 'cannot configure running VPN'
    g.config['vpn_host'] = host
    g.config['vpn_proto'] = proto
    g.config['vpn_port'] = port
    if 'server_cert' in g.config:
        g.config['vpn_state'] = 'ready'
    else:
        g.config['vpn_state'] = 'no_pki'

def configure_pki(name, keylen=2048):
    if 'vpn_state' in g.config and g.config['vpn_state'] == 'running':
        raise ValueError, 'cannot regen keys for running VPN'
    g.config['vpn_name'] = name
    ca_key, ca_cert = pki.make_ca(name, keylen=keylen)
    server_key = pki.make_key()
    server_cert = pki.make_cert(server_key, 'server.%s' % name, ca_key, ca_cert)
    g.config['ca_key'] = ca_key
    g.config['ca_cert'] = ca_cert
    g.config['server_key'] = server_key
    g.config['server_cert'] = server_cert
    if 'server_dhparam' not in g.config:
        g.config['server_dhparam'] = pki.make_dhparam()
