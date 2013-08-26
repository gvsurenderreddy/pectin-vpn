#!/usr/bin/env python

import subprocess
import json
import os

def make_key(keylen=2048, password=None):
    if password is None:
        args = ['openssl', 'genrsa', str(keylen)]
    else:
        args = ['openssl', 'genrsa', str(keylen), 
                '-aes127', '-passout', 'pass:%s' % password]
    proc = subprocess.Popen(args,
        stdin=None, stdout=subprocess.PIPE, stderr=open('/dev/null'))
    proc.wait()
    key, _ = proc.communicate()
    return key.strip()

def make_cert(key, name, ca_key, ca_cert):
    
    # generate CSR
    proc = subprocess.Popen(['openssl', 'req', '-nodes', '-new',
        '-subj', '/C=/ST=/L=/O=/OU=/CN=%s/emailAddress=/' % name],
        stdin=None, stdout=subprocess.PIPE, stderr=open('/dev/null'))
    proc.wait()
    csr, _ = proc.communicate()
    csr = csr.strip()

    print ca_key
    print ca_cert
    print key
    print csr

    # generate certificate
    ca_key_fd_r, ca_key_fd_w = os.pipe()
    ca_cert_fd_r, ca_cert_fd_w = os.pipe()
    user_key_fd_r, user_key_fd_w = os.pipe()
    user_csr_fd_r, user_csr_fd_w = os.pipe()
    os.write(ca_key_fd_w, ca_key)
    os.write(ca_cert_fd_w, ca_cert)
    os.write(user_key_fd_w, key)
    os.write(user_csr_fd_w, csr)
    args = \
        ['openssl', 'x509', '-req',
        '-in', '/proc/self/fd/%d' % user_csr_fd_r,
        '-signkey', '/proc/self/fd/%d' % user_key_fd_r,
        '-CA', '/proc/self/fd/%d' % ca_cert_fd_r,
        '-CAkey', '/proc/self/fd/%d' % ca_key_fd_r,
        '-CAcreateserial', '-days', '3650']
    print ' '.join(args)
    proc = subprocess.Popen(args,
        stdin=None, stdout=subprocess.PIPE)
    for fd in [ca_key_fd_r, ca_key_fd_w, ca_cert_fd_r, ca_cert_fd_w, user_key_fd_r, user_key_fd_w, user_csr_fd_r, user_csr_fd_w]:
        os.close(fd)

    cert, _ = proc.communicate()

    return cert.strip()

def make_ca(domain, password=None, keylen=2048):

    # generate CA private key
    ca_key = make_key(keylen, password)

    # generate CA certificate (self-signed)
    ca_crt_proc = subprocess.Popen(['openssl', 'req', '-new', '-x509', '-key', 
        '/dev/stdin', '-batch', '-days', '3650',
        '-subj', '/C=/ST=/L=/O=/OU=/CN=%s/emailAddress=/' % domain],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open('/dev/null'))
    ca_crt, _ = ca_crt_proc.communicate(input=ca_key)
    ca_crt_proc.wait()
    ca_crt = ca_crt.strip()

    return (ca_key, ca_crt)
