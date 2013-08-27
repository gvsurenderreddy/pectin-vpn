
import subprocess
import json
import os

def make_key(keylen=2048, password=None):
    if password is None:
        args = ['openssl', 'genrsa', str(keylen)]
    else:
        args = ['openssl', 'genrsa', str(keylen), 
                '-aes128', '-passout', 'pass:%s' % password]
    proc = subprocess.Popen(args,
        stdin=None, stdout=subprocess.PIPE, stderr=open('/dev/null'))
    proc.wait()
    key, _ = proc.communicate()
    return key.strip()

def make_cert(key, name, ca_key, ca_cert, key_password=None):
    
    # generate CSR
    proc = subprocess.Popen(['openssl', 'req', '-nodes', '-new',
        '-subj', '/C=/ST=/L=/O=/OU=/CN=%s/emailAddress=/' % name],
        stdin=None, stdout=subprocess.PIPE, stderr=open('/dev/null'))
    proc.wait()
    csr, _ = proc.communicate()
    csr = csr.strip()

    # generate certificate
    open('var/ca.key', 'w').write(ca_key)
    open('var/ca.crt', 'w').write(ca_cert)
    open('var/user.key', 'w').write(key)
    open('var/user.csr', 'w').write(csr)
    args = \
        ['openssl', 'x509', '-req',
        '-in', 'var/user.csr',
        '-signkey', 'var/user.key',
        '-CA', 'var/ca.crt',
        '-CAkey', 'var/ca.key',
        '-CAcreateserial', '-days', '3650']
    if key_password is not None:
        args.extend(['-passin', 'pass:%s' % key_password])
    proc = subprocess.Popen(args,
        stdin=None, stdout=subprocess.PIPE, stderr=open('/dev/null'))
    cert, _ = proc.communicate()
    for filename in ['var/ca.key', 'var/ca.crt', 'var/user.key', 'var/user.csr']:
        os.remove(filename)

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

def make_dhparam(keylen=1024):
    dhparam_proc = subprocess.Popen(['openssl', 'dhparam', str(keylen)],
        stdin=None, stdout=subprocess.PIPE, stderr=open('/dev/null'))
    dhparam, _ = dhparam_proc.communicate()
    dhparam_proc.wait()
    return dhparam.strip()
