
import StringIO
import zipfile
import json
import sys
import os
import re

from flask import Flask, url_for, redirect, abort, session, render_template
from flask import request, escape, make_response, g
from flask_mail import Mail, Message

import model
import vpn

app = Flask(__name__)
try:
    app.secret_key = ''.join(open('session.key'))
except IOError:
    app.secret_key = os.urandom(16)
    open('session.key', 'w').write(app.secret_key)

@app.before_request
def before_request():
    g.db = model.get_db()
    g.config = model.Config()
    g.users = model.Users()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/')
def index():
    if 'username' in session:
        if session['username'] == 'admin':
            return redirect(url_for('admin_panel'))
        else:
            return redirect(url_for('user_panel'))
    return redirect(url_for('login'))

#
# Account management
#

@app.route('/create_user', methods=['GET','POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in ['admin', 'server', 'ca'] or username in g.users:
            return redirect(url_of('new_user_failed'))
        g.users.create(username, password)
        session['username'] = username
        return redirect(url_for('user_panel'))
    elif request.method == 'GET':
        return render_template('create_user.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin':
            if password == 'password':
                session['username'] = 'admin'
                return redirect(url_for('admin_panel'))
        else:
            if username in g.users and g.users[username].check_login(password):
                session['username'] = username
                return redirect(url_for('user_panel'))
        return render_template('login.html', failure=True)
    elif request.method == 'GET':
        return render_template('login.html', failure=False)

@app.route('/logout', methods=['GET','POST'])
def logout():
    if 'username' in session:
        del session['username']
    return redirect(url_for('index'))

#
# User control panel
#

@app.route('/user')
def user_panel():
    if 'username' not in session:
        return abort(403)
    return render_template('user_panel.html', username=session['username'])

@app.route('/user/keys')
def user_keys():
    if 'username' not in session:
        return abort(403)

    zf = StringIO.StringIO()
    z = zipfile.ZipFile(zf, 'w')
    z.writestr('%s.%s.ovpn' % (session['username'], g.config['vpn_name']),
        render_template('client.conf',
        vpn_host = g.config['vpn_host'],
        vpn_port = g.config['vpn_port'],
        vpn_proto = g.config['vpn_proto'],
        vpn_name = g.config['vpn_name'],
        user_name = session['username']).encode('utf-8'))
    z.writestr('ca.%s.crt' % g.config['vpn_name'], g.config['ca_cert'].encode('utf-8'))
    z.writestr('%s.%s.crt' % (session['username'], g.config['vpn_name']),
        g.users[session['username']].certificate.encode('utf-8'))
    z.writestr('%s.%s.key' % (session['username'], g.config['vpn_name']),
        g.users[session['username']].private_key.encode('utf-8'))
    z.close()

    response = make_response(zf.getvalue())
    response.headers['Content-Disposition'] = \
        'attachment; filename=%s.zip' % escape(session['username'] + '.' + g.config['vpn_name'])
    return response

#
# Admin control panel
#

@app.route('/admin')
def admin_panel():
    if 'username' not in session or session['username'] != 'admin':
        return abort(403)
    return render_template('admin_panel.html')

@app.route('/admin/pki/config', methods=['GET','POST'])
def admin_pki_config(name='pectin'):
    if 'username' not in session or session['username'] != 'admin':
        return abort(403)
    model.destroy_users()
    model.configure_pki(name)
    return redirect(url_for('admin_panel'))

@app.route('/admin/vpn/config', methods=['GET','POST'])
def admin_vpn_config(host='construct.greyhat-ctf.org', proto='tcp', port='1194'):
    if 'username' not in session or session['username'] != 'admin':
        return abort(403)
    model.destroy_users()
    model.configure_vpn(host, proto, port)
    return redirect(url_for('admin_panel'))

@app.route('/admin/vpn/start', methods=['GET','POST'])
def admin_vpn_start():
    if 'username' not in session or session['username'] != 'admin':
        return abort(403)
    vpn.start(g.config['server_key'],
              g.config['server_cert'],
              g.config['ca_cert'],
              g.config['server_dhparam'],
              render_template('server.conf',
                  vpn_subnet='10.8.0.0',
                  vpn_netmask='255.255.255.0',
                  vpn_host=g.config['vpn_host'],
                  vpn_port=g.config['vpn_port'],
                  vpn_proto=g.config['vpn_proto']))
    return redirect(url_for('admin_panel'))

@app.route('/admin/vpn/stop', methods=['GET','POST'])
def admin_vpn_stop():
    if 'username' not in session or session['username'] != 'admin':
        return abort(403)
    vpn.stop()
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'debug':
        app.run(debug=True)
    else:
        app.run()
