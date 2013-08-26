
import json
import sys
import os
import re

from flask import Flask, url_for, redirect, abort, session, render_template
from flask import request, escape, make_response, g
from flask_mail import Mail, Message

import model

app = Flask(__name__)
try:
    app.secret_key = ''.join(open('session.key'))
except IOError:
    app.secret_key = os.urandom(16)
    open('session.key', 'w').write(app.secret_key)

with app.app_context():
    g.db = model.get_db()
    model.init()
    g.config = model.Config()
    model.init_ca()

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
        if username == 'admin' or username in g.users:
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
    response = make_response('no keys for you!')
    response.headers['Content-Disposition'] = \
        'attachment; filename=%s.zip' % escape(session['username'])
    return response

#
# Admin control panel
#

@app.route('/admin')
def admin_panel():
    if 'username' not in session or session['username'] != 'admin':
        return abort(403)
    return render_template('admin_panel.html')

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'debug':
        app.run(debug=True)
    else:
        app.run()
