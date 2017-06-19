#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: ameihm@mozilla.com

from flask import Flask, request, session, g, redirect, url_for, \
        abort, render_template, flash, request
from flask_bootstrap import Bootstrap
from flask_bootstrap import StaticCDN
from flask_wtf import Form
from wtforms import StringField
from wtforms import validators
import json
import errno
import uuid
import pyservicelib as slib
import pyes
import time

app = None

class SearchForm(Form):
    hostname = StringField('Hostname', validators=[validators.Optional()])

def get_config():
    config = {'SECRET_KEY': str(uuid.uuid4()),
            'PROPAGATE_EXCEPTIONS': True,
            'CUSTOM': {
                'apiurl': 'https://127.0.0.1:4444',
                'verifyssl': False
                }
            }
    try:
        fd = open('/etc/serviceui.conf', 'r')
    except IOError as e:
        if e.errno == errno.ENOENT:
            return config
        else:
            raise
    config.update(json.loads(fd.read()))
    fd.close()
    return config

def confinit():
    app.extensions['bootstrap']['cdns']['bootstrap'] = StaticCDN()
    app.extensions['bootstrap']['cdns']['jquery'] = StaticCDN()
    app.jinja_env.add_extension('jinja2.ext.do')
    slib.config.sslverify = app.config['CUSTOM']['verifyssl']
    slib.config.apihost = app.config['CUSTOM']['apiurl']

app = Flask(__name__)
app.config.update(get_config())
Bootstrap(app)
confinit()

@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    params = None
    if form.validate_on_submit():
        ns = slib.Search()
        if len(form.hostname.data) == 0:
            abort(500)
        ns.add_host(form.hostname.data)
        ns.execute()
        params = ns.result_host(form.hostname.data)
    return render_template('search.html', form=form, results=params)

@app.route('/searchmatch', methods=['GET', 'POST'])
def searchmatch():
    form = SearchForm()
    params = None
    if form.validate_on_submit():
        if len(form.hostname.data) == 0:
            abort(500)
        params = slib.searchmatch(form.hostname.data)
        sysgrps = slib.get_sysgroups()
        if params['hosts'] != None:
            for x in params['hosts']:
                for y in sysgrps['results']:
                    if y['id'] == x['sysgroupid']:
                        x['sysgroupname'] = y['name']
                        break
        else:
            params['hosts'] = []
    return render_template('searchmatch.html', form=form, results=params)

@app.route('/vulnlist', methods=['GET'])
def vulnlist():
    target = request.args.getlist('target')
    if len(target) == 0:
        abort(500)
    res = slib.get_vulns(target)
    return render_template('vulnlist.html', vulns=res)

@app.route('/getsysgroup', methods=['GET'])
def getsysgroup():
    sgid = request.args.get('sysgroupid')
    if sgid == None:
        abort(500)
    res = slib.get_sysgroup(sgid)
    return render_template('sysgroup.html', results=res)

@app.route('/sysgroups', methods=['GET'])
def sysgroups():
    res = slib.get_sysgroups()
    return render_template('sysgroups.html', results=res)

@app.route('/getrra', methods=['GET'])
def getrra():
    rraid = request.args.get('rraid')
    if rraid == None:
        abort(500)
    res = slib.get_rra(rraid)
    return render_template('rra.html', results=res)

@app.route('/rras', methods=['GET'])
def rras():
    res = slib.get_rras()
    return render_template('rras.html', results=res)

@app.route('/servicerisk', methods=['GET'])
def servicerisk():
    res = slib.get_risks()
    return render_template('servicerisk.html', results=res)

@app.route('/')
def rootpage():
    return render_template('rootpage.html')

def domain():
    app.run(host='0.0.0.0', port=4445)
