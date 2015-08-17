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
import uuid
import pyservicelib
import pyes

import time

class SearchForm(Form):
    hostname = StringField('Hostname', validators=[validators.Optional()])

def get_config():
    config = {'SECRET_KEY': str(uuid.uuid4()),
            'PROPAGATE_EXCEPTIONS': True,
            'CUSTOM': {
                'apiurl': 'https://127.0.0.1:4444/api/v1',
                'verifyssl': False
                }
            }
    return config

app = Flask(__name__)
app.config.update(get_config())
Bootstrap(app)

def apiopt():
    return app.config['CUSTOM']['apiurl'], app.config['CUSTOM']['verifyssl']

@app.route('/search', methods=['GET', 'POST'])
def search():
    url, vs = apiopt()
    form = SearchForm()
    params = None
    if form.validate_on_submit():
        ns = pyservicelib.Search(url, verify=vs)
        if len(form.hostname.data) == 0:
            abort(500)
        ns.add_host(form.hostname.data)
        ns.execute()
        params = ns.result_host(form.hostname.data)
    return render_template('search.html', form=form, results=params)

@app.route('/vulnlist', methods=['GET'])
def vulnlist():
    url, vs = apiopt()
    target = request.args.getlist('target')

    if len(target) == 0:
        abort(500)
    res = pyservicelib.get_vulns(url, target, verify=vs)
    return render_template('vulnlist.html', vulns=res)

@app.route('/getsysgroup', methods=['GET'])
def getsysgroup():
    url, vs = apiopt()
    sgid = request.args.get('sysgroupid')
    if sgid == None:
        abort(500)
    res = pyservicelib.get_sysgroup(url, sgid, verify=vs)
    return render_template('sysgroup.html', results=res)

@app.route('/sysgroups', methods=['GET'])
def sysgroups():
    url, vs = apiopt()
    res = pyservicelib.get_sysgroups(url, verify=vs)
    return render_template('sysgroups.html', results=res)

@app.route('/getrra', methods=['GET'])
def getrra():
    url, vs = apiopt()
    rraid = request.args.get('rraid')
    if rraid == None:
        abort(500)
    res = pyservicelib.get_rra(url, rraid, verify=vs)
    return render_template('rra.html', results=res)

@app.route('/rras', methods=['GET'])
def rras():
    url, vs = apiopt()
    res = pyservicelib.get_rras(url, verify=vs)
    return render_template('rras.html', results=res)

@app.route('/')
def rootpage():
    return render_template('rootpage.html')

def domain():
    app.extensions['bootstrap']['cdns']['bootstrap'] = StaticCDN()
    app.extensions['bootstrap']['cdns']['jquery'] = StaticCDN()
    app.run(host='0.0.0.0', port=4445)
