#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: ameihm@mozilla.com

import requests
import json
import search
import config as cfg

def get_rra(rraid):
    u = cfg.config.apiurl() + '/rra/id'
    payload = { 'id': rraid }
    r = requests.get(u, params=payload, verify=cfg.config.sslverify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
    return json.loads(r.text)

def get_rras():
    u = cfg.config.apiurl() + '/rras'
    r = requests.get(u, verify=cfg.config.sslverify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
    return json.loads(r.text)

def get_risks():
    u = cfg.config.apiurl() + '/risks'
    r = requests.get(u, verify=cfg.config.sslverify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
    return json.loads(r.text)

# Submits an RRA to be updated via the API, rradict should be a dict
# representation of the RRA; the RRA information itself should be stored
# in a 'details' struct there, and it should also have a lastmodified
# element that is the lastmodified timestamp from the RRA
def update_rra(rradict):
    u = cfg.config.apiurl() + '/rra/update'
    payload = {'rra': json.dumps(rradict)}
    r = requests.post(u, data=payload, verify=cfg.config.sslverify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
