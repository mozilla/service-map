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

def get_sysgroup(groupid):
    u = cfg.config.apiurl() + '/sysgroup/id'
    payload = { 'id': groupid }
    r = requests.get(u, params=payload, verify=cfg.config.sslverify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
    return json.loads(r.text)

def get_sysgroups():
    u = cfg.config.apiurl() + '/sysgroups'
    r = requests.get(u, verify=cfg.config.sslverify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
    return json.loads(r.text)
