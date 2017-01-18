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

def get_vulns(targets):
    u = cfg.config.apiurl() + '/vulns/target'
    ret = { 'vulns': [] }
    for x in targets:
        payload = { 'target': x }
        r = requests.get(u, params=payload, verify=cfg.config.sslverify)
        if r.status_code != requests.codes.ok:
            err = 'Request error: response {}'.format(r.status_code)
            raise search.SLIBException(err)
        buf = json.loads(r.text)
        if buf['vulnerabilities']['vulnerabilities'] != None and \
            len(buf['vulnerabilities']['vulnerabilities']) > 0:
            for x in buf['vulnerabilities']['vulnerabilities']:
                nv = x
                nv['hostname'] = buf['vulnerabilities']['asset']['hostname']
                nv['utctimestamp'] = buf['vulnerabilities']['utctimestamp']
                ret['vulns'].append(nv)
    return ret
