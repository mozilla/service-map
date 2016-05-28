#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: ameihm@mozilla.com

import requests
import uuid
import json
import search
import config as cfg

class Indicators(object):
    def __init__(self):
        self._url = cfg.config.apiurl()
        self._verify = cfg.config.sslverify
        self._indicators = []

    def add_host(self, hostname, checkclass, checktype, status):
        if hostname == None or len(hostname) == 0:
            raise search.SLIBException('invalid hostname')
        if checkclass != 'vuln':
            raise search.SLIBException('check class must be vuln')
        self._indicators.append({'host': hostname, 'class': checkclass, 'checktype': checktype,
            'status': status})

    def execute(self):
        if len(self._indicators) == 0:
            return
        buf = {'indicators': self._indicators}
        u = self._url + '/indicator'
        payload = {'params': json.dumps(buf)}
        r = requests.post(u, data=payload, verify=self._verify)
        if r.status_code != requests.codes.ok:
            err = 'Indicator request error: response {}, "{}"'.format(r.status_code, r.text.strip())
            raise search.SLIBException(err)
