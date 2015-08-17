#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: ameihm@mozilla.com

import requests
import json
import search

def get_rra(api, rraid, verify=True):
    u = api + '/rra/id'
    payload = { 'id': rraid }
    r = requests.get(u, params=payload, verify=verify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
    return json.loads(r.text)

def get_rras(api, verify=True):
    u = api + '/rras'
    r = requests.get(u, verify=verify)
    if r.status_code != requests.codes.ok:
        err = 'Request error: response {}'.format(r.status_code)
        raise search.SLIBException(err)
    return json.loads(r.text)
