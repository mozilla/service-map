#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: ameihm@mozilla.com

import requests

class SearchException(Exception):
    def __init__(self, m):
        self._message = m

    def __str__(self):
        return self._message

def search_request(apiurl, payload):
    try:
        r = requests.get(apiurl, params=payload)
    except requests.exceptions.ConnectionError as e:
        raise SearchException(str(e))
    if r.status_code == requests.codes.ok:
        return r.json()
    err = 'Search error: response {}, "{}"'.format(r.status_code, r.text.strip())
    raise SearchException(err)

def search(apiurl, hostname=None):
    if hostname != None:
        payload = { 'hostname': hostname }
    else:
        raise SearchException('No search parameters specified')
    return search_request(apiurl, payload)
