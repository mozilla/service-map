#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: ameihm@mozilla.com

class Config(object):
    def __init__(self):
        self.sslverify = './ca.crt'
        self.apihost = 'https://127.0.0.1:4444'

    def apiurl(self):
        return self.apihost + '/api/v1'

config = Config()
