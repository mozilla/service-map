#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: ameihm@mozilla.com

from distutils.core import setup

setup(
    name = "pyservicelib",
    packages = [ "pyservicelib" ],
    version = "1.0.0",
    author = "Aaron Meihm",
    author_email = "ameihm@mozilla.com",
    description = ("A library to access the service map API"),
    license = "MPL",
    keywords = "service api library"
)
