#!/bin/bash

source /etc/serviceapiprofile
cd /home/serviceapi/app/ansible
/usr/local/bin/ansible-container --debug build >/home/serviceapi/build.log 2>&1
