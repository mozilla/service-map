#!/bin/bash

source /etc/serviceapiprofile
cd /home/serviceapi/app/ansible
/usr/local/bin/ansible-container build
