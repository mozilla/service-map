#!/bin/bash

cd /home/serviceapi/app

/usr/local/bin/ansible-container build

cp /home/serviceapi/app/etc/supervisor-ansible.conf /etc/supervisor/conf.d
