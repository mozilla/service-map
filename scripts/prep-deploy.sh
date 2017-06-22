#!/bin/bash

if [[ -f /home/serviceapi/app/ansible/container.yml ]]; then
	(cd /home/serviceapi/app/ansible && ansible-container stop)
fi

rm -rf /home/serviceapi/app
mkdir -p /home/serviceapi/app
