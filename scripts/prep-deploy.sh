#!/bin/bash

# Create a fresh application environment
touch /etc/serviceapienv
chmod 600 /etc/serviceapienv
bash /home/serviceapi/app/scripts/appenv.sh > /etc/serviceapienv
if [[ $? -ne 0 ]]; then
	exit 1
fi

if [[ -f /home/serviceapi/app/Dockerfile ]]; then
	docker rm $(docker stop $(docker ps -a -q --filter ancestor=serviceapi:latest))
fi

rm -rf /home/serviceapi/app
mkdir -p /home/serviceapi/app
