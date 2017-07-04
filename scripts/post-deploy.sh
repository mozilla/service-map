#!/bin/bash

# Create a fresh application environment
touch /etc/serviceapienv
chmod 600 /etc/serviceapienv
bash /home/serviceapi/app/scripts/appenv.sh > /etc/serviceapienv
if [[ $? -ne 0 ]]; then
	exit 1
fi

docker run -d --env-file /etc/serviceapienv -p 0.0.0.0:8080:8080 serviceapi:latest
