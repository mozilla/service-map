#!/bin/bash

if [[ -f /home/serviceapi/app/Dockerfile ]]; then
	docker rm $(docker stop $(docker ps -a -q --filter ancestor=serviceapi:latest))
fi

rm -rf /home/serviceapi/app
mkdir -p /home/serviceapi/app
