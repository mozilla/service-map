#!/bin/bash

cd /home/serviceapi/app
docker build -t serviceapi:latest .
if [[ $? -ne 0 ]]; then exit 1; fi
