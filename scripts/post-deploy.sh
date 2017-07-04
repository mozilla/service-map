#!/bin/bash

docker run -d --env-file /etc/serviceapienv -p 0.0.0.0:8080:8080 serviceapi:latest
