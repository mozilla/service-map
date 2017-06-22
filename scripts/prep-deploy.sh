#!/bin/bash

systemctl stop supervisor

rm -rf /home/serviceapi/app

mkdir -p /home/serviceapi/app
