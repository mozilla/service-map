#!/bin/bash

# Builds the application environment used by serviceapi using credstash and
# other resources on the system

if [[ -f "/etc/serviceapidbhost" ]]; then
	source /etc/serviceapidbhost
fi

if [[ -z "$PGHOST" ]]; then
	echo unable to set PGHOST
	exit 1
fi

PGPASSWORD=$(credstash --region us-west-2 get service-map:dbpass application=service-map)
if [[ $? -ne 0 ]]; then
	echo unable to set PGPASSWORD
	exit 1
fi

PGUSER=serviceapi

echo "PGUSER=${PGUSER}"
echo "PGPASSWORD=${PGPASSWORD}"
echo "PGHOST=${PGHOST}"
