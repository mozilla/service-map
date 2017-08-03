#!/bin/bash

dbname=servicemap
dbuser=serviceapi
psql="psql -f - ${dbname}"

$psql << EOF
DROP TABLE IF EXISTS rra_assetgroup;
DROP TABLE IF EXISTS indicator;
DROP TABLE IF EXISTS asset;
DROP TABLE IF EXISTS assetowners;
DROP TABLE IF EXISTS risk;
DROP TABLE IF EXISTS rra;
DROP TABLE IF EXISTS assetgroup;
DROP TABLE IF EXISTS apikey;
CREATE TABLE rra (
	rraid SERIAL PRIMARY KEY,
	service TEXT NOT NULL,
	impact_availrep TEXT NOT NULL,
	impact_availprd TEXT NOT NULL,
	impact_availfin TEXT NOT NULL,
	impact_confirep TEXT NOT NULL,
	impact_confiprd TEXT NOT NULL,
	impact_confifin TEXT NOT NULL,
	impact_integrep TEXT NOT NULL,
	impact_integprd TEXT NOT NULL,
	impact_integfin TEXT NOT NULL,
	prob_availrep TEXT NOT NULL,
	prob_availprd TEXT NOT NULL,
	prob_availfin TEXT NOT NULL,
	prob_confirep TEXT NOT NULL,
	prob_confiprd TEXT NOT NULL,
	prob_confifin TEXT NOT NULL,
	prob_integrep TEXT NOT NULL,
	prob_integprd TEXT NOT NULL,
	prob_integfin TEXT NOT NULL,
	datadefault TEXT NOT NULL,
	lastupdated TIMESTAMP WITH TIME ZONE NOT NULL,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	raw JSONB NOT NULL,
	UNIQUE(service, lastupdated)
);
CREATE INDEX ON rra (service);
CREATE INDEX ON rra USING gin (raw);
CREATE TABLE risk (
	rraid INTEGER REFERENCES rra (rraid),
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	risk JSONB NOT NULL
);
CREATE INDEX ON risk (rraid);
CREATE INDEX ON risk (timestamp);
CREATE INDEX ON risk USING gin (risk);
CREATE TABLE assetgroup (
	assetgroupid SERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	UNIQUE(name)
);
CREATE TABLE rra_assetgroup (
	rraid INTEGER REFERENCES rra (rraid),
	assetgroupid INTEGER REFERENCES assetgroup (assetgroupid),
	UNIQUE(rraid, assetgroupid)
);
CREATE TABLE assetowners (
	ownerid SERIAL PRIMARY KEY,
	team TEXT NOT NULL,
	operator TEXT NOT NULL,
	UNIQUE (team, operator)
);
CREATE TABLE asset (
	assetid SERIAL PRIMARY KEY,
	assettype TEXT NOT NULL,
	name TEXT NOT NULL,
	zone TEXT NOT NULL,
	assetgroupid INTEGER REFERENCES assetgroup (assetgroupid),
	ownerid INTEGER REFERENCES assetowners (ownerid),
	triageoverride TEXT,
	lastindicator TIMESTAMP WITH TIME ZONE NOT NULL,
	UNIQUE(assettype, name, zone)
);
CREATE INDEX ON asset (name);
CREATE INDEX ON asset (assettype);
CREATE INDEX ON asset (assetgroupid);
CREATE TABLE indicator (
	indicatorid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	event_source TEXT NOT NULL,
	likelihood_indicator TEXT NOT NULL,
	assetid INTEGER REFERENCES asset (assetid),
	details JSONB NOT NULL,
	UNIQUE (assetid, event_source, timestamp)
);
CREATE INDEX ON indicator (timestamp);
CREATE INDEX ON indicator (assetid);
CREATE INDEX ON indicator USING gin (details);
CREATE TABLE apikey (
	keyid SERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	hash TEXT NOT NULL,
	UNIQUE(name),
	UNIQUE(hash)
);
CREATE ROLE serviceapi;
ALTER ROLE serviceapi WITH login;
GRANT ALL ON ALL TABLES IN SCHEMA public TO serviceapi;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO serviceapi;
EOF

exit 0
