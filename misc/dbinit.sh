#!/bin/bash

dbname=servicemap
psql="psql -f - ${dbname}"

$psql << EOF
DROP TABLE IF EXISTS rra_sysgroup;
DROP TABLE IF EXISTS hostmatch;
DROP TABLE IF EXISTS host;
DROP TABLE IF EXISTS rra;
DROP TABLE IF EXISTS sysgroup;
CREATE TABLE rra (
	rraid SERIAL PRIMARY KEY,
	service TEXT NOT NULL UNIQUE
);
CREATE TABLE sysgroup (
	sysgroupid SERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	environment TEXT NOT NULL,
	UNIQUE(name, environment)
);
CREATE TABLE rra_sysgroup (
	rraid INTEGER REFERENCES rra (rraid),
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid),
	UNIQUE(rraid, sysgroupid)
);
CREATE TABLE hostmatch (
	hostmatchid SERIAL PRIMARY KEY,
	expression TEXT NOT NULL UNIQUE,
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid)
);
CREATE TABLE host (
	hostid SERIAL PRIMARY KEY,
	hostname TEXT NOT NULL UNIQUE,
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid)
);
EOF

exit 0
