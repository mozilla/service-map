#!/bin/bash

dbname=servicemap
psql="psql -f - ${dbname}"

$psql << EOF
DROP TABLE IF EXISTS rra_sysgroup;
DROP TABLE IF EXISTS hostmatch;
DROP TABLE IF EXISTS host;
DROP TABLE IF EXISTS rra;
DROP TABLE IF EXISTS sysgroup;
DROP TABLE IF EXISTS searchresults;
CREATE TABLE rra (
	rraid SERIAL PRIMARY KEY,
	service TEXT NOT NULL UNIQUE,
	ari TEXT,
	api TEXT,
	afi TEXT,
	cri TEXT,
	cpi TEXT,
	cfi TEXT,
	iri TEXT,
	ipi TEXT,
	ifi TEXT,
	datadefault TEXT
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
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid),
	comment TEXT
);
CREATE TABLE host (
	hostid SERIAL PRIMARY KEY,
	hostname TEXT NOT NULL UNIQUE,
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid),
	comment TEXT
);
CREATE TABLE searchresults (
	opid TEXT NOT NULL,
	identifier TEXT NOT NULL,
	result TEXT NOT NULL,
	timestamp TIMESTAMP NOT NULL,
	UNIQUE(opid, identifier)
);
EOF

exit 0
