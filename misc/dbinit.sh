#!/bin/bash

dbname=servicemap
psql="psql -f - ${dbname}"

$psql << EOF
DROP TABLE IF EXISTS compscore;
DROP TABLE IF EXISTS rra_sysgroup;
DROP TABLE IF EXISTS hostmatch;
DROP TABLE IF EXISTS host;
DROP TABLE IF EXISTS rra;
DROP TABLE IF EXISTS sysgroup;
DROP TABLE IF EXISTS searchresults;
CREATE TABLE rra (
	rraid SERIAL PRIMARY KEY,
	service TEXT NOT NULL UNIQUE,
	ari TEXT NOT NULL,
	api TEXT NOT NULL,
	afi TEXT NOT NULL,
	cri TEXT NOT NULL,
	cpi TEXT NOT NULL,
	cfi TEXT NOT NULL,
	iri TEXT NOT NULL,
	ipi TEXT NOT NULL,
	ifi TEXT NOT NULL,
	arp TEXT NOT NULL,
	app TEXT NOT NULL,
	afp TEXT NOT NULL,
	crp TEXT NOT NULL,
	cpp TEXT NOT NULL,
	cfp TEXT NOT NULL,
	irp TEXT NOT NULL,
	ipp TEXT NOT NULL,
	ifp TEXT NOT NULL,
	datadefault TEXT NOT NULL,
	lastupdated TIMESTAMP NOT NULL
);
CREATE TABLE techowners (
	techownerid SERIAL PRIMARY KEY,
	techowner TEXT
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
CREATE INDEX ON hostmatch (expression text_pattern_ops);
CREATE TABLE host (
	hostid SERIAL PRIMARY KEY,
	hostname TEXT NOT NULL UNIQUE,
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid),
	comment TEXT,
	requiretcw BOOLEAN,
	requirecab BOOLEAN,
	techownerid INTEGER REFERENCES techowners (techownerid),
	dynamic BOOLEAN NOT NULL,
	dynamic_added TIMESTAMP,
	dynamic_confidence INTEGER,
	lastused TIMESTAMP NOT NULL
);
CREATE INDEX ON host (hostname);
CREATE INDEX ON host (sysgroupid);
CREATE TABLE searchresults (
	opid TEXT NOT NULL,
	identifier TEXT NOT NULL,
	result TEXT NOT NULL,
	timestamp TIMESTAMP NOT NULL,
	UNIQUE(opid, identifier)
);
CREATE TABLE compscore (
	scoreid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP NOT NULL,
	hostid INTEGER REFERENCES host (hostid),
	checkref TEXT NOT NULL,
	status BOOLEAN
);
EOF

exit 0
