#!/bin/bash

dbname=servicemap
psql="psql -f - ${dbname}"

$psql << EOF
DROP TABLE IF EXISTS importcomphostcfg;
DROP TABLE IF EXISTS vulnscore;
DROP TABLE IF EXISTS compscore;
DROP TABLE IF EXISTS rra_sysgroup;
DROP TABLE IF EXISTS host;
DROP TABLE IF EXISTS rra;
DROP TABLE IF EXISTS sysgroup;
DROP TABLE IF EXISTS searchresults;
DROP TABLE IF EXISTS techowners;
DROP TABLE IF EXISTS interlinks;
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
	lastupdated TIMESTAMP NOT NULL,
	raw JSON NOT NULL
);
CREATE TABLE techowners (
	techownerid SERIAL PRIMARY KEY,
	techowner TEXT NOT NULL
);
CREATE TABLE sysgroup (
	sysgroupid SERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	UNIQUE(name)
);
CREATE TABLE rra_sysgroup (
	rraid INTEGER REFERENCES rra (rraid),
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid),
	UNIQUE(rraid, sysgroupid)
);
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
	lastused TIMESTAMP NOT NULL,
	lastcompscore TIMESTAMP NOT NULL,
	lastvulnscore TIMESTAMP NOT NULL
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
	status BOOLEAN NOT NULL
);
CREATE TABLE vulnscore (
	scoreid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP NOT NULL,
	hostid INTEGER REFERENCES host (hostid),
	maxcount INTEGER DEFAULT 0 NOT NULL,
	highcount INTEGER DEFAULT 0 NOT NULL,
	mediumcount INTEGER DEFAULT 0 NOT NULL,
	lowcount INTEGER DEFAULT 0 NOT NULL
);
CREATE TABLE importcomphostcfg (
	exid SERIAL PRIMARY KEY,
	hostmatch TEXT NOT NULL UNIQUE
);
CREATE TABLE interlinks (
	ruleid SERIAL PRIMARY KEY,
	ruletype INTEGER NOT NULL,
	srchostmatch TEXT,
	srcsysgroupmatch TEXT,
	destsysgroupmatch TEXT,
	destservicematch TEXT
);
EOF

exit 0
