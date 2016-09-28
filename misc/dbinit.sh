#!/bin/bash

dbname=servicemap
psql="psql -f - ${dbname}"

$psql << EOF
DROP TABLE IF EXISTS importcomphostcfg;
DROP TABLE IF EXISTS vulnscore;
DROP TABLE IF EXISTS vulnstatus;
DROP TABLE IF EXISTS migstatus;
DROP TABLE IF EXISTS compscore;
DROP TABLE IF EXISTS httpobsscore;
DROP TABLE IF EXISTS rra_sysgroup;
DROP TABLE IF EXISTS asset;
DROP TABLE IF EXISTS assetawsmeta;
DROP TABLE IF EXISTS assetowners;
DROP TABLE IF EXISTS risk;
DROP TABLE IF EXISTS rra;
DROP TABLE IF EXISTS sysgroup;
DROP TABLE IF EXISTS searchresults;
DROP TABLE IF EXISTS interlinks;
CREATE TABLE rra (
	rraid SERIAL PRIMARY KEY,
	service TEXT NOT NULL,
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
	lastupdated TIMESTAMP WITH TIME ZONE NOT NULL,
	lastmodified TIMESTAMP WITH TIME ZONE NOT NULL,
	raw JSON NOT NULL,
	UNIQUE(service, lastmodified)
);
CREATE TABLE risk (
	rraid INTEGER REFERENCES rra (rraid),
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	risk JSON NOT NULL
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
CREATE TABLE assetowners (
	ownerid SERIAL PRIMARY KEY,
	team TEXT NOT NULL,
	operator TEXT NOT NULL,
	UNIQUE (team, operator)
);
CREATE TABLE assetawsmeta (
	assetawsmetaid SERIAL PRIMARY KEY,
	accountid TEXT NOT NULL,
	accountname TEXT NOT NULL,
	region TEXT NOT NULL,
	instancetype TEXT NOT NULL,
	instanceid TEXT NOT NULL,
	public_ip INET,
	private_ip INET,
	private_dns TEXT,
	public_dns TEXT,
	tags JSON,
	lastupdated TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE TABLE asset (
	assetid SERIAL PRIMARY KEY,
	assettype TEXT NOT NULL,
	hostname TEXT,
	website TEXT,
	sysgroupid INTEGER REFERENCES sysgroup (sysgroupid),
	ownerid INTEGER REFERENCES assetowners (ownerid),
	assetawsmetaid INTEGER REFERENCES assetawsmeta (assetawsmetaid),
	v2boverride TEXT,
	comment TEXT,
	dynamic BOOLEAN NOT NULL,
	dynamic_added TIMESTAMP WITH TIME ZONE,
	dynamic_confidence INTEGER,
	lastused TIMESTAMP WITH TIME ZONE NOT NULL,
	lastcompscore TIMESTAMP WITH TIME ZONE NOT NULL,
	lastvulnscore TIMESTAMP WITH TIME ZONE NOT NULL,
	lasthttpobsscore TIMESTAMP WITH TIME ZONE NOT NULL,
	UNIQUE(assettype, hostname)
);
CREATE INDEX ON asset (hostname);
CREATE INDEX ON asset (sysgroupid);
CREATE TABLE searchresults (
	opid TEXT NOT NULL,
	identifier TEXT NOT NULL,
	result TEXT NOT NULL,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	UNIQUE(opid, identifier)
);
CREATE TABLE compscore (
	scoreid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	assetid INTEGER REFERENCES asset (assetid),
	checkref TEXT NOT NULL,
	status BOOLEAN NOT NULL
);
CREATE INDEX ON compscore (assetid, timestamp DESC);
CREATE TABLE vulnscore (
	scoreid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	assetid INTEGER REFERENCES asset (assetid),
	maxcount INTEGER DEFAULT 0 NOT NULL,
	highcount INTEGER DEFAULT 0 NOT NULL,
	mediumcount INTEGER DEFAULT 0 NOT NULL,
	lowcount INTEGER DEFAULT 0 NOT NULL,
	likelihoodindicator INTEGER DEFAULT 0 NOT NULL
);
CREATE INDEX ON vulnscore (assetid, timestamp DESC);
CREATE TABLE httpobsscore (
	scoreid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	assetid INTEGER REFERENCES asset (assetid),
	score INTEGER NOT NULL,
	grade TEXT NOT NULL,
	passcount INTEGER NOT NULL,
	failcount INTEGER NOT NULL,
	totalcount INTEGER NOT NULL
);
CREATE INDEX ON httpobsscore (assetid);
CREATE TABLE vulnstatus (
	statusid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	assetid INTEGER REFERENCES asset (assetid),
	checktype TEXT NOT NULL,
	status BOOLEAN NOT NULL
);
CREATE INDEX ON vulnstatus (assetid);
CREATE TABLE migstatus (
	statusid SERIAL PRIMARY KEY,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	assetid INTEGER REFERENCES asset (assetid),
	version TEXT NOT NULL,
	env JSON,
	tags JSON
);
CREATE TABLE importcomphostcfg (
	exid SERIAL PRIMARY KEY,
	hostmatch TEXT NOT NULL UNIQUE
);
CREATE TABLE interlinks (
	ruleid SERIAL PRIMARY KEY,
	ruletype INTEGER NOT NULL,
	srchostmatch TEXT,
	srcawssqlmatch TEXT,
	srcsysgroupmatch TEXT,
	destsysgroupmatch TEXT,
	destservicematch TEXT,
	srcwebsitematch TEXT,
	destwebsitematch TEXT,
	destoperatormatch TEXT,
	destteammatch TEXT,
	destv2boverride TEXT
);
EOF

exit 0
