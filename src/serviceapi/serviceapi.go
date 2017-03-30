// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"gopkg.in/gcfg.v1"
	"net/http"
	"os"
	"os/signal"
	slib "servicelib"
	"strings"
	"sync"
	"syscall"
	"time"
)

var pidFile string
var pidFD *os.File

type opContext struct {
	tx    *sql.Tx
	db    *sql.DB
	opid  string
	rhost string
}

func (o *opContext) newContext(db *sql.DB, useTransaction bool, rhost string) (err error) {
	o.opid = slib.NewUUID()
	o.db = db
	o.rhost = rhost
	if useTransaction {
		o.tx, err = db.Begin()
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *opContext) Query(qs string, args ...interface{}) (*sql.Rows, error) {
	if o.tx != nil {
		return o.tx.Query(qs, args...)
	}
	return o.db.Query(qs, args...)
}

func (o *opContext) QueryRow(qs string, args ...interface{}) *sql.Row {
	if o.tx != nil {
		return o.tx.QueryRow(qs, args...)
	}
	return o.db.QueryRow(qs, args...)
}

func (o *opContext) Exec(qs string, args ...interface{}) (sql.Result, error) {
	if o.tx != nil {
		return o.tx.Exec(qs, args...)
	}
	return o.db.Exec(qs, args...)
}

func (o *opContext) commit() error {
	if o.tx == nil {
		return nil
	}
	return o.tx.Commit()
}

func (o *opContext) rollback() error {
	return o.tx.Rollback()
}

func (o *opContext) logf(s string, args ...interface{}) {
	buf := fmt.Sprintf(s, args...)
	clnt := "none"
	if o.rhost != "" {
		clnt = o.rhost
	}
	logf("[%v:%v] %v", o.opid, clnt, buf)
}

type Config struct {
	General struct {
		Listen         string
		Key            string
		Cert           string
		RiskCacheEvery string
	}
	Risk struct {
		VulnMaxHighGracePeriod int
	}
	Database struct {
		Hostname string
		Database string
	}
	Interlink struct {
		RulePath              string
		RunEvery              string
		AWSStripDNSSuffixList string
	}
	HTTPObs struct {
		ScoringBatchSize int
		ScoreEvery       string
	}
	Vulnerabilities struct {
		ESHost           string
		Index            string
		ScoringBatchSize int
		ScoreEvery       string
	}
	Compliance struct {
		ESHost           string
		Index            string
		ScoringBatchSize int
		ScoreEvery       string
	}
	AWSMeta struct {
		MetaFile string
		Lifetime string
	}
}

func (c *Config) validate() error {
	if c.General.Listen == "" {
		return fmt.Errorf("missing configuration option: general..listen")
	}
	if c.Database.Hostname == "" {
		return fmt.Errorf("missing configuration option: database..hostname")
	}
	if c.Database.Database == "" {
		return fmt.Errorf("missing configuration option: database..database")
	}
	return nil
}

var cfg Config
var dbconn *sql.DB

var wg sync.WaitGroup
var logChan chan string

// Used by various dynamic host importers, this adds the host to the database
// if it does not exist, and updates the lastused timestamp
func updateDynamicHost(op opContext, hn string, comment string, confidence int) error {
	_, err := op.Exec(`INSERT INTO asset
		(hostname, comment, dynamic, dynamic_added, dynamic_confidence, lastused,
		lastcompscore, lastvulnscore, lasthttpobsscore, assettype)
		SELECT $1, $2, TRUE, now(),
		$3, now(),
		now() - INTERVAL '5 days',
		now() - INTERVAL '5 days',
		now() - INTERVAL '5 days',
		'host'
		WHERE NOT EXISTS (
			SELECT 1 FROM asset WHERE lower(hostname) = lower($4) AND
			assettype = 'host'
		)`, hn, comment, confidence, hn)
	if err != nil {
		return err
	}
	_, err = op.Exec(`UPDATE asset
		SET lastused = now()
		WHERE lower(hostname) = lower($1) AND
		assettype = 'host'`, hn)
	if err != nil {
		return err
	}
	return nil
}

// Update a website in the asset table
func updateWebsite(op opContext, ws string, comment string, confidence int) error {
	_, err := op.Exec(`INSERT INTO asset
		(website, comment, dynamic, dynamic_added, dynamic_confidence, lastused,
		lastcompscore, lastvulnscore, lasthttpobsscore, assettype)
		SELECT $1, $2, TRUE, now(),
		$3, now(),
		now() - INTERVAL '5 days',
		now() - INTERVAL '5 days',
		now() - INTERVAL '5 days',
		'website'
		WHERE NOT EXISTS (
			SELECT 1 FROM asset WHERE lower(website) = lower($4) AND
			assettype = 'website'
		)`, ws, comment, confidence, ws)
	if err != nil {
		return err
	}
	_, err = op.Exec(`UPDATE asset
		SET lastused = now()
		WHERE lower(website) = lower($1) AND
		assettype = 'website'`, ws)
	if err != nil {
		return err
	}
	return nil
}

// Associate any services linked to a given system group specified in s
func serviceLookup(op opContext, s *slib.Service) error {
	useid := s.SystemGroup.ID
	rows, err := op.Query(`SELECT service, rraid,
		ari, api, afi, cri, cpi, cfi,
		iri, ipi, ifi,
		arp, app, afp,
		crp, cpp, cfp,
		irp, ipp, ifp,
		datadefault
		FROM rra x
		WHERE rraid IN (
		SELECT rraid FROM rra_sysgroup
		WHERE sysgroupid = $1 ) AND
		lastmodified = (
			SELECT MAX(lastmodified) FROM rra y
			WHERE x.service = y.service
		)`, useid)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns slib.RRAService
		err = rows.Scan(&ns.Name, &ns.ID, &ns.AvailRepImpact, &ns.AvailPrdImpact,
			&ns.AvailFinImpact, &ns.ConfiRepImpact, &ns.ConfiPrdImpact,
			&ns.ConfiFinImpact, &ns.IntegRepImpact, &ns.IntegPrdImpact,
			&ns.IntegFinImpact,
			&ns.AvailRepProb, &ns.AvailPrdProb, &ns.AvailFinProb,
			&ns.ConfiRepProb, &ns.ConfiPrdProb, &ns.ConfiFinProb,
			&ns.IntegRepProb, &ns.IntegPrdProb, &ns.IntegFinProb,
			&ns.DefData)
		if err != nil {
			rows.Close()
			return err
		}
		s.Services = append(s.Services, ns)
	}
	err = rows.Err()
	if err != nil {
		return err
	}
	return nil
}

// Merge the specified system group into Service s, which populates it with
// linked services and other information
func mergeSystemGroup(op opContext, s *slib.Service, group slib.SystemGroup) error {
	s.SystemGroup = group
	err := serviceLookup(op, s)
	if err != nil {
		return err
	}
	return nil
}

// Update the lastused value for an asset to indicate that we have recieved
// a search for this asset
func updateLastUsedHost(op opContext, hn string) error {
	_, err := op.Exec(`UPDATE asset
		SET lastused = now()
		WHERE lower(hostname) = lower($1) AND
		assettype = 'host'`, hn)
	if err != nil {
		return err
	}
	return nil
}

// Execute a service search using hostname criteria hn
func searchUsingHost(op opContext, hn string) (slib.Service, error) {
	var ret slib.Service
	err := updateLastUsedHost(op, hn)
	if err != nil {
		return ret, err
	}
	found := false
	var (
		grp                    slib.SystemGroup
		sgid                   sql.NullInt64
		sgname, owteam, owoper sql.NullString
		v2bover                sql.NullString
	)
	err = op.QueryRow(`SELECT sysgroup.sysgroupid,
		sysgroup.name, assetowners.operator, assetowners.team,
		asset.v2boverride
		FROM asset
		LEFT OUTER JOIN sysgroup ON (sysgroup.sysgroupid = asset.sysgroupid)
		LEFT OUTER JOIN assetowners ON (assetowners.ownerid = asset.ownerid)
		WHERE lower(hostname) = lower($1) AND assettype = 'host'`,
		hn).Scan(&sgid, &sgname, &owoper, &owteam, &v2bover)
	if err != nil {
		if err == sql.ErrNoRows {
			return ret, nil
		}
		return ret, err
	}
	if sgname.Valid && sgname.String != "" {
		grp.ID = int(sgid.Int64)
		grp.Name = sgname.String
		err = mergeSystemGroup(op, &ret, grp)
		if err != nil {
			return ret, err
		}
		found = true
	}
	if (owoper.Valid && owoper.String != "") ||
		(owteam.Valid && owteam.String != "") {
		if owteam.Valid {
			ret.Owner.Team = owteam.String
		}
		if owoper.Valid {
			ret.Owner.Operator = owoper.String
		}
		// If both the team and operator were set, construct a
		// default v2bkey
		if ret.Owner.Team != "" && ret.Owner.Operator != "" {
			ret.Owner.V2BKey = ret.Owner.Operator + "-" + ret.Owner.Team
		}
		found = true
	}
	// If the asset has a V2B override set, apply it here
	if v2bover.Valid && v2bover.String != "" {
		ret.Owner.V2BKey = v2bover.String
	}
	ret.Found = found
	return ret, nil
}

// Execute a service search based on the hostname of an asset
func searchHost(op opContext, hn string, conf int) (ret slib.Service, err error) {
	hn = strings.ToLower(hn)
	if conf > 50 {
		// XXX If this is a new host and it matches something in the
		// interlink rule set, this initial response is likely not to
		// contain the information until the rule set runs the next
		// time, once it sees this addition.
		err = updateDynamicHost(op, hn, "dynamic host search", conf)
		if err != nil {
			return
		}
	}
	return searchUsingHost(op, hn)
}

// Execute a service search using the criteria specified in s
func runSearch(o opContext, s slib.Search) error {
	var sres slib.Service
	var err error
	if s.Host != "" {
		sres, err = searchHost(o, s.Host, s.Confidence)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("a search did not specify any criteria")
	}
	sresstr, err := json.Marshal(&sres)
	if err != nil {
		return err
	}
	_, err = o.Exec(`INSERT INTO searchresults
		VALUES ( $1, $2, $3, now())`, o.opid, s.Identifier, string(sresstr))
	if err != nil {
		return err
	}
	return nil
}

// Process a new service lookup request.
func serviceNewSearch(rw http.ResponseWriter, req *http.Request) {
	req.ParseMultipartForm(10000000)

	val := req.FormValue("params")
	if val == "" {
		logf("no search criteria specified")
		http.Error(rw, "no search criteria specified", 500)
		return
	}
	var params slib.SearchParams
	err := json.Unmarshal([]byte(val), &params)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	for _, x := range params.Searches {
		err = runSearch(op, x)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
	}

	sr := slib.SearchResponse{SearchID: op.opid}
	buf, err := json.Marshal(&sr)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprint(rw, string(buf))
}

// Purge used search results from the database.
func purgeSearchResult(op opContext, sid string) error {
	_, err := op.Exec(`DELETE FROM searchresults
		WHERE opid = $1`, sid)
	if err != nil {
		return err
	}
	return nil
}

// Given a search ID, respond with any results.
func serviceGetSearchID(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	sid := req.FormValue("id")
	if sid == "" {
		op.logf("must specify a valid search id")
		http.Error(rw, "must specify a valid search id", 500)
		return
	}

	rows, err := op.Query(`SELECT identifier, result
		FROM searchresults WHERE opid = $1`, sid)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	sidr := slib.SearchIDResponse{}
	sidr.Results = make([]slib.SearchResult, 0)
	for rows.Next() {
		var resstr string
		var s slib.Service
		nr := slib.SearchResult{}
		err = rows.Scan(&nr.Identifier, &resstr)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			rows.Close()
			return
		}
		err = json.Unmarshal([]byte(resstr), &s)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			rows.Close()
			return
		}
		nr.Service = s
		sidr.Results = append(sidr.Results, nr)
	}

	buf, err := json.Marshal(&sidr)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	err = purgeSearchResult(op, sid)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	fmt.Fprint(rw, string(buf))
}

// Search for any hosts that contain a given substring.
func serviceSearchMatch(rw http.ResponseWriter, req *http.Request) {
	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	hm := req.FormValue("hostname")
	if hm == "" {
		http.Error(rw, "no search criteria specified", 500)
		return
	}
	hm = "%" + hm + "%"
	rows, err := op.Query(`SELECT assetid, hostname, sysgroupid,
		dynamic FROM asset WHERE hostname ILIKE $1 AND
		assettype = 'host'`, hm)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	resp := slib.SearchMatchResponse{}
	for rows.Next() {
		hn := slib.Host{}
		var sgid sql.NullInt64
		var dynamic bool
		err = rows.Scan(&hn.ID, &hn.Hostname, &sgid, &dynamic)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			rows.Close()
			return
		}
		if sgid.Valid {
			hn.SysGroupID = int(sgid.Int64)
		}
		resp.Hosts = append(resp.Hosts, hn)
	}

	buf, err := json.Marshal(&resp)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprintf(rw, string(buf))
}

// Process a new indicator request
func serviceIndicator(rw http.ResponseWriter, req *http.Request) {
	req.ParseMultipartForm(10000000)

	val := req.FormValue("params")
	if val == "" {
		logf("no indicator criteria specified")
		http.Error(rw, "no indicator criteria specified", 500)
		return
	}
	var params slib.IndicatorParams
	err := json.Unmarshal([]byte(val), &params)
	if err != nil {
		logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}

	op := opContext{}
	op.newContext(dbconn, false, req.RemoteAddr)

	for _, x := range params.Indicators {
		if x.Host == "" {
			continue
		}
		err = updateDynamicHost(op, x.Host, "indicator request", 90)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
		err = processIndicator(op, x)
		if err != nil {
			op.logf(err.Error())
			http.Error(rw, err.Error(), 500)
			return
		}
	}

	ir := slib.IndicatorResponse{OK: true}
	buf, err := json.Marshal(&ir)
	if err != nil {
		op.logf(err.Error())
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprint(rw, string(buf))
}

// Periodically prune old RRAs
func rraCleanup() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in rra cleanup: %v", e)
		}
	}()
	op := opContext{}
	op.newContext(dbconn, true, "rracleanup")
	cutoff := time.Now().UTC().Add(-(168 * time.Hour))
	_, err := op.Exec(`DELETE FROM rra_sysgroup WHERE
		rraid IN (SELECT rraid FROM rra WHERE 
		lastupdated < $1)`, cutoff)
	if err != nil {
		op.rollback()
		panic(err)
	}
	_, err = op.Exec(`DELETE FROM risk WHERE
		rraid IN (SELECT rraid FROM rra WHERE
		lastupdated < $1)`, cutoff)
	if err != nil {
		op.rollback()
		panic(err)
	}
	_, err = op.Exec(`DELETE FROM rra WHERE
		lastupdated < $1)`, cutoff)
	if err != nil {
		op.rollback()
		panic(err)
	}
	err = op.commit()
	if err != nil {
		panic(err)
	}
}

// Periodically prune dynamic assets from the database that have not been seen
// within a given period.
func dynAssetManager() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in dynamic asset manager: %v", e)
		}
	}()
	op := opContext{}
	op.newContext(dbconn, false, "dynassetmanager")
	// Remove any assets which we have not seen evidence of in the past 7 days
	cutoff := time.Now().UTC().Add(-(168 * time.Hour))
	rows, err := op.Query(`SELECT assetid FROM asset
			WHERE dynamic = true AND lastused < $1`, cutoff)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		var assetid int
		err = rows.Scan(&assetid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		logf("removing asset %v", assetid)
		_, err = op.Exec(`DELETE FROM compscore
				WHERE assetid = $1`, assetid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		_, err = op.Exec(`DELETE FROM vulnscore
				WHERE assetid = $1`, assetid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		_, err = op.Exec(`DELETE FROM vulnstatus
				WHERE assetid = $1`, assetid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		_, err = op.Exec(`DELETE FROM migstatus
				WHERE assetid = $1`, assetid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		_, err = op.Exec(`DELETE FROM httpobsscore
				WHERE assetid = $1`, assetid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		_, err = op.Exec(`DELETE FROM asset
				WHERE assetid = $1`, assetid)
		if err != nil {
			rows.Close()
			panic(err)
		}
	}
	err = rows.Err()
	if err != nil {
		panic(err)
	}

	// Drop any AWS instance metadata that we have not seen since configured
	// cutoff time
	dur, err := time.ParseDuration(cfg.AWSMeta.Lifetime)
	if err != nil {
		panic(err)
	}
	cutoff = time.Now().UTC().Add(-1 * dur)
	rows, err = op.Query(`SELECT assetawsmetaid FROM assetawsmeta
		WHERE lastupdated < $1`, cutoff)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		var metaid int
		err = rows.Scan(&metaid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		logf("removing assetawsmetaid %v", metaid)
		_, err = op.Exec(`UPDATE asset SET assetawsmetaid = NULL
			WHERE assetawsmetaid = $1`, metaid)
		if err != nil {
			rows.Close()
			panic(err)
		}
		_, err = op.Exec(`DELETE FROM assetawsmeta WHERE
			assetawsmetaid = $1`, metaid)
		if err != nil {
			rows.Close()
			panic(err)
		}
	}
	err = rows.Err()
	if err != nil {
		panic(err)
	}
}

func dbInit() error {
	var err error
	connstr := fmt.Sprintf("dbname=%v host=%v", cfg.Database.Database, cfg.Database.Hostname)
	dbconn, err = sql.Open("postgres", connstr)
	if err != nil {
		return err
	}
	return nil
}

func logf(s string, args ...interface{}) {
	buf := fmt.Sprintf(s, args...)
	tstr := time.Now().Format("2006-01-02 15:04:05")
	logbuf := fmt.Sprintf("[%v] %v", tstr, buf)
	logChan <- logbuf
}

func doExit(r int) {
	close(logChan)
	wg.Wait()
	os.Remove(pidFile)
	os.Exit(r)
}

func createPid() error {
	var err error
	pidFD, err = os.OpenFile(pidFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	fmt.Fprintf(pidFD, "%v", os.Getpid())
	pidFD.Close()
	return nil
}

func main() {
	var cfgpath string

	flag.StringVar(&cfgpath, "f", "", "path to configuration file")
	flag.StringVar(&pidFile, "p", "/var/run/serviceapi.pid", "path to pid file")
	flag.Parse()

	if cfgpath == "" {
		fmt.Fprintf(os.Stderr, "error: must specify configuration file with -f\n")
		os.Exit(1)
	}

	err := gcfg.ReadFileInto(&cfg, cfgpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	err = cfg.validate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = dbInit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigch
		doExit(0)
	}()

	logChan = make(chan string, 64)
	wg.Add(1)
	go func() {
		for x := range logChan {
			fmt.Fprintf(os.Stdout, "%v\n", x)
		}
		wg.Done()
	}()

	err = createPid()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Spawn the compliance scoring process
	go func() {
		logf("spawning compliance scoring routine")
		for {
			scoreCompliance()
			time.Sleep(5 * time.Second)
		}
	}()
	// Spawn the vulnerability scoring process
	go func() {
		logf("spawning vulnerability scoring routine")
		for {
			scoreVuln()
			time.Sleep(5 * time.Second)
		}
	}()
	// Spawn risk cache process
	go func() {
		logf("spawning risk cache routine")
		for {
			riskCache()
			time.Sleep(5 * time.Second)
		}
	}()
	// Spawn the http observatory scoring process
	go func() {
		logf("spawning http observatory scoring routine")
		for {
			scoreHTTPObs()
			time.Sleep(5 * time.Second)
		}
	}()
	// Spawn AWS metadata import process
	go func() {
		logf("spawning aws metadata import routine")
		for {
			importAWSMeta()
			time.Sleep(15 * time.Second)
		}
	}()
	// Spawn compliance host import process
	go func() {
		logf("spawning compliance host import routine")
		for {
			importCompHosts()
			time.Sleep(60 * time.Minute)
		}
	}()
	// Spawn dynamic host manager
	go func() {
		logf("spawning dynamic asset manager")
		for {
			time.Sleep(1 * time.Minute)
			dynAssetManager()
		}
	}()
	// Spawn RRA cleanup routine
	go func() {
		logf("spawning rra cleanup routine")
		for {
			time.Sleep(1 * time.Minute)
			rraCleanup()
		}
	}()
	go func() {
		logf("spawning interlink manager")
		for {
			sd, err := time.ParseDuration(cfg.Interlink.RunEvery)
			if err != nil {
				logf("interlink: bad value for runevery, default to 10m")
				sd, _ = time.ParseDuration("10m")
			}
			interlinkManager()
			logf("interlink: waiting %v for next run", sd)
			time.Sleep(sd)
		}
	}()

	logf("Starting processing")

	r := mux.NewRouter()
	s := r.PathPrefix("/api/v1").Subrouter()
	s.HandleFunc("/search", serviceNewSearch).Methods("POST")
	s.HandleFunc("/search/results/id", serviceGetSearchID).Methods("GET")
	s.HandleFunc("/search/match", serviceSearchMatch).Methods("GET")
	s.HandleFunc("/indicator", serviceIndicator).Methods("POST")
	s.HandleFunc("/sysgroups", serviceSysGroups).Methods("GET")
	s.HandleFunc("/sysgroup/id", serviceGetSysGroup).Methods("GET")
	s.HandleFunc("/rras", serviceRRAs).Methods("GET")
	s.HandleFunc("/risks", serviceRisks).Methods("GET")
	s.HandleFunc("/rra/id", serviceGetRRA).Methods("GET")
	s.HandleFunc("/rra/update", serviceUpdateRRA).Methods("POST")
	s.HandleFunc("/rra/risk", serviceGetRRARisk).Methods("GET")
	s.HandleFunc("/vulns/target", serviceGetVulnsTarget).Methods("GET")
	s.HandleFunc("/legacy/vulnauto", serviceVulnAuto).Methods("GET")
	s.HandleFunc("/owners", serviceOwners).Methods("GET")
	http.Handle("/", context.ClearHandler(r))
	listenAddr := cfg.General.Listen
	err = http.ListenAndServeTLS(listenAddr, cfg.General.Cert, cfg.General.Key, nil)
	if err != nil {
		logf("http.ListenAndServeTLS: %v", err)
		doExit(1)
	}

	doExit(0)
}
