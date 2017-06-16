// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	slib "github.com/mozilla/service-map/servicelib"
	"gopkg.in/gcfg.v1"
	"net/http"
	"os"
	"os/signal"
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
		User     string
		Password string
	}
	Interlink struct {
		RulePath              string
		RunEvery              string
		AWSStripDNSSuffixList string
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
		lastupdated < $1`, cutoff)
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
}

func dbInit() error {
	var err error
	connstr := fmt.Sprintf("dbname=%v host=%v user=%v password=%v",
		cfg.Database.Database, cfg.Database.Hostname, cfg.Database.User,
		cfg.Database.Password)
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

	// Spawn risk cache process
	go func() {
		logf("spawning risk cache routine")
		for {
			riskCache()
			time.Sleep(5 * time.Second)
		}
	}()
	// Spawn asset manager
	go func() {
		logf("spawning asset manager")
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
	s.HandleFunc("/indicator", serviceIndicator).Methods("POST")
	s.HandleFunc("/assetgroups", serviceAssetGroups).Methods("GET")
	s.HandleFunc("/assetgroup/id", serviceGetAssetGroup).Methods("GET")
	s.HandleFunc("/rras", serviceRRAs).Methods("GET")
	s.HandleFunc("/risks", serviceRisks).Methods("GET")
	s.HandleFunc("/rra/id", serviceGetRRA).Methods("GET")
	s.HandleFunc("/rra/update", serviceUpdateRRA).Methods("POST")
	s.HandleFunc("/rra/risk", serviceGetRRARisk).Methods("GET")
	s.HandleFunc("/owners", serviceOwners).Methods("GET")
	http.Handle("/", context.ClearHandler(r))
	err = http.ListenAndServe(cfg.General.Listen, nil)
	if err != nil {
		logf("http.ListenAndServe: %v", err)
		doExit(1)
	}

	doExit(0)
}
