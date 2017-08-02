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

type config struct {
	General struct {
		Listen         string
		RiskCacheEvery string
		DisableAPIAuth bool
	}
	Database struct {
		Hostname string
		Database string
		User     string
		Password string
	}
	Interlink struct {
		RulePath string
		RunEvery string
	}
}

func (c *config) validate() error {
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

var cfg config
var dbconn *sql.DB

var wg sync.WaitGroup
var logChan chan string

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

	flag.StringVar(&cfgpath, "f", "/etc/serviceapi.conf", "path to configuration file")
	flag.StringVar(&pidFile, "p", "/var/run/serviceapi.pid", "path to pid file")
	flag.Parse()

	err := gcfg.ReadFileInto(&cfg, cfgpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	// Import any configuration values set in the environment, and if set
	// override config file
	envvar := os.Getenv("PGHOST")
	if envvar != "" {
		cfg.Database.Hostname = envvar
	}
	envvar = os.Getenv("PGUSER")
	if envvar != "" {
		cfg.Database.User = envvar
	}
	envvar = os.Getenv("PGPASSWORD")
	if envvar != "" {
		cfg.Database.Password = envvar
	}
	// If the database name is not set, use the default
	if cfg.Database.Database == "" {
		cfg.Database.Database = "servicemap"
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
	s.HandleFunc("/indicator", authenticate(serviceIndicator)).Methods("POST")
	s.HandleFunc("/assetgroups", authenticate(serviceAssetGroups)).Methods("GET")
	s.HandleFunc("/assetgroup/id", authenticate(serviceGetAssetGroup)).Methods("GET")
	s.HandleFunc("/rras", authenticate(serviceRRAs)).Methods("GET")
	s.HandleFunc("/risks", authenticate(serviceRisks)).Methods("GET")
	s.HandleFunc("/rra/id", authenticate(serviceGetRRA)).Methods("GET")
	s.HandleFunc("/rra/update", authenticate(serviceUpdateRRA)).Methods("POST")
	s.HandleFunc("/rra/risk", authenticate(serviceGetRRARisk)).Methods("GET")
	s.HandleFunc("/owners", authenticate(serviceOwners)).Methods("GET")
	s.HandleFunc("/ping", servicePing).Methods("GET")
	http.Handle("/", context.ClearHandler(r))
	err = http.ListenAndServe(cfg.General.Listen, nil)
	if err != nil {
		logf("http.ListenAndServe: %v", err)
		doExit(1)
	}

	doExit(0)
}

func servicePing(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(rw, "pong\n")
}

// Generalized API authentication wrapper
func authenticate(runfunc func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		if cfg.General.DisableAPIAuth {
			runfunc(rw, r)
			return
		}
		hdr := r.Header.Get("SERVICEAPIKEY")
		if hdr == "" {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, err := apiAuthenticate(hdr)
		if err != nil {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		runfunc(rw, r)
	}
}
