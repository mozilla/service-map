// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"code.google.com/p/gcfg"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"net/http"
	"os"
	slib "servicelib"
	"sync"
	"time"
)

type opContext struct {
	tx   *sql.Tx
	db   *sql.DB
	opid string
}

func (o *opContext) newContext(db *sql.DB, useTransaction bool) (err error) {
	o.opid = slib.NewUUID()
	if useTransaction {
		o.tx, err = db.Begin()
		if err != nil {
			return err
		}
	}
	return nil
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

type Config struct {
	General struct {
		Listen string
	}
	Database struct {
		Hostname string
		Database string
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

func serviceLookup(s *slib.Service) error {
	useid := s.SystemGroup.ID
	rows, err := dbconn.Query(`SELECT service FROM rra
		WHERE rraid IN (
		SELECT rraid FROM rra_sysgroup
		WHERE sysgroupid = $1 )`, useid)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns slib.RRAService
		rows.Scan(&ns.Name)
		s.Services = append(s.Services, ns)
	}
	return nil
}

func mergeSystemGroups(s *slib.Service, groups []slib.SystemGroup) error {
	if len(groups) == 0 {
		return nil
	}
	s.Found = true
	s.SystemGroup = groups[0]
	err := serviceLookup(s)
	if err != nil {
		return err
	}
	return nil
}

func searchUsingHost(hn string) (slib.Service, error) {
	var ret slib.Service
	rows, err := dbconn.Query(`SELECT sysgroupid, name
		FROM sysgroup WHERE sysgroupid IN (
		SELECT DISTINCT sysgroupid
		FROM host WHERE hostname = $1 )`, hn)
	if err != nil {
		return ret, err
	}
	groups := make([]slib.SystemGroup, 0)
	for rows.Next() {
		var n slib.SystemGroup
		err = rows.Scan(&n.ID, &n.Name)
		groups = append(groups, n)
	}
	err = mergeSystemGroups(&ret, groups)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func searchUsingHostMatch(hn string) (slib.Service, error) {
	var ret slib.Service

	// Use hostmatch to see if we can identify the system group.
	rows, err := dbconn.Query(`SELECT sysgroupid, name
		FROM sysgroup WHERE sysgroupid IN (
		SELECT DISTINCT sysgroupid
		FROM hostmatch WHERE
		$1 ~* expression )`, hn)
	if err != nil {
		return ret, err
	}
	groups := make([]slib.SystemGroup, 0)
	for rows.Next() {
		var n slib.SystemGroup
		err = rows.Scan(&n.ID, &n.Name)
		groups = append(groups, n)
	}
	err = mergeSystemGroups(&ret, groups)
	if err != nil {
		return ret, err
	}

	return ret, nil
}

func searchHost(hn string) (slib.Service, error) {
	sr, err := searchUsingHost(hn)
	if err != nil || sr.Found {
		return sr, err
	}
	sr, err = searchUsingHostMatch(hn)
	if err != nil || sr.Found {
		return sr, err
	}
	return sr, nil
}

func runSearch(o opContext, s slib.Search) error {
	var sres slib.Service
	var err error
	if s.Host != "" {
		sres, err = searchHost(s.Host)
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
	_, err = o.tx.Exec(`INSERT INTO searchresults
	VALUES ( $1, $2, $3, now())`, o.opid, s.Identifier, string(sresstr))
	if err != nil {
		return err
	}
	return nil
}

func serviceNewSearch(rw http.ResponseWriter, req *http.Request) {
	req.ParseMultipartForm(10000000)

	val := req.FormValue("params")
	if val == "" {
		http.Error(rw, "no search criteria specified", 500)
		return
	}
	var params slib.SearchParams
	err := json.Unmarshal([]byte(val), &params)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	op := opContext{}
	op.newContext(dbconn, true)

	for _, x := range params.Searches {
		err = runSearch(op, x)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			err = op.rollback()
			if err != nil {
				panic(err)
			}
			return
		}
	}
	op.commit()

	sr := slib.SearchResponse{SearchID: op.opid}
	buf, err := json.Marshal(&sr)
	if err != nil {
		panic(err)
	}
	fmt.Fprint(rw, string(buf))
}

func purgeSearchResult(sid string) error {
	_, err := dbconn.Exec(`DELETE FROM searchresults
		WHERE opid = $1`, sid)
	if err != nil {
		return err
	}
	return nil
}

func serviceGetSearchID(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	sid := req.FormValue("id")
	if sid == "" {
		http.Error(rw, "must specify a valid search id", 500)
		return
	}

	rows, err := dbconn.Query(`SELECT identifier, result
		FROM searchresults WHERE opid = $1`, sid)
	if err != nil {
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
			http.Error(rw, err.Error(), 500)
			return
		}
		err = json.Unmarshal([]byte(resstr), &s)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		nr.Service = s
		sidr.Results = append(sidr.Results, nr)
	}

	buf, err := json.Marshal(&sidr)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	err = purgeSearchResult(sid)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}

	fmt.Fprint(rw, string(buf))
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
	os.Exit(r)
}

func main() {
	var cfgpath string

	flag.StringVar(&cfgpath, "f", "", "path to configuration file")
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

	logChan = make(chan string, 64)
	wg.Add(1)
	go func() {
		for x := range logChan {
			fmt.Fprintf(os.Stdout, "%v\n", x)
		}
		wg.Done()
	}()

	logf("Starting processing")

	r := mux.NewRouter()
	s := r.PathPrefix("/api/v1").Subrouter()
	s.HandleFunc("/search", serviceNewSearch).Methods("POST")
	s.HandleFunc("/search/results/id", serviceGetSearchID).Methods("GET")
	http.Handle("/", context.ClearHandler(r))
	listenAddr := cfg.General.Listen
	err = http.ListenAndServe(listenAddr, nil)

	doExit(0)
}
