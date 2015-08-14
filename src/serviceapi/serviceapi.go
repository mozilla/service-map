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
	"sync"
	"time"
)

type serviceResponse struct {
	Services    []rraService `json:"services,omitempty"`
	SystemGroup sysGroup     `json:"systemgroup,omitempty"`
	Found       bool         `json:"found"`
}

func (s *serviceResponse) jsonString() string {
	buf, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(buf)
}

func (s *serviceResponse) serviceLookup() error {
	useid := s.SystemGroup.ID
	rows, err := dbconn.Query(`SELECT service FROM rra
		WHERE rraid IN (
		SELECT rraid FROM rra_sysgroup
		WHERE sysgroupid = $1 )`, useid)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ns rraService
		rows.Scan(&ns.Name)
		s.Services = append(s.Services, ns)
	}
	return nil
}

func (s *serviceResponse) mergeSystemGroups(groups []sysGroup) error {
	if len(groups) == 0 {
		return nil
	}
	s.Found = true
	s.SystemGroup = groups[0]
	err := s.serviceLookup()
	if err != nil {
		return err
	}
	return nil
}

type sysGroup struct {
	Name string `json:"name,omitempty"`
	ID   int    `json:"id,omitempty"`
}

type rraService struct {
	Name string `json:"name"`
}

type Config struct {
	Database struct {
		Hostname string
		Database string
	}
}

var cfg Config
var dbconn *sql.DB

var wg sync.WaitGroup
var logChan chan string

func searchUsingHost(hn string) (serviceResponse, error) {
	var sr serviceResponse
	rows, err := dbconn.Query(`SELECT sysgroupid, name
		FROM sysgroup WHERE sysgroupid IN (
		SELECT DISTINCT sysgroupid
		FROM host WHERE hostname = $1 )`, hn)
	if err != nil {
		return sr, err
	}
	groups := make([]sysGroup, 0)
	for rows.Next() {
		var n sysGroup
		err = rows.Scan(&n.ID, &n.Name)
		groups = append(groups, n)
	}
	err = sr.mergeSystemGroups(groups)
	if err != nil {
		return sr, err
	}
	return sr, nil
}

func searchUsingHostMatch(hn string) (serviceResponse, error) {
	var sr serviceResponse

	// Use hostmatch to see if we can identify the system group.
	rows, err := dbconn.Query(`SELECT sysgroupid, name
		FROM sysgroup WHERE sysgroupid IN (
		SELECT DISTINCT sysgroupid
		FROM hostmatch WHERE
		$1 ~* expression )`, hn)
	if err != nil {
		return sr, err
	}
	groups := make([]sysGroup, 0)
	for rows.Next() {
		var n sysGroup
		err = rows.Scan(&n.ID, &n.Name)
		groups = append(groups, n)
	}
	err = sr.mergeSystemGroups(groups)
	if err != nil {
		return sr, err
	}

	return sr, nil
}

func searchHost(hn string) (serviceResponse, error) {
	sr, err := searchUsingHostMatch(hn)
	if err != nil || sr.Found {
		return sr, err
	}
	sr, err = searchUsingHost(hn)
	if err != nil || sr.Found {
		return sr, err
	}
	return sr, nil
}

func serviceSearch(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	hostreq := req.FormValue("hostname")

	if hostreq == "" {
		http.Error(rw, "no search criteria specified", 500)
	}

	ret, err := searchHost(hostreq)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	fmt.Fprint(rw, ret.jsonString())
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

	err := gcfg.ReadFileInto(&cfg, cfgpath)
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
	s.HandleFunc("/search", serviceSearch).Methods("GET")
	http.Handle("/", context.ClearHandler(r))
	listenAddr := "0.0.0.0:4444"
	err = http.ListenAndServe(listenAddr, nil)

	doExit(0)
}
