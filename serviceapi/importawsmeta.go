// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	slib "github.com/mozilla/service-map/servicelib"
	"io/ioutil"
)

// Handles peridically importing AWS instance metadata and associating it
// with known assets

func processAWSInstanceMeta(mi slib.AWSInstanceMeta) error {
	op := opContext{}
	op.newContext(dbconn, false, "importawsmeta")

	tbuf, err := json.Marshal(mi.Tags)
	if err != nil {
		return err
	}
	_, err = op.Exec(`INSERT INTO assetawsmeta
		(accountid, accountname, region, instancetype,
		instanceid, public_ip, private_ip, private_dns,
		public_dns, tags, lastupdated)
		SELECT $1, $2, $3, $4,
		$5, $6, $7, $8,
		$9, $10, now()
		WHERE NOT EXISTS (
			SELECT 1 FROM assetawsmeta WHERE
			accountid = $11 AND
			instanceid = $12
		)`, mi.AWSAccountID, mi.AWSAccountName, mi.Region,
		mi.InstanceType, mi.InstanceID, mi.PublicIP,
		mi.PrivateIP, mi.PrivateDNS, mi.PublicDNS, tbuf,
		mi.AWSAccountID, mi.InstanceID)
	if err != nil {
		return err
	}

	_, err = op.Exec(`UPDATE assetawsmeta
		SET accountname = $1,
		region = $2,
		instancetype = $3,
		public_ip = $4,
		private_ip = $5,
		private_dns = $6,
		public_dns = $7,
		tags = $8,
		lastupdated = now()
		WHERE accountid = $9 AND
		instanceid = $10`, mi.AWSAccountName,
		mi.Region, mi.InstanceType, mi.PublicIP,
		mi.PrivateIP, mi.PrivateDNS,
		mi.PublicDNS, tbuf, mi.AWSAccountID,
		mi.InstanceID)
	if err != nil {
		return err
	}
	return nil
}

func processAWSMeta(m slib.AWSMeta) error {
	for _, x := range m.Instances {
		err := processAWSInstanceMeta(x)
		if err != nil {
			return err
		}
	}
	return nil
}

func getAWSMeta() (ret slib.AWSMeta, err error) {
	buf, err := ioutil.ReadFile(cfg.AWSMeta.MetaFile)
	if err != nil {
		return
	}
	err = json.Unmarshal(buf, &ret)
	return
}

// Entry point for AWS metadata import routine
func importAWSMeta() {
	defer func() {
		if e := recover(); e != nil {
			logf("error in aws metadata import routine: %v", e)
		}
	}()
	meta, err := getAWSMeta()
	if err != nil {
		panic(err)
	}
	err = processAWSMeta(meta)
	if err != nil {
		panic(err)
	}
}
