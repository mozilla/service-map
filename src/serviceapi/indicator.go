// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"fmt"
	slib "servicelib"
)

// Validate an indicator and update the database
func processIndicator(op opContext, ind slib.Indicator) (err error) {
	// Verify it's a class we expect, currently only vuln
	if ind.Class != "vuln" {
		return fmt.Errorf("unknown indicator class")
	}
	_, err = op.Exec(`INSERT INTO vulnstatus
		(timestamp, assetid, checktype, status)
		VALUES (now(),
		(SELECT assetid FROM asset WHERE
		lower(hostname) = lower($1) AND
		assettype = 'host'),
		$2, $3)`, ind.Host, ind.CheckType, ind.Status)
	if err != nil {
		return err
	}
	return nil
}
