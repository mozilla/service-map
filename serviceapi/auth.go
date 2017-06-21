// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"errors"
)

// Authenticate a request with an API key token
func apiAuthenticate(hdr string) (name string, err error) {
	op := opContext{}
	op.newContext(dbconn, false, "apiAuthenticate")

	err = op.QueryRow(`SELECT name FROM apikey WHERE
		hash = crypt($1, hash)`, hdr).Scan(&name)
	if err != nil {
		err = errors.New("api key invalid")
	}
	return
}
