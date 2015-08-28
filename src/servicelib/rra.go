// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// Describes an RRA.
type RRAService struct {
	Name     string `json:"name,omitempty"`
	ID       int    `json:"id,omitempty"`
	AvailRep string `json:"availrep,omitempty"`
	AvailPrd string `json:"availprd,omitempty"`
	AvailFin string `json:"availfin,omitempty"`
	IntegRep string `json:"integrep,omitempty"`
	IntegPrd string `json:"integprd,omitempty"`
	IntegFin string `json:"integfin,omitempty"`
	ConfiRep string `json:"confirep,omitempty"`
	ConfiPrd string `json:"confiprd,omitempty"`
	ConfiFin string `json:"confifin,omitempty"`
	DefData  string `json:"defdata,omitempty"`

	SupportGrps []SystemGroup `json:"supportgrps,omitempty"` // Supporting system groups
}
