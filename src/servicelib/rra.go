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
	ID       int    `json:"id"`
	AvailRep string `json:"availrep"`
	AvailPrd string `json:"availprd"`
	AvailFin string `json:"availfin"`
	IntegRep string `json:"integrep"`
	IntegPrd string `json:"integprd`
	IntegFin string `json:"integfin"`
	ConfiRep string `json:"confirep"`
	ConfiPrd string `json:"confiprd"`
	ConfiFin string `json:"confifin"`
	DefData  string `json:"defdata"`

	SupportGrps []SystemGroup `json:"supportgrps"` // Supporting system groups
}
