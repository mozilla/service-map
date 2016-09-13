// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package servicelib

// Describes format of AWS metadata returned by metadata service
type AWSMeta struct {
	Instances []AWSInstanceMeta `json:"instances"`
}

type AWSInstanceMeta struct {
	AWSAccountID   string      `json:"aws_account_id"`
	AWSAccountName string      `json:"aws_account_name"`
	InstanceID     string      `json:"id"`
	ImageID        string      `json:"image_id"`
	InstanceType   string      `json:"instance_type"`
	PublicIP       string      `json:"ip_address"`
	PrivateIP      string      `json:"private_ip_address"`
	Platform       string      `json:"platform"`
	PrivateDNS     string      `json:"private_dns_name"`
	PublicDNS      string      `json:"public_dns_name"`
	Region         string      `json:"region"`
	Tags           interface{} `json:"tags"`
}
