// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"io/ioutil"
)

var s3Key = "interlink.rules"

var s3LastETag string

func interlinkUpdateFromS3(bucket string, region string) error {
	sess := session.Must(session.NewSession())
	svc := s3.New(sess, &aws.Config{
		Region: &region,
	})

	obj := &s3.GetObjectInput{
		Bucket:      &bucket,
		Key:         &s3Key,
		IfNoneMatch: &s3LastETag,
	}
	result, err := svc.GetObject(obj)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == "NotModified" {
				return nil
			}
		}
		return err
	}
	s3LastETag = *result.ETag
	logf("interlink: writing updates from s3")
	buf, err := ioutil.ReadAll(result.Body)
	if err != nil {
		result.Body.Close()
		return err
	}
	result.Body.Close()
	err = ioutil.WriteFile(cfg.Interlink.RulePath, buf, 0644)
	if err != nil {
		return err
	}

	return nil
}
