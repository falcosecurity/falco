// Copyright 2012-2018 The Sysdig Tech Marketing Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build ignore

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
)

func main() {
	var topic = flag.String("t", "", "The AWS SNS topic ARN")
	var pipePath = flag.String("f", "/var/run/falco/nats", "The named pipe path")

	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	session, err := session.NewSession(&aws.Config{Region: aws.String(os.Getenv("AWS_DEFAULT_REGION"))})
	if err != nil {
		log.Fatal(err)
	}
	svc := sns.New(session)

	pipe, err := os.OpenFile(*pipePath, os.O_RDONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Opened pipe %s", *pipePath)

	reader := bufio.NewReader(pipe)
	scanner := bufio.NewScanner(reader)

	log.Printf("Scanning %s", *pipePath)

	for scanner.Scan() {
		msg := []byte(scanner.Text())
		alert := parseAlert(msg)

		params := &sns.PublishInput{
			Message: aws.String(string(msg)),
			MessageAttributes: map[string]*sns.MessageAttributeValue{
				"priority": &sns.MessageAttributeValue{
					DataType:    aws.String("String"),
					StringValue: aws.String(alert.Priority),
				},
				"rule": &sns.MessageAttributeValue{
					DataType:    aws.String("String"),
					StringValue: aws.String(alert.Rule),
				},
			},
			TopicArn: aws.String(*topic),
		}

		_, err := svc.Publish(params)
		if err != nil {
			log.Fatal(err)
		} else {
			log.Printf("Published [%s] : '%s'\n", *topic, msg)
		}
	}
}

func usage() {
	log.Fatalf("Usage: falco-sns -t topic <subject> <msg> \n")
}

type parsedAlert struct {
	Priority string `json:"priority"`
	Rule     string `json:"rule"`
}

func parseAlert(alert []byte) *parsedAlert {
	var result parsedAlert
	err := json.Unmarshal(alert, &result)
	if err != nil {
		log.Fatal(err)
	}

	return &result
}
