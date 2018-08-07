// Copyright 2012-2018 The NATS Authors
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
	"github.com/nats-io/go-nats"
	"log"
	"os"
	"regexp"
	"strings"
)

var slugRegularExpression = regexp.MustCompile("[^a-z0-9]+")

func main() {
	var urls = flag.String("s", "nats://nats.nats-io.svc.cluster.local:4222", "The nats server URLs (separated by comma)")
	var pipePath = flag.String("f", "/var/run/falco/nats", "The named pipe path")

	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	nc, err := nats.Connect(*urls)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

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

		subj, err := subjectAndRuleSlug(msg)
		if err != nil {
			log.Fatal(err)
		}
		nc.Publish(subj, msg)
		nc.Flush()

		if err := nc.LastError(); err != nil {
			log.Fatal(err)
		} else {
			log.Printf("Published [%s] : '%s'\n", subj, msg)
		}
	}
}

func usage() {
	log.Fatalf("Usage: nats-pub [-s server (%s)] <subject> <msg> \n", nats.DefaultURL)
}

type parsedAlert struct {
	Priority string `json:"priority"`
	Rule     string `json:"rule"`
}

func subjectAndRuleSlug(alert []byte) (string, error) {
	var result parsedAlert
	err := json.Unmarshal(alert, &result)

	if err != nil {
		return "", err
	}

	subject := "falco." + result.Priority + "." + slugify(result.Rule)
	subject = strings.ToLower(subject)

	return subject, nil
}

func slugify(input string) string {
	return strings.Trim(slugRegularExpression.ReplaceAllString(strings.ToLower(input), "_"), "_")
}
