#!/bin/bash
#
# Copyright (C) 2016-2018 Draios Inc dba Sysdig.
#
# This file is part of falco.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
SCRIPT=$(readlink -f $0)
SCRIPTDIR=$(dirname $SCRIPT)
BRANCH=$1

function download_trace_files() {
    echo "branch=$BRANCH"
    for TRACE in traces-positive traces-negative traces-info ; do
	rm -rf $SCRIPTDIR/$TRACE
	curl -fso $SCRIPTDIR/$TRACE.zip https://s3.amazonaws.com/download.draios.com/falco-tests/$TRACE-$BRANCH.zip || curl -fso $SCRIPTDIR/$TRACE.zip https://s3.amazonaws.com/download.draios.com/falco-tests/$TRACE.zip &&
	unzip -d $SCRIPTDIR $SCRIPTDIR/$TRACE.zip &&
	rm -rf $SCRIPTDIR/$TRACE.zip
    done
}

function prepare_multiplex_fileset() {

    dir=$1
    detect=$2

    for trace in $SCRIPTDIR/$dir/*.scap ; do
	[ -e "$trace" ] || continue
	NAME=`basename $trace .scap`

	# falco_traces.yaml might already have an entry for this trace
	# file, with specific detection levels and counts. If so, skip
	# it. Otherwise, add a generic entry showing whether or not to
	# detect anything.
	grep -q "$NAME:" $SCRIPTDIR/falco_traces.yaml && continue

	cat << EOF >> $SCRIPTDIR/falco_traces.yaml
  $NAME:
    detect: $detect
    detect_level: WARNING
    trace_file: $trace
EOF
    done
}

function prepare_multiplex_file() {
    cp $SCRIPTDIR/falco_traces.yaml.in $SCRIPTDIR/falco_traces.yaml

    prepare_multiplex_fileset traces-positive True
    prepare_multiplex_fileset traces-negative False
    prepare_multiplex_fileset traces-info True

    echo "Contents of $SCRIPTDIR/falco_traces.yaml:"
    cat $SCRIPTDIR/falco_traces.yaml
}

function print_test_failure_details() {
    echo "Showing full job logs for any tests that failed:"
    jq '.tests[] | select(.status != "PASS") | .logfile' $SCRIPTDIR/job-results/latest/results.json  | xargs cat
}

function run_tests() {
    rm -rf /tmp/falco_outputs
    mkdir /tmp/falco_outputs
    TEST_RC=0
    for mult in $SCRIPTDIR/falco_traces.yaml $SCRIPTDIR/falco_tests.yaml $SCRIPTDIR/falco_k8s_audit_tests.yaml; do
	CMD="avocado run --multiplex $mult --job-results-dir $SCRIPTDIR/job-results -- $SCRIPTDIR/falco_test.py"
	echo "Running: $CMD"
	$CMD
	RC=$?
	TEST_RC=$((TEST_RC+$RC))
	if [ $RC -ne 0 ]; then
	    print_test_failure_details
	fi
    done
}

download_trace_files
prepare_multiplex_file
run_tests
exit $TEST_RC
