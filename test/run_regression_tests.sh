#!/bin/bash

SCRIPT=$(readlink -f $0)
SCRIPTDIR=$(dirname $SCRIPT)
MULT_FILE=$SCRIPTDIR/falco_tests.yaml
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
    detect_level=$3
    json_output=$4

    for trace in $SCRIPTDIR/$dir/*.scap ; do
	[ -e "$trace" ] || continue
	NAME=`basename $trace .scap`
	cat << EOF >> $MULT_FILE
  $NAME-detect-$detect-json-$json_output:
    detect: $detect
    detect_level: $detect_level
    trace_file: $trace
    json_output: $json_output
EOF
    done
}

function prepare_multiplex_file() {
    cp $SCRIPTDIR/falco_tests.yaml.in $MULT_FILE

    prepare_multiplex_fileset traces-positive True WARNING False
    prepare_multiplex_fileset traces-negative False WARNING True
    prepare_multiplex_fileset traces-info True INFO False

    prepare_multiplex_fileset traces-positive True WARNING True
    prepare_multiplex_fileset traces-info True INFO True

    echo "Contents of $MULT_FILE:"
    cat $MULT_FILE
}

function run_tests() {
    CMD="avocado run --multiplex $MULT_FILE --job-results-dir $SCRIPTDIR/job-results -- $SCRIPTDIR/falco_test.py"
    echo "Running: $CMD"
    $CMD
    TEST_RC=$?
}


function print_test_failure_details() {
    echo "Showing full job logs for any tests that failed:"
    jq '.tests[] | select(.status != "PASS") | .logfile' $SCRIPTDIR/job-results/latest/results.json  | xargs cat
}

download_trace_files
prepare_multiplex_file
run_tests
if [ $TEST_RC -ne 0 ]; then
   print_test_failure_details
fi

exit $TEST_RC
