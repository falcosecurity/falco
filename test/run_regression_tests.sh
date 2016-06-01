#!/bin/bash

SCRIPT=$(readlink -f $0)
SCRIPTDIR=$(dirname $SCRIPT)
MULT_FILE=$SCRIPTDIR/falco_tests.yaml

function download_trace_files() {
    for TRACE in traces-positive traces-negative traces-info ; do
	rm -rf $SCRIPTDIR/$TRACE
	curl -so $SCRIPTDIR/$TRACE.zip https://s3.amazonaws.com/download.draios.com/falco-tests/$TRACE.zip &&
	unzip -d $SCRIPTDIR $SCRIPTDIR/$TRACE.zip &&
	rm -rf $SCRIPTDIR/$TRACE.zip
    done
}

function prepare_multiplex_file() {
    echo "trace_files: !mux" > $MULT_FILE

    for trace in $SCRIPTDIR/traces-positive/*.scap ; do
	[ -e "$trace" ] || continue
	NAME=`basename $trace .scap`
	cat << EOF >> $MULT_FILE
  $NAME:
    detect: True
    detect_level: Warning
    trace_file: $trace
EOF
    done

    for trace in $SCRIPTDIR/traces-negative/*.scap ; do
	[ -e "$trace" ] || continue
	NAME=`basename $trace .scap`
	cat << EOF >> $MULT_FILE
  $NAME:
    detect: False
    trace_file: $trace
EOF
    done

    for trace in $SCRIPTDIR/traces-info/*.scap ; do
	[ -e "$trace" ] || continue
	NAME=`basename $trace .scap`
	cat << EOF >> $MULT_FILE
  $NAME:
    detect: True
    detect_level: Informational
    trace_file: $trace
EOF
    done

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
