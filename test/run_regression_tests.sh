#!/bin/bash

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
    detect_level=$3
    json_output=$4
    valgrind=$5

    MULT_FILE="$dir-tests.yaml"

    echo "$dir:" >> $MULT_FILE

    if [ $json_output == "yes" ]; then
	cat << EOF >> $MULT_FILE
  json_output: !mux
    enabled:
      json_output: True
    disabled:
      json_output: False
EOF
    fi

    if [ $valgrind == "yes" ]; then
	cat << EOF >> $MULT_FILE
  valgrind: !mux
    enabled:
      valgrind: True
    disabled:
      valgrind: False
EOF
    fi

    echo "  test_trace_files: !mux" >> $MULT_FILE

    for trace in $SCRIPTDIR/$dir/*.scap ; do
	[ -e "$trace" ] || continue
	NAME=`basename $trace .scap`
	cat << EOF >> $MULT_FILE
    $NAME:
      detect: $detect
      detect_level: $detect_level
      trace_file: $trace
EOF
    done

    echo "Contents of $MULT_FILE:"
    cat $MULT_FILE
}

function prepare_multiplex_files() {
    prepare_multiplex_fileset traces-positive True WARNING yes yes
    prepare_multiplex_fileset traces-negative False WARNING no no
    prepare_multiplex_fileset traces-info True INFO yes yes
}

function run_avocado() {

    MULT_FILE=$1

    rm -rf /tmp/falco_outputs
    mkdir /tmp/falco_outputs
    CMD="avocado run --multiplex $MULT_FILE --job-results-dir $SCRIPTDIR/job-results -- $SCRIPTDIR/falco_test.py"
    echo "Running: $CMD"
    $CMD
    TEST_RC=$?

    if [ $TEST_RC -ne 0 ]; then
	echo "Showing full job logs for any tests that failed:"
	jq '.tests[] | select(.status != "PASS") | .logfile' $SCRIPTDIR/job-results/latest/results.json  | xargs cat
    fi

    return $TEST_RC
}

function run_tests() {
    run_avocado $SCRIPTDIR/falco_tests.yaml
    rc1=$?
    run_avocado traces-positive-tests.yaml
    rc2=$?
    run_avocado traces-negative-tests.yaml
    rc3=$?
    run_avocado traces-info-tests.yaml
    rc4=$?

    return $rc1 || $rc2 || $rc3 || $rc4
}

download_trace_files
prepare_multiplex_files
run_tests
exit $?
