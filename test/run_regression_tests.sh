#!/usr/bin/env bash
#
# Copyright (C) 2020 The Falco Authors.
#
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
set -euo pipefail

SCRIPT=$(readlink -f $0)
SCRIPTDIR=$(dirname "$SCRIPT")
SKIP_PACKAGES_TESTS=${SKIP_PACKAGES_TESTS:-false}
TRACE_FILES_BASE_URL=${TRACE_FILES_BASE_URL:-"https://download.falco.org/fixtures/trace-files/"}

# Trace file tarballs are now versioned. Any time a substantial change
# is made that affects the interaction of rules+engine and the trace
# files here, upload a new trace file zip file and change the version
# suffix here.
TRACE_FILES_VERSION=20200831

function download_trace_files() {
    for TRACE in traces-positive traces-negative traces-info ; do
    if [ ! -e "$TRACE_DIR/$TRACE" ]; then
        if [ "$OPT_BRANCH" != "none" ]; then
        curl -fso "$TRACE_DIR/$TRACE.zip" "$TRACE_FILES_BASE_URL$TRACE-$OPT_BRANCH.zip"
        else
        curl -fso "$TRACE_DIR/$TRACE.zip" "$TRACE_FILES_BASE_URL$TRACE-$TRACE_FILES_VERSION.zip"
        fi
        unzip -d "$TRACE_DIR" "$TRACE_DIR/$TRACE.zip"
        rm -rf "$TRACE_DIR/$TRACE.zip"
    else
        if ${OPT_VERBOSE}; then
            echo "Trace directory $TRACE_DIR/$TRACE already exist: skipping"
        fi
    fi
    done
}

function prepare_multiplex_fileset() {
    dir=$1
    detect=$2

    for trace in "$TRACE_DIR/$dir"/*.scap ; do
        [ -e "$trace" ] || continue
        NAME=$(basename "$trace" .scap)

        # falco_traces.yaml might already have an entry for this trace file, with specific detection levels and counts.
        # If so, skip it.
        # Otherwise, add a generic entry showing whether or not to detect anything.
        if grep -q "$NAME:" "$SCRIPTDIR/falco_traces.yaml"; then
            if ${OPT_VERBOSE}; then
                echo "Entry $NAME already exist: skipping"
            fi
            continue
        fi

        cat << EOF >> "$SCRIPTDIR/falco_traces.yaml"

  $NAME:
    detect: $detect
    detect_level: WARNING
    trace_file: $trace
EOF
    done
}

function prepare_multiplex_file() {
    /bin/cp -f "$SCRIPTDIR/falco_traces.yaml.in" "$SCRIPTDIR/falco_traces.yaml"

    prepare_multiplex_fileset traces-positive True
    prepare_multiplex_fileset traces-negative False
    prepare_multiplex_fileset traces-info True

    if ${OPT_VERBOSE}; then
        echo "Contents of $SCRIPTDIR/falco_traces.yaml"
        cat "$SCRIPTDIR/falco_traces.yaml"
    fi
}

function print_test_failure_details() {
    echo "Showing full job logs for any tests that failed:"
    jq '.tests[] | select(.status != "PASS") | .logfile' "$SCRIPTDIR/job-results/latest/results.json" | xargs cat
}

function run_tests() {
    rm -rf /tmp/falco_outputs
    mkdir /tmp/falco_outputs
    # If we got this far, we can undo set -e,
    # as we're watching the return status when running avocado.
    set +e
    TEST_RC=0
    suites=($SCRIPTDIR/falco_traces.yaml $SCRIPTDIR/falco_tests.yaml $SCRIPTDIR/falco_k8s_audit_tests.yaml $SCRIPTDIR/falco_tests_psp.yaml $SCRIPTDIR/falco_tests_exceptions.yaml)

    if [ "$SKIP_PACKAGES_TESTS" = false ] ; then
        suites+=($SCRIPTDIR/falco_tests_package.yaml)
    fi
    
    XUNIT_DIR="${OPT_BUILD_DIR}/integration-tests-xunit"
    mkdir -p "${XUNIT_DIR}"

    for mult in "${suites[@]}"; do
        XUNIT_FILE_NAME="${XUNIT_DIR}/$(basename "${mult}").xml"
        CMD="avocado run --xunit ${XUNIT_FILE_NAME} --mux-yaml $mult --job-results-dir $SCRIPTDIR/job-results -- $SCRIPTDIR/falco_test.py"
        echo "Running $CMD"
        BUILD_DIR=${OPT_BUILD_DIR} $CMD
        RC=$?
        TEST_RC=$((TEST_RC+RC))
        if [ $RC -ne 0 ]; then
            print_test_failure_details
        fi
    done
}

OPT_ONLY_PREPARE="false"
OPT_VERBOSE="false"
OPT_BUILD_DIR="$(dirname "$SCRIPTDIR")/build"
OPT_BRANCH="none"
while getopts ':p :h :v :b: :d:' 'OPTKEY'; do
    case ${OPTKEY} in
        'p')
            OPT_ONLY_PREPARE="true"
            ;;
        'h')
            /bin/bash usage
            exit 0
            ;;
        'v')
            OPT_VERBOSE="true"
            ;;
        'd')
            OPT_BUILD_DIR=${OPTARG}
            ;;
        'b')
            OPT_BRANCH=${OPTARG}
            ;;
        '?')
            echo "Invalid option: ${OPTARG}." >&2
            /bin/bash usage
            exit 1
            ;;
        ':')
            echo "Missing argument for option: ${OPTARG}." >&2
            /bin/bash usage
            exit 1
            ;;
        *)
            echo "Unimplemented option: ${OPTKEY}." >&2
            /bin/bash usage
            exit 1
            ;;
        esac
done

TRACE_DIR=$OPT_BUILD_DIR/test

if ${OPT_VERBOSE}; then
    echo "Build directory = $OPT_BUILD_DIR"
    echo "Trace directory = $TRACE_DIR"
    echo "Custom branch   = $OPT_BRANCH"
fi

mkdir -p "$TRACE_DIR"

download_trace_files
prepare_multiplex_file

if ! ${OPT_ONLY_PREPARE}; then
    run_tests
    exit $TEST_RC
fi
