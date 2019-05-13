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

#set -x

trap "cleanup; exit" SIGHUP SIGINT SIGTERM

function download_trace_files() {

    (mkdir -p $TRACEDIR && rm -rf $TRACEDIR/traces-perf && curl -fo $TRACEDIR/traces-perf.zip https://s3.amazonaws.com/download.draios.com/falco-tests/traces-perf.zip && unzip -d $TRACEDIR $TRACEDIR/traces-perf.zip && rm -f $TRACEDIR/traces-perf.zip) || exit 1

}

function time_cmd() {
    cmd="$1"
    file="$2"

    benchmark=`basename $file .scap`

    echo -n "$benchmark: "
    for i in `seq 1 5`; do
	echo -n "$i "
	time=`date --iso-8601=sec`
	/usr/bin/time -a -o $RESULTS_FILE --format "{\"time\": \"$time\", \"benchmark\": \"$benchmark\", \"file\": \"$file\", \"variant\": \"$VARIANT\", \"elapsed\": {\"real\": %e, \"user\": %U, \"sys\": %S}}," $cmd >> $OUTPUT_FILE 2>&1
    done
    echo ""
}

function run_falco_on() {
    file="$1"

    if [ -z $RULES_FILE ]; then
	RULES_FILE=$SOURCE/rules/falco_rules.yaml
    fi

    cmd="$ROOT/userspace/falco/falco -c $SOURCE/falco.yaml -r $SOURCE/rules/falco_rules.yaml --option=stdout_output.enabled=false -e $file -A"

    time_cmd "$cmd" "$file"
}

function run_sysdig_on() {
    file="$1"

    cmd="$ROOT/userspace/sysdig/sysdig -N -z -r $file evt.type=none"

    time_cmd "$cmd" "$file"
}

function write_agent_config() {
    cat > $ROOT/userspace/dragent/dragent.yaml <<EOF
customerid: XXX
app_checks_enabled: false
log:
  file_priority: info
  console_priority: info
  event_priority: info
jmx:
  enabled: false
statsd:
  enabled: false
collector: collector-staging.sysdigcloud.com
EOF

    if [ $FALCO_AGENT == 1 ]; then
	cat >> $ROOT/userspace/dragent/dragent.yaml <<EOF
falco_engine:
  enabled: true
  rules_filename: /etc/falco_rules.yaml
  sampling_multiplier: 0
EOF
    else
	cat >> $ROOT/userspace/dragent/dragent.yaml <<EOF
falco_engine:
  enabled: false
EOF
    fi

    if [ $AGENT_AUTODROP == 1 ]; then
	cat >> $ROOT/userspace/dragent/dragent.yaml <<EOF
autodrop:
  enabled: true
EOF
    else
	cat >> $ROOT/userspace/dragent/dragent.yaml <<EOF
autodrop:
  enabled: false
EOF
    fi

    cat $ROOT/userspace/dragent/dragent.yaml
}

function run_agent_on() {

    file="$1"

    write_agent_config

    cmd="$ROOT/userspace/dragent/dragent -r $file"

    time_cmd "$cmd" "$file"
}

function run_trace() {

    if [ ! -e $TRACEDIR ]; then
	download_trace_files
    fi

    trace_file="$1"

    if [ $trace_file == "all" ]; then
	files=($TRACEDIR/traces-perf/*.scap)
    else
	files=($TRACEDIR/traces-perf/$trace_file.scap)
    fi

    for file in ${files[@]}; do
	if [[ $ROOT == *"falco"* ]]; then
	    run_falco_on "$file"
	elif [[ $ROOT == *"sysdig"* ]]; then
	    run_sysdig_on "$file"
	else
	    run_agent_on "$file"
	fi
    done
}

function start_monitor_cpu_usage() {
    echo "   monitoring cpu usage for sysdig/falco program"

    setsid bash `dirname $0`/cpu_monitor.sh $SUBJ_PID $live_test $VARIANT $RESULTS_FILE $CPU_INTERVAL &
    CPU_PID=$!
    sleep 5
}

function start_subject_prog() {

    # Do a blocking sudo command now just to ensure we have a password
    sudo bash -c ""

    if [[ $ROOT == *"multimatch"* ]]; then
	echo "   starting test_mm..."
	if [ -z $RULES_FILE ]; then
	    RULES_FILE=$SOURCE/../output/rules.yaml
	fi
	sudo FALCO_STATS_EXTRA_variant=$VARIANT FALCO_STATS_EXTRA_benchmark=$live_test $ROOT/test_mm -S $SOURCE/search_order.yaml -s $STATS_FILE -r $RULES_FILE > ./prog-output.txt 2>&1 &
    elif [[ $ROOT == *"falco"* ]]; then
	echo "   starting falco..."
	if [ -z $RULES_FILE ]; then
	    RULES_FILE=$SOURCE/rules/falco_rules.yaml
	fi
	sudo FALCO_STATS_EXTRA_variant=$VARIANT FALCO_STATS_EXTRA_benchmark=$live_test $ROOT/userspace/falco/falco -c $SOURCE/falco.yaml -s $STATS_FILE -r $RULES_FILE --option=stdout_output.enabled=false > ./prog-output.txt -A 2>&1 &
    elif [[ $ROOT == *"sysdig"* ]]; then
	echo "   starting sysdig..."
	sudo $ROOT/userspace/sysdig/sysdig -N -z evt.type=none &
    else
	echo "   starting agent..."
	write_agent_config
	pushd $ROOT/userspace/dragent
	sudo ./dragent > ./prog-output.txt 2>&1 &
	popd
    fi

    SUDO_PID=$!
    sleep 5
    if [[ $ROOT == *"agent"* ]]; then
	# The agent spawns several processes all below a main monitor
	# process. We want the child with the lowest pid.
	MON_PID=`ps -h -o pid --ppid $SUDO_PID`
	SUBJ_PID=`ps -h -o pid --ppid $MON_PID | head -1`
    else
	SUBJ_PID=`ps -h -o pid --ppid $SUDO_PID`
    fi

    if [ -z $SUBJ_PID ]; then
	echo "Could not find pid of subject program--did it start successfully? Not continuing."
	exit 1
    fi
}

function run_htop() {
    screen -S htop-screen -d -m /usr/bin/htop -d2
    sleep 90
    screen -X -S htop-screen quit
}

function run_juttle_examples() {
    pushd $SCRIPTDIR/../../juttle-engine/examples
    docker-compose -f dc-juttle-engine.yml -f aws-cloudwatch/dc-aws-cloudwatch.yml -f elastic-newstracker/dc-elastic.yml -f github-tutorial/dc-elastic.yml -f nginx_logs/dc-nginx-logs.yml -f postgres-diskstats/dc-postgres.yml -f cadvisor-influx/dc-cadvisor-influx.yml up -d
    sleep 120
    docker-compose -f dc-juttle-engine.yml -f aws-cloudwatch/dc-aws-cloudwatch.yml -f elastic-newstracker/dc-elastic.yml -f github-tutorial/dc-elastic.yml -f nginx_logs/dc-nginx-logs.yml -f postgres-diskstats/dc-postgres.yml -f cadvisor-influx/dc-cadvisor-influx.yml stop
    docker-compose -f dc-juttle-engine.yml -f aws-cloudwatch/dc-aws-cloudwatch.yml -f elastic-newstracker/dc-elastic.yml -f github-tutorial/dc-elastic.yml -f nginx_logs/dc-nginx-logs.yml -f postgres-diskstats/dc-postgres.yml -f cadvisor-influx/dc-cadvisor-influx.yml rm -fv
    popd
}

function run_kubernetes_demo() {
    pushd $SCRIPTDIR/../../infrastructure/test-infrastructures/kubernetes-demo
    sudo bash run-local.sh
    sudo bash init.sh
    sleep 600
    docker stop $(docker ps -qa)
    docker rm -fv $(docker ps -qa)
    popd
}

function run_live_test() {

    live_test="$1"

    echo "Running live test $live_test"

    case "$live_test" in
	htop ) CPU_INTERVAL=2;;
	* ) CPU_INTERVAL=10;;
    esac

    start_subject_prog
    start_monitor_cpu_usage

    echo "   starting live program and waiting for it to finish"
    case "$live_test" in
	htop ) run_htop ;;
	juttle-examples ) run_juttle_examples ;;
	kube-demo ) run_kubernetes_demo ;;
	* ) usage; cleanup; exit 1 ;;
    esac

    cleanup

}

function cleanup() {

    if [ -n "$SUBJ_PID" ] ; then
	echo "   stopping falco/sysdig program $SUBJ_PID"
	sudo kill $SUBJ_PID
    fi

    if [ -n "$CPU_PID" ] ; then
	echo "   stopping cpu monitor program $CPU_PID"
	kill -- -$CPU_PID
    fi
}

run_live_tests() {
    test="$1"

    if [ $test == "all" ]; then
	tests="htop juttle-examples kube-demo"
    else
	tests=$test
    fi

    for test in $tests; do
	run_live_test $test
    done
}

function run_phoronix_test() {

    live_test="$1"

    case "$live_test" in
	pts/aio-stress | pts/fs-mark | pts/iozone | pts/network-loopback | pts/nginx | pts/pybench | pts/redis | pts/sqlite | pts/unpack-linux ) CPU_INTERVAL=2;;
	* ) CPU_INTERVAL=10;;
    esac

    echo "Running phoronix test $live_test"

    start_subject_prog
    start_monitor_cpu_usage

    echo "   starting phoronix test and waiting for it to finish"

    TEST_RESULTS_NAME=$VARIANT FORCE_TIMES_TO_RUN=1 phoronix-test-suite default-run $live_test

    cleanup

}

# To install and configure phoronix:
#  (redhat instructions, adapt as necessary for ubuntu or other distros)
#   - install phoronix: yum install phoronix-test-suite.noarch
#   - install dependencies not handled by phoronix: yum install libaio-devel pcre-devel popt-devel glibc-static zlib-devel nc bc
#   - fix trivial bugs in tests:
#      - edit ~/.phoronix-test-suite/installed-tests/pts/network-loopback-1.0.1/network-loopback line "nc -d -l 9999 > /dev/null &" to "nc -d -l 9999 > /dev/null &"
#      - edit ~/.phoronix-test-suite/test-profiles/pts/nginx-1.1.0/test-definition.xml line "<Arguments>-n 500000 -c 100 http://localhost:8088/test.html</Arguments>" to "<Arguments>-n 500000 -c 100 http://127.0.0.1:8088/test.html</Arguments>"
#   - phoronix batch-install <test list below>

function run_phoronix_tests() {

    test="$1"

    if [ $test == "all" ]; then
	tests="pts/aio-stress pts/apache pts/blogbench pts/compilebench pts/dbench pts/fio pts/fs-mark pts/iozone pts/network-loopback pts/nginx pts/pgbench pts/phpbench pts/postmark pts/pybench pts/redis pts/sqlite pts/unpack-linux"
    else
	tests=$test
    fi

    for test in $tests; do
	run_phoronix_test $test
    done
}

run_tests() {

    IFS=':' read -ra PARTS <<< "$TEST"

    case "${PARTS[0]}" in
	trace ) run_trace "${PARTS[1]}" ;;
	live ) run_live_tests "${PARTS[1]}" ;;
	phoronix ) run_phoronix_tests "${PARTS[1]}" ;;
	* ) usage; exit 1 ;;
    esac
}

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "   -h/--help: show this help"
    echo "   -v/--variant: a variant name to attach to this set of test results"
    echo "   -r/--root: root directory containing falco/sysdig binaries (i.e. where you ran 'cmake')"
    echo "   -s/--source: root directory containing falco/sysdig source code"
    echo "   -R/--results: append test results to this file"
    echo "   -S/--stats: append capture statistics to this file (only works for falco/test_mm)"
    echo "   -o/--output: append program output to this file"
    echo "   -U/--rules: path to rules file (only applicable for falco/test_mm)"
    echo "   -t/--test: test to run. Argument has the following format:"
    echo "       trace:<trace>: read the specified trace file."
    echo "            trace:all means run all traces"
    echo "       live:<live test>: run the specified live test."
    echo "            live:all means run all live tests."
    echo "            possible live tests:"
    echo "                live:htop: run htop -d2"
    echo "                live:kube-demo: run kubernetes demo from infrastructure repo"
    echo "                live:juttle-examples: run a juttle demo environment based on docker-compose"
    echo "       phoronix:<test>: run the specified phoronix test."
    echo "            if <test> is not 'all', it is passed directly to the command line of \"phoronix-test-suite run <test>\""
    echo "            if <test> is 'all', a built-in set of phoronix tests will be chosen and run"
    echo "   -T/--tracedir: Look for trace files in this directory. If doesn't exist, will download trace files from s3"
    echo "   -A/--agent-autodrop: When running an agent, whether or not to enable autodrop"
    echo "   -F/--falco-agent: When running an agent, whether or not to enable falco"
}

OPTS=`getopt -o hv:r:s:R:S:o:U:t:T: --long help,variant:,root:,source:,results:,stats:,output:,rules:,test:,tracedir:,agent-autodrop:,falco-agent: -n $0 -- "$@"`

if [ $? != 0 ]; then
    echo "Exiting" >&2
    exit 1
fi

eval set -- "$OPTS"

VARIANT="falco"
ROOT=`dirname $0`/../build
SOURCE=$ROOT
SCRIPTDIR=`dirname $0`
RESULTS_FILE=`dirname $0`/results.json
STATS_FILE=`dirname $0`/capture_stats.json
OUTPUT_FILE=`dirname $0`/program-output.txt
RULES_FILE=
TEST=trace:all
TRACEDIR=/tmp/falco-perf-traces.$USER
CPU_INTERVAL=10
AGENT_AUTODROP=1
FALCO_AGENT=1

while true; do
    case "$1" in
	-h | --help ) usage; exit 1;;
	-v | --variant ) VARIANT="$2"; shift 2;;
	-r | --root ) ROOT="$2"; shift 2;;
	-s | --source ) SOURCE="$2"; shift 2;;
	-R | --results ) RESULTS_FILE="$2"; shift 2;;
	-S | --stats ) STATS_FILE="$2"; shift 2;;
	-o | --output ) OUTPUT_FILE="$2"; shift 2;;
	-U | --rules ) RULES_FILE="$2"; shift 2;;
	-t | --test ) TEST="$2"; shift 2;;
	-T | --tracedir ) TRACEDIR="$2"; shift 2;;
	-A | --agent-autodrop ) AGENT_AUTODROP="$2"; shift 2;;
	-F | --falco-agent ) FALCO_AGENT="$2"; shift 2;;
	* ) break;;
    esac
done

if [ -z $VARIANT ]; then
    echo "A test variant name must be provided. Not continuing."
    exit 1
fi

if [ -z $ROOT ]; then
    echo "A root directory containing a falco/sysdig binary must be provided. Not continuing."
    exit 1
fi

ROOT=`realpath $ROOT`

if [ -z $SOURCE ]; then
    echo "A source directory containing falco/sysdig source code. Not continuing."
    exit 1
fi

SOURCE=`realpath $SOURCE`

if [ -z $RESULTS_FILE ]; then
    echo "An output file for test results must be provided. Not continuing."
    exit 1
fi

if [ -z $STATS_FILE ]; then
    echo "An output file for capture statistics must be provided. Not continuing."
    exit 1
fi

if [ -z $OUTPUT_FILE ]; then
    echo "An file for program output must be provided. Not continuing."
    exit 1
fi

if [ -z $TEST ]; then
    echo "A test must be provided. Not continuing."
    exit 1
fi

run_tests
