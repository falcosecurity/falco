#!/bin/bash

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

    cmd="$ROOT/userspace/falco/falco -c $ROOT/../falco.yaml -r $ROOT/../rules/falco_rules.yaml --option=stdout_output.enabled=false -e $file"

    time_cmd "$cmd" "$file"
}

function run_sysdig_on() {
    file="$1"

    cmd="$ROOT/userspace/sysdig/sysdig -N -z -r $file evt.type=none"

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
	else
	    run_sysdig_on "$file"
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

    echo "   starting falco/sysdig program"
    # Do a blocking sudo command now just to ensure we have a password
    sudo bash -c ""

    if [[ $ROOT == *"falco"* ]]; then
	sudo $ROOT/userspace/falco/falco -c $ROOT/../falco.yaml -r $ROOT/../rules/falco_rules.yaml --option=stdout_output.enabled=false > ./prog-output.txt 2>&1 &
    else
	sudo $ROOT/userspace/sysdig/sysdig -N -z evt.type=none &
    fi

    SUDO_PID=$!
    sleep 5
    SUBJ_PID=`ps -h -o pid --ppid $SUDO_PID`

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
    bash run-local.sh
    bash init.sh
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
    echo "   -R/--results: append test results to this file"
    echo "   -o/--output: append program output to this file"
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
}

OPTS=`getopt -o hv:r:R:o:t:T: --long help,variant:,root:,results:,output:,test:,tracedir: -n $0 -- "$@"`

if [ $? != 0 ]; then
    echo "Exiting" >&2
    exit 1
fi

eval set -- "$OPTS"

VARIANT="falco"
ROOT=`dirname $0`/../build
SCRIPTDIR=`dirname $0`
RESULTS_FILE=`dirname $0`/results.json
OUTPUT_FILE=`dirname $0`/program-output.txt
TEST=trace:all
TRACEDIR=/tmp/falco-perf-traces.$USER
CPU_INTERVAL=10

while true; do
    case "$1" in
	-h | --help ) usage; exit 1;;
	-v | --variant ) VARIANT="$2"; shift 2;;
	-r | --root ) ROOT="$2"; shift 2;;
	-R | --results ) RESULTS_FILE="$2"; shift 2;;
	-o | --output ) OUTPUT_FILE="$2"; shift 2;;
	-t | --test ) TEST="$2"; shift 2;;
	-T | --tracedir ) TRACEDIR="$2"; shift 2;;
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


if [ -z $RESULTS_FILE ]; then
    echo "An output file for test results must be provided. Not continuing."
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
