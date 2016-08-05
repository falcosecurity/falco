#!/bin/bash

SUBJ_PID=$1
BENCHMARK=$2
VARIANT=$3
RESULTS_FILE=$4
CPU_INTERVAL=$5

top -d $CPU_INTERVAL -b -p $SUBJ_PID | grep -E '(falco|sysdig|dragent)' --line-buffered | awk -v benchmark=$BENCHMARK -v variant=$VARIANT '{printf("{\"time\": \"%s\", \"sample\": %d, \"benchmark\": \"%s\", \"variant\": \"%s\", \"cpu_usage\": %s},\n", strftime("%Y-%m-%d %H:%M:%S", systime(), 1), NR, benchmark, variant, $9); fflush();}' >> $RESULTS_FILE
