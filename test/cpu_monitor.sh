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

SUBJ_PID=$1
BENCHMARK=$2
VARIANT=$3
RESULTS_FILE=$4
CPU_INTERVAL=$5

top -d $CPU_INTERVAL -b -p $SUBJ_PID | grep -E '(falco|sysdig|dragent|test_mm)' --line-buffered | awk -v benchmark=$BENCHMARK -v variant=$VARIANT '{printf("{\"time\": \"%s\", \"sample\": %d, \"benchmark\": \"%s\", \"variant\": \"%s\", \"cpu_usage\": %s},\n", strftime("%Y-%m-%d %H:%M:%S", systime(), 1), NR, benchmark, variant, $9); fflush();}' >> $RESULTS_FILE
