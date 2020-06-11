#!/bin/bash
#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
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
#
# This script runs sysdig on all the trace files (i.e. all the files with scap 
# extension) in the current directory, and compares the result with the one of 
# a previous run.
#
# Arguments:
#  - sysdig path
#  - sysdig chisels directory
#  - sysdig command line
#  - traces directory
#  - prefix of the result directory (it will be completed with the current 
#    date/time)
#  - directory to use as a reference
#
# Examples:
#  ./sysdig_batch_parser.sh "-p%thread.exectime" exetime exetime_2014-04-28_10-18-30
#  ./sysdig_batch_parser.sh "-ctopconns" topconns topconns_2014-04-28_02-51-34 
#
# Note: 
#  if the comparison succeeds, the result directory is deleted. Otherwise, it's 
#  kept there for reference/analysis.
#
set -eu

SYSDIG=$1
SYSDIG_CHISEL_DIR=$2
ARGS=$3
TRACESDIR=$4
DIRNAME=$5
REFERENCEDIR=$6

export SYSDIG_CHISEL_DIR

unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
	TIMEOUT_BIN="timeout"
elif [[ "$unamestr" == 'Darwin' ]]; then
	TIMEOUT_BIN="gtimeout"
fi

rm -rf $DIRNAME || true
mkdir -p $DIRNAME

if [ ! -e $REFERENCEDIR ]; then
    echo "Reference directory $REFERENCEDIR does not exist--skipping directory entirely"
    exit 0
fi

for f in $TRACESDIR/*
do
    ref=$REFERENCEDIR/$(basename $f).output;
    if [ ! -e $ref ]; then
	echo "Corresponding reference file $ref does not exist--skipping"
    else
	echo "Processing $f"
	TZ=UTC eval ${TIMEOUT_BIN} 60 $SYSDIG -r $f $ARGS > $DIRNAME/$(basename $f).output
    fi
done

echo Data saved in $DIRNAME

diff -r $DIRNAME $REFERENCEDIR
rm -rf $DIRNAME
