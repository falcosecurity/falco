#!/bin/bash
#
# Copyright (C) 2013-2019 Draios Inc dba Sysdig.
#
# This file is part of sysdig.
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
# Simple script to build the BPF probe. Assumes that all the dependencies
# and requirements are already satisfied (as they are in the accompanying
# docker container)
#

set -exu

echo "* Building probe ${BPF_PROBE_FILENAME}"

# On some distros, the modules dir links into /usr/src, so we need to make sure
# we have that sorted so we can build properly
for i in $(ls /host/usr/src); do
	ln -s /host/usr/src/$i /usr/src/$i
done

# Again, on some distros, we need to populate the /lib/modules directory
# because the kernel header info is split among several subdirs

mkdir -p /lib/modules

for i in $(ls /host/lib/modules); do
	ln -s /host/lib/modules/$i /lib/modules/$i
done

cd /driver/bpf
echo "Building bpf"
KERNELDIR=/kernel make

echo "** Done building probe"
cp probe.o /out/${BPF_PROBE_FILENAME}
