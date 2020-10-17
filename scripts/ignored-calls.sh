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
scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
parentdir="$(dirname "$scriptdir")"
sysdigdir="${parentdir}/build/sysdig-repo/sysdig-prefix/src/sysdig"
cat "${sysdigdir}/userspace/libscap/syscall_info_table.c" | grep EF_DROP_SIMPLE_CONS | sed -e 's/.*\"\(.*\)\".*/\1/'  | sort > /tmp/ignored_syscall_info_table.txt
cat "${sysdigdir}/driver/event_table.c" | grep EF_DROP_SIMPLE_CONS | sed -e 's/[^\"]*\"\([^\"]*\)\".*/\1/' | sort | uniq > /tmp/ignored_driver_event_table.txt

cat /tmp/ignored_driver_event_table.txt /tmp/ignored_syscall_info_table.txt | sort | uniq | tr '\n' ', '

