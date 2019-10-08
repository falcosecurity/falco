#!/usr/bin/env bash
#
# Copyright (C) 2019 The Falco Authors.
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

cat ../sysdig/userspace/libscap/syscall_info_table.c | grep EF_DROP_FALCO | sed -e 's/.*\"\(.*\)\".*/\1/'  | sort > ignored_syscall_info_table.txt
cat ../sysdig/driver/event_table.c | grep EF_DROP_FALCO | sed -e 's/[^\"]*\"\([^\"]*\)\".*/\1/' | sort | uniq > ignored_driver_event_table.txt
cat ../sysdig/userspace/libscap/event_table.c | grep EF_DROP_FALCO | sed -e 's/[^\"]*\"\([^\"]*\)\".*/\1/' | sort | uniq > ignored_userspace_event_table.txt


diff -up ignored_driver_event_table.txt ignored_userspace_event_table.txt

if [ $? -ne 0 ]; then
    echo "Expected ignored_driver_event_table.txt and ignored_userspace_event_table.txt to have same calls"
fi


cat ignored_userspace_event_table.txt ignored_syscall_info_table.txt | sort | uniq | tr '\n' ', '

