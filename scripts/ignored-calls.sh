#!/bin/bash

cat ../sysdig/userspace/libscap/syscall_info_table.c | grep EF_DROP_FALCO | sed -e 's/.*\"\(.*\)\".*/\1/'  | sort > ignored_syscall_info_table.txt
cat ../sysdig/driver/event_table.c | grep EF_DROP_FALCO | sed -e 's/[^\"]*\"\([^\"]*\)\".*/\1/' | sort | uniq > ignored_driver_event_table.txt
cat ../sysdig/userspace/libscap/event_table.c | grep EF_DROP_FALCO | sed -e 's/[^\"]*\"\([^\"]*\)\".*/\1/' | sort | uniq > ignored_userspace_event_table.txt


diff -up ignored_driver_event_table.txt ignored_userspace_event_table.txt

if [ $? -ne 0 ]; then
    echo "Expected ignored_driver_event_table.txt and ignored_userspace_event_table.txt to have same calls"
fi


cat ignored_userspace_event_table.txt ignored_syscall_info_table.txt | sort | uniq | tr '\n' ', '

