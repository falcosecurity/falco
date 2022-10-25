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


echo "* Setting up /usr/src links from host"

for i in "$HOST_ROOT/usr/src"/*
do
    base=$(basename "$i")
    ln -s "$i" "/usr/src/$base"
done

if [ -n "$HOST_ROOT" ] && [ "$HOST_ROOT" != "/" ]; then
    echo "* Setting up /lib/modules links from host"
    ln -s /lib/modules $HOST_ROOT/lib/modules 
    
    # If HOST_ROOT is set, but HOST_ROOT/proc does not exist
    # link real /proc to HOST_ROOT/proc, so that Falco can run gracefully.
    # This is mostly useful when dealing with an hypervisor, like aws Fargate,
    # where the container running Falco does not need to bind-mount the host proc volume,
    # and its /proc already sees all task processes because it shares the same namespace.
    if [ ! -d "$HOST_ROOT/proc" ]; then
        echo "* Setting up /proc links from host"
        ln -s "/proc" "$HOST_ROOT/proc"
    fi
fi

/usr/bin/falco-driver-loader "$@"
