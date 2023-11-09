#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

# Set the SKIP_DRIVER_LOADER variable to skip loading the driver

if [[ -z "${SKIP_DRIVER_LOADER}" ]]; then
    echo "* Setting up /usr/src links from host"

    for i in "$HOST_ROOT/usr/src"/*
    do
        base=$(basename "$i")
        ln -s "$i" "/usr/src/$base"
    done

    # convert the optional space-separated env variable FALCO_DRIVER_LOADER_OPTIONS to array, prevent 
    # shell expansion and use it as argument list for falcoctl
    read -a falco_driver_loader_option_arr <<< $FALCO_DRIVER_LOADER_OPTIONS
    /usr/bin/falcoctl driver config "${falco_driver_loader_option_arr[@]}"
    /usr/bin/falcoctl driver install
fi

exec "$@"
