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


print_usage() {
	echo ""
	echo "Usage:"
	echo "  docker run -i -t --privileged -v /root/.falco:/root/.falco -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro -e 'FALCO_DRIVER_LOADER_OPTIONS=[driver] [options]' falcosecurity/falco:latest"
	echo ""
	echo "Available FALCO_DRIVER_LOADER_OPTIONS drivers:"
	echo "  kmod           kernel module (default)"
	echo "  ebpf           eBPF probe"
	echo ""
	echo "FALCO_DRIVER_LOADER_OPTIONS options:"
	echo "  --help           show this help message"
	echo "  --clean          try to remove an already present driver installation"
	echo "  --compile        try to compile the driver locally (default true)"
	echo "  --download       try to download a prebuilt driver (default true)"
 	echo "  --http-insecure	 enable insecure downloads"
	echo "  --print-env      skip execution and print env variables for other tools to consume"
	echo ""
	echo "Environment variables:"
	echo "  FALCOCTL_DRIVER_REPOS         specify different URL(s) where to look for prebuilt Falco drivers (comma separated)"
	echo "  FALCOCTL_DRIVER_NAME          specify a different name for the driver"
	echo "  FALCOCTL_DRIVER_HTTP_HEADERS  specify comma separated list of http headers for driver download (e.g. 'x-emc-namespace: default,Proxy-Authenticate: Basic')"
	echo ""
}

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

    ENABLE_COMPILE="false"
    ENABLE_DOWNLOAD="false"
    HTTP_INSECURE="false"
    has_driver=
    has_opts=
    for opt in "${falco_driver_loader_option_arr[@]}"
    do
        case "$opt" in
            kmod|ebpf)
                if [ -n "$has_driver" ]; then
                    >&2 echo "Only one driver per invocation"
                    print_usage
                    exit 1
                else
                    /usr/bin/falcoctl driver config --type $opt
                    has_driver="true"
                fi
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;    
            --clean)
                /usr/bin/falcoctl driver cleanup
                exit 0
                ;;
            --compile)
                ENABLE_COMPILE="true"
                has_opts="true"
                ;;
            --download)
                ENABLE_DOWNLOAD="true"
                has_opts="true"
                ;;
	    --http-insecure)
		HTTP_INSECURE="true"
		;;
            --source-only)
                >&2 echo "Support dropped in Falco 0.37.0."
                print_usage
                exit 1
                ;;    
            --print-env)
                /usr/bin/falcoctl driver printenv
                exit 0
                ;;
            --*)
                >&2 echo "Unknown option: $1"
                print_usage
                exit 1
                ;;
            *)
                >&2 echo "Unknown driver: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    if [ -z "$has_opts" ]; then
        ENABLE_COMPILE="true"
        ENABLE_DOWNLOAD="true"
    fi
    /usr/bin/falcoctl driver install --compile=$ENABLE_COMPILE --download=$ENABLE_DOWNLOAD --http-insecure=$HTTP_INSECURE --http-headers="$FALCOCTL_DRIVER_HTTP_HEADERS"

fi

exec "$@"
