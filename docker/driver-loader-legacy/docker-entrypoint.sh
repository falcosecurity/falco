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
	echo "  falco-driver-loader-legacy [driver] [options]"
	echo ""
	echo "Available drivers:"
	echo "  kmod           kernel module (default)"
	echo "  ebpf           eBPF probe"
	echo ""
	echo "Options:"
	echo "  --help         show this help message"
	echo "  --clean        try to remove an already present driver installation"
	echo "  --compile      try to compile the driver locally (default true)"
	echo "  --download     try to download a prebuilt driver (default true)"
	echo "  --print-env    skip execution and print env variables for other tools to consume"
	echo ""
	echo "Environment variables:"
	echo "  FALCOCTL_DRIVER_REPOS             specify different URL(s) where to look for prebuilt Falco drivers (comma separated)"
	echo "  FALCOCTL_DRIVER_NAME              specify a different name for the driver"
	echo ""
}

echo "* Setting up /usr/src links from host"

for i in "$HOST_ROOT/usr/src"/*
do
    base=$(basename "$i")
    ln -s "$i" "/usr/src/$base"
done

ENABLE_COMPILE="false"
ENABLE_DOWNLOAD="false"
has_driver=
has_opts=
while test $# -gt 0; do
	case "$1" in
		kmod|ebpf)
			if [ -n "$has_driver" ]; then
				>&2 echo "Only one driver per invocation"
				print_usage
				exit 1
			else
				/usr/bin/falcoctl driver config --type $1
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
    shift
done

if [ -z "$has_opts" ]; then
	ENABLE_COMPILE="true"
	ENABLE_DOWNLOAD="true"
fi

/usr/bin/falcoctl driver install --compile=$ENABLE_COMPILE --download=$ENABLE_DOWNLOAD
