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
	echo "  docker run -i -t --privileged -v /root/.falco:/root/.falco -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro falcosecurity/falco-driver-loader:latest [driver] [options]"
	echo ""
	echo "Available drivers:"
	echo "  auto	       leverage automatic driver selection logic (default)"
	echo "	modern_ebpf    modern eBPF CORE probe"
	echo "  kmod           kernel module"
	echo "  ebpf           eBPF probe"
	echo ""
	echo "Options:"
	echo "  --help                   show this help message"
	echo "  --clean                  try to remove an already present driver installation"
	echo "  --compile                try to compile the driver locally (default true)"
	echo "  --download               try to download a prebuilt driver (default true)"
	echo "  --kernel-release <value> set the kernel release"
	echo "  --kernel-version <value> set the kernel version"
 	echo "  --http-insecure	         enable insecure downloads"
	echo "  --print-env              skip execution and print env variables for other tools to consume"
	echo ""
	echo "Environment variables:"
	echo "  FALCOCTL_DRIVER_REPOS         specify different URL(s) where to look for prebuilt Falco drivers (comma separated)"
	echo "  FALCOCTL_DRIVER_NAME          specify a different name for the driver"
	echo "  FALCOCTL_DRIVER_HTTP_HEADERS  specify comma separated list of http headers for driver download (e.g. 'x-emc-namespace: default,Proxy-Authenticate: Basic')"
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
HTTP_INSECURE="false"
driver=
has_opts=
extra_args=

while test $# -gt 0; do
	case "$1" in
		auto|kmod|ebpf|modern_ebpf)
			if [ -n "$driver" ]; then
				>&2 echo "Only one driver per invocation"
				print_usage
				exit 1
			else
				driver=$1
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
		--kernel-release)
			extra_args+="--kernelrelease=$2 "
			shift
			;;
		--kernel-version)
			extra_args+="--kernelversion=$2 "
			shift
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

# No opts passed, enable both compile and download
if [ -z "$has_opts" ]; then
    ENABLE_COMPILE="true"
    ENABLE_DOWNLOAD="true"
fi

# Default value: auto
if [ -z "$driver" ]; then
  driver="auto"
fi

if [ "$driver" != "auto" ]; then
  /usr/bin/falcoctl driver config --type $driver
else
  # Needed because we need to configure Falco to start with correct driver
  /usr/bin/falcoctl driver config --type modern_ebpf --type kmod --type ebpf
fi

/usr/bin/falcoctl driver install --compile=$ENABLE_COMPILE --download=$ENABLE_DOWNLOAD --http-insecure=$HTTP_INSECURE --http-headers="$FALCOCTL_DRIVER_HTTP_HEADERS" $extra_args

exec "$@"
