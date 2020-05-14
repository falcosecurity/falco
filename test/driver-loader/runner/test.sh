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
set -euo pipefail

FALCO="falco -M 1"
FALCO_DRIVER_LOADER=falco-driver-loader
DRIVER_NAME=falco
KERNEL_RELEASE=$(uname -r)
KERNEL_VERSION=$(uname -v | sed 's/#\([[:digit:]]\+\).*/\1/')


function get_target_id() {
	if [ -f "${HOST_ROOT}/etc/os-release" ]; then
		# freedesktop.org and systemd
		# shellcheck source=/dev/null
		source "${HOST_ROOT}/etc/os-release"
		OS_ID=$ID
	elif [ -f "${HOST_ROOT}/etc/debian_version" ]; then
		# Older Debian
		# fixme > can this happen on older Ubuntu?
		OS_ID=debian
	elif [ -f "${HOST_ROOT}/etc/centos-release" ]; then
		# Older CentOS
		OS_ID=centos
	else
		>&2 echo "Detected an unsupported target system, please get in touch with the Falco community"
		exit 1
	fi

	case "${OS_ID}" in
	("amzn")
		if [[ $VERSION_ID == "2" ]]; then
			TARGET_ID="amazonlinux2"
		else
			TARGET_ID="amazonlinux"
		fi
		;;
	("ubuntu")
		if [[ $KERNEL_RELEASE == *"aws"* ]]; then
			TARGET_ID="ubuntu-aws"
		else
			TARGET_ID="ubuntu"
		fi
		;;
	(*)
		TARGET_ID=$(echo "${OS_ID}" | tr '[:upper:]' '[:lower:]')
		;;
	esac
}

function cleanup_drivers() {
    echo "CLEANUP: remove drivers, if any"

    # kernel module
    rmmod "$DRIVER_NAME" > /dev/null 2>&1 || true
    dkms uninstall "$DRIVER_NAME/$DRIVER_VERSION" > /dev/null 2>&1 || true
    rm -f "$FALCO_KERNEL_MODULE_PATH"

    # bpf probe
    rm -f "$FALCO_BPF_PROBE_PATH"
    rm -f "$PROBE_INSTALL_PATH"
}

function run_test() {
    echo ""
    echo "TEST: $1"
	cleanup_drivers
	echo ""
    $1
	echo ""
    echo "PASS: $1"
    echo ""
}

function assert_kernel_module() {
	echo "ASSERT: module loaded"
    local KMOD_NAME=$(echo "${DRIVER_NAME}" | tr "-" "_")
    if ! lsmod | grep "${KMOD_NAME}" > /dev/null 2>&1; then
        echo "FAIL: module not loaded"
        exit 1
    fi
	echo "ASSERT: falco works with module"
	if ! $FALCO; then
		echo "FAIL: falco does not work with module"
		exit 1
	fi
}

function assert_bpf_probe() {
	echo "ASSERT: eBPF probe at $PROBE_INSTALL_PATH"
    if ! test -f "$PROBE_INSTALL_PATH"; then 
        echo "FAIL: eBPF probe not found"
        exit 1
    fi
	echo "ASSERT: falco works with bpf"
	if ! FALCO_BPF_PROBE="" $FALCO; then
		echo "FAIL: falco does not work with bpf"
		exit 1
	fi
}

function test_kernel_module() {
    $FALCO_DRIVER_LOADER
	assert_kernel_module
}


function test_bpf_probe() {
    $FALCO_DRIVER_LOADER bpf
	assert_bpf_probe
}

echo "falco-driver-loader tester"
echo ""
echo "Falco version: $FALCO_VERSION"
echo "Driver version: $DRIVER_VERSION"
echo "HOST_ROOT: ${HOST_ROOT}"
echo ""

if [ -n "${HOST_ROOT}" ]; then
	echo "Setting up /usr/src links from host"
	for i in "$HOST_ROOT/usr/src"/*
	do
		base=$(basename "$i")
		ln -s "$i" "/usr/src/$base"
	done
fi

get_target_id
FALCO_KERNEL_MODULE_PATH="${HOME}/.falco/${DRIVER_NAME}_${TARGET_ID}_${KERNEL_RELEASE}_${KERNEL_VERSION}.ko"
FALCO_BPF_PROBE_PATH="${HOME}/.falco/${DRIVER_NAME}_${TARGET_ID}_${KERNEL_RELEASE}_${KERNEL_VERSION}.o"
PROBE_INSTALL_PATH="${HOME}/.falco/${DRIVER_NAME}-bpf.o"

run_test "test_kernel_module"
run_test "test_bpf_probe"

cleanup_drivers