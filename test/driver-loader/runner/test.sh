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


function init() {

	# We need this here since is not part of the falco-driver-loader script
	#
	# todo(leogr): maybe this can be moved into falco-driver-loader directly
	# since it depends on HOST_ROOT
	if [ -n "${HOST_ROOT}" ]; then
		echo "INIT: Setting up /usr/src links from host"
		for i in "$HOST_ROOT/usr/src"/*
		do
			base=$(basename "$i")
			ln -s "$i" "/usr/src/$base"
		done
	fi

	local EXPECTED_DRIVER_VERSION=${DRIVER_VERSION}

	# We need some env vars to be populated
	# Just source falco-driver-loader, and call get_target_id
	# Loaded driver will be cleaned up later, if any.
	echo "INIT: Sourcing ${FALCO_DRIVER_LOADER} to get env vars populated"
	set +eu
	source $FALCO_DRIVER_LOADER --source-only
	get_target_id
	set -eu

	if [ ! "${EXPECTED_DRIVER_VERSION}" = "${DRIVER_VERSION}" ]; then
		echo "INIT: Unexpected DRIVER_VERSION in falco-driver-loader"
		echo "Expected: ${EXPECTED_DRIVER_VERSION}"
		echo "Found: ${DRIVER_VERSION}"
		exit 1
	fi

	FALCO_KERNEL_MODULE_PATH="${HOME}/.falco/${DRIVER_NAME}_${TARGET_ID}_${KERNEL_RELEASE}_${KERNEL_VERSION}.ko"
	FALCO_BPF_PROBE_PATH="${HOME}/.falco/${DRIVER_NAME}_${TARGET_ID}_${KERNEL_RELEASE}_${KERNEL_VERSION}.o"
	cleanup_drivers
}

function cleanup_drivers() {
    echo "CLEANUP: remove drivers, if any"

    # kernel module
    rmmod "$DRIVER_NAME" > /dev/null 2>&1 || true
    dkms uninstall "$DRIVER_NAME/$DRIVER_VERSION" > /dev/null 2>&1 || true
    rm -f "$FALCO_KERNEL_MODULE_PATH"

    # bpf probe
	local PROBE_INSTALL_PATH="${HOME}/.falco/${DRIVER_NAME}-bpf.o"
    rm -f "$FALCO_BPF_PROBE_PATH"
    rm -f "$PROBE_INSTALL_PATH"
}

function run_test() {
    echo ""
    echo "TEST: $1"
	echo ""
    $1
	echo ""
    echo "PASS: $1"
    echo ""
	cleanup_drivers
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
	local PROBE_INSTALL_PATH="${HOME}/.falco/${DRIVER_NAME}-bpf.o"
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

init

run_test "test_kernel_module"
run_test "test_bpf_probe"