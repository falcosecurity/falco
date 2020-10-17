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

BUILD_DIR=$1

SCRIPT=$(readlink -f $0)
SCRIPTDIR=$(dirname "$SCRIPT")
RUNNERDIR="${SCRIPTDIR}/runner"
FALCO_VERSION=$(cat ${BUILD_DIR}/userspace/falco/config_falco.h | grep 'FALCO_VERSION ' | cut -d' ' -f3 | sed -e 's/^"//' -e 's/"$//')
DRIVER_VERSION=$(cat ${BUILD_DIR}/userspace/falco/config_falco.h | grep 'DRIVER_VERSION ' | cut -d' ' -f3 | sed -e 's/^"//' -e 's/"$//')
FALCO_PACKAGE="falco-${FALCO_VERSION}-x86_64.tar.gz"

cp "${BUILD_DIR}/${FALCO_PACKAGE}" "${RUNNERDIR}"
pushd "${RUNNERDIR}"
docker build --build-arg FALCO_VERSION="$FALCO_VERSION" \
    -t falcosecurity/falco:test-driver-loader \
    -f "${RUNNERDIR}/Dockerfile" "${RUNNERDIR}"
popd
rm -f "${RUNNERDIR}/${FALCO_PACKAGE}"

docker run --rm --privileged \
    -e FALCO_VERSION="$FALCO_VERSION" \
    -e DRIVER_VERSION="$DRIVER_VERSION" \
    -v /dev:/host/dev \
    -v /proc:/host/proc:ro \
    -v /boot:/host/boot:ro \
    -v /lib/modules:/host/lib/modules:ro \
    -v /usr:/host/usr:ro \
    -v /etc:/host/etc:ro \
    falcosecurity/falco:test-driver-loader

docker rmi -f falcosecurity/falco:test-driver-loader