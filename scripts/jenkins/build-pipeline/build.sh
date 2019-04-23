#!/bin/bash

set -xeuo pipefail

export FALCO_VERSION=0.1.$((2700+BUILD_NUMBER))dev

rm -rf ${WORKSPACE}/build
mkdir ${WORKSPACE}/build

docker run --user $(id -u):$(id -g) -v /etc/passwd:/etc/passwd:ro -e FALCO_VERSION=${FALCO_VERSION} -e MAKE_JOBS=4 -v ${WORKSPACE}:/source -v ${WORKSPACE}/build:/build falcosecurity/falco-builder cmake
docker run --user $(id -u):$(id -g) -v /etc/passwd:/etc/passwd:ro -e FALCO_VERSION=${FALCO_VERSION} -e MAKE_JOBS=4 -v ${WORKSPACE}:/source -v ${WORKSPACE}/build:/build falcosecurity/falco-builder package
