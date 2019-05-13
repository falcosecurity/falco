#!/bin/bash

set -xeuo pipefail

export FALCO_VERSION=0.1.$((2700+BUILD_NUMBER))dev

docker pull falcosecurity/falco-tester
docker run -v /boot:/boot:ro -v /var/run/docker.sock:/var/run/docker.sock -v /etc/passwd:/etc/passwd:ro -e FALCO_VERSION=${FALCO_VERSION} -v ${WORKSPACE}:/source -v ${WORKSPACE}/build:/build falcosecurity/falco-tester

exit 0
