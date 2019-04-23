#!/bin/bash

set -euxo pipefail

SOURCE_DIR=/source
BUILD_DIR=/build
TASK=${1:-test}

if [ $TASK == "test" ]; then
    echo "Building local docker image falcosecurity/falco:test from latest debian package..."
    cp $BUILD_DIR/$BUILD_TYPE/falco*.deb $BUILD_DIR/$BUILD_TYPE/docker/local
    cd $BUILD_DIR/$BUILD_TYPE/docker/local && docker build --build-arg FALCO_VERSION=${FALCO_VERSION} -t falcosecurity/falco:test .

    echo "Running regression tests"
    cd $SOURCE_DIR/falco/test
    bash run_regression_tests.sh $BUILD_DIR/$BUILD_TYPE

    docker rmi falcosecurity/falco:test || true
    exit 0
fi

if [ $TASK == "bash" ]; then
    exec /bin/bash
fi
