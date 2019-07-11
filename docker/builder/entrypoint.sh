#!/usr/bin/env bash

set -euxo pipefail

SOURCE_DIR=/source
BUILD_DIR=/build
TASK=${1:-all}

MANPATH=
. /opt/rh/devtoolset-2/enable

if [ "$TASK" == "cmake" ]; then
    mkdir -p "$BUILD_DIR/$BUILD_TYPE"
    cd "$BUILD_DIR/$BUILD_TYPE"
    cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DFALCO_VERSION="$FALCO_VERSION" -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_DRIVER="$BUILD_DRIVER" -DBUILD_BPF="$BUILD_BPF" -DBUILD_WARNINGS_AS_ERRORS="$BUILD_WARNINGS_AS_ERRORS" $SOURCE_DIR/falco
    exit 0
fi

if [ "$TASK" == "bash" ]; then
    exec /bin/bash
fi

cd "$BUILD_DIR/$BUILD_TYPE"
make -j"$MAKE_JOBS" "$TASK"