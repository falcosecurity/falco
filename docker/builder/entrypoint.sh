#!/bin/bash

set -euxo pipefail

SOURCE_DIR=/source
BUILD_DIR=/build
TASK=${1:-all}

MANPATH=

. /opt/rh/devtoolset-2/enable

# Download and install cmake if not downloaded
CMAKE_DIR=$BUILD_DIR/cmake
if [ ! -e $CMAKE_DIR ]; then
    cd $BUILD_DIR
    mkdir -p $BUILD_DIR/cmake
    wget -nv https://s3.amazonaws.com/download.draios.com/dependencies/cmake-3.3.2.tar.gz
    tar -C $CMAKE_DIR --strip-components 1 -xzf cmake-3.3.2.tar.gz
    cd $CMAKE_DIR
    ./bootstrap --system-curl
    make -j$MAKE_JOBS
fi

if [ $TASK == "cmake" ]; then
    mkdir -p $BUILD_DIR/$BUILD_TYPE
    cd $BUILD_DIR/$BUILD_TYPE
    $CMAKE_DIR/bin/cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DFALCO_VERSION=$FALCO_VERSION -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_DRIVER=${BUILD_DRIVER} -DBUILD_BPF=${BUILD_BPF} -DBUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS} $SOURCE_DIR/falco
    exit 0
fi

if [ $TASK == "bash" ]; then
    exec /bin/bash
fi

cd $BUILD_DIR/$BUILD_TYPE
make -j$MAKE_JOBS $TASK



