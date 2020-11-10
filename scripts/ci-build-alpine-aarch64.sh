#!/usr/bin/env sh

set -xeu

apk update -y
apk add -y g++ gcc cmake cmake make ncurses-dev git bash perl linux-headers autoconf automake m4 libtool elfutils-dev libelf-static patch binutils

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake -DUSE_BUNDLED_DEPS=On -DMUSL_OPTIMIZED_BUILD=On ..
make -j4 all
make tests
make -j4 package

