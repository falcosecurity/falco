#!/usr/bin/env sh

set -xeu

: "${BUILD_DIR?"Missing BUILD_DIR environment variable"}"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

apk update
apk add g++ gcc cmake cmake make ncurses-dev git bash perl linux-headers autoconf automake m4 libtool elfutils-dev libelf-static patch binutils

while test $# -gt 0; do
    case "$1" in
        cmake)
            cmake -DUSE_BUNDLED_DEPS=On -DMUSL_OPTIMIZED_BUILD=On -DBUILD_DRIVER=Off /falco
            exit 0
            ;;
        falco)
            make -j4 falco
            exit 0
            ;;
        grpc)
            make -j4 grpc
            exit 0
            ;;
        all)
            make -j4 all
            exit 0
            ;;
        tests)
            make tests
            exit 0
            ;;
        packages)
            make -j4 package
            exit 0
            ;;
    esac
done