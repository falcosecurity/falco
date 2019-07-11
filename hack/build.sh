#!/usr/bin/env bash

set -xeuo pipefail

SOURCE_DIR=$1
BUILD_DIR=$2
FALCOBUILDER_IMAGE=$3

docker run --user "$(id -u)":"$(id -g)" -v /etc/passwd:/etc/passwd:ro -e BUILD_TYPE="$BUILD_TYPE" -v "$SOURCE_DIR":/source -v "$BUILD_DIR":/build "$FALCOBUILDER_IMAGE" cmake
docker run --user "$(id -u)":"$(id -g)" -v /etc/passwd:/etc/passwd:ro -e BUILD_TYPE="$BUILD_TYPE" -v "$SOURCE_DIR":/source -v "$BUILD_DIR":/build "$FALCOBUILDER_IMAGE" package
docker run --user "$(id -u)":"$(id -g)" -v /etc/passwd:/etc/passwd:ro -e BUILD_TYPE="$BUILD_TYPE" -v "$SOURCE_DIR":/source -v "$BUILD_DIR":/build "$FALCOBUILDER_IMAGE" tests

docker run -v /boot:/boot:ro -v /var/run/docker.sock:/var/run/docker.sock -v /etc/passwd:/etc/passwd:ro -e BUILD_TYPE="$BUILD_TYPE" -v "$SOURCE_DIR":/source -v "$BUILD_DIR":/build falcosecurity/falco-tester
