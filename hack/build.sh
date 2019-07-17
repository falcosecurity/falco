#!/usr/bin/env bash

set -xeuo pipefail

SOURCE_DIR=$1
BUILD_DIR=$2
FALCOBUILDER_IMAGE="falcosecurity/falco-builder:chore-travis"
FALCOTESTER_IMAGE="falcosecurity/falco-tester:chore-travis"

docker run --user "$(id -u)":"$(id -g)" -v /etc/passwd:/etc/passwd:ro -e BUILD_TYPE="$BUILD_TYPE" -v "$SOURCE_DIR":/source -v "$BUILD_DIR":/build "$FALCOBUILDER_IMAGE" cmake
docker run --user "$(id -u)":"$(id -g)" -v /etc/passwd:/etc/passwd:ro -e BUILD_TYPE="$BUILD_TYPE" -v "$SOURCE_DIR":/source -v "$BUILD_DIR":/build "$FALCOBUILDER_IMAGE" package
docker run --user "$(id -u)":"$(id -g)" -v /etc/passwd:/etc/passwd:ro -e BUILD_TYPE="$BUILD_TYPE" -v "$SOURCE_DIR":/source -v "$BUILD_DIR":/build "$FALCOBUILDER_IMAGE" tests

# Deduct currently built version
CURRENT_FALCO_VERSION=$(docker run -v "$BUILD_DIR":/build -ti "$FALCOBUILDER_IMAGE" bash -c "./build/$BUILD_TYPE/userspace/falco/falco --version" | cut -d' ' -f3)
# CURRENT_FALCO_VERSION="${CURRENT_FALCO_VERSION#"${CURRENT_FALCO_VERSION%%[![:space:]]*}"}"
# CURRENT_FALCO_VERSION="${CURRENT_FALCO_VERSION%"${CURRENT_FALCO_VERSION##*[![:space:]]}"}"

# Execute regression tests
docker run \
    -v /boot:/boot:ro \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /etc/passwd:/etc/passwd:ro \
    -v "$SOURCE_DIR":/source \
    -v "$BUILD_DIR":/build \
    -e BUILD_TYPE="$BUILD_TYPE" \
    -e FALCO_VERSION="$CURRENT_FALCO_VERSION" \
    "$FALCOTESTER_IMAGE"