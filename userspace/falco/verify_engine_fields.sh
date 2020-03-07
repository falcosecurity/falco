#!/bin/sh

set -euo pipefail

SOURCE_DIR=$1
OPENSSL=$2

if ! command -v "${OPENSSL}" version > /dev/null 2>&1; then
    echo "No openssl command at ${OPENSSL}"
    exit 1
fi

NEW_CHECKSUM=$(./falco --list -N | ${OPENSSL} dgst -sha256 | awk '{print $2}')
CUR_CHECKSUM=$(grep FALCO_FIELDS_CHECKSUM "${SOURCE_DIR}/userspace/engine/falco_engine_version.h" | awk '{print $3}' | sed -e 's/"//g')


if [ "$NEW_CHECKSUM" != "$CUR_CHECKSUM" ]; then
    echo "Set of fields supported has changed (new checksum $NEW_CHECKSUM != old checksum $CUR_CHECKSUM)."
    echo "Update checksum and/or version in falco_engine_version.h."
    exit 1
fi

exit 0
