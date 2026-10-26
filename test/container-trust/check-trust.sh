#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 The Falco Authors.
# Offline regression test for the eMudhra CA distrust, using the image's OpenSSL.
set -eu
export LC_ALL=C

if [ "$#" -gt 2 ]; then
    echo "Usage: $0 [CA_BUNDLE [CA_PATH]]" >&2
    exit 2
fi

bundle=${1:-/etc/ssl/certs/ca-certificates.crt}
capath=${2:-/etc/ssl/certs}
openssl=${OPENSSL:-openssl}
fixtures=$(CDPATH= cd "$(dirname "$0")/fixtures" && pwd)
# The advisory leaves are deliberately short-lived. Never use the current time.
verify_time=1792756800 # 2026-10-23T12:00:00Z

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

command -v "$openssl" >/dev/null 2>&1 || fail "openssl is required"
[ -s "$bundle" ] || fail "missing or empty CA bundle: $bundle"
[ -d "$capath" ] || fail "missing CA directory: $capath"
set -- "$fixtures"/rejected/*.pem
[ "$#" -eq 14 ] || fail "expected exactly 14 advisory chain fixtures"

# OpenSSL 1.1.1 has no CAstore option; OpenSSL 3 adds another default store.
# Disable every implicit source, even when an explicit CAfile/CApath is supplied.
verify_help=$("$openssl" verify -help 2>&1 || true)
has_castore=false
case "$verify_help" in *-no-CAstore*) has_castore=true ;; esac

verify() {
    store_mode=$1
    store=$2
    certificate=$3
    hostname=$4
    set -- -no-CAfile -no-CApath -attime "$verify_time"
    if [ "$has_castore" = true ]; then
        set -- "$@" -no-CAstore
    fi
    case "$store_mode" in
        bundle) set -- "$@" -CAfile "$store" ;;
        capath) set -- "$@" -CApath "$store" ;;
        *) fail "unknown trust-store mode: $store_mode" ;;
    esac
    if [ -n "$hostname" ]; then
        set -- "$@" -purpose sslserver -verify_hostname "$hostname"
    else
        # A root CA is not itself a server leaf (its key usage may only allow
        # signing certificates). Check its presence in the store without asking
        # it to authenticate as a TLS server.
        set -- "$@" -purpose any
    fi
    "$openssl" verify "$@" -untrusted "$certificate" "$certificate"
}

expect() {
    expected=$1
    label=$2
    shift 2
    status=0
    result=$(verify "$@" 2>&1) || status=$?
    case "$expected" in
        accept)
            if [ "$status" -ne 0 ]; then
                printf '%s\n' "$result" >&2
                fail "$label must verify"
            fi
            ;;
        reject)
            [ "$status" -ne 0 ] || fail "$label is unexpectedly trusted"
            # Require missing trust, not expiry, hostname mismatch, parse errors,
            # an unsupported option, or a failed executable. Fixture controls
            # below independently prove each chain is valid at the fixed time.
            if ! printf '%s\n' "$result" | grep -Eq 'error 20 at [0-9]+ depth lookup'; then
                printf '%s\n' "$result" >&2
                fail "$label failed for a reason other than missing trust"
            fi
            if printf '%s\n' "$result" | grep -E 'error [0-9]+ at' | grep -Evq 'error 20 at'; then
                printf '%s\n' "$result" >&2
                fail "$label also reported a non-trust verification error"
            fi
            ;;
        *) fail "unknown expected result: $expected" ;;
    esac
    printf 'PASS: %s (%s)\n' "$label" "$expected"
}

printf 'Checking trust at 2026-10-23T12:00:00Z with %s\n' "$("$openssl" version)"

# Explicit legacy trust proves that all 14 fixtures would expose the regression.
# These roots are test inputs only; they must never be installed in the image.
legacy_roots=$fixtures/controls/legacy-roots.pem
for chain in "$fixtures"/rejected/*.pem; do
    host=${chain##*/}
    host=${host%.pem}
    expect accept "legacy control: $host" bundle "$legacy_roots" "$chain" "$host"
done

positive=$fixtures/controls/download.falco.org.pem
# An unrelated explicit store must not silently fall back to system trust.
expect reject 'isolated-store control: download.falco.org' bundle "$legacy_roots" "$positive" download.falco.org

for mode in bundle capath; do
    case "$mode" in bundle) store=$bundle ;; capath) store=$capath ;; esac
    expect accept "$mode: download.falco.org" "$mode" "$store" "$positive" download.falco.org
    for root in isrg-root-x1 digicert-global-root-g2; do
        expect accept "$mode: unaffected $root" "$mode" "$store" "$fixtures/controls/$root.pem" ''
    done
    for chain in "$fixtures"/rejected/*.pem; do
        host=${chain##*/}
        host=${host%.pem}
        expect reject "$mode: $host" "$mode" "$store" "$chain" "$host"
    done
done

echo 'PASS: both trust stores reject all 14 compromised chains and preserve the positive controls'
