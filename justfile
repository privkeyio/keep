# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

set dotenv-load := false

default:
    @just --list

build:
    cargo build --release

build-reproducible:
    docker build -f Dockerfile.reproducible -o type=local,dest=./dist .

build-reproducible-hash:
    #!/usr/bin/env bash
    set -euo pipefail
    just build-reproducible
    sha256sum dist/keep | tee dist/keep.sha256

verify-reproducible:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf dist dist-verify
    just build-reproducible
    mv dist dist-verify
    just build-reproducible
    HASH1=$(sha256sum dist-verify/keep | cut -d' ' -f1)
    HASH2=$(sha256sum dist/keep | cut -d' ' -f1)
    echo "Build 1: $HASH1"
    echo "Build 2: $HASH2"
    if [ "$HASH1" != "$HASH2" ]; then
        echo "Build mismatch"
        exit 1
    fi
    echo "Reproducible build verified"

verify-sha expected_hash:
    #!/usr/bin/env bash
    set -euo pipefail
    just build-reproducible
    ACTUAL=$(sha256sum dist/keep | cut -d' ' -f1)
    if [ "$ACTUAL" != "{{expected_hash}}" ]; then
        echo "Expected: {{expected_hash}}"
        echo "Actual:   $ACTUAL"
        exit 1
    fi
    echo "Hash verified: $ACTUAL"

clean:
    rm -rf dist dist-verify target

test:
    cargo test --workspace --lib --bins
    cargo test -p keep-core --test integration_tests
    cargo test -p keep-frost-net --test multinode_test
    cargo test -p keep-enclave-host --test integration_tests

test-property:
    cargo test -p keep-core --test property_tests
    cargo test -p keep-frost-net --test property_tests

fmt:
    cargo fmt

clippy:
    cargo clippy -- -D warnings
