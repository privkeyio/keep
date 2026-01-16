# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

set shell := ["bash", "-uc"]

msrv := "1.83"

default:
    @just --list

build:
    cargo build --release

test:
    cargo test

lint:
    cargo fmt -- --check
    cargo clippy -- -D warnings

fmt:
    cargo fmt

doc:
    cargo doc --no-deps --document-private-items

bench:
    cargo bench

fuzz target:
    cargo +nightly fuzz run {{target}}

ci: lint test build

msrv-check:
    cargo +{{msrv}} check --all-targets
