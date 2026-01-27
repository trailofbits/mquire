#
# Copyright (c) 2025-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

default:
    @just --list

check:
    cargo check --all-targets --all-features --examples --tests --workspace
    cargo clippy --all-targets --all-features --examples -- -D warnings
    cargo fmt --check

    cd integration-tests/sql-queries/verifier && uv run ruff check src/
    cd integration-tests/sql-queries/verifier && uv run ruff format --check src/
    cd integration-tests/sql-queries/verifier && uv run mypy src/

test:
    cargo test

integration-test config="linux_simple":
    cd integration-tests/sql-queries/verifier && \
        uv run mquire-sql-query-verifier --skip-download ../cfg/{{config}}.json test.xml

integration-update config="linux_simple":
    cd integration-tests/sql-queries/verifier && \
        uv run mquire-sql-query-verifier --skip-download ../cfg/{{config}}.json test.xml --update

fmt:
    cargo fmt
    cd integration-tests/sql-queries/verifier && uv run ruff format src/

[linux]
package:
    cargo build --release --target x86_64-unknown-linux-musl
    cmake -S package -B package-build -DMQUIRE_REPOSITORY_PATH="$(pwd)"
    cmake --build package-build --target package
