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

integration-test:
    for config in integration-tests/sql-queries/cfg/*.json; do \
        name=$(basename "$config" .json); \
        output="test-${name}-$(date +%Y%m%d-%H%M%S).xml"; \
        echo "Running $name -> $output"; \
        (cd integration-tests/sql-queries/verifier && \
        uv run mquire-sql-query-verifier ../cfg/${name}.json "$output"); \
    done

integration-update:
    for config in integration-tests/sql-queries/cfg/*.json; do \
        name=$(basename "$config" .json); \
        output="test-${name}-$(date +%Y%m%d-%H%M%S).xml"; \
        echo "Updating $name -> $output"; \
        (cd integration-tests/sql-queries/verifier && \
        uv run mquire-sql-query-verifier ../cfg/${name}.json "$output" --update); \
    done

format:
    cargo fmt
    cd integration-tests/sql-queries/verifier && uv run ruff format src/

[linux]
package:
    cargo build --release --target x86_64-unknown-linux-musl
    cmake -S package -B package-build -DMQUIRE_REPOSITORY_PATH="$(pwd)"
    cmake --build package-build --target package
