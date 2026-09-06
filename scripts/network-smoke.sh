#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 DISPOSABLE_REFLINK_DIRECTORY" >&2
    exit 2
fi

export MUTUALBACKUP_REFLINK_TEST_ROOT=$1
cargo test -p mutualbackup --test prototype_acceptance -- --ignored --nocapture
