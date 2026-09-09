#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
LAB=$SCRIPT_DIR/docker-lab.sh
TEST_ROOT=$(mktemp -d /tmp/mutualbackup-lab-safety.XXXXXX)

cleanup() {
    if [[ $TEST_ROOT == /tmp/mutualbackup-lab-safety.* && -d $TEST_ROOT ]]; then
        rm -rf -- "$TEST_ROOT"
    fi
}
trap cleanup EXIT

expect_rejected() {
    local root=$1
    if MUTUALBACKUP_DOCKER_LAB_ROOT=$root "$LAB" path 0 \
        >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
        printf 'unsafe lab root was accepted: %s\n' "$root" >&2
        exit 1
    fi
    grep -Fq 'refusing unsafe lab root' "$TEST_ROOT/stderr"
}

mkdir "$TEST_ROOT/safe"
safe_alias=$TEST_ROOT/safe/../lab
expected=$(readlink -m -- "$TEST_ROOT/lab/mounts/node2/exchange")
actual=$(MUTUALBACKUP_DOCKER_LAB_ROOT=$safe_alias "$LAB" path 2)
[[ $actual == "$expected" ]]

expect_rejected "$REPO_ROOT/docs//.."
expect_rejected "$(dirname "$REPO_ROOT")"

ln -s / "$TEST_ROOT/root-alias"
expect_rejected "$TEST_ROOT/root-alias"

ln -s "$REPO_ROOT" "$TEST_ROOT/repository-alias"
expect_rejected "$TEST_ROOT/repository-alias"

[[ ! -e $REPO_ROOT/controller.lock ]]
printf 'Docker lab path safety checks passed\n'
