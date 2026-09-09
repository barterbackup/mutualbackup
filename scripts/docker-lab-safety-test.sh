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

expect_namespace_rejected() {
    local root=$1
    if MUTUALBACKUP_DOCKER_LAB_ROOT=$root "$LAB" path 0 \
        >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
        printf 'substituted lab namespace was accepted: %s\n' "$root" >&2
        exit 1
    fi
    grep -Fq 'must be a non-symlink directory' "$TEST_ROOT/stderr"
}

expect_marker_rejected() {
    local root=$1
    if MUTUALBACKUP_DOCKER_LAB_ROOT=$root "$LAB" path 0 \
        >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
        printf 'unmarked lab namespace was accepted: %s\n' "$root" >&2
        exit 1
    fi
    grep -Fq 'has no owned marker' "$TEST_ROOT/stderr"
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

for role in images mounts loops seeds configs; do
    namespace_root=$TEST_ROOT/substituted-$role
    mkdir "$namespace_root" "$TEST_ROOT/external-$role"
    ln -s "$TEST_ROOT/external-$role" "$namespace_root/$role"
    expect_namespace_rejected "$namespace_root"
done

nested_root=$TEST_ROOT/substituted-node-mount
mkdir -p "$nested_root/mounts" "$TEST_ROOT/external-node-mount"
ln -s "$TEST_ROOT/external-node-mount" "$nested_root/mounts/node0"
expect_namespace_rejected "$nested_root"

marked_root=$TEST_ROOT/marked-root
mkdir "$marked_root" "$marked_root/configs"
marked_checksum=$(printf '%s' "$marked_root" | cksum | awk '{print $1}')
printf 'mutualbackup-docker-lab-directory-v1\nlab=%s\nrole=root\n' "$marked_checksum" \
    >"$marked_root/.mutualbackup-docker-lab-directory-v1"
expect_marker_rejected "$marked_root"

[[ ! -e $REPO_ROOT/controller.lock ]]
printf 'Docker lab path safety checks passed\n'
