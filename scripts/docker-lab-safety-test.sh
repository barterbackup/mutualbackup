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

initialize_namespace() {
    local root=$1
    MUTUALBACKUP_DOCKER_LAB_ROOT=$root bash -c '
        source "$1"
        validate_layout
        ensure_lab_namespace
    ' bash "$LAB"
}

expect_leaf_rejected() {
    local root=$1 expected=$2
    if MUTUALBACKUP_DOCKER_LAB_ROOT=$root "$LAB" path 0 \
        >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
        printf 'unsafe Docker lab leaf was accepted: %s\n' "$root" >&2
        exit 1
    fi
    grep -Fq "$expected" "$TEST_ROOT/stderr"
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

recoverable_root=$TEST_ROOT/recoverable-root
mkdir "$recoverable_root"
recoverable_checksum=$(printf '%s' "$recoverable_root" | cksum | awk '{print $1}')
printf 'mutualbackup-docker-lab-directory-v1\nlab=%s\nrole=root\n' "$recoverable_checksum" \
    >"$recoverable_root/..mutualbackup-docker-lab-directory-v1.tmp.interrupted"
initialize_namespace "$recoverable_root"
[[ -f $recoverable_root/.mutualbackup-docker-lab-directory-v1 ]]
[[ ! -e $recoverable_root/..mutualbackup-docker-lab-directory-v1.tmp.interrupted ]]

partial_root=$TEST_ROOT/partial-marker-root
mkdir "$partial_root"
: >"$partial_root/..mutualbackup-docker-lab-directory-v1.tmp.interrupted"
initialize_namespace "$partial_root"
[[ -f $partial_root/.mutualbackup-docker-lab-directory-v1 ]]
[[ ! -e $partial_root/..mutualbackup-docker-lab-directory-v1.tmp.interrupted ]]

aliased_marker_root=$TEST_ROOT/aliased-marker-root
mkdir "$aliased_marker_root"
printf 'must survive\n' >"$TEST_ROOT/external-marker"
ln "$TEST_ROOT/external-marker" \
    "$aliased_marker_root/..mutualbackup-docker-lab-directory-v1.tmp.interrupted"
if initialize_namespace "$aliased_marker_root" >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
    printf 'hard-linked temporary namespace marker was accepted\n' >&2
    exit 1
fi
grep -Fq 'must have exactly one hard link' "$TEST_ROOT/stderr"
grep -Fqx 'must survive' "$TEST_ROOT/external-marker"

leaf_root=$TEST_ROOT/leaf-root
initialize_namespace "$leaf_root"
printf 'external image bytes\n' >"$TEST_ROOT/external-image"
ln "$TEST_ROOT/external-image" "$leaf_root/images/node0.btrfs"
expect_leaf_rejected "$leaf_root" 'must have exactly one hard link'
rm "$leaf_root/images/node0.btrfs"

ln "$TEST_ROOT/external-image" "$leaf_root/images/node0.btrfs.creating"
expect_leaf_rejected "$leaf_root" 'must have exactly one hard link'
rm "$leaf_root/images/node0.btrfs.creating"

printf '/dev/loop999\n' >"$TEST_ROOT/external-loop-record"
ln "$TEST_ROOT/external-loop-record" "$leaf_root/loops/node0"
expect_leaf_rejected "$leaf_root" 'must have exactly one hard link'
rm "$leaf_root/loops/node0"

ln -s "$TEST_ROOT/external-loop-record" "$leaf_root/loops/node0"
expect_leaf_rejected "$leaf_root" 'must be a regular non-symlink file'
rm "$leaf_root/loops/node0"

printf 'external seed\n' >"$TEST_ROOT/external-seed"
ln "$TEST_ROOT/external-seed" "$leaf_root/seeds/node0.seed"
expect_leaf_rejected "$leaf_root" 'must have exactly one hard link'
rm "$leaf_root/seeds/node0.seed"

truncate -s 1M "$leaf_root/images/node1.btrfs"
fake_losetup=$TEST_ROOT/fake-losetup
cat >"$fake_losetup" <<'EOF'
#!/usr/bin/env bash
if [[ $1 == --associated ]]; then
    printf '/dev/loop777\n'
elif [[ $1 == --detach ]]; then
    printf 'unexpected detach\n' >>"$FAKE_DETACH_LOG"
fi
EOF
chmod +x "$fake_losetup"
if MUTUALBACKUP_DOCKER_LAB_ROOT=$leaf_root FAKE_DETACH_LOG=$TEST_ROOT/detached \
    bash -c '
        source "$1"
        SUDO=()
        LOSETUP=$2
        findmnt() { return 0; }
        detach_image_loops "$LAB_ROOT/images/node1.btrfs"
    ' bash "$LAB" "$fake_losetup" >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
    printf 'teardown detached a loop that was still mounted elsewhere\n' >&2
    exit 1
fi
grep -Fq 'while it is mounted' "$TEST_ROOT/stderr"
[[ ! -e $TEST_ROOT/detached ]]

[[ ! -e $REPO_ROOT/controller.lock ]]
printf 'Docker lab path safety checks passed\n'
