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

unreadable_root=$TEST_ROOT/unreadable-root
mkdir "$unreadable_root"
printf 'must survive\n' >"$unreadable_root/foreign"
chmod 000 "$unreadable_root"
if initialize_namespace "$unreadable_root" >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
    printf 'unreadable nonempty namespace was accepted\n' >&2
    exit 1
fi
chmod 700 "$unreadable_root"
grep -Fq 'cannot enumerate Docker lab root namespace safely' "$TEST_ROOT/stderr"
[[ ! -e $unreadable_root/.mutualbackup-docker-lab-directory-v1 ]]
grep -Fqx 'must survive' "$unreadable_root/foreign"

failed_scan_root=$TEST_ROOT/failed-marker-scan-root
mkdir "$failed_scan_root"
if MUTUALBACKUP_DOCKER_LAB_ROOT=$failed_scan_root bash -c '
    source "$1"
    validate_layout
    find() { return 42; }
    recover_namespace_marker "$LAB_ROOT" root
' bash "$LAB" >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
    printf 'failed namespace marker scan was accepted\n' >&2
    exit 1
fi
grep -Fq 'cannot enumerate Docker lab root namespace safely' "$TEST_ROOT/stderr"
[[ ! -e $failed_scan_root/.mutualbackup-docker-lab-directory-v1 ]]

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

printf '/dev/loop999\nunterminated' >"$leaf_root/loops/node0"
expect_leaf_rejected "$leaf_root" 'loop record has trailing data'
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

node_a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
node_b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
guild=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
fake_cli=$TEST_ROOT/fake-mutualbackup
cat >"$fake_cli" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${1:-} == identity ]] || exit 90
shift
seed=
while (($#)); do
    case $1 in
        --seed-file) seed=$2; shift 2 ;;
        *) exit 91 ;;
    esac
done
case $(<"$seed") in
    node-a) value=$FAKE_NODE_A ;;
    node-b) value=$FAKE_NODE_B ;;
    *) exit 92 ;;
esac
printf 'node id:       %s\nlibp2p peer id: fake\n' "$value"
EOF
chmod +x "$fake_cli"

expect_initial_reinit_identity_rejected() {
    local case_name=$1 seed_value=$2 expected_error=$3
    local root=$TEST_ROOT/reinit-$case_name
    initialize_namespace "$root"
    printf '%s\n' "$seed_value" >"$root/seeds/node0.seed"
    printf 'node id:       %s\nlibp2p peer id: fake\n' "$node_a" \
        >"$root/seeds/node0.identity"
    chmod 600 "$root/seeds/node0.seed" "$root/seeds/node0.identity"
    printf 'original image\n' >"$root/images/node0.btrfs"
    if MUTUALBACKUP_DOCKER_LAB_ROOT=$root MUTUALBACKUP_CLI_BIN=$fake_cli \
        FAKE_NODE_A=$node_a FAKE_NODE_B=$node_b FAKE_GUILD=$guild \
        bash -c '
            source "$1"
            prepare_host() { :; }
            acquire_lock() { :; }
            container_running() { return 0; }
            cli_raw() {
                shift
                case "$*" in
                    status) printf "node id:       %s\nrecovery ready: true\n" "$FAKE_NODE_A" ;;
                    *) return 0 ;;
                esac
            }
            guild_phase() { printf "Active\n"; }
            guild_id() { printf "%s\n" "$FAKE_GUILD"; }
            validate_recovery_survivors() { :; }
            confirm_reinit() { :; }
            resume_recovery_transaction() { printf called >"$LAB_ROOT/resume-called"; }
            command_reinit 0 --yes
        ' bash "$LAB" >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
        printf 'reinit accepted %s retained seed\n' "$case_name" >&2
        exit 1
    fi
    grep -Fq "$expected_error" "$TEST_ROOT/stderr"
    grep -Fqx 'original image' "$root/images/node0.btrfs"
    [[ ! -e $root/seeds/node0.recovery-intent ]]
    [[ ! -e $root/resume-called ]]
}

expect_initial_reinit_identity_rejected wrong-member node-b 'does not match its running identity'
expect_initial_reinit_identity_rejected corrupt corrupt-seed 'retained recovery string for node 0 is invalid'

resumed_root=$TEST_ROOT/reinit-resumed
initialize_namespace "$resumed_root"
printf 'node-b\n' >"$resumed_root/seeds/node0.seed"
printf 'node id:       %s\nlibp2p peer id: fake\n' "$node_a" \
    >"$resumed_root/seeds/node0.identity"
printf 'format=2\nphase=prepared\nbootstrap_node=1\nrestore_name=recovered\nguild_id=%s\nexpected_node_id=%s\n' \
    "$guild" "$node_a" >"$resumed_root/seeds/node0.recovery-intent"
chmod 600 "$resumed_root/seeds/node0.seed" "$resumed_root/seeds/node0.identity" \
    "$resumed_root/seeds/node0.recovery-intent"
printf 'original image\n' >"$resumed_root/images/node0.btrfs"
if MUTUALBACKUP_DOCKER_LAB_ROOT=$resumed_root MUTUALBACKUP_CLI_BIN=$fake_cli \
    FAKE_NODE_A=$node_a FAKE_NODE_B=$node_b \
    bash -c '
        source "$1"
        validate_layout
        validate_recovery_survivors() { :; }
        prepare_recovery_container() {
            printf called >"$LAB_ROOT/prepare-called"
            rm -- "$LAB_ROOT/images/node0.btrfs"
        }
        resume_recovery_transaction 0
    ' bash "$LAB" >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
    printf 'resumed reinit accepted a wrong-member retained seed\n' >&2
    exit 1
fi
grep -Fq 'belongs to another identity' "$TEST_ROOT/stderr"
grep -Fqx 'original image' "$resumed_root/images/node0.btrfs"
[[ ! -e $resumed_root/prepare-called ]]

printf 'Docker lab path safety checks passed\n'
