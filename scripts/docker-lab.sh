#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

LAB_ROOT=${MUTUALBACKUP_DOCKER_LAB_ROOT:-"$REPO_ROOT/.docker-lab"}
if [[ $LAB_ROOT != /* ]]; then
    LAB_ROOT=$PWD/$LAB_ROOT
fi

CLI_BIN=${MUTUALBACKUP_CLI_BIN:-"$REPO_ROOT/dist/mutualbackup-x86_64-linux"}
DAEMON_BIN=${MUTUALBACKUP_DAEMON_BIN:-"$REPO_ROOT/dist/mutualbackupd-x86_64-linux"}
if [[ $CLI_BIN != /* ]]; then
    CLI_BIN=$PWD/$CLI_BIN
fi
if [[ $DAEMON_BIN != /* ]]; then
    DAEMON_BIN=$PWD/$DAEMON_BIN
fi
CONTAINER_IMAGE=${MUTUALBACKUP_LAB_IMAGE:-debian:bookworm-slim}
DISK_SIZE=${MUTUALBACKUP_LAB_DISK_SIZE:-1G}
PARITY_BUDGET_BYTES=${MUTUALBACKUP_LAB_PARITY_BUDGET_BYTES:-536870912}
IP_PREFIX=${MUTUALBACKUP_LAB_IP_PREFIX:-172.30.77}
P2P_BASE_PORT=${MUTUALBACKUP_LAB_P2P_BASE_PORT:-44000}
NODE_COUNT=5
NAMESPACE_MARKER=.mutualbackup-docker-lab-directory-v1
NAMESPACE_ROLES=(images mounts loops seeds configs)

LAB_CHECKSUM=
NAME_PREFIX=
NETWORK_NAME=
LAB_LABEL=

DOCKER=()
SUDO=()
LOSETUP=
MKFS_BTRFS=
MOUNT=
UMOUNT=
BLKID=

say() {
    printf '%s\n' "$*"
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: scripts/docker-lab.sh COMMAND [ARGUMENTS]

Environment lifecycle:
  up                         Create/mount/start the five-node lab and form its guild
  down                       Remove containers/network, unmount Btrfs, detach loops

Node lifecycle:
  stop NODE                  Stop one daemon container
  start NODE                 Start one stopped daemon container
  restart NODE               Restart one daemon container
  reinit NODE [NAME] [--yes] Wipe one node, recreate it from its recovery string, restore to NAME

Interaction and inspection:
  cli NODE [ARGS...]         Run mutualbackup against NODE's private control socket
  shell NODE                 Open a shell in a running node container
  logs NODE [ARGS...]        Run docker logs for a node
  status [NODE]              Show MutualBackup status for one node or all nodes
  info                       Show containers, IPs, loops, mounts, and host exchange dirs
  mounts                     Print the five host-visible exchange directory paths
  path NODE                  Print only NODE's host-visible exchange directory
  help                       Show this help

NODE is 0, 1, 2, 3, or 4. NAME defaults to recovered after reinit.

This script never builds MutualBackup or a Docker image. It requires the two
prebuilt static binaries in dist/ (or paths supplied with MUTUALBACKUP_CLI_BIN
and MUTUALBACKUP_DAEMON_BIN) and injects them into a pulled base container.
EOF
}

validate_layout() {
    command -v readlink >/dev/null || die "readlink is required"
    [[ $LAB_ROOT != *,* && $CLI_BIN != *,* && $DAEMON_BIN != *,* ]] ||
        die "Docker lab and binary paths must not contain commas"
    LAB_ROOT=$(readlink -m -- "$LAB_ROOT") || die "cannot resolve Docker lab root: $LAB_ROOT"
    [[ $LAB_ROOT == /* ]] || die "resolved Docker lab root is not absolute: $LAB_ROOT"
    if [[ $LAB_ROOT == / || $REPO_ROOT == "$LAB_ROOT" || $REPO_ROOT == "$LAB_ROOT"/* ]]; then
        die "refusing unsafe lab root: $LAB_ROOT"
    fi
    LAB_CHECKSUM=$(printf '%s' "$LAB_ROOT" | cksum | awk '{print $1}')
    NAME_PREFIX=mutualbackup-lab-$LAB_CHECKSUM
    NETWORK_NAME=$NAME_PREFIX
    LAB_LABEL=io.mutualbackup.lab=$LAB_CHECKSUM
    validate_existing_namespace_shape

    [[ $IP_PREFIX =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] ||
        die "MUTUALBACKUP_LAB_IP_PREFIX must contain three IPv4 octets"
    local octet
    IFS=. read -r -a octets <<<"$IP_PREFIX"
    for octet in "${octets[@]}"; do
        ((10#$octet >= 0 && 10#$octet <= 255)) || die "invalid IPv4 prefix: $IP_PREFIX"
    done
    [[ $P2P_BASE_PORT =~ ^[0-9]+$ ]] || die "P2P base port must be numeric"
    P2P_BASE_PORT=$((10#$P2P_BASE_PORT))
    ((P2P_BASE_PORT >= 1024 && P2P_BASE_PORT + NODE_COUNT < 65536)) ||
        die "P2P base port leaves the valid unprivileged UDP range"
    if [[ ! $PARITY_BUDGET_BYTES =~ ^[0-9]+$ ]] || ((10#$PARITY_BUDGET_BYTES == 0)); then
        die "parity budget must be a positive byte count"
    fi
}

validate_directory_shape() {
    local path=$1 label=$2 resolved
    [[ -d $path && ! -L $path ]] || die "$label must be a non-symlink directory: $path"
    resolved=$(readlink -e -- "$path") || die "cannot resolve $label: $path"
    [[ $resolved == "$path" ]] || die "$label resolves outside its managed path: $path"
}

validate_owned_directory() {
    local path=$1 label=$2
    validate_directory_shape "$path" "$label"
    [[ -O $path ]] || die "$label must be owned by the current user: $path"
}

validate_existing_namespace_shape() {
    local role path node mount_path marked=false
    if [[ ! -e $LAB_ROOT && ! -L $LAB_ROOT ]]; then
        return
    fi
    validate_owned_directory "$LAB_ROOT" "Docker lab root"
    if [[ -e $LAB_ROOT/$NAMESPACE_MARKER || -L $LAB_ROOT/$NAMESPACE_MARKER ]]; then
        validate_namespace_marker "$LAB_ROOT" root
        marked=true
    fi
    for role in "${NAMESPACE_ROLES[@]}"; do
        path=$LAB_ROOT/$role
        if [[ -e $path || -L $path ]]; then
            validate_owned_directory "$path" "Docker lab $role namespace"
            if [[ $marked == true ]]; then
                validate_namespace_marker "$path" "$role"
            fi
        fi
    done
    if [[ -d $LAB_ROOT/mounts && ! -L $LAB_ROOT/mounts ]]; then
        for node in 0 1 2 3 4; do
            mount_path=$LAB_ROOT/mounts/node$node
            if [[ -e $mount_path || -L $mount_path ]]; then
                validate_directory_shape "$mount_path" "Docker lab node $node mount path"
            fi
        done
    fi
}

namespace_marker_contents() {
    local role=$1
    printf 'mutualbackup-docker-lab-directory-v1\nlab=%s\nrole=%s' "$LAB_CHECKSUM" "$role"
}

validate_namespace_marker() {
    local directory=$1 role=$2 marker expected actual
    marker=$directory/$NAMESPACE_MARKER
    [[ -f $marker && ! -L $marker && -O $marker ]] ||
        die "Docker lab $role namespace has no owned marker: $marker"
    expected=$(namespace_marker_contents "$role")
    actual=$(<"$marker")
    [[ $actual == "$expected" ]] || die "Docker lab $role namespace marker is invalid: $marker"
}

write_namespace_marker() {
    local directory=$1 role=$2 marker temporary
    marker=$directory/$NAMESPACE_MARKER
    if [[ -e $marker || -L $marker ]]; then
        validate_namespace_marker "$directory" "$role"
        return
    fi
    temporary=$directory/.$NAMESPACE_MARKER.tmp.$$.$RANDOM
    (umask 077 && namespace_marker_contents "$role" >"$temporary")
    sync "$temporary"
    mv -T -- "$temporary" "$marker"
    sync "$directory"
    validate_namespace_marker "$directory" "$role"
}

directory_is_empty() {
    local directory=$1
    [[ -z $(find "$directory" -mindepth 1 -maxdepth 1 -print -quit) ]]
}

ensure_namespace_directory() {
    local role=$1 path staging
    path=$LAB_ROOT/$role
    if [[ -e $path || -L $path ]]; then
        validate_owned_directory "$path" "Docker lab $role namespace"
        if mountpoint -q "$path"; then
            die "Docker lab $role namespace must not be a mount point: $path"
        fi
        validate_namespace_marker "$path" "$role"
        return
    fi

    staging=$LAB_ROOT/.$role.namespace-init-$$-$RANDOM
    (umask 077 && mkdir -- "$staging")
    write_namespace_marker "$staging" "$role"
    if ! mv -T -- "$staging" "$path"; then
        die "cannot publish Docker lab $role namespace: $path"
    fi
    sync "$LAB_ROOT"
    validate_owned_directory "$path" "Docker lab $role namespace"
    validate_namespace_marker "$path" "$role"
}

ensure_node_mount_directory() {
    local node=$1 path
    path=$(node_mount "$node")
    if [[ -e $path || -L $path ]]; then
        if mountpoint -q "$path"; then
            validate_directory_shape "$path" "Docker lab node $node mount path"
        else
            validate_owned_directory "$path" "Docker lab node $node mount path"
        fi
    else
        (umask 077 && mkdir -- "$path")
        validate_owned_directory "$path" "Docker lab node $node mount path"
    fi
}

ensure_lab_namespace() {
    local parent role
    parent=$(dirname "$LAB_ROOT")
    [[ -d $parent && ! -L $parent ]] ||
        die "Docker lab root parent must already be a non-symlink directory: $parent"
    if [[ -e $LAB_ROOT || -L $LAB_ROOT ]]; then
        validate_owned_directory "$LAB_ROOT" "Docker lab root"
        if [[ -e $LAB_ROOT/$NAMESPACE_MARKER || -L $LAB_ROOT/$NAMESPACE_MARKER ]]; then
            validate_namespace_marker "$LAB_ROOT" root
        else
            directory_is_empty "$LAB_ROOT" ||
                die "refusing unmarked nonempty Docker lab root: $LAB_ROOT"
            write_namespace_marker "$LAB_ROOT" root
        fi
    else
        (umask 077 && mkdir -- "$LAB_ROOT")
        validate_owned_directory "$LAB_ROOT" "Docker lab root"
        write_namespace_marker "$LAB_ROOT" root
    fi

    local lock=$LAB_ROOT/controller.lock
    if [[ -e $lock || -L $lock ]]; then
        [[ -f $lock && ! -L $lock && -O $lock ]] ||
            die "Docker lab lock must be an owned non-symlink file: $lock"
    else
        (umask 077 && : >"$lock")
    fi
    exec 9<>"$lock"
    flock -n 9 || die "another Docker lab operation is in progress"

    for role in "${NAMESPACE_ROLES[@]}"; do
        ensure_namespace_directory "$role"
    done
    validate_existing_namespace_shape
    validate_namespace_marker "$LAB_ROOT" root
}

validate_node() {
    local node=${1:-}
    [[ $node =~ ^[0-4]$ ]] || die "NODE must be one of 0, 1, 2, 3, or 4"
}

find_tool() {
    local name=$1
    shift
    local candidate
    if candidate=$(command -v "$name" 2>/dev/null); then
        printf '%s\n' "$candidate"
        return
    fi
    for candidate in "$@"; do
        if [[ -x $candidate ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    return 1
}

require_binary() {
    local path=$1
    local label=$2
    [[ -f $path && -x $path ]] ||
        die "$label is missing or not executable: $path (run the Nix release build elsewhere and copy its artifact here)"
}

prepare_privileges() {
    if ((EUID != 0)); then
        command -v sudo >/dev/null || die "sudo is required to manage loop-backed Btrfs filesystems"
        SUDO=(sudo)
        "${SUDO[@]}" -v
    fi
}

prepare_docker() {
    local docker_bin
    docker_bin=$(find_tool docker /usr/bin/docker) || die "Docker is not installed"
    if "$docker_bin" info >/dev/null 2>&1; then
        DOCKER=("$docker_bin")
    else
        if ((${#SUDO[@]} == 0)); then
            prepare_privileges
        fi
        "${SUDO[@]}" "$docker_bin" info >/dev/null 2>&1 ||
            die "cannot talk to the Docker daemon"
        DOCKER=("${SUDO[@]}" "$docker_bin")
    fi
}

prepare_host() {
    validate_layout
    require_binary "$CLI_BIN" "MutualBackup CLI"
    require_binary "$DAEMON_BIN" "MutualBackup daemon"
    [[ $(uname -s) == Linux ]] || die "the Docker lab requires a Linux host"
    [[ $(uname -m) == x86_64 ]] || die "the supplied release binaries require x86-64 Linux"
    command -v truncate >/dev/null || die "truncate is required"
    command -v findmnt >/dev/null || die "findmnt is required"
    command -v mountpoint >/dev/null || die "mountpoint is required"
    command -v readlink >/dev/null || die "readlink is required"
    command -v sync >/dev/null || die "sync is required"
    command -v flock >/dev/null || die "flock is required"
    BLKID=$(find_tool blkid /usr/sbin/blkid) || die "blkid is required"
    LOSETUP=$(find_tool losetup /usr/sbin/losetup) || die "losetup is required"
    MKFS_BTRFS=$(find_tool mkfs.btrfs /usr/sbin/mkfs.btrfs) || die "btrfs-progs is required"
    MOUNT=$(find_tool mount /usr/bin/mount /bin/mount) || die "mount is required"
    UMOUNT=$(find_tool umount /usr/bin/umount /bin/umount) || die "umount is required"
    prepare_privileges
    prepare_docker
}

prepare_cleanup_host() {
    validate_layout
    command -v findmnt >/dev/null || die "findmnt is required"
    command -v mountpoint >/dev/null || die "mountpoint is required"
    command -v readlink >/dev/null || die "readlink is required"
    command -v flock >/dev/null || die "flock is required"
    LOSETUP=$(find_tool losetup /usr/sbin/losetup) || die "losetup is required"
    MOUNT=$(find_tool mount /usr/bin/mount /bin/mount) || die "mount is required"
    UMOUNT=$(find_tool umount /usr/bin/umount /bin/umount) || die "umount is required"
    prepare_privileges
    prepare_docker
}

prepare_docker_only() {
    validate_layout
    require_binary "$CLI_BIN" "MutualBackup CLI"
    prepare_docker
}

acquire_lock() {
    command -v mountpoint >/dev/null || die "mountpoint is required"
    command -v find >/dev/null || die "find is required"
    ensure_lab_namespace
}

node_name() {
    printf '%s-node%s\n' "$NAME_PREFIX" "$1"
}

node_ip() {
    printf '%s.%s\n' "$IP_PREFIX" "$((10 + $1))"
}

node_port() {
    printf '%s\n' "$((P2P_BASE_PORT + $1))"
}

node_image() {
    printf '%s/images/node%s.btrfs\n' "$LAB_ROOT" "$1"
}

node_mount() {
    printf '%s/mounts/node%s\n' "$LAB_ROOT" "$1"
}

node_exchange() {
    printf '%s/exchange\n' "$(node_mount "$1")"
}

node_seed() {
    printf '%s/seeds/node%s.seed\n' "$LAB_ROOT" "$1"
}

node_identity() {
    printf '%s/seeds/node%s.identity\n' "$LAB_ROOT" "$1"
}

node_recovery_intent() {
    printf '%s/seeds/node%s.recovery-intent\n' "$LAB_ROOT" "$1"
}

RECOVERY_PHASE=
RECOVERY_BOOTSTRAP_NODE=
RECOVERY_RESTORE_NAME=
RECOVERY_GUILD_ID=

load_recovery_intent() {
    local path=$1
    local key value format_seen=false phase_seen=false bootstrap_seen=false restore_seen=false guild_seen=false
    if [[ ! -e $path && ! -L $path ]]; then
        return 1
    fi
    [[ -f $path && ! -L $path ]] ||
        die "recovery intent must be a regular non-symlink file: $path"
    [[ -O $path ]] || die "recovery intent must be owned by the current user: $path"
    RECOVERY_PHASE=
    RECOVERY_BOOTSTRAP_NODE=
    RECOVERY_RESTORE_NAME=
    RECOVERY_GUILD_ID=
    while IFS='=' read -r key value; do
        case $key in
            format)
                [[ $format_seen == false ]] || die "duplicate recovery format in $path"
                [[ $value == 1 ]] || die "unsupported recovery intent format in $path"
                format_seen=true
                ;;
            phase)
                [[ $phase_seen == false ]] || die "duplicate recovery phase in $path"
                RECOVERY_PHASE=$value
                phase_seen=true
                ;;
            bootstrap_node)
                [[ $bootstrap_seen == false ]] || die "duplicate recovery bootstrap in $path"
                RECOVERY_BOOTSTRAP_NODE=$value
                bootstrap_seen=true
                ;;
            restore_name)
                [[ $restore_seen == false ]] || die "duplicate recovery target in $path"
                RECOVERY_RESTORE_NAME=$value
                restore_seen=true
                ;;
            guild_id)
                [[ $guild_seen == false ]] || die "duplicate recovery guild in $path"
                RECOVERY_GUILD_ID=$value
                guild_seen=true
                ;;
            *) die "invalid recovery intent field in $path: $key" ;;
        esac
    done <"$path"
    [[ $format_seen == true && $phase_seen == true && $bootstrap_seen == true && $restore_seen == true && $guild_seen == true ]] ||
        die "incomplete recovery intent: $path"
    [[ $RECOVERY_PHASE =~ ^(prepared|erasing|erased|initialized|container_created|restoring)$ ]] ||
        die "invalid recovery phase in $path: $RECOVERY_PHASE"
    validate_node "$RECOVERY_BOOTSTRAP_NODE"
    [[ $RECOVERY_RESTORE_NAME =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
        die "invalid recovery target in $path"
    [[ $RECOVERY_GUILD_ID =~ ^[0-9a-fA-F]{64}$ ]] || die "invalid recovery guild in $path"
}

write_recovery_intent() {
    local node=$1 phase=$2 bootstrap_node=$3 restore_name=$4 expected_guild=$5
    local path temporary parent
    path=$(node_recovery_intent "$node")
    parent=$(dirname "$path")
    mkdir -p "$parent"
    temporary=$path.tmp.$$
    (umask 077 && printf 'format=1\nphase=%s\nbootstrap_node=%s\nrestore_name=%s\nguild_id=%s\n' \
        "$phase" "$bootstrap_node" "$restore_name" "$expected_guild" >"$temporary")
    sync "$temporary"
    mv "$temporary" "$path"
    sync "$parent"
}

advance_recovery_intent() {
    local node=$1 phase=$2
    write_recovery_intent "$node" "$phase" "$RECOVERY_BOOTSTRAP_NODE" \
        "$RECOVERY_RESTORE_NAME" "$RECOVERY_GUILD_ID"
    RECOVERY_PHASE=$phase
}

clear_recovery_intent() {
    local node=$1 path parent
    path=$(node_recovery_intent "$node")
    parent=$(dirname "$path")
    rm -f "$path"
    sync "$parent"
}

node_config() {
    printf '%s/configs/node%s.toml\n' "$LAB_ROOT" "$1"
}

loop_record() {
    printf '%s/loops/node%s\n' "$LAB_ROOT" "$1"
}

container_exists() {
    "${DOCKER[@]}" container inspect "$(node_name "$1")" >/dev/null 2>&1
}

container_owned() {
    local actual
    actual=$("${DOCKER[@]}" container inspect --format '{{ index .Config.Labels "io.mutualbackup.lab" }}' "$(node_name "$1")" 2>/dev/null || true)
    [[ $actual == "$LAB_CHECKSUM" ]]
}

container_running() {
    [[ $("${DOCKER[@]}" container inspect --format '{{.State.Running}}' "$(node_name "$1")" 2>/dev/null || true) == true ]]
}

remove_container() {
    local node=$1
    if ! container_exists "$node"; then
        return
    fi
    container_owned "$node" || die "container name collision: $(node_name "$node") is not owned by this lab"
    if container_running "$node"; then
        "${DOCKER[@]}" stop --time 20 "$(node_name "$node")" >/dev/null
    fi
    "${DOCKER[@]}" rm "$(node_name "$node")" >/dev/null
}

ensure_network() {
    if "${DOCKER[@]}" network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
        local actual subnet
        actual=$("${DOCKER[@]}" network inspect --format '{{ index .Labels "io.mutualbackup.lab" }}' "$NETWORK_NAME")
        [[ $actual == "$LAB_CHECKSUM" ]] || die "Docker network name collision: $NETWORK_NAME"
        subnet=$("${DOCKER[@]}" network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK_NAME")
        [[ $subnet == "$IP_PREFIX.0/24" ]] ||
            die "existing lab network uses $subnet, not $IP_PREFIX.0/24; restore the original IP prefix or run down first"
        return
    fi
    "${DOCKER[@]}" network create \
        --driver bridge \
        --subnet "$IP_PREFIX.0/24" \
        --label "$LAB_LABEL" \
        "$NETWORK_NAME" >/dev/null
}

remove_network() {
    if ! "${DOCKER[@]}" network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
        return
    fi
    local actual
    actual=$("${DOCKER[@]}" network inspect --format '{{ index .Labels "io.mutualbackup.lab" }}' "$NETWORK_NAME")
    [[ $actual == "$LAB_CHECKSUM" ]] || die "refusing to remove foreign Docker network $NETWORK_NAME"
    "${DOCKER[@]}" network rm "$NETWORK_NAME" >/dev/null
}

associated_loops() {
    local image=$1
    "${SUDO[@]}" "$LOSETUP" --associated "$image" --output NAME --noheadings 2>/dev/null |
        awk 'NF {print $1}'
}

verified_mounted_loop() {
    local node=$1
    local image mount_dir filesystem source candidate source_real candidate_real
    image=$(node_image "$node")
    mount_dir=$(node_mount "$node")
    filesystem=$(findmnt -rn -o FSTYPE --target "$mount_dir")
    [[ $filesystem == btrfs ]] ||
        die "$mount_dir is mounted, but it is not Btrfs"
    [[ -e $image || -L $image ]] ||
        die "$mount_dir is mounted, but node $node's image is missing: $image"
    validate_regular_image "$image"
    source=$(findmnt -rn -o SOURCE --target "$mount_dir")
    [[ $source =~ ^/dev/loop[0-9]+$ ]] ||
        die "$mount_dir is mounted from unexpected source $source"
    source_real=$(readlink -f -- "$source")
    while IFS= read -r candidate; do
        [[ -z $candidate ]] && continue
        candidate_real=$(readlink -f -- "$candidate")
        if [[ $candidate_real == "$source_real" ]]; then
            printf '%s\n' "$source"
            return
        fi
    done < <(associated_loops "$image")
    die "$mount_dir is mounted from $source, which is not attached to node $node's image $image"
}

require_mounted_filesystem() {
    local node=$1
    mountpoint -q "$(node_mount "$node")" ||
        die "node $node Btrfs filesystem is not mounted; run 'up' to restore it"
    verified_mounted_loop "$node" >/dev/null
}

validate_regular_image() {
    local image=$1
    [[ -f $image && ! -L $image ]] ||
        die "Btrfs image must be a regular non-symlink file: $image"
    [[ -O $image ]] || die "Btrfs image must be owned by the current user: $image"
    # Images contain the node's plaintext exchange/source tree as well as its
    # encrypted databases. Interrupted staging files may have been created
    # under a permissive umask, so normalize both staged and completed images
    # before attaching them.
    chmod 600 "$image"
}

detach_image_loops() {
    local image=$1
    local loop
    while IFS= read -r loop; do
        [[ -z $loop ]] && continue
        [[ $loop =~ ^/dev/loop[0-9]+$ ]] || die "refusing unexpected loop device: $loop"
        if findmnt -rn --source "$loop" >/dev/null; then
            die "cannot resume image creation while $loop is mounted"
        fi
        "${SUDO[@]}" "$LOSETUP" --detach "$loop"
    done < <(associated_loops "$image")
}

publish_new_filesystem_image() {
    local node=$1
    local image=$2
    local staging=$image.creating
    local loop
    if [[ -e $staging || -L $staging ]]; then
        validate_regular_image "$staging"
        detach_image_loops "$staging"
    else
        (umask 077 && : >"$staging")
    fi
    truncate -s "$DISK_SIZE" "$staging"
    loop=$("${SUDO[@]}" "$LOSETUP" --find --show "$staging")
    [[ $loop =~ ^/dev/loop[0-9]+$ ]] || die "unexpected loop device returned for $staging: $loop"
    if ! "${SUDO[@]}" "$MKFS_BTRFS" --quiet --force --label "mb-lab-node$node" "$loop"; then
        "${SUDO[@]}" "$LOSETUP" --detach "$loop" || true
        die "cannot format node $node's staged Btrfs image"
    fi
    "${SUDO[@]}" sync "$loop"
    "${SUDO[@]}" "$LOSETUP" --detach "$loop"
    mv "$staging" "$image"
    sync "$(dirname "$image")"
}

normalize_filesystem_root() {
    local node=$1 mount_dir
    mount_dir=$(node_mount "$node")
    "${SUDO[@]}" chown "$(id -u):$(id -g)" "$mount_dir"
    chmod 700 "$mount_dir"
    mkdir -p "$(node_exchange "$node")"
}

ensure_filesystem() {
    local node=$1
    local image mount_dir record loop filesystem staging
    image=$(node_image "$node")
    mount_dir=$(node_mount "$node")
    record=$(loop_record "$node")
    ensure_node_mount_directory "$node"

    if mountpoint -q "$mount_dir"; then
        loop=$(verified_mounted_loop "$node")
        printf '%s\n' "$loop" >"$record"
        normalize_filesystem_root "$node"
        return
    fi

    staging=$image.creating
    if [[ -e $image || -L $image ]]; then
        validate_regular_image "$image"
        [[ ! -e $staging && ! -L $staging ]] ||
            die "both completed and staged images exist for node $node; inspect $image and $staging"
    else
        publish_new_filesystem_image "$node" "$image"
    fi

    detach_image_loops "$image"
    loop=$("${SUDO[@]}" "$LOSETUP" --find --show "$image")
    [[ $loop =~ ^/dev/loop[0-9]+$ ]] || die "unexpected loop device returned for $image: $loop"
    filesystem=$("${SUDO[@]}" "$BLKID" -p -s TYPE -o value "$loop" 2>/dev/null || true)
    if [[ $filesystem != btrfs ]]; then
        "${SUDO[@]}" "$LOSETUP" --detach "$loop" || true
        die "existing node $node image is not a completed Btrfs filesystem: $image"
    fi
    printf '%s\n' "$loop" >"$record"

    if ! "${SUDO[@]}" "$MOUNT" -t btrfs -o noatime,compress=zstd "$loop" "$mount_dir"; then
        "${SUDO[@]}" "$LOSETUP" --detach "$loop" || true
        die "cannot mount node $node Btrfs image; is the kernel btrfs module available?"
    fi
    if [[ ${MUTUALBACKUP_TEST_FAIL_AFTER_BTRFS_MOUNT:-} == "$node" ]]; then
        die "test interruption after mounting node $node Btrfs filesystem"
    fi
    normalize_filesystem_root "$node"
}

unmount_filesystem() {
    local node=$1
    local image mount_dir record loop
    image=$(node_image "$node")
    mount_dir=$(node_mount "$node")
    record=$(loop_record "$node")
    if mountpoint -q "$mount_dir"; then
        verified_mounted_loop "$node" >/dev/null
        "${SUDO[@]}" "$UMOUNT" "$mount_dir" ||
            die "cannot unmount $mount_dir; close shells and files using it, then retry"
    fi
    if [[ -f $image ]]; then
        while IFS= read -r loop; do
            [[ -z $loop ]] && continue
            [[ $loop =~ ^/dev/loop[0-9]+$ ]] || die "refusing unexpected loop device: $loop"
            "${SUDO[@]}" "$LOSETUP" --detach "$loop"
        done < <(associated_loops "$image")
    fi
    rm -f "$record"
}

ensure_seed() {
    local node=$1
    local seed identity recovery_intent state manifest temporary seed_exists=false manifest_exists=false
    seed=$(node_seed "$node")
    identity=$(node_identity "$node")
    recovery_intent=$(node_recovery_intent "$node")
    state=$(node_mount "$node")/state
    manifest=$state/identity.toml
    if [[ -e $seed || -L $seed ]]; then
        [[ -f $seed && ! -L $seed ]] ||
            die "recovery string must be a regular non-symlink file: $seed"
        seed_exists=true
    fi
    if [[ -e $manifest || -L $manifest ]]; then
        [[ -f $manifest && ! -L $manifest ]] ||
            die "identity manifest must be a regular non-symlink file: $manifest"
        manifest_exists=true
    fi
    if load_recovery_intent "$recovery_intent"; then
        die "node $node has a pending recovery transaction; resume it through up or reinit"
    fi
    if [[ $seed_exists == false ]]; then
        [[ $manifest_exists == false ]] ||
            die "node $node has identity state but no recovery string; restore $seed before running up"
        "$CLI_BIN" init --seed-file "$seed" --data-dir "$state" >/dev/null
        say "generated and retained recovery string for node $node: $seed"
    elif [[ $manifest_exists == false ]]; then
        "$CLI_BIN" init --seed-file "$seed" --data-dir "$state" >/dev/null
        say "resumed new-node initialization for node $node from: $seed"
    fi
    chmod 600 "$seed"
    if [[ ! -f $identity ]]; then
        temporary="$identity.tmp.$$"
        "$CLI_BIN" identity --seed-file "$seed" >"$temporary"
        chmod 600 "$temporary"
        mv "$temporary" "$identity"
    fi
}

peer_id() {
    sed -n 's/^libp2p peer id: *//p' "$(node_identity "$1")"
}

peer_endpoint() {
    local node=$1
    printf '/ip4/%s/udp/%s/quic-v1/p2p/%s\n' \
        "$(node_ip "$node")" "$(node_port "$node")" "$(peer_id "$node")"
}

write_normal_config() {
    local node=$1
    local config temporary bootstrap relay relay_server
    config=$(node_config "$node")
    temporary=$config.tmp.$$
    bootstrap='[]'
    relay='[]'
    relay_server=false
    if ((node == 0)); then
        relay_server=true
    else
        bootstrap="[\"$(peer_endpoint 0)\"]"
        relay=$bootstrap
    fi
    umask 077
    cat >"$temporary" <<EOF
data_dir = "/node/state"
seed_file = "/secrets/node.seed"
control_socket = "/node/run/control.sock"
failure_domain = "docker-lab-node-$node"
parity_budget_bytes = $PARITY_BUDGET_BYTES
p2p_listen_addresses = ["/ip4/0.0.0.0/udp/$(node_port "$node")/quic-v1"]
p2p_external_addresses = ["/ip4/$(node_ip "$node")/udp/$(node_port "$node")/quic-v1"]
p2p_bootstrap_addresses = $bootstrap
p2p_relay_addresses = $relay
enable_relay_server = $relay_server
enable_hole_punching = true
enable_dht_maintenance = true
max_connections = 32
EOF
    sync "$temporary"
    mv "$temporary" "$config"
    sync "$(dirname "$config")"
}

write_recovery_config() {
    local node=$1
    local bootstrap_node=$2
    local config temporary relay relay_server
    config=$(node_config "$node")
    temporary=$config.tmp.$$
    relay='[]'
    relay_server=false
    if ((node == 0)); then
        relay_server=true
    else
        relay="[\"$(peer_endpoint 0)\"]"
    fi
    umask 077
    cat >"$temporary" <<EOF
data_dir = "/node/state"
seed_file = "/secrets/node.seed"
control_socket = "/node/run/control.sock"
parity_budget_bytes = $PARITY_BUDGET_BYTES
p2p_listen_addresses = ["/ip4/0.0.0.0/udp/$(node_port "$node")/quic-v1"]
p2p_external_addresses = ["/ip4/$(node_ip "$node")/udp/$(node_port "$node")/quic-v1"]
p2p_bootstrap_addresses = ["$(peer_endpoint "$bootstrap_node")"]
p2p_relay_addresses = $relay
enable_relay_server = $relay_server
enable_hole_punching = true
enable_dht_maintenance = true
max_connections = 32
EOF
    sync "$temporary"
    mv "$temporary" "$config"
    sync "$(dirname "$config")"
}

create_container() {
    local node=$1
    local name
    name=$(node_name "$node")
    if container_exists "$node"; then
        container_owned "$node" || die "container name collision: $name"
        return
    fi
    mountpoint -q "$(node_mount "$node")" || die "node $node Btrfs filesystem is not mounted"
    grep -Fq "p2p_external_addresses = [\"/ip4/$(node_ip "$node")/udp/$(node_port "$node")/quic-v1\"]" \
        "$(node_config "$node")" ||
        die "node $node config does not match the selected lab IP/port; restore the original environment settings or use a fresh lab root"
    "${DOCKER[@]}" create \
        --name "$name" \
        --hostname "mb-node$node" \
        --label "$LAB_LABEL" \
        --label "io.mutualbackup.node=$node" \
        --network "$NETWORK_NAME" \
        --ip "$(node_ip "$node")" \
        --user "$(id -u):$(id -g)" \
        --init \
        --read-only \
        --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --security-opt no-new-privileges \
        --cap-drop ALL \
        --stop-signal SIGINT \
        --stop-timeout 20 \
        --mount "type=bind,src=$CLI_BIN,dst=/opt/mutualbackup,readonly" \
        --mount "type=bind,src=$DAEMON_BIN,dst=/opt/mutualbackupd,readonly" \
        --mount "type=bind,src=$(node_mount "$node"),dst=/node" \
        --mount "type=bind,src=$(node_seed "$node"),dst=/secrets/node.seed,readonly" \
        --mount "type=bind,src=$(node_config "$node"),dst=/config/node.toml,readonly" \
        --env RUST_LOG=info \
        "$CONTAINER_IMAGE" \
        /opt/mutualbackupd --config /config/node.toml >/dev/null
}

cli_raw() {
    local node=$1
    shift
    "${DOCKER[@]}" exec "$(node_name "$node")" \
        /opt/mutualbackup --socket /node/run/control.sock "$@"
}

wait_for_node() {
    local node=$1
    local deadline=$((SECONDS + 30))
    while ((SECONDS < deadline)); do
        if container_running "$node" && cli_raw "$node" status >/dev/null 2>&1; then
            return
        fi
        sleep 0.2
    done
    "${DOCKER[@]}" logs --tail 80 "$(node_name "$node")" >&2 || true
    die "node $node did not become ready"
}

start_node_internal() {
    local node=$1
    container_exists "$node" || die "node $node container does not exist; run 'up' first"
    container_owned "$node" || die "node $node container is not owned by this lab"
    if ! container_running "$node"; then
        "${DOCKER[@]}" start "$(node_name "$node")" >/dev/null
    fi
    wait_for_node "$node"
}

guild_phase() {
    cli_raw "$1" guild status 2>/dev/null | sed -n 's/^phase: *//p'
}

guild_id() {
    cli_raw "$1" guild status 2>/dev/null | sed -n 's/^guild id: *//p'
}

validate_recovery_survivors() {
    local recovering_node=$1
    local expected_guild=$2
    local count=0 candidate first=
    for candidate in 0 1 2 3 4; do
        if ((candidate != recovering_node)) && container_running "$candidate" &&
            cli_raw "$candidate" status >/dev/null 2>&1 &&
            [[ $(guild_phase "$candidate") == Active ]] &&
            [[ $(guild_id "$candidate") == "$expected_guild" ]]; then
            ((count += 1))
            [[ -n $first ]] || first=$candidate
        fi
    done
    ((count >= 3)) ||
        die "reinit requires at least three responsive members of guild $expected_guild"
    if [[ $RECOVERY_BOOTSTRAP_NODE == "$recovering_node" ]] ||
        ! container_running "$RECOVERY_BOOTSTRAP_NODE" ||
        [[ $(guild_phase "$RECOVERY_BOOTSTRAP_NODE") != Active ]] ||
        [[ $(guild_id "$RECOVERY_BOOTSTRAP_NODE") != "$expected_guild" ]]; then
        RECOVERY_BOOTSTRAP_NODE=$first
        if [[ -e "$(node_recovery_intent "$recovering_node")" ]]; then
            remove_container "$recovering_node"
            write_recovery_intent "$recovering_node" "$RECOVERY_PHASE" \
                "$RECOVERY_BOOTSTRAP_NODE" "$RECOVERY_RESTORE_NAME" "$RECOVERY_GUILD_ID"
        fi
    fi
}

archive_reinit_config() {
    local node=$1
    local config previous timestamp
    config=$(node_config "$node")
    if [[ -f $config && ! -L $config ]]; then
        timestamp=$(date -u +%Y%m%dT%H%M%SZ)
        previous=$config.before-reinit-$timestamp-$$
        [[ ! -e $previous ]] || die "refusing to overwrite previous config $previous"
        mv "$config" "$previous"
        sync "$(dirname "$config")"
        say "previous config retained at: $previous"
    elif [[ -e $config || -L $config ]]; then
        die "node config is not a regular file: $config"
    fi
}

prepare_recovery_container() {
    local node=$1
    local image staging manifest config seed
    image=$(node_image "$node")
    staging=$image.creating
    manifest=$(node_mount "$node")/state/identity.toml
    config=$(node_config "$node")
    seed=$(node_seed "$node")
    [[ -f $seed && ! -L $seed && -O $seed ]] ||
        die "cannot resume reinit without the retained recovery string: $seed"

    if [[ $RECOVERY_PHASE == prepared ]]; then
        advance_recovery_intent "$node" erasing
    fi
    if [[ $RECOVERY_PHASE == erasing ]]; then
        archive_reinit_config "$node"
        remove_container "$node"
        unmount_filesystem "$node"
        if [[ -e $image || -L $image ]]; then
            validate_regular_image "$image"
            detach_image_loops "$image"
            rm "$image"
        fi
        if [[ -e $staging || -L $staging ]]; then
            validate_regular_image "$staging"
            detach_image_loops "$staging"
            rm "$staging"
        fi
        sync "$(dirname "$image")"
        advance_recovery_intent "$node" erased
    fi
    if [[ $RECOVERY_PHASE == erased ]]; then
        ensure_filesystem "$node"
        if [[ ! -e $manifest && ! -L $manifest ]]; then
            "$CLI_BIN" recover-init \
                --seed-file "$(node_seed "$node")" \
                --data-dir "$(node_mount "$node")/state" >/dev/null
        fi
        [[ -f $manifest && ! -L $manifest ]] ||
            die "recovery initialization did not create a safe identity manifest for node $node"
        grep -Fqx 'intent = "recovery"' "$manifest" ||
            die "node $node recovery filesystem contains a non-recovery identity"
        advance_recovery_intent "$node" initialized
    fi
    if [[ $RECOVERY_PHASE =~ ^(initialized|container_created|restoring)$ ]]; then
        ensure_filesystem "$node"
        [[ -f $manifest && ! -L $manifest ]] ||
            die "node $node recovery identity disappeared"
        grep -Fqx 'intent = "recovery"' "$manifest" ||
            die "node $node recovery filesystem contains a non-recovery identity"
        if container_exists "$node"; then
            container_owned "$node" || die "container name collision: $(node_name "$node")"
            grep -Fq "p2p_bootstrap_addresses = [\"$(peer_endpoint "$RECOVERY_BOOTSTRAP_NODE")\"]" "$config" ||
                die "existing recovery container has an unexpected bootstrap config"
        else
            write_recovery_config "$node" "$RECOVERY_BOOTSTRAP_NODE"
            create_container "$node"
        fi
        if [[ $RECOVERY_PHASE == initialized ]]; then
            advance_recovery_intent "$node" container_created
        fi
    fi
}

resume_recovery_transaction() {
    local node=$1
    local intent expected_guild restore_name
    intent=$(node_recovery_intent "$node")
    load_recovery_intent "$intent" || die "node $node has no recovery transaction to resume"
    expected_guild=$RECOVERY_GUILD_ID
    restore_name=$RECOVERY_RESTORE_NAME
    if [[ $RECOVERY_PHASE != restoring ]]; then
        validate_recovery_survivors "$node" "$expected_guild"
    fi
    prepare_recovery_container "$node"
    start_node_internal "$node"
    if [[ $RECOVERY_PHASE == container_created ]]; then
        advance_recovery_intent "$node" restoring
    fi
    say "recovering guild state and latest owned revision into /node/exchange/$restore_name"
    if ! cli_raw "$node" restore "/node/exchange/$restore_name"; then
        say "recovery did not complete; its durable transaction remains at: $intent" >&2
        say "retry with: $0 reinit $node $restore_name --yes (or run up)" >&2
        return 1
    fi
    [[ $(guild_phase "$node") == Active && $(guild_id "$node") == "$expected_guild" ]] ||
        die "recovered node $node did not rejoin its original active guild"
    clear_recovery_intent "$node"
    say "host-visible restored tree: $(node_exchange "$node")/$restore_name"
}

ensure_guild() {
    local phase expected_guild
    phase=$(guild_phase 0)
    if [[ -z $phase ]]; then
        say "creating the fixed five-member guild"
        cli_raw 0 guild create >/dev/null
        phase=Draft
    fi
    expected_guild=$(guild_id 0)
    [[ -n $expected_guild ]] || die "node 0 did not report its guild ID"
    if [[ $phase == Active ]]; then
        local node
        for node in 1 2 3 4; do
            [[ $(guild_phase "$node") == Active && $(guild_id "$node") == "$expected_guild" ]] ||
                die "node $node does not have node 0's active guild; use reinit or choose a fresh lab root"
        done
        return
    fi

    local node invite node_phase
    for node in 1 2 3 4; do
        node_phase=$(guild_phase "$node")
        if [[ -z $node_phase ]]; then
            invite=$(cli_raw 0 guild invite | sed -n 's/^invitation: //p')
            [[ -n $invite ]] || die "node 0 did not return an invitation for node $node"
            cli_raw "$node" guild join "$invite" >/dev/null
        elif [[ $node_phase == Joining ]]; then
            say "retrying the pending guild join for node $node"
            cli_raw "$node" guild retry >/dev/null
        elif [[ $node_phase == Active ]]; then
            [[ $(guild_id "$node") == "$expected_guild" ]] ||
                die "node $node has a different active guild"
            say "node $node already installed the pending guild; resuming finalization"
        else
            die "node $node is in unexpected guild phase $node_phase"
        fi
    done
    cli_raw 0 guild finalize >/dev/null
    [[ $(guild_phase 0) == Active ]] || die "guild finalization did not become active"
    for node in 1 2 3 4; do
        [[ $(guild_phase "$node") == Active && $(guild_id "$node") == "$expected_guild" ]] ||
            die "node $node did not converge on the finalized guild"
    done
    say "five-member guild is active"
}

command_up() {
    prepare_host
    acquire_lock
    chmod 700 "$LAB_ROOT" "$LAB_ROOT"/{images,mounts,loops,seeds,configs}

    if ! "${DOCKER[@]}" image inspect "$CONTAINER_IMAGE" >/dev/null 2>&1; then
        say "pulling container base image $CONTAINER_IMAGE (no image build)"
        "${DOCKER[@]}" pull "$CONTAINER_IMAGE"
    fi
    ensure_network

    local node pending_node=
    for node in 0 1 2 3 4; do
        if load_recovery_intent "$(node_recovery_intent "$node")"; then
            [[ -z $pending_node ]] ||
                die "multiple pending reinit transactions require manual recovery"
            pending_node=$node
        fi
    done
    for node in 0 1 2 3 4; do
        if [[ $node == "$pending_node" ]]; then
            continue
        fi
        ensure_filesystem "$node"
    done
    for node in 0 1 2 3 4; do
        if [[ $node == "$pending_node" ]]; then
            continue
        fi
        ensure_seed "$node"
    done
    for node in 0 1 2 3 4; do
        if [[ $node == "$pending_node" ]]; then
            continue
        fi
        write_normal_config "$node"
        create_container "$node"
    done
    for node in 0 1 2 3 4; do
        if [[ $node == "$pending_node" ]]; then
            continue
        fi
        start_node_internal "$node"
    done
    if [[ -n $pending_node ]]; then
        resume_recovery_transaction "$pending_node"
    fi
    ensure_guild
    command_info
}

command_down() {
    prepare_cleanup_host
    acquire_lock
    local node
    for node in 0 1 2 3 4; do
        remove_container "$node"
    done
    remove_network
    for node in 0 1 2 3 4; do
        unmount_filesystem "$node"
    done
    say "lab is down; containers and loop attachments were removed"
    say "Btrfs images, configs, and seeds remain under: $LAB_ROOT"
}

command_stop() {
    local node=$1
    prepare_docker_only
    validate_node "$node"
    acquire_lock
    container_exists "$node" || die "node $node container does not exist; run 'up' first"
    container_owned "$node" || die "node $node container is not owned by this lab"
    if container_running "$node"; then
        "${DOCKER[@]}" stop --time 20 "$(node_name "$node")" >/dev/null
    fi
    say "node $node is stopped"
}

command_start() {
    local node=$1
    prepare_host
    validate_node "$node"
    acquire_lock
    require_mounted_filesystem "$node"
    start_node_internal "$node"
    say "node $node is running"
}

command_restart() {
    local node=$1
    prepare_host
    validate_node "$node"
    acquire_lock
    require_mounted_filesystem "$node"
    container_exists "$node" || die "node $node container does not exist; run 'up' first"
    container_owned "$node" || die "node $node container is not owned by this lab"
    "${DOCKER[@]}" restart --time 20 "$(node_name "$node")" >/dev/null
    wait_for_node "$node"
    say "node $node restarted"
}

confirm_reinit() {
    local node=$1
    local assume_yes=$2
    if [[ $assume_yes == true ]]; then
        return
    fi
    [[ -t 0 ]] || die "reinit is destructive; rerun with --yes"
    printf 'Reinitializing node %s permanently erases its Btrfs image. Type node%s to continue: ' "$node" "$node" >&2
    local answer
    read -r answer
    [[ $answer == "node$node" ]] || die "reinit cancelled"
}

command_reinit() {
    local node=${1:-}
    shift || true
    validate_node "$node"
    local restore_name=recovered
    local assume_yes=false
    local restore_name_seen=false
    while (($#)); do
        case $1 in
            --yes) assume_yes=true ;;
            -*) die "unknown reinit option: $1" ;;
            *)
                [[ $restore_name_seen == false ]] || die "reinit accepts at most one restore NAME"
                restore_name=$1
                restore_name_seen=true
                ;;
        esac
        shift
    done
    [[ $restore_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
        die "restore NAME must be a simple relative directory name"

    prepare_host
    acquire_lock
    local recovery_intent expected_guild bootstrap_node='' candidate
    recovery_intent=$(node_recovery_intent "$node")
    if load_recovery_intent "$recovery_intent"; then
        if [[ $restore_name_seen == true && $restore_name != "$RECOVERY_RESTORE_NAME" ]]; then
            die "pending reinit target is $RECOVERY_RESTORE_NAME, not $restore_name"
        fi
        resume_recovery_transaction "$node"
        return
    fi
    container_running "$node" || die "node $node must be running before reinit"
    cli_raw "$node" status | grep -q '^recovery ready: true$' ||
        die "node $node is not seed-recovery-ready; wait for DHT publication before reinit"
    [[ $(guild_phase "$node") == Active ]] || die "node $node is not in an active guild"
    expected_guild=$(guild_id "$node")
    [[ $expected_guild =~ ^[0-9a-fA-F]{64}$ ]] || die "node $node reported an invalid guild ID"
    for candidate in 0 1 2 3 4; do
        if ((candidate != node)) && container_running "$candidate" &&
            cli_raw "$candidate" status >/dev/null 2>&1 &&
            [[ $(guild_phase "$candidate") == Active ]] &&
            [[ $(guild_id "$candidate") == "$expected_guild" ]]; then
            bootstrap_node=$candidate
            break
        fi
    done
    [[ -n $bootstrap_node ]] || die "no responsive bootstrap member belongs to the same guild"
    RECOVERY_PHASE=prepared
    RECOVERY_BOOTSTRAP_NODE=$bootstrap_node
    RECOVERY_RESTORE_NAME=$restore_name
    RECOVERY_GUILD_ID=$expected_guild
    validate_recovery_survivors "$node" "$expected_guild"
    confirm_reinit "$node" "$assume_yes"
    write_recovery_intent "$node" prepared "$RECOVERY_BOOTSTRAP_NODE" "$restore_name" "$expected_guild"
    say "recorded durable recovery intent; preserving $(node_seed "$node")"
    resume_recovery_transaction "$node"
}

command_cli() {
    local node=${1:-}
    shift || true
    prepare_docker_only
    validate_node "$node"
    container_running "$node" || die "node $node is not running"
    cli_raw "$node" "$@"
}

command_shell() {
    local node=${1:-}
    prepare_docker_only
    validate_node "$node"
    container_running "$node" || die "node $node is not running"
    "${DOCKER[@]}" exec -it "$(node_name "$node")" /bin/sh
}

command_logs() {
    local node=${1:-}
    shift || true
    prepare_docker_only
    validate_node "$node"
    container_exists "$node" || die "node $node container does not exist"
    container_owned "$node" || die "node $node container is not owned by this lab"
    "${DOCKER[@]}" logs "$@" "$(node_name "$node")"
}

command_mounts() {
    local node
    for node in 0 1 2 3 4; do
        printf 'node %s: %s' "$node" "$(node_exchange "$node")"
        if mountpoint -q "$(node_mount "$node")"; then
            printf ' (mounted)\n'
        else
            printf ' (unmounted; run up)\n'
        fi
    done
}

command_path() {
    local node=${1:-}
    validate_node "$node"
    printf '%s\n' "$(node_exchange "$node")"
}

command_info() {
    prepare_docker_only
    local node name state ip loop exchange
    printf 'lab root:       %s\n' "$LAB_ROOT"
    printf 'Docker network: %s (%s.0/24)\n' "$NETWORK_NAME" "$IP_PREFIX"
    printf 'base image:     %s\n\n' "$CONTAINER_IMAGE"
    printf '%-4s %-11s %-15s %-12s %-12s %s\n' NODE STATE IP P2P LOOP HOST_EXCHANGE
    for node in 0 1 2 3 4; do
        name=$(node_name "$node")
        state=absent
        ip=$(node_ip "$node")
        if container_exists "$node"; then
            state=$("${DOCKER[@]}" container inspect --format '{{.State.Status}}' "$name")
            ip=$("${DOCKER[@]}" container inspect --format "{{with index .NetworkSettings.Networks \"$NETWORK_NAME\"}}{{.IPAddress}}{{end}}" "$name")
        fi
        loop=-
        if [[ -f $(loop_record "$node") ]]; then
            loop=$(<"$(loop_record "$node")")
        fi
        exchange=$(node_exchange "$node")
        printf '%-4s %-11s %-15s %-12s %-12s %s\n' "$node" "$state" "${ip:--}" "udp/$(node_port "$node")" "$loop" "$exchange"
    done
}

command_status() {
    local requested=${1:-}
    prepare_docker_only
    local first=0 last=4 node
    if [[ -n $requested ]]; then
        validate_node "$requested"
        first=$requested
        last=$requested
    fi
    for ((node = first; node <= last; node++)); do
        say "== node $node ($(node_ip "$node")) =="
        if container_running "$node"; then
            cli_raw "$node" status
        elif container_exists "$node"; then
            say "container is stopped"
        else
            say "container is absent"
        fi
        ((node == last)) || printf '\n'
    done
}

main() {
    local command=${1:-help}
    shift || true
    if [[ $command == help || $command == -h || $command == --help ]]; then
        usage
        return
    fi
    validate_layout
    case $command in
        up) (($# == 0)) || die "up takes no arguments"; command_up ;;
        down) (($# == 0)) || die "down takes no arguments"; command_down ;;
        stop) (($# == 1)) || die "usage: $0 stop NODE"; command_stop "$1" ;;
        start) (($# == 1)) || die "usage: $0 start NODE"; command_start "$1" ;;
        restart) (($# == 1)) || die "usage: $0 restart NODE"; command_restart "$1" ;;
        reinit) (($# >= 1)) || die "usage: $0 reinit NODE [NAME] [--yes]"; command_reinit "$@" ;;
        cli) (($# >= 1)) || die "usage: $0 cli NODE [ARGS...]"; command_cli "$@" ;;
        shell) (($# == 1)) || die "usage: $0 shell NODE"; command_shell "$1" ;;
        logs) (($# >= 1)) || die "usage: $0 logs NODE [DOCKER-LOGS-ARGS...]"; command_logs "$@" ;;
        status) (($# <= 1)) || die "usage: $0 status [NODE]"; command_status "$@" ;;
        info) (($# == 0)) || die "info takes no arguments"; command_info ;;
        mounts) (($# == 0)) || die "mounts takes no arguments"; command_mounts ;;
        path) (($# == 1)) || die "usage: $0 path NODE"; command_path "$1" ;;
        *) usage >&2; die "unknown command: $command" ;;
    esac
}

main "$@"
