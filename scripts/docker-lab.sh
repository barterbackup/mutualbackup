#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

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

LAB_CHECKSUM=$(printf '%s' "$LAB_ROOT" | cksum | awk '{print $1}')
NAME_PREFIX=mutualbackup-lab-$LAB_CHECKSUM
NETWORK_NAME=$NAME_PREFIX
LAB_LABEL=io.mutualbackup.lab=$LAB_CHECKSUM

DOCKER=()
SUDO=()
LOSETUP=
MKFS_BTRFS=
MOUNT=
UMOUNT=

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
  reinit NODE [NAME] [--yes] Wipe one node, recreate it from its seed, restore to NAME

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
    [[ $LAB_ROOT != / && $LAB_ROOT != "$REPO_ROOT" ]] ||
        die "refusing unsafe lab root: $LAB_ROOT"
    [[ $LAB_ROOT != *,* && $CLI_BIN != *,* && $DAEMON_BIN != *,* ]] ||
        die "Docker lab and binary paths must not contain commas"
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
    command -v flock >/dev/null || die "flock is required"
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
    mkdir -p "$LAB_ROOT"
    exec 9>"$LAB_ROOT/controller.lock"
    flock -n 9 || die "another Docker lab operation is in progress"
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

ensure_filesystem() {
    local node=$1
    local image mount_dir record loop new_image=false
    image=$(node_image "$node")
    mount_dir=$(node_mount "$node")
    record=$(loop_record "$node")
    mkdir -p "$(dirname "$image")" "$mount_dir" "$(dirname "$record")"

    if mountpoint -q "$mount_dir"; then
        [[ $(findmnt -rn -o FSTYPE --target "$mount_dir") == btrfs ]] ||
            die "$mount_dir is mounted, but it is not Btrfs"
        findmnt -rn -o SOURCE --target "$mount_dir" >"$record"
        mkdir -p "$(node_exchange "$node")"
        return
    fi

    if [[ ! -f $image ]]; then
        truncate -s "$DISK_SIZE" "$image"
        new_image=true
    fi

    loop=$(associated_loops "$image" | head -n 1)
    if [[ -z $loop ]]; then
        loop=$("${SUDO[@]}" "$LOSETUP" --find --show "$image")
    fi
    [[ $loop =~ ^/dev/loop[0-9]+$ ]] || die "unexpected loop device returned for $image: $loop"
    printf '%s\n' "$loop" >"$record"

    if [[ $new_image == true ]]; then
        "${SUDO[@]}" "$MKFS_BTRFS" --quiet --force --label "mb-lab-node$node" "$loop"
    fi
    if ! "${SUDO[@]}" "$MOUNT" -t btrfs -o noatime,compress=zstd "$loop" "$mount_dir"; then
        "${SUDO[@]}" "$LOSETUP" --detach "$loop" || true
        die "cannot mount node $node Btrfs image; is the kernel btrfs module available?"
    fi
    "${SUDO[@]}" chown "$(id -u):$(id -g)" "$mount_dir"
    chmod 700 "$mount_dir"
    mkdir -p "$(node_exchange "$node")"
}

unmount_filesystem() {
    local node=$1
    local image mount_dir record loop
    image=$(node_image "$node")
    mount_dir=$(node_mount "$node")
    record=$(loop_record "$node")
    if mountpoint -q "$mount_dir"; then
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
    local seed
    seed=$(node_seed "$node")
    if [[ -f $seed ]]; then
        chmod 600 "$seed"
        return
    fi
    "$CLI_BIN" init --seed-file "$seed" >/dev/null
    say "generated and retained seed for node $node: $seed"
}

peer_id() {
    "$CLI_BIN" identity --seed-file "$(node_seed "$1")" |
        sed -n 's/^libp2p peer id: *//p'
}

peer_endpoint() {
    local node=$1
    printf '/ip4/%s/udp/%s/quic-v1/p2p/%s\n' \
        "$(node_ip "$node")" "$(node_port "$node")" "$(peer_id "$node")"
}

write_normal_config() {
    local node=$1
    local config bootstrap relay relay_server
    config=$(node_config "$node")
    if [[ -f $config ]]; then
        return
    fi
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
    cat >"$config" <<EOF
format_version = 1
data_dir = "/node/state"
seed_file = "/secrets/node.seed"
control_socket = "/node/run/control.sock"
failure_domain = "docker-lab-node-$node"
recovery_mode = false
parity_budget_bytes = $PARITY_BUDGET_BYTES
p2p_listen_addresses = ["/ip4/0.0.0.0/udp/$(node_port "$node")/quic-v1"]
p2p_external_addresses = ["/ip4/$(node_ip "$node")/udp/$(node_port "$node")/quic-v1"]
p2p_bootstrap_addresses = $bootstrap
p2p_relay_addresses = $relay
enable_relay_server = $relay_server
EOF
}

write_recovery_config() {
    local node=$1
    local bootstrap_node=$2
    local config relay relay_server
    config=$(node_config "$node")
    relay='[]'
    relay_server=false
    if ((node == 0)); then
        relay_server=true
    else
        relay="[\"$(peer_endpoint 0)\"]"
    fi
    umask 077
    cat >"$config" <<EOF
format_version = 1
data_dir = "/node/state"
seed_file = "/secrets/node.seed"
control_socket = "/node/run/control.sock"
failure_domain = ""
recovery_mode = true
parity_budget_bytes = $PARITY_BUDGET_BYTES
p2p_listen_addresses = ["/ip4/0.0.0.0/udp/$(node_port "$node")/quic-v1"]
p2p_external_addresses = ["/ip4/$(node_ip "$node")/udp/$(node_port "$node")/quic-v1"]
p2p_bootstrap_addresses = ["$(peer_endpoint "$bootstrap_node")"]
p2p_relay_addresses = $relay
enable_relay_server = $relay_server
EOF
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

ensure_guild() {
    local phase
    phase=$(guild_phase 0)
    if [[ -z $phase ]]; then
        say "creating the fixed five-member guild"
        cli_raw 0 guild create >/dev/null
        phase=Draft
    fi
    if [[ $phase == Active ]]; then
        local node
        for node in 1 2 3 4; do
            [[ $(guild_phase "$node") == Active ]] ||
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
        else
            die "node $node is in unexpected guild phase $node_phase"
        fi
    done
    cli_raw 0 guild finalize >/dev/null
    [[ $(guild_phase 0) == Active ]] || die "guild finalization did not become active"
    say "five-member guild is active"
}

command_up() {
    prepare_host
    acquire_lock
    mkdir -p "$LAB_ROOT"/{images,mounts,loops,seeds,configs}
    chmod 700 "$LAB_ROOT" "$LAB_ROOT/seeds" "$LAB_ROOT/configs"

    if ! "${DOCKER[@]}" image inspect "$CONTAINER_IMAGE" >/dev/null 2>&1; then
        say "pulling container base image $CONTAINER_IMAGE (no image build)"
        "${DOCKER[@]}" pull "$CONTAINER_IMAGE"
    fi
    ensure_network

    local node
    for node in 0 1 2 3 4; do
        ensure_filesystem "$node"
    done
    for node in 0 1 2 3 4; do
        ensure_seed "$node"
    done
    for node in 0 1 2 3 4; do
        write_normal_config "$node"
        create_container "$node"
    done
    for node in 0 1 2 3 4; do
        start_node_internal "$node"
    done
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
    prepare_docker_only
    validate_node "$node"
    acquire_lock
    start_node_internal "$node"
    say "node $node is running"
}

command_restart() {
    local node=$1
    prepare_docker_only
    validate_node "$node"
    acquire_lock
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
    container_running "$node" || die "node $node must be running before reinit"
    cli_raw "$node" status | grep -q '^recovery ready: true$' ||
        die "node $node is not seed-recovery-ready; wait for DHT publication before reinit"

    local bootstrap_node='' bootstrap_count=0 candidate
    for candidate in 0 1 2 3 4; do
        if ((candidate != node)) && container_running "$candidate" &&
            cli_raw "$candidate" status >/dev/null 2>&1; then
            ((bootstrap_count += 1))
            if [[ -z $bootstrap_node ]]; then
                bootstrap_node=$candidate
            fi
        fi
    done
    ((bootstrap_count >= 3)) || die "reinit requires at least three other healthy nodes"
    confirm_reinit "$node" "$assume_yes"

    say "removing node $node container and disposable Btrfs state; preserving $(node_seed "$node")"
    remove_container "$node"
    unmount_filesystem "$node"
    rm -f "$(node_image "$node")"
    ensure_filesystem "$node"

    local config previous timestamp
    config=$(node_config "$node")
    if [[ -f $config ]]; then
        timestamp=$(date -u +%Y%m%dT%H%M%SZ)
        previous=$config.before-reinit-$timestamp-$$
        [[ ! -e $previous ]] || die "refusing to overwrite previous config $previous"
        mv "$config" "$previous"
        say "previous config retained at: $previous"
    fi
    write_recovery_config "$node" "$bootstrap_node"
    create_container "$node"
    start_node_internal "$node"

    say "node $node has its original seed identity and is connected through node $bootstrap_node"
    say "recovering guild state and latest owned revision into /node/exchange/$restore_name"
    if ! cli_raw "$node" restore "/node/exchange/$restore_name"; then
        say "recovery did not complete; the recovery-mode container remains running for inspection/retry" >&2
        say "retry with: $0 cli $node restore /node/exchange/$restore_name" >&2
        return 1
    fi
    say "host-visible restored tree: $(node_exchange "$node")/$restore_name"
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
        help|-h|--help) usage ;;
        *) usage >&2; die "unknown command: $command" ;;
    esac
}

main "$@"
