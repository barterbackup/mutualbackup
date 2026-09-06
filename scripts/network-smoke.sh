#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 MUTUALBACKUP_BINARY REFLINK_WORK_DIRECTORY [BASE_PORT]" >&2
    exit 2
fi

binary=$(realpath "$1")
work_root=$(realpath "$2")
base_port=${3:-45100}
run_root=$(mktemp -d "$work_root/mutualbackup-network-smoke.XXXXXX")
source_dir="$run_root/source-that-will-be-deleted"
seed_dir="$run_root/seeds-kept-off-node"
log_dir="$run_root/logs"
mkdir -p "$source_dir/documents" "$seed_dir" "$log_dir"

pids=()
cleanup() {
    if ((${#pids[@]})); then
        kill "${pids[@]}" 2>/dev/null || true
        wait "${pids[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

wait_for_port() {
    local port=$1
    local attempt
    for attempt in $(seq 1 100); do
        if (exec 9<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 9>&-
            exec 9<&-
            return 0
        fi
        sleep 0.1
    done
    echo "service on port $port did not become ready" >&2
    return 1
}

printf '%s\n' 'This tree was recovered through five independent node processes.' \
    >"$source_dir/documents/hello.txt"
truncate -s 393216 "$source_dir/sparse-with-data.bin"
printf '%s' 'data beyond a sparse extent' \
    | dd of="$source_dir/sparse-with-data.bin" bs=1 seek=300000 conv=notrunc status=none
(
    cd "$source_dir"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$run_root/expected.sha256"

for index in $(seq 0 4); do
    "$binary" init --seed-file "$seed_dir/node-$index.seed" \
        >"$log_dir/init-$index.log"
done
leader_id=$(
    "$binary" identity --seed-file "$seed_dir/node-0.seed" \
        | sed -n 's/^node id: *//p'
)
if [[ -z "$leader_id" ]]; then
    echo "could not derive coordinator node ID" >&2
    exit 1
fi

directory_port=$base_port
"$binary" serve-directory --listen "127.0.0.1:$directory_port" \
    >"$log_dir/directory.log" 2>&1 &
pids+=("$!")
wait_for_port "$directory_port"

peers=()
for index in $(seq 0 4); do
    port=$((base_port + index + 1))
    peers+=("127.0.0.1:$port")
    "$binary" serve-node \
        --seed-file "$seed_dir/node-$index.seed" \
        --data-dir "$run_root/node-$index" \
        --listen "127.0.0.1:$port" \
        --public-endpoint "tcp://127.0.0.1:$port" \
        --failure-domain "test-host-$index" \
        --trusted-coordinator "$leader_id" \
        >"$log_dir/node-$index.log" 2>&1 &
    pids+=("$!")
    wait_for_port "$port"
done

peer_args=()
for peer in "${peers[@]}"; do
    peer_args+=(--peer "$peer")
done
"$binary" commit \
    --seed-file "$seed_dir/node-0.seed" \
    --source "$source_dir" \
    --directory "127.0.0.1:$directory_port" \
    "${peer_args[@]}" | tee "$log_dir/commit.log"

# Lose the owner and one helper completely. The seed remains outside node state,
# modelling the user's offline recovery copy.
kill "${pids[1]}" "${pids[2]}"
wait "${pids[1]}" 2>/dev/null || true
wait "${pids[2]}" 2>/dev/null || true
rm -rf -- "$run_root/node-0" "$run_root/node-1" "$source_dir"

"$binary" recover \
    --seed-file "$seed_dir/node-0.seed" \
    --data-dir "$run_root/recovered-node-state" \
    --restore "$run_root/restored-from-seed" \
    --directory "127.0.0.1:$directory_port" | tee "$log_dir/recover.log"

(
    cd "$run_root/restored-from-seed"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$run_root/restored.sha256"
cmp "$run_root/expected.sha256" "$run_root/restored.sha256"

echo "five-process seed-only recovery smoke test passed"
echo "test state and logs: $run_root"
