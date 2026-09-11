#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
namespace="mbpm-$$"
host_veth="mph$$"
peer_veth="mpn$$"
fixture_pid=""
scratch=$(mktemp -d /tmp/mutualbackup-port-mapping.XXXXXX)
events="$scratch/events"

cleanup() {
  set +e
  if [[ -n "$fixture_pid" ]]; then
    kill "$fixture_pid" 2>/dev/null
    wait "$fixture_pid" 2>/dev/null
  fi
  sudo ip netns del "$namespace" 2>/dev/null
  sudo ip link del "$host_veth" 2>/dev/null
  unlink "$events" 2>/dev/null
  rmdir "$scratch" 2>/dev/null
}
trap cleanup EXIT INT TERM

for command in awk cargo find ip python3 sort sudo; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

cd "$repo"

cargo test --locked -p mb-node --lib \
  real_nat_pmp_mapping_is_published_replaced_reacquired_and_withdrawn --no-run
target_dir=${CARGO_TARGET_DIR:-$repo/target}
test_binary=$(
  find "$target_dir/debug/deps" -maxdepth 1 -type f -perm -u+x \
    -name 'mb_node-*' -printf '%T@ %p\n' |
    sort -nr | awk 'NR == 1 { print $2 }'
)
[[ -n "$test_binary" ]] || {
  echo "could not locate the compiled mb-node test binary" >&2
  exit 1
}

sudo ip netns add "$namespace"
sudo ip link add "$host_veth" type veth peer name "$peer_veth"
sudo ip addr add 10.254.93.1/30 dev "$host_veth"
sudo ip link set "$host_veth" up
sudo ip link set "$peer_veth" netns "$namespace"
sudo ip netns exec "$namespace" ip link set lo up
sudo ip netns exec "$namespace" ip addr add 10.254.93.2/30 dev "$peer_veth"
sudo ip netns exec "$namespace" ip link set "$peer_veth" up
sudo ip netns exec "$namespace" ip route add default via 10.254.93.1

python3 "$repo/scripts/nat-pmp-fixture.py" \
  --bind 10.254.93.1 --events "$events" &
fixture_pid=$!
for _ in $(seq 1 50); do
  [[ -s "$events" ]] && break
  sleep 0.1
done
[[ -s "$events" ]] || {
  echo "NAT-PMP fixture did not become ready" >&2
  exit 1
}

sudo ip netns exec "$namespace" env \
  MUTUALBACKUP_NAT_PMP_CONTROL=10.254.93.1:5352 \
  MUTUALBACKUP_NAT_PMP_EVENTS="$events" \
  "$test_binary" \
    network::port_mapping::tests::real_nat_pmp_mapping_is_published_replaced_reacquired_and_withdrawn \
    --exact --nocapture

echo "port-mapping acceptance passed"
