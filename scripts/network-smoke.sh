#!/usr/bin/env bash
set -euo pipefail

# The four daemon roles run in separate network namespaces. The coordinator and
# punched peer sit behind different port-preserving NATs; their private
# addresses are blocked cross-subnet, while DCUtR-observed public addresses are
# mapped back to the listener ports. The fallback peer has no inbound mapping.

if [[ $# -ne 1 ]]; then
  echo "usage: $0 DISPOSABLE_REFLINK_DIRECTORY" >&2
  exit 2
fi

test_root=$1
if [[ ! -d "$test_root" ]]; then
  echo "disposable reflink directory does not exist: $test_root" >&2
  exit 2
fi

for program in sudo ip iptables setpriv env sysctl; do
  if ! command -v "$program" >/dev/null 2>&1; then
    echo "$program is required for isolated network acceptance" >&2
    exit 2
  fi
done
if ! sudo -n true; then
  echo "passwordless sudo is required for disposable network namespaces" >&2
  exit 2
fi

sudo_program="$(command -v sudo)"
ip_program="$(command -v ip)"
iptables_program="$(command -v iptables)"
setpriv_program="$(command -v setpriv)"
env_program="$(command -v env)"
sysctl_program="$(command -v sysctl)"

run_sudo() {
  "$sudo_program" -n "$@"
}

run_iptables() {
  run_sudo "$iptables_program" "$@"
}

if ! run_iptables -m conntrack -h >/dev/null 2>&1; then
  echo "iptables conntrack support is required for isolated network acceptance" >&2
  exit 2
fi

suffix="$(printf '%x%x' "$$" "$RANDOM")"
suffix="${suffix: -7}"
coordinator_ns="mb-coordinator-$suffix"
punched_ns="mb-punched-$suffix"
fallback_ns="mb-fallback-$suffix"
relay_ns="mb-relay-$suffix"
coordinator_if="mbc$suffix"
punched_if="mbp$suffix"
fallback_if="mbf$suffix"
relay_if="mbr$suffix"
filter_chain="MBF$suffix"
prerouting_chain="MBR$suffix"
postrouting_chain="MBP$suffix"
original_forwarding="$($sysctl_program -n net.ipv4.ip_forward)"

cleanup() {
  set +e
  run_iptables -w -D FORWARD -j "$filter_chain" >/dev/null 2>&1
  run_iptables -w -F "$filter_chain" >/dev/null 2>&1
  run_iptables -w -X "$filter_chain" >/dev/null 2>&1
  run_iptables -w -t nat -D PREROUTING -j "$prerouting_chain" >/dev/null 2>&1
  run_iptables -w -t nat -D POSTROUTING -j "$postrouting_chain" >/dev/null 2>&1
  run_iptables -w -t nat -F "$prerouting_chain" >/dev/null 2>&1
  run_iptables -w -t nat -F "$postrouting_chain" >/dev/null 2>&1
  run_iptables -w -t nat -X "$prerouting_chain" >/dev/null 2>&1
  run_iptables -w -t nat -X "$postrouting_chain" >/dev/null 2>&1
  for namespace in "$coordinator_ns" "$punched_ns" "$fallback_ns" "$relay_ns"; do
    run_sudo "$ip_program" netns delete "$namespace" >/dev/null 2>&1
  done
  run_sudo "$sysctl_program" -q -w "net.ipv4.ip_forward=$original_forwarding" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

for namespace in "$coordinator_ns" "$punched_ns" "$fallback_ns" "$relay_ns"; do
  run_sudo "$ip_program" netns add "$namespace"
done

run_sudo "$ip_program" link add "$coordinator_if" type veth peer name eth0 netns "$coordinator_ns"
run_sudo "$ip_program" address add 10.203.0.1/24 dev "$coordinator_if"
run_sudo "$ip_program" link set "$coordinator_if" up
run_sudo "$ip_program" -n "$coordinator_ns" link set lo up
run_sudo "$ip_program" -n "$coordinator_ns" link set eth0 up
run_sudo "$ip_program" -n "$coordinator_ns" address add 10.203.0.2/24 dev eth0
run_sudo "$ip_program" -n "$coordinator_ns" route add default via 10.203.0.1

run_sudo "$ip_program" link add "$punched_if" type veth peer name eth0 netns "$punched_ns"
run_sudo "$ip_program" address add 10.204.0.1/24 dev "$punched_if"
run_sudo "$ip_program" link set "$punched_if" up
run_sudo "$ip_program" -n "$punched_ns" link set lo up
run_sudo "$ip_program" -n "$punched_ns" link set eth0 up
run_sudo "$ip_program" -n "$punched_ns" address add 10.204.0.2/24 dev eth0
run_sudo "$ip_program" -n "$punched_ns" route add default via 10.204.0.1

run_sudo "$ip_program" link add "$fallback_if" type veth peer name eth0 netns "$fallback_ns"
run_sudo "$ip_program" address add 10.205.0.1/24 dev "$fallback_if"
run_sudo "$ip_program" link set "$fallback_if" up
run_sudo "$ip_program" -n "$fallback_ns" link set lo up
run_sudo "$ip_program" -n "$fallback_ns" link set eth0 up
run_sudo "$ip_program" -n "$fallback_ns" address add 10.205.0.2/24 dev eth0
run_sudo "$ip_program" -n "$fallback_ns" route add default via 10.205.0.1

run_sudo "$ip_program" link add "$relay_if" type veth peer name eth0 netns "$relay_ns"
run_sudo "$ip_program" address add 198.18.0.1/24 dev "$relay_if"
run_sudo "$ip_program" address add 198.18.0.10/32 dev "$relay_if"
run_sudo "$ip_program" address add 198.18.0.11/32 dev "$relay_if"
run_sudo "$ip_program" address add 198.18.0.12/32 dev "$relay_if"
run_sudo "$ip_program" link set "$relay_if" up
run_sudo "$ip_program" -n "$relay_ns" link set lo up
run_sudo "$ip_program" -n "$relay_ns" link set eth0 up
run_sudo "$ip_program" -n "$relay_ns" address add 198.18.0.2/24 dev eth0
run_sudo "$ip_program" -n "$relay_ns" route add default via 198.18.0.1

run_sudo "$sysctl_program" -q -w net.ipv4.ip_forward=1

run_iptables -w -t nat -N "$prerouting_chain"
run_iptables -w -t nat -A PREROUTING -j "$prerouting_chain"
run_iptables -w -t nat -A "$prerouting_chain" -p udp -d 198.18.0.10 -j DNAT --to-destination 10.203.0.2
run_iptables -w -t nat -A "$prerouting_chain" -p udp -d 198.18.0.11 -j DNAT --to-destination 10.204.0.2

run_iptables -w -t nat -N "$postrouting_chain"
run_iptables -w -t nat -A POSTROUTING -j "$postrouting_chain"
run_iptables -w -t nat -A "$postrouting_chain" -s 10.203.0.0/24 -j SNAT --to-source 198.18.0.10
run_iptables -w -t nat -A "$postrouting_chain" -s 10.204.0.0/24 -j SNAT --to-source 198.18.0.11
run_iptables -w -t nat -A "$postrouting_chain" -s 10.205.0.0/24 -j SNAT --to-source 198.18.0.12

run_iptables -w -N "$filter_chain"
run_iptables -w -I FORWARD 1 -j "$filter_chain"
run_iptables -w -A "$filter_chain" -m conntrack --ctstate DNAT -j ACCEPT
run_iptables -w -A "$filter_chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for source in 10.203.0.0/24 10.204.0.0/24 10.205.0.0/24; do
  for destination in 10.203.0.0/24 10.204.0.0/24 10.205.0.0/24; do
    if [[ "$source" != "$destination" ]]; then
      run_iptables -w -A "$filter_chain" -s "$source" -d "$destination" -j REJECT
    fi
  done
  run_iptables -w -A "$filter_chain" -s "$source" -j ACCEPT
done
run_iptables -w -A "$filter_chain" -s 198.18.0.0/24 -j ACCEPT
run_iptables -w -A "$filter_chain" -j RETURN

export MUTUALBACKUP_REFLINK_TEST_ROOT="$test_root"
export MUTUALBACKUP_TEST_NETNS_COORDINATOR="$coordinator_ns"
export MUTUALBACKUP_TEST_NETNS_PUNCHED="$punched_ns"
export MUTUALBACKUP_TEST_NETNS_FALLBACK="$fallback_ns"
export MUTUALBACKUP_TEST_NETNS_RELAY="$relay_ns"
export MUTUALBACKUP_TEST_COORDINATOR_IP=10.203.0.2
export MUTUALBACKUP_TEST_PUNCHED_IP=10.204.0.2
export MUTUALBACKUP_TEST_RELAY_IP=198.18.0.2
export MUTUALBACKUP_TEST_HOST_IP=198.18.0.1
export MUTUALBACKUP_TEST_SUDO="$sudo_program"
export MUTUALBACKUP_TEST_IP="$ip_program"
export MUTUALBACKUP_TEST_SETPRIV="$setpriv_program"
export MUTUALBACKUP_TEST_ENV="$env_program"

cargo test -p mutualbackup --test prototype_acceptance \
  five_daemons_recover_latest_snapshot_from_seed_and_dht \
  --locked -- --ignored --exact --nocapture
