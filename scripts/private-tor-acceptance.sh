#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MUTUALBACKUP_REFLINK_TEST_ROOT:-}" ]]; then
  echo "MUTUALBACKUP_REFLINK_TEST_ROOT must name a disposable reflink filesystem" >&2
  exit 2
fi
if [[ ! -d "$MUTUALBACKUP_REFLINK_TEST_ROOT" ]]; then
  echo "MUTUALBACKUP_REFLINK_TEST_ROOT is not a directory: $MUTUALBACKUP_REFLINK_TEST_ROOT" >&2
  exit 2
fi
if [[ -z "${CHUTNEY_PATH:-}" || ! -x "$CHUTNEY_PATH/chutney" ]]; then
  echo "CHUTNEY_PATH must name the pinned Chutney source; use nix develop .#private-tor" >&2
  exit 2
fi

for command in arti awk cargo date python3 readlink sed tor; do
  if ! command -v "$command" >/dev/null; then
    echo "required command is unavailable: $command" >&2
    exit 2
  fi
done

# Tor's control sockets have a small platform path limit.  Do not inherit a
# potentially long Nix/Btrfs TMPDIR here: only MutualBackup's test root needs
# reflinks, while the disposable Chutney network needs short socket names.
work_dir="$(mktemp -d /tmp/mbtor.XXXXXX)"
export CHUTNEY_DATA_DIR="$work_dir/chutney-data"
export CHUTNEY_CONFIG_PHASE=1
export CHUTNEY_LAUNCH_PHASE=1
export CHUTNEY_START_TIME="${CHUTNEY_START_TIME:-300}"
export CHUTNEY_TOR_SANDBOX="${CHUTNEY_TOR_SANDBOX:-0}"
CHUTNEY_ARTI="$(command -v arti)"
CHUTNEY_TOR="$(command -v tor)"
PYTHON="$(command -v python3)"
export CHUTNEY_ARTI CHUTNEY_TOR PYTHON

network_started=0
test_succeeded=0
network_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/chutney/mutualbackup"

run_chutney() {
  (cd "$CHUTNEY_PATH" && ./chutney "$@")
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if (( network_started )); then
    run_chutney stop || true
  fi
  if (( test_succeeded )); then
    case "$work_dir" in
      /tmp/mbtor.*)
        rm -rf -- "$work_dir"
        ;;
      *)
        echo "refusing to remove unexpected temporary path: $work_dir" >&2
        ;;
    esac
  else
    echo "Private-Tor fixture retained for diagnosis: $work_dir" >&2
  fi
  exit "$exit_status"
}
trap cleanup EXIT INT TERM

run_chutney init --net-from-script-path "$network_file"
run_chutney configure
nodes_dir="$(readlink -f "$CHUTNEY_DATA_DIR/nodes")"

# A hidden service is fully reachable only after the consensus contains enough
# shared-random history for both its current and secondary HSDir rings. Speed
# up only Chutney's initial voting cycle so the fixture can establish that
# history in minutes rather than waiting through production-length rounds.
for authority in "$nodes_dir"/00[0-3]a; do
  sed -i -E \
    -e 's/^TestingV3AuthInitialVotingInterval .*/TestingV3AuthInitialVotingInterval 5/' \
    -e 's/^TestingV3AuthInitialVoteDelay .*/TestingV3AuthInitialVoteDelay 2/' \
    -e 's/^TestingV3AuthInitialDistDelay .*/TestingV3AuthInitialDistDelay 2/' \
    -e 's/^V3AuthVotingInterval .*/V3AuthVotingInterval 10/' \
    -e 's/^V3AuthVoteDelay .*/V3AuthVoteDelay 2/' \
    -e 's/^V3AuthDistDelay .*/V3AuthDistDelay 2/' \
    "$authority/torrc"
done

network_started=1
run_chutney start
run_chutney wait_for_bootstrap

generated_config="$nodes_dir/arti.toml"
if [[ ! -f "$generated_config" ]]; then
  echo "Chutney did not generate its Arti client configuration" >&2
  exit 1
fi

# Chutney's relay bootstrap check can finish before the next authority votes
# have published every relay and completed the shared-random protocol. Wait for
# the complete relay set and both shared-random values before freezing the
# disposable network's consensus interval.
consensus="$nodes_dir/000a/cached-microdesc-consensus"
consensus_deadline=$((SECONDS + 600))
while :; do
  published_relays=0
  current_srv=0
  previous_srv=0
  if [[ -f "$consensus" ]]; then
    published_relays="$(awk '$1 == "r" { count++ } END { print count + 0 }' "$consensus")"
    read -r current_srv previous_srv <<<"$(
      awk '
        $1 == "shared-rand-current-value" { current = 1 }
        $1 == "shared-rand-previous-value" { previous = 1 }
        END { print current + 0, previous + 0 }
      ' "$consensus"
    )"
  fi
  if (( published_relays >= 24 && current_srv == 1 && previous_srv == 1 )); then
    break
  fi
  if (( SECONDS >= consensus_deadline )); then
    echo \
      "private Tor consensus has $published_relays/24 relays, current SRV=$current_srv, previous SRV=$previous_srv" \
      >&2
    exit 1
  fi
  sleep 1
done

# Chutney's 20-second voting interval is useful while the disposable network
# forms, but it makes Arti withdraw and republish onion listeners on every
# synthetic directory transition. Once all relays are present, reload the four
# authorities with a long-lived consensus and wait until that consensus has
# actually been published with a quorum of signatures.
for authority in "$nodes_dir"/00[0-3]a; do
  sed -i -E \
    's/^V3AuthVotingInterval .*/V3AuthVotingInterval 1800/' \
    "$authority/torrc"
  authority_pid="$(<"$authority/pid")"
  if [[ ! "$authority_pid" =~ ^[0-9]+$ ]] || ! kill -0 "$authority_pid" 2>/dev/null; then
    echo "private Tor authority is not running: $authority" >&2
    exit 1
  fi
  kill -HUP "$authority_pid"
done

stable_deadline=$((SECONDS + 90))
while :; do
  published_relays="$(awk '$1 == "r" { count++ } END { print count + 0 }' "$consensus")"
  consensus_signatures="$(awk '$1 == "directory-signature" { count++ } END { print count + 0 }' "$consensus")"
  shared_random_values="$(awk '$1 ~ /^shared-rand-(current|previous)-value$/ { count++ } END { print count + 0 }' "$consensus")"
  valid_after="$(awk '$1 == "valid-after" { print $2 " " $3; exit }' "$consensus")"
  fresh_until="$(awk '$1 == "fresh-until" { print $2 " " $3; exit }' "$consensus")"
  freshness=0
  if [[ -n "$valid_after" && -n "$fresh_until" ]]; then
    freshness=$((
      $(date -u -d "$fresh_until" +%s) - $(date -u -d "$valid_after" +%s)
    ))
  fi
  if (( published_relays >= 24 && consensus_signatures >= 3 && shared_random_values >= 2 && freshness >= 1800 )); then
    break
  fi
  if (( SECONDS >= stable_deadline )); then
    echo "private Tor consensus did not stabilize after authority reload" >&2
    exit 1
  fi
  sleep 1
done

# Chutney's network configuration is shared, but each MutualBackup daemon must
# retain its own cache and state. Removing only this generated section lets the
# daemon inject its private paths while preserving the private consensus.
arti_config="$work_dir/arti-network.toml"
awk '
  /^\[storage(\.[^]]+)?\][[:space:]]*$/ { skipping_storage = 1; next }
  /^\[/ { skipping_storage = 0 }
  /^\[override_net_params\][[:space:]]*$/ {
    print
    print "\"guard-min-filtered-sample-size\" = 5"
    next
  }
  !skipping_storage { print }
' "$generated_config" >"$arti_config"

MUTUALBACKUP_PRIVATE_TOR_CONFIG="$arti_config" \
  cargo test -p mutualbackup --test prototype_acceptance \
  five_daemons_recover_from_seed_over_onion_only_libp2p \
  --locked -- --ignored --exact --nocapture

test_succeeded=1
