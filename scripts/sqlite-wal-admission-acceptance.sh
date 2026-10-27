#!/usr/bin/env bash
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/mutualbackup-wal-admission.XXXXXXXX")
cleanup() {
  status=$?
  if (( status == 0 )); then
    rm -rf -- "$work"
  else
    echo "SQLITE_WAL_ADMISSION_NEGATIVE_FIXTURE $work" >&2
  fi
}
trap cleanup EXIT

for mode in default debug; do
  flags=()
  if [[ $mode == debug ]]; then
    flags+=(-DSQLITE_DEBUG)
  fi
  mkdir -- "$work/$mode"
  "${CC:-cc}" -O0 -UNDEBUG -DMUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD=1043 \
    -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION "${flags[@]}" \
    -I"$repository/vendor/libsqlite3-sys/sqlite3" \
    "$repository/vendor/libsqlite3-sys/sqlite3/sqlite3.c" \
    "$repository/scripts/sqlite-wal-admission-probe.c" \
    -pthread -ldl -lm -o "$work/$mode/probe"
  (cd -- "$work/$mode" && ./probe)
done
