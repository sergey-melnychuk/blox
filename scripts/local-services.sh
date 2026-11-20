#!/usr/bin/env bash
# Runs a local Blox setup for end-to-end tries without Docker or TLS (RUN.md):
# anvil, the relay over plain HTTP, and the mock keystore (unless --no-keystore, when the
# Android app is the keystore). Everything listens on localhost. Ctrl-C stops everything.
#
#   scripts/local-services.sh                  # mock keystore
#   scripts/local-services.sh --phone          # the app over USB: --no-keystore plus adb reverse
#
# Give the mock keystore a QR string from a requester:
#   echo 'BLOX:…' > target/local/keystore.in
#
# Environment: ANVIL_PORT (8545), RELAY_PORT (8080),
# BLOX_LOCAL_DIR (target/local), ANVIL (anvil on the PATH or ~/.foundry/bin/anvil),
# BLOX_LOG (info). Logs and the keystore's output go to BLOX_LOCAL_DIR.
set -euo pipefail

keystore=1
phone=0
for a in "$@"; do
    case "$a" in
        --no-keystore) keystore=0 ;;
        --phone) keystore=0; phone=1 ;;
        -h | --help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done

root=$(cd "$(dirname "$0")/.." && pwd)
anvil_port=${ANVIL_PORT:-8545}
relay_port=${RELAY_PORT:-8080}
dir=${BLOX_LOCAL_DIR:-$root/target/local}
anvil=${ANVIL:-$(command -v anvil || echo "$HOME/.foundry/bin/anvil")}
[ -x "$anvil" ] || { echo "anvil not found: install Foundry or set ANVIL" >&2; exit 1; }

(cd "$root" && cargo build --release -q -p blox-relay -p blox-mock-keystore --bins)
bin=$root/target/release
mkdir -p "$dir"
rm -f "$dir"/{anvil,relay,keystore}.log "$dir/keystore.in"

pids=()
cleanup() {
    trap - EXIT INT TERM
    [ ${#pids[@]} -gt 0 ] && kill "${pids[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "$dir/keystore.in"
}
trap cleanup EXIT
trap 'cleanup; exit 0' INT TERM

"$anvil" --port "$anvil_port" > "$dir/anvil.log" 2>&1 &
pids+=($!)
BLOX_LISTEN="localhost:$relay_port" BLOX_LOG=${BLOX_LOG:-info} "$bin/blox-relay" > "$dir/relay.log" 2>&1 &
pids+=($!)

anvil_url=http://localhost:$anvil_port
relay_url=http://localhost:$relay_port

wait_for() { # what, command…
    local what=$1; shift
    for _ in $(seq 1 100); do "$@" > /dev/null 2>&1 && return 0; sleep 0.1; done
    echo "$what did not start; see $dir" >&2
    exit 1
}
wait_for anvil curl -sf -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$anvil_url"
wait_for relay curl -sf "http://localhost:$relay_port/v1/info"

if [ "$keystore" = 1 ]; then
    # A FIFO this script also holds open for writing, so the keystore never sees EOF and
    # each `echo … > keystore.in` reaches it.
    mkfifo "$dir/keystore.in"
    exec 3<> "$dir/keystore.in"
    "$bin/blox-mock-keystore" --endpoint "31337=$anvil_url" < "$dir/keystore.in" > "$dir/keystore.log" 2>&1 &
    pids+=($!)
    wait_for "mock keystore" grep -q ready "$dir/keystore.log"
fi

if [ "$phone" = 1 ]; then
    # The phone's localhost ports become this machine's, over USB.
    adb reverse "tcp:$anvil_port" "tcp:$anvil_port" > /dev/null
    adb reverse "tcp:$relay_port" "tcp:$relay_port" > /dev/null
fi

echo "anvil   $anvil_url  (chain 31337)"
echo "relay   $relay_url"
if [ "$phone" = 1 ]; then
    echo "phone   adb reverse done; in the app add the endpoint $anvil_url (chain 31337)"
fi
if [ "$keystore" = 1 ]; then
    echo "keystore  echo 'BLOX:…' > $dir/keystore.in   (output: $dir/keystore.log)"
fi
echo "requester example:"
echo "  cargo run -p blox-client --example send -- --relay $relay_url --print-uri \\"
echo "      --chain 31337 --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1000000000000000"
echo "Logs in $dir. Ctrl-C stops everything."

# Exit (and stop the rest) when any of them exits.
while kill -0 "${pids[@]}" 2> /dev/null; do sleep 1; done
echo "a service exited; see $dir" >&2
exit 1
