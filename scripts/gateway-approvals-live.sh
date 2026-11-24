#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# A throwaway agent gateway with approvals, left running for a person to
# drive by hand: pair an approver (keep-desktop built with the test-approver
# feature, or a phone running a test build), then ask for signatures as an
# agent and decide them on the approver. Everything it makes, users, groups,
# vault and sockets, is removed when it exits.
#
# It sets up what scripts/gateway-approvals-e2e.sh does, with its own users,
# and needs the same e2e build of keep, whose test attestation root the
# desktop test approver's attestation is minted under:
#
#   scripts/lib/inject-e2e-pki.sh /tmp/pki
#   KEEP_E2E_CA_DER=/tmp/pki/ca.der RUSTFLAGS='--cfg keep_e2e_roots' \
#     cargo build --release -p keep-cli --target-dir target/e2e-roots
#   cargo build --release -p keep-agent --features mcp --example approval_peer
#   sudo KEEP_GATEWAY_LIVE=1 scripts/gateway-approvals-live.sh \
#     target/e2e-roots/release/keep target/release/examples/approval_peer
#
# It runs only as root, on a terminal, and only when KEEP_GATEWAY_LIVE=1.
# If it is killed with SIGKILL, nothing cleans up: stop the kglive* users'
# processes (pkill -u), remove the users and groups, and /run/kglive.

set -euo pipefail

if [[ "${KEEP_GATEWAY_LIVE:-}" != 1 ]]; then
    echo "refusing to run: this creates system users; set KEEP_GATEWAY_LIVE=1" >&2
    exit 2
fi
if [[ $(id -u) -ne 0 ]]; then
    echo "run as root" >&2
    exit 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
    echo "run on a terminal: pairing asks you to compare a fingerprint" >&2
    exit 2
fi
BIN_SRC=${1:?usage: gateway-approvals-live.sh path/to/e2e-keep path/to/approval_peer}
PEER_SRC=${2:?usage: gateway-approvals-live.sh path/to/e2e-keep path/to/approval_peer}

P=kglive
GW=${P}gw
RELAY_USER=${P}relay
ADMIN=${P}admin
A1=${P}a1
AGENTS=${P}agents
ADMINS=${P}admins
RUN=/run/${P}
PASS=live-vault-password
GW_PID=
HELPER_PID=
RELAY_PID=
CREATED_RUN=
. "$(dirname "$0")/lib/gateway-e2e.sh"

refuse_users $GW $RELAY_USER $ADMIN $A1
refuse_groups $GW $RELAY_USER $ADMIN $A1 $AGENTS $ADMINS
refuse_paths "$RUN"
WORK=$(mktemp -d /tmp/${P}.XXXXXX)

fail_context() {
    for log in gateway helper relay; do
        if [[ -f $WORK/$log.log ]]; then
            echo "--- $log log ---"
            tail -20 "$WORK/$log.log"
        fi
    done
}

cleanup() {
    stop_pid "$HELPER_PID" "$GW_PID" "$RELAY_PID"
    remove_created_accounts
    rm -rf "$WORK"
    if [[ -n $CREATED_RUN ]]; then rm -rf "$RUN"; fi
    echo "removed the live gateway, its users and its files"
}
trap cleanup EXIT

wait_for() {
    local file=$1 pattern=$2 secs=${3:-30}
    for _ in $(seq $((secs * 10))); do
        [[ -f $file ]] && grep -q -- "$pattern" "$file" && return 0
        sleep 0.1
    done
    fail "no \"$pattern\" in $(basename "$file") within $secs seconds"
}

for g in $AGENTS $ADMINS; do
    groupadd --system "$g"
    CREATED_GROUPS+=("$g")
done
add_user --user-group "$GW"
add_user --user-group "$RELAY_USER"
add_user --user-group -G "$ADMINS" "$ADMIN"
add_user --user-group -G "$AGENTS" "$A1"

chmod 0755 "$WORK"
umask 077
install -m 0755 "$BIN_SRC" "$WORK/keep"
install -m 0755 "$PEER_SRC" "$WORK/approval_peer"
KEEP=$WORK/keep
grep -q keep-e2e-roots-build "$KEEP" || fail "$BIN_SRC is not an e2e build, so it cannot take a test approver's attestation"
printf '{"entries":{}}' >"$WORK/attestation-status.json"
chmod 0644 "$WORK/attestation-status.json"

install -d -m 0700 -o "$GW" -g "$GW" "$WORK/vault-home"
VAULT=$WORK/vault-home/vault
as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" init --size 10 >/dev/null 2>&1
NPUB=$(as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" generate --name agent 2>&1 \
    | grep -o 'npub1[0-9a-z]*' | head -1)
[[ -n $NPUB ]] || fail "no key generated"

install -d -m 0755 "$RUN"
CREATED_RUN=1
install -d -m 0750 -o "$GW" -g "$AGENTS" "$RUN/agent"
install -d -m 0750 -o "$GW" -g "$ADMINS" "$RUN/admin"
install -d -m 0750 -o "$GW" -g "$RELAY_USER" "$RUN/relay"
AGENT_SOCK=$RUN/agent/agent.sock
ADMIN_SOCK=$RUN/admin/admin.sock
RELAY_SOCK=$RUN/relay/relay.sock

CREDS=$WORK/creds
make_creds "$CREDS"
KEY=$(as "$GW" "$KEEP" gateway channel-key new 2>/dev/null | cat)
[[ $KEY =~ ^[0-9a-f]{64}$ ]] || fail "the channel key is not 64 hex digits"
printf '%s\n' "$KEY" >"$CREDS/channel-key"
KEY=
chown "$GW" "$CREDS/channel-key"
chmod 0400 "$CREDS/channel-key"
chmod 0500 "$CREDS"

PORT=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
RELAY_URL=ws://127.0.0.1:$PORT
as "$RELAY_USER" "$WORK/approval_peer" relay "$PORT" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
wait_for "$WORK/relay.log" "^relay "

setpriv --reuid="$GW" --regid="$(id -g "$GW")" --init-groups \
    env -i PATH=/usr/bin:/bin HOME="$WORK" CREDENTIALS_DIRECTORY="$CREDS" RUST_LOG=info \
    "$KEEP" --path "$VAULT" gateway serve \
    --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" \
    --admin-uid "$(uid "$ADMIN")" \
    --approval-relay "$RELAY_URL" --approval-deadline 120 \
    --relay-socket "$RELAY_SOCK" --relay-user "$RELAY_USER" \
    >>"$WORK/gateway.log" 2>&1 &
GW_PID=$!
for _ in $(seq 100); do
    "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1 && break
    kill -0 "$GW_PID" 2>/dev/null || fail "the gateway exited at start: $(tail -5 "$WORK/gateway.log")"
    sleep 0.1
done
as "$RELAY_USER" env RUST_LOG=info "$KEEP" gateway relay --relay-socket "$RELAY_SOCK" --gateway-user "$GW" \
    >>"$WORK/helper.log" 2>&1 &
HELPER_PID=$!
wait_for "$WORK/gateway.log" "relay helper connected"

install -d -m 0700 "$WORK/root-out"
"$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name live --uid "$(uid "$A1")" \
    --key "$NPUB" --op get_public_key --op sign_nostr_event --kind 1 --kind 0 --per-minute 60 \
    --token-out "$WORK/root-out/token" >"$WORK/issue.json" 2>"$WORK/issue.err" \
    || fail "issue: $(cat "$WORK/issue.err")"
CID=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/issue.json")
install -d -m 0700 -o "$A1" "$WORK/a1"
install -m 0600 -o "$A1" "$WORK/root-out/token" "$WORK/a1/token"

cat >"$WORK/client.py" <<'PY'
import json, socket, sys
sock_path, token_path = sys.argv[1], sys.argv[2]
token = open(token_path).read().strip()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(150)
s.connect(sock_path)
f = s.makefile("rwb")
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    f.write((json.dumps({"token": token, "message": json.loads(line)}) + "\n").encode())
    f.flush()
    answer = f.readline()
    if not answer:
        print("the gateway closed the connection", flush=True)
        break
    answer = json.loads(answer)
    if "result" not in answer:
        print("error:", json.dumps(answer.get("error", answer)), flush=True)
        continue
    reply = answer["result"]
    text = reply["content"][0]["text"]
    if reply.get("isError"):
        print("refused:", text, flush=True)
    else:
        print("signed:", json.loads(text)["sig"], flush=True)
PY
chmod 0644 "$WORK/client.py"

pass "gateway running, key $NPUB, credential $CID for $A1 (kinds 0 and 1)"
echo
echo "Pair your approver now. In keep-desktop (built with --features test-approver),"
echo "open Test Approver, paste the pairing link printed below, and answer yes here"
echo "only if the fingerprint the app shows matches."
echo
"$KEEP" gateway approver pair --label Desktop --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" \
    --attestation-status "$WORK/attestation-status.json" || fail "pairing did not finish"

echo
echo "Ask as the agent. Kind 1 signs at once, kind 0 waits up to 120 s for your"
echo "decision on the approver, and a freeze there refuses both."
echo "  <kind> [text]  ask for a signature, e.g. '0 my profile' or '1 hello'"
echo "  status         the gateway's status"
echo "  quit           stop and remove everything"
n=0
while read -r -p "agent> " kind text; do
    case $kind in
        quit | q) break ;;
        status) "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" || echo "status failed" ;;
        '' ) ;;
        *[!0-9]* | 0?*) echo "a kind number without leading zeros, status or quit" ;;
        *)
            n=$((n + 1))
            content=$(python3 -I -c 'import json,sys; print(json.dumps(sys.argv[1])[1:-1])' "${text:-hello from the live gateway}")
            # Ctrl-C ends only this request, not the session.
            trap ':' INT
            printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"sign_nostr_event","arguments":{"kind":%s,"content":"%s"}}}\n' \
                "$n" "$kind" "$content" \
                | as "$A1" python3 -I "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/token" \
                || echo "the request failed"
            trap - INT
            ;;
    esac
done
