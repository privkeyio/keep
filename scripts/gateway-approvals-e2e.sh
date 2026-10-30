#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# End-to-end test of the agent gateway's approvals, with real users and a
# real relay: the gateway runs as its own user with the channel key in its
# credentials directory, the relay helper as another, an agent as a third,
# and a stand-in phone (keep-agent's approval_peer example) pairs through
# `keep gateway approver pair` and decides over a local relay.
#
# The stand-in phone's attestation is minted under a test root that only an
# e2e build of keep trusts, so the keep given is that build (see
# scripts/lib/inject-e2e-pki.sh for the inject test root it also needs).
#
# Creates and removes system users and groups, so it runs only as root and
# only when KEEP_GATEWAY_E2E=1:
#
#   scripts/lib/inject-e2e-pki.sh /tmp/pki
#   KEEP_E2E_CA_DER=/tmp/pki/ca.der RUSTFLAGS='--cfg keep_e2e_roots' \
#     cargo build --release -p keep-cli --target-dir target/e2e-roots
#   cargo build --release -p keep-agent --features mcp --example approval_peer
#   sudo KEEP_GATEWAY_E2E=1 scripts/gateway-approvals-e2e.sh \
#     target/e2e-roots/release/keep target/release/examples/approval_peer [old-keep]
#
# Built with KEEP_E2E_APP_SIGNER also set, to a test signing key's SHA-256
# certificate digest as `apksigner verify --print-certs` prints it, the same
# keep pairs a real phone running Keep signed with that key. A release build
# takes only the release key.
#
# With KEEP_E2E_PHONE naming keep-mobile's mobile_approver example, that is
# the phone instead: the app's own approver code, against the real gateway.
#
# With an older keep binary as the third argument, it also runs old and new
# binaries against each other: the old bridge and admin commands against
# the new gateway, and the new bridge against an old gateway.

set -euo pipefail

if [[ "${KEEP_GATEWAY_E2E:-}" != 1 ]]; then
    echo "refusing to run: this creates system users; set KEEP_GATEWAY_E2E=1" >&2
    exit 2
fi
if [[ $(id -u) -ne 0 ]]; then
    echo "run as root" >&2
    exit 2
fi
BIN_SRC=${1:?usage: gateway-approvals-e2e.sh path/to/keep path/to/approval_peer [path/to/old-keep]}
PEER_SRC=${2:?usage: gateway-approvals-e2e.sh path/to/keep path/to/approval_peer [path/to/old-keep]}
OLD_SRC=${3:-}

P=kgwap
GW=${P}gw
RELAY_USER=${P}relay
ADMIN=${P}admin
A1=${P}a1
AGENTS=${P}agents
ADMINS=${P}admins
RUN=/run/${P}
PASS=e2e-vault-password
GW_PID=
HELPER_PID=
RELAY_PID=
PHONE_PID=
OLD_GW_PID=
PAIR_PID=
AGENT_PID=
CLI_PID=
MCP_PID=
CREATED_RUN=
. "$(dirname "$0")/lib/gateway-e2e.sh"

refuse_users $GW $RELAY_USER $ADMIN $A1
refuse_groups $GW $RELAY_USER $ADMIN $A1 $AGENTS $ADMINS
refuse_paths "$RUN"
WORK=$(mktemp -d /tmp/${P}.XXXXXX)

fail_context() {
    for log in gateway helper phone; do
        if [[ -f $WORK/$log.log ]]; then
            echo "--- $log log ---"
            tail -40 "$WORK/$log.log"
        fi
    done
}

cleanup() {
    { exec 7>&-; } 2>/dev/null || true
    stop_pid "$PAIR_PID" "$CLI_PID" "$MCP_PID" "$AGENT_PID" "$PHONE_PID" "$HELPER_PID" "$GW_PID" "$OLD_GW_PID" "$RELAY_PID"
    remove_created_accounts
    rm -rf "$WORK"
    if [[ -n $CREATED_RUN ]]; then rm -rf "$RUN"; fi
}
trap cleanup EXIT

for g in $AGENTS $ADMINS; do
    groupadd --system "$g"
    CREATED_GROUPS+=("$g")
done
add_user --user-group "$GW"
add_user --user-group "$RELAY_USER"
add_user --user-group -G "$ADMINS" "$ADMIN"
add_user --user-group -G "$AGENTS" "$A1"

chmod 0755 "$WORK"
install -m 0755 "$BIN_SRC" "$WORK/keep"
install -m 0755 "$PEER_SRC" "$WORK/approval_peer"
KEEP=$WORK/keep
grep -q keep-e2e-roots-build "$KEEP" || fail "$BIN_SRC is not an e2e build, so it cannot take the stand-in phone's attestation"
# Google's attestation status list, as the pair command reads it: nothing
# revoked, and one that revokes the stand-in's intermediate.
printf '{"entries":{}}' >"$WORK/attestation-status.json"
printf '{"entries":{"2c8c":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}' >"$WORK/attestation-revoked.json"
chmod 0644 "$WORK/attestation-status.json" "$WORK/attestation-revoked.json"
PEER=$WORK/approval_peer
PHONE=$PEER
if [[ -n ${KEEP_E2E_PHONE:-} ]]; then
    install -m 0755 "$KEEP_E2E_PHONE" "$WORK/phone"
    PHONE=$WORK/phone
fi
OLD=
if [[ -n $OLD_SRC ]]; then
    install -m 0755 "$OLD_SRC" "$WORK/old-keep"
    OLD=$WORK/old-keep
fi
# Wait at most `secs` seconds for `file` to hold `count` lines matching
# `pattern`. grep reads the file itself: nothing is piped into grep -q.
wait_for() {
    local file=$1 pattern=$2 count=${3:-1} secs=${4:-60}
    for _ in $(seq $((secs * 10))); do
        if [[ -f $file ]] && [[ $(grep -c -- "$pattern" "$file" || true) -ge $count ]]; then
            return 0
        fi
        sleep 0.1
    done
    fail "no $count of \"$pattern\" in $(basename "$file") within $secs seconds"
}

# The vault, owned by the gateway's user.
install -d -m 0700 -o "$GW" -g "$GW" "$WORK/vault-home"
VAULT=$WORK/vault-home/vault
as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" init --size 10 >/dev/null 2>&1
NPUB=$(as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" generate --name agent 2>&1 \
    | grep -o 'npub1[02-9ac-hj-np-z]*' | head -1)
[[ -n $NPUB ]] || fail "no key generated"
# A fixed key, so the PSBT below spends its wallet: a 9,900 sat payment plus a
# 100 sat fee, 10,000 leaving the wallet.
BTC_NSEC=nsec1qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qursl6edet
BTC_NPUB=$(as "$GW" env KEEP_PASSWORD=$PASS KEEP_NSEC=$BTC_NSEC "$KEEP" --path "$VAULT" import --name btc 2>&1 \
    | grep -o 'npub1[02-9ac-hj-np-z]*' | head -1)
[[ -n $BTC_NPUB ]] || fail "no key imported"
PSBT_10K=cHNidP8BAIkCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AqwmAAAAAAAAIlEgSDozZGbTHivoWJKTHsZhPKGfmmdiMpaYtMPnFRwBEiuQXwEAAAAAACJRIBdkDVXpEkGdKY8b7CMugitBSCKlL015dMRbbjJfMvDyAAAAAAABASughgEAAAAAACJRINRr8NHDB6I1lP/aFgiyPX+qRronccmpiPC3H6oQJ0qEIRbiZSIirsrwjZtJGRd/9GgjsQH+XrPXYy6Ykdg4jjcyhhkA4oZ7tlYAAIABAACAAAAAgAAAAAAAAAAAARcg4mUiIq7K8I2bSRkXf/RoI7EB/l6z12MumJHYOI43MoYAAAEFIB7t8WA86BP/Kclg28W5Rx+5Lfc7rknIiP3Jvqq1cD6bIQce7fFgPOgT/ynJYNvFuUcfuS33O65JyIj9yb6qtXA+mxkA4oZ7tlYAAIABAACAAAAAgAEAAAAAAAAAAA==
pass "vault created with keys $NPUB and $BTC_NPUB"

install -d -m 0755 "$RUN"
CREATED_RUN=1
install -d -m 0750 -o "$GW" -g "$AGENTS" "$RUN/agent"
install -d -m 0750 -o "$GW" -g "$ADMINS" "$RUN/admin"
install -d -m 0750 -o "$GW" -g "$RELAY_USER" "$RUN/relay"
AGENT_SOCK=$RUN/agent/agent.sock
ADMIN_SOCK=$RUN/admin/admin.sock
RELAY_SOCK=$RUN/relay/relay.sock

# The channel key goes only to a pipe.
if as "$GW" "$KEEP" gateway channel-key new >"$WORK/channel-key.file" 2>"$WORK/channel-key.err"; then
    fail "the channel key was written to a file"
fi
[[ ! -s $WORK/channel-key.file ]] || fail "the channel key reached a file"
grep -q "only to a pipe" "$WORK/channel-key.err" || fail "channel key to a file: $(cat "$WORK/channel-key.err")"
new_channel_key() {
    local dir=$1 key
    key=$(as "$GW" "$KEEP" gateway channel-key new 2>"$WORK/channel-key.err" | cat)
    [[ $key =~ ^[0-9a-f]{64}$ ]] || fail "the channel key is not 64 hex digits"
    grep -q "channel key npub1" "$WORK/channel-key.err" || fail "no public key on stderr"
    printf '%s\n' "$key" >"$dir/channel-key"
    chown "$GW" "$dir/channel-key"
    chmod 0400 "$dir/channel-key"
}

# Credentials as systemd hands them to the gateway: the vault password, and
# the channel key in a directory of its own for each case below.
CREDS=$WORK/creds
make_creds "$CREDS"
new_channel_key "$CREDS"
chmod 0500 "$CREDS"
NO_KEY=$WORK/creds-no-key
make_creds "$NO_KEY"
chmod 0500 "$NO_KEY"
OTHER_KEY=$WORK/creds-other-key
make_creds "$OTHER_KEY"
new_channel_key "$OTHER_KEY"
chmod 0500 "$OTHER_KEY"
pass "the channel key goes only to a pipe, with its public key on stderr"

# A local relay.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
RELAY_URL=ws://127.0.0.1:$PORT
"$PEER" relay "$PORT" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
wait_for "$WORK/relay.log" "^relay " 1 10
pass "relay at $RELAY_URL"

GW_CREDS=$CREDS
start_gateway() {
    setpriv --reuid="$GW" --regid="$(id -g "$GW")" --init-groups \
        env -i PATH=/usr/bin:/bin HOME="$WORK" CREDENTIALS_DIRECTORY="$GW_CREDS" RUST_LOG=info \
        "$KEEP" --path "$VAULT" gateway serve \
        --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" \
        --admin-uid "$(uid "$ADMIN")" --wallet-budget-sats 100000 \
        --approval-relay "$RELAY_URL" --approval-deadline 30 \
        --relay-socket "$RELAY_SOCK" --relay-user "$RELAY_USER" \
        >>"$WORK/gateway.log" 2>&1 &
    GW_PID=$!
    for _ in $(seq 100); do
        "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1 && return 0
        kill -0 "$GW_PID" 2>/dev/null || fail "gateway exited at start"
        sleep 0.1
    done
    fail "gateway did not start"
}
stop_gateway() {
    kill -TERM "$GW_PID"
    local status=0
    reap "$GW_PID" || status=$?
    GW_PID=
    [[ $status -eq 0 ]] || fail "gateway exited $status on SIGTERM"
}
# A gateway that must refuse to start, and why.
refuses_start() {
    local creds=$1 want=$2 msg
    shift 2
    if msg=$(as "$GW" timeout 20 env CREDENTIALS_DIRECTORY="$creds" "$KEEP" --path "$VAULT" gateway serve \
        --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" --admin-uid "$(uid "$ADMIN")" \
        --relay-socket "$RELAY_SOCK" --relay-user "$RELAY_USER" "$@" </dev/null 2>&1); then
        fail "the gateway started, though: $want"
    fi
    grep -q -- "$want" <<<"$msg" || fail "expected \"$want\": $msg"
    [[ ! -e $AGENT_SOCK && ! -e $ADMIN_SOCK && ! -e $RELAY_SOCK ]] || fail "a refused gateway left a socket"
}

# Approvals need a relay.
refuses_start "$CREDS" "at least one relay"
pass "a channel key without a relay is refused"

start_gateway
status_field() {
    "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" 2>/dev/null \
        | python3 -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1].split("."): v=v[k]
print(json.dumps(v))' "$1"
}
[[ $(status_field approvals.configured) == true ]] || fail "approvals not configured"
[[ $(status_field approvals.approvers) == 0 ]] || fail "approvers before pairing"
pass "gateway running with approvals configured and no approver"

# The relay helper: never root, and only as the relay user.
if msg=$(timeout 10 "$KEEP" gateway relay --relay-socket "$RELAY_SOCK" --gateway-user "$GW" </dev/null 2>&1); then
    fail "the relay helper ran as root"
fi
grep -q "never root" <<<"$msg" || fail "helper as root: $msg"
as "$RELAY_USER" env RUST_LOG=info "$KEEP" gateway relay --relay-socket "$RELAY_SOCK" --gateway-user "$GW" \
    >>"$WORK/helper.log" 2>&1 &
HELPER_PID=$!
wait_for "$WORK/helper.log" "connected to the gateway's relay socket" 1 20
wait_for "$WORK/gateway.log" "relay helper connected" 1 20
if as "$A1" python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])' "$RELAY_SOCK" 2>/dev/null; then
    fail "an agent reached the relay socket"
fi
pass "the relay helper runs as $RELAY_USER, never root, and agents cannot reach its socket"

# A credential for agent 1, issued at once while no phone is paired.
install -d -m 0700 "$WORK/root-out"
"$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name e2e --uid "$(uid "$A1")" \
    --key "$NPUB" --op get_public_key --op sign_nostr_event --kind 1 --kind 0 --per-minute 60 \
    --token-out "$WORK/root-out/token" >"$WORK/issue.json" 2>"$WORK/issue.err" \
    || fail "issue: $(cat "$WORK/issue.err")"
CID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/issue.json")
install -d -m 0700 -o "$A1" "$WORK/a1"
install -m 0600 -o "$A1" "$WORK/root-out/token" "$WORK/a1/token"
# And a testnet PSBT signer whose spends past 5,000 sats in a day need an
# approval.
"$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name btc --uid "$(uid "$A1")" \
    --key "$BTC_NPUB" --op sign_psbt --network testnet --per-psbt-sats 20000 --window-sats 50000 \
    --approval-above-sats 5000 --token-out "$WORK/root-out/btc" >/dev/null 2>"$WORK/issue.err" \
    || fail "issue the Bitcoin credential: $(cat "$WORK/issue.err")"
install -m 0600 -o "$A1" "$WORK/root-out/btc" "$WORK/a1/btc"
pass "issued credentials without approval while no phone is paired"

# The agent client: one envelope per line, waiting up to 150 seconds for
# each answer, as `keep agent connect` does.
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
        print("CLOSED", flush=True)
        break
    print(answer.decode().strip(), flush=True)
PY
chmod 0644 "$WORK/client.py"
sign() {
    printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"sign_nostr_event","arguments":{"kind":%s,"content":"%s"}}}\n' \
        "$1" "$2" "${3:-hello}"
}
# Agent 1 asks; the answer lands in `out`.
agent() {
    local out=$1
    shift
    printf '%s\n' "$@" | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/token" >"$out" 2>&1
}
is_signed() { python3 -c 'import json,sys
a=json.loads(open(sys.argv[1]).readline())
r=a["result"]; assert r["isError"] is False, a
e=json.loads(r["content"][0]["text"]); assert len(e["sig"])==128, e' "$1"; }
error_text() { python3 -c 'import json,sys
a=json.loads(open(sys.argv[1]).readline())
r=a.get("result")
print(r["content"][0]["text"] if r and r.get("isError") else json.dumps(a))' "$1"; }

agent "$WORK/kind0-off.out" "$(sign 1 0)"
grep -q "cannot obtain yet" <<<"$(error_text "$WORK/kind0-off.out")" \
    || fail "kind 0 with no phone: $(cat "$WORK/kind0-off.out")"
pass "a request that needs approval is refused while no phone is paired"

# Pairing needs a terminal to confirm the fingerprint on, checked before
# the gateway is asked.
if msg=$("$KEEP" gateway approver pair --label Phone --admin-socket "$ADMIN_SOCK" \
    --gateway-user "$GW" --attestation-status "$WORK/attestation-status.json" </dev/null 2>&1); then
    fail "pairing went ahead without a terminal"
fi
grep -q "confirmed on a terminal" <<<"$msg" || fail "pairing without a terminal: $msg"
pass "pairing without a terminal is refused before the gateway is asked"

# Only root pairs the first phone: the admin uid, on a terminal, is refused
# by the gateway.
if msg=$(as "$ADMIN" timeout 20 python3 -c 'import os, pty, sys
sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' \
    "$KEEP" gateway approver pair --label Phone --admin-socket "$ADMIN_SOCK" \
    --gateway-user "$GW" --attestation-status "$WORK/attestation-status.json" </dev/null 2>&1); then
    fail "the admin uid paired the first phone"
fi
grep -q "only root may pair the first" <<<"$msg" || fail "admin pairing first: $msg"
pass "only root pairs the first phone"

# Pairing on a terminal: the driver runs `keep gateway approver pair` on a
# pty, hands the pairing code to the phone, and answers the fingerprint
# question with whether the phone shows the same.
write_pair_driver "$WORK/pair.py"

# A phone whose attestation chain holds a certificate Google revoked is
# refused before its fingerprint is shown, and the session is used up.
python3 "$WORK/pair.py" "$WORK/uri-revoked" "$WORK/phone-revoked.fp" "$WORK/pair-revoked.answer" \
    "$KEEP" gateway approver pair --label Phone --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" \
    --attestation-status "$WORK/attestation-revoked.json" >"$WORK/pair-revoked.out" 2>&1 &
PAIR_PID=$!
for _ in $(seq 300); do [[ -f $WORK/uri-revoked ]] && break; sleep 0.1; done
[[ -f $WORK/uri-revoked ]] || fail "no pairing code: $(cat "$WORK/pair-revoked.out")"
"$PHONE" phone "$(cat "$WORK/uri-revoked")" </dev/null >"$WORK/phone-revoked.log" 2>&1 &
PHONE_PID=$!
if wait "$PAIR_PID"; then
    fail "a phone with a revoked attestation certificate paired: $(cat "$WORK/pair-revoked.out")"
fi
PAIR_PID=
grep -q "certificate 2c8c is revoked or suspended" "$WORK/pair-revoked.out" \
    || fail "the revoked attestation was not named: $(cat "$WORK/pair-revoked.out")"
grep -qE "shows fingerprint: +[0-9a-f]{4} " "$WORK/pair-revoked.out" && fail "the fingerprint was shown for a revoked attestation"
for _ in $(seq 300); do grep -q '^refused' "$WORK/phone-revoked.log" && break; sleep 0.1; done
grep -q '^refused' "$WORK/phone-revoked.log" || fail "the phone was not refused: $(cat "$WORK/phone-revoked.log")"
stop_pid "$PHONE_PID"
PHONE_PID=
pass "a phone whose attestation names a revoked certificate is refused"

python3 "$WORK/pair.py" "$WORK/uri" "$WORK/phone.fp" "$WORK/pair.answer" \
    "$KEEP" gateway approver pair --label Phone --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" \
    --attestation-status "$WORK/attestation-status.json" >"$WORK/pair.out" 2>&1 &
PAIR_PID=$!
for _ in $(seq 300); do [[ -f $WORK/uri ]] && break; sleep 0.1; done
[[ -f $WORK/uri ]] || fail "no pairing code: $(cat "$WORK/pair.out")"
mkfifo -m 0600 "$WORK/phone.in"
"$PHONE" phone "$(cat "$WORK/uri")" <"$WORK/phone.in" >"$WORK/phone.log" 2>&1 &
PHONE_PID=$!
exec 7>"$WORK/phone.in"
phone() { printf '%s\n' "$1" >&7; }
wait_for "$WORK/phone.log" "^fingerprint " 1 30
awk '/^fingerprint / {sub(/^fingerprint /, ""); print; exit}' "$WORK/phone.log" >"$WORK/phone.fp.tmp"
mv "$WORK/phone.fp.tmp" "$WORK/phone.fp"
wait "$PAIR_PID" || fail "pairing: $(cat "$WORK/pair.out")"
[[ $(cat "$WORK/pair.answer") == same ]] || fail "the fingerprints differ"
wait_for "$WORK/phone.log" "^paired$" 1 30
[[ $(status_field approvals.approvers) == 1 ]] || fail "no approver after pairing"
grep -q "keep-approver:v1?" "$WORK/pair.out" || fail "no pairing code shown"
pass "root paired the phone after comparing fingerprints $(cat "$WORK/phone.fp")"

requests() { grep -c "^request " "$WORK/phone.log" || true; }
outcomes() { grep -c "^outcome " "$WORK/phone.log" || true; }

# Kind 1 needs no approval; kind 0 waits for the phone.
agent "$WORK/kind1.out" "$(sign 2 1)"
is_signed "$WORK/kind1.out" || fail "kind 1: $(cat "$WORK/kind1.out")"
n=$(requests)
agent "$WORK/kind0.out" "$(sign 3 0)" &
AGENT_PID=$!
wait_for "$WORK/phone.log" '^request .*sign_nostr_event' $((n + 1)) 30
phone approve
wait "$AGENT_PID" || true
is_signed "$WORK/kind0.out" || fail "approved kind 0: $(cat "$WORK/kind0.out")"
wait_for "$WORK/phone.log" '^outcome .*"approved"' 1 30
pass "an approved request is signed and the phone is told"

# A spend past the threshold waits for the phone, which checks its figures.
n=$(requests)
printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sign_bitcoin_psbt","arguments":{"psbt":"%s"}}}\n' \
    "$PSBT_10K" | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/btc" >"$WORK/psbt.out" 2>&1 &
AGENT_PID=$!
wait_for "$WORK/phone.log" "^request " $((n + 1)) 30
grep '^request ' "$WORK/phone.log" | tail -1 >"$WORK/psbt.request"
# The stand-in phone prints the reason as sent; keep-mobile's approver as
# the app shows it.
grep -qE '"sign_psbt" (\{"type":"above_threshold","requested":10000,"spent":0,"threshold":5000\}|spends 10000 sats with 0 sats already spent, above the 5000 sats)' "$WORK/psbt.request" \
    || fail "the phone was not shown the spend: $(cat "$WORK/psbt.request")"
phone approve
wait "$AGENT_PID" || true
python3 -c 'import json,sys
r=json.loads(open(sys.argv[1]).readline())["result"]; assert r["isError"] is False, r
t=json.loads(r["content"][0]["text"]); assert t["inputs_signed"]==1 and t["leaving_wallet_sats"]==10000, t' \
    "$WORK/psbt.out" || fail "approved PSBT: $(cat "$WORK/psbt.out")"
pass "a spend above the threshold is signed once the phone approves"

# One request per credential waits at a time; a denial is the agent's answer.
n=$(requests)
agent "$WORK/deny1.out" "$(sign 4 0)" &
AGENT_PID=$!
wait_for "$WORK/phone.log" "^request " $((n + 1)) 30
agent "$WORK/second.out" "$(sign 5 0)"
grep -q "already pending" <<<"$(error_text "$WORK/second.out")" || fail "second request: $(cat "$WORK/second.out")"
phone deny
wait "$AGENT_PID" || true
[[ $(error_text "$WORK/deny1.out") == "denied by the approver" ]] || fail "denied: $(cat "$WORK/deny1.out")"
wait_for "$WORK/phone.log" '^outcome .*"denied"' 1 30
pass "a second request waits for none; a denial reaches the agent"

# No decision within the deadline: refused.
n=$(requests)
o=$(outcomes)
start=$(date +%s)
agent "$WORK/expire.out" "$(sign 6 0)" &
AGENT_PID=$!
wait_for "$WORK/phone.log" "^request " $((n + 1)) 30
wait "$AGENT_PID" || true
took=$(($(date +%s) - start))
[[ $(error_text "$WORK/expire.out") == "no approval within 30 seconds" ]] || fail "expiry: $(cat "$WORK/expire.out")"
[[ $took -ge 29 ]] || fail "expired after only $took seconds"
wait_for "$WORK/phone.log" '^outcome .*"expired"' 1 30
pass "a request with no decision expires at the deadline ($took s)"

# Three denials within a day freeze the credential.
for i in 7 8; do
    n=$(requests)
    agent "$WORK/deny$i.out" "$(sign "$i" 0)" &
    AGENT_PID=$!
    wait_for "$WORK/phone.log" "^request " $((n + 1)) 30
    phone deny
    wait "$AGENT_PID" || true
    [[ $(error_text "$WORK/deny$i.out") == "denied by the approver" ]] || fail "deny $i: $(cat "$WORK/deny$i.out")"
done
agent "$WORK/frozen.out" "$(sign 9 1)"
grep -q '"code":-32001' "$WORK/frozen.out" || fail "frozen credential served: $(cat "$WORK/frozen.out")"
pass "three denials froze the credential"

# Unfreezing it waits for the phone.
n=$(requests)
"$KEEP" gateway unfreeze "$CID" --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" \
    >"$WORK/unfreeze.out" 2>&1 &
CLI_PID=$!
wait_for "$WORK/phone.log" '^request .*"management"' 1 30
phone approve
wait "$CLI_PID" || fail "unfreeze: $(cat "$WORK/unfreeze.out")"
grep -q "Waiting for an approver device" "$WORK/unfreeze.out" || fail "unfreeze did not wait: $(cat "$WORK/unfreeze.out")"
agent "$WORK/thawed.out" "$(sign 10 1)"
is_signed "$WORK/thawed.out" || fail "after the unfreeze: $(cat "$WORK/thawed.out")"
pass "an unfreeze waits for the phone's approval"

# The phone freezes everything at once, and lifts it with its approver key.
phone "freeze all"
wait_for "$WORK/phone.log" "^anchor [0-9]* true" 1 30
agent "$WORK/all-frozen.out" "$(sign 11 1)"
grep -q '"code":-32001' "$WORK/all-frozen.out" || fail "served while frozen: $(cat "$WORK/all-frozen.out")"
lines=$(grep -c "^anchor [0-9]* false" "$WORK/phone.log" || true)
phone "unfreeze all"
wait_for "$WORK/phone.log" "^anchor [0-9]* false" $((lines + 1)) 30
agent "$WORK/all-thawed.out" "$(sign 12 1)"
is_signed "$WORK/all-thawed.out" || fail "after the phone's unfreeze: $(cat "$WORK/all-thawed.out")"
pass "the phone freezes and unfreezes the gateway"

# Issuing waits for the phone: approved, denied, and withdrawn by the admin
# going away.
# Run in the background, so exec: $! is then the command itself.
issue() {
    exec "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name "$1" --uid "$(uid "$A1")" \
        --key "$NPUB" --op get_public_key --token-out "$WORK/root-out/$1.token"
}
count_credentials() {
    "$KEEP" gateway list --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" 2>/dev/null \
        | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'
}
before=$(count_credentials)
m=$(grep -c '^request .*"management"' "$WORK/phone.log")
issue approved >"$WORK/issue-approved.out" 2>&1 &
CLI_PID=$!
wait_for "$WORK/phone.log" '^request .*"management"' $((m + 1)) 30
phone approve
wait "$CLI_PID" || fail "approved issue: $(cat "$WORK/issue-approved.out")"
[[ -s $WORK/root-out/approved.token ]] || fail "no token for the approved issue"
issue denied >"$WORK/issue-denied.out" 2>&1 &
CLI_PID=$!
wait_for "$WORK/phone.log" '^request .*"management"' $((m + 2)) 30
phone deny
if wait "$CLI_PID"; then fail "a denied issue succeeded"; fi
grep -q "denied by the approver" "$WORK/issue-denied.out" || fail "denied issue: $(cat "$WORK/issue-denied.out")"
[[ ! -e $WORK/root-out/denied.token ]] || fail "a denied issue left a token file"
c=$(grep -c '^outcome .*"canceled"' "$WORK/phone.log" || true)
issue gone >"$WORK/issue-gone.out" 2>&1 &
CLI_PID=$!
wait_for "$WORK/phone.log" '^request .*"management"' $((m + 3)) 30
kill -KILL "$CLI_PID"
wait "$CLI_PID" 2>/dev/null || true
wait_for "$WORK/phone.log" '^outcome .*"canceled"' $((c + 1)) 30
[[ $(count_credentials) == $((before + 1)) ]] || fail "credentials: $(count_credentials), expected $((before + 1))"
pass "an issue waits for the phone: approved, denied, or withdrawn when the admin goes away"

# The audit log holds each request, decision, freeze and pairing.
"$KEEP" gateway audit --limit 500 --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >"$WORK/audit.json" 2>&1
for t in agent_approval_requested agent_approval_decided agent_approver_freeze agent_approver_added; do
    grep -q "$t" "$WORK/audit.json" || fail "no $t in the audit log"
done
pass "the audit log records requests, decisions, freezes and the pairing"

# A gateway with a paired phone needs the same channel key to start.
stop_gateway
refuses_start "$NO_KEY" "needs its channel-key"
refuses_start "$NO_KEY" "approvals need the \"channel-key\" credential" --approval-relay "$RELAY_URL"
refuses_start "$OTHER_KEY" "not the one the approver devices were paired with" --approval-relay "$RELAY_URL"
pass "the gateway refuses to start without the paired channel key, or with another"

# Restarted, it serves approvals again once the helper reconnects.
start_gateway
wait_for "$WORK/gateway.log" "relay helper connected" 2 60
n=$(requests)
agent "$WORK/restarted.out" "$(sign 13 0)" &
AGENT_PID=$!
wait_for "$WORK/phone.log" "^request " $((n + 1)) 30
phone approve
wait "$AGENT_PID" || true
is_signed "$WORK/restarted.out" || fail "after the restart: $(cat "$WORK/restarted.out")"
pass "after a restart the helper reconnects and approvals work"

# An MCP client that gives up sends notifications/cancelled; the bridge
# passes it on and the request is withdrawn, while the bridge still answers.
cat >"$WORK/cancel.py" <<'PY'
import json, os, select, subprocess, sys, time
phone_log, seen = sys.argv[1], int(sys.argv[2])
server = subprocess.Popen(sys.argv[3:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def send(message):
    server.stdin.write((json.dumps(message) + "\n").encode())
    server.stdin.flush()
def answer():
    ready, _, _ = select.select([server.stdout], [], [], 60)
    return server.stdout.readline().decode().strip() if ready else "NO ANSWER"
send({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}}})
answer()
send({"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": {"name": "sign_nostr_event", "arguments": {"kind": 0, "content": "{}"}}})
for _ in range(300):
    lines = [l for l in open(phone_log) if l.startswith("request ")]
    if len(lines) > seen:
        break
    time.sleep(0.1)
send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 21, "reason": "gave up"}})
print(answer(), flush=True)
server.stdin.close()
server.wait(timeout=10)
PY
chmod 0644 "$WORK/cancel.py"
n=$(requests)
c=$(grep -c '^outcome .*"canceled"' "$WORK/phone.log" || true)
as "$A1" python3 "$WORK/cancel.py" "$WORK/phone.log" "$n" "$KEEP" agent connect --token-file "$WORK/a1/token" \
    --socket "$AGENT_SOCK" --gateway-user "$GW" >"$WORK/cancel.out" 2>"$WORK/cancel.err" || true
grep -q '"id":21' "$WORK/cancel.out" || fail "no answer to the cancelled request: $(cat "$WORK/cancel.out")"
grep -q "canceled: the request was withdrawn" "$WORK/cancel.out" || fail "cancelled: $(cat "$WORK/cancel.out")"
wait_for "$WORK/phone.log" '^outcome .*"canceled"' $((c + 1)) 30
pass "a client's notifications/cancelled withdraws its request through the bridge"

if [[ -n $OLD ]]; then
    # The old bridge against the new gateway: a request that waits is
    # answered once approved.
    cat >"$WORK/mcp.py" <<'PY'
import json, select, subprocess, sys
server = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
for i, line in enumerate(sys.stdin):
    server.stdin.write(line.encode())
    server.stdin.flush()
    ready, _, _ = select.select([server.stdout], [], [], 150)
    print(server.stdout.readline().decode().strip() if ready else "NO ANSWER", flush=True)
server.stdin.close()
server.wait(timeout=10)
PY
    chmod 0644 "$WORK/mcp.py"
    init='{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}'
    n=$(requests)
    printf '%s\n' "$init" "$(sign 14 0)" | as "$A1" python3 "$WORK/mcp.py" "$OLD" agent connect \
        --token-file "$WORK/a1/token" --socket "$AGENT_SOCK" --gateway-user "$GW" \
        >"$WORK/old-bridge.out" 2>"$WORK/old-bridge.err" &
    MCP_PID=$!
    wait_for "$WORK/phone.log" "^request " $((n + 1)) 30
    phone approve
    wait "$MCP_PID" || true
    grep '"id":14' "$WORK/old-bridge.out" >"$WORK/old-bridge.last" || true
    is_signed "$WORK/old-bridge.last" || fail "old bridge: $(cat "$WORK/old-bridge.out")"
    pass "the old bridge is answered after an approval"

    # The old admin commands against the new gateway: reading works; an
    # issue that waits is not understood, and is withdrawn when it leaves.
    "$OLD" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1 || fail "old status"
    "$OLD" gateway list --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1 || fail "old list"
    before=$(count_credentials)
    # An old keep from before approvals leaves at once and its request is
    # canceled; one that waits for the phone gives up at the deadline, when
    # the request expires. Either way nothing is issued.
    ended='^outcome .*"\(canceled\|expired\)"'
    c=$(grep -c -- "$ended" "$WORK/phone.log" || true)
    if "$OLD" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name old --uid "$(uid "$A1")" \
        --key "$NPUB" --op get_public_key --token-out "$WORK/root-out/old.token" >"$WORK/old-issue.out" 2>&1; then
        fail "the old issue succeeded without an approval: $(cat "$WORK/old-issue.out")"
    fi
    wait_for "$WORK/phone.log" "$ended" $((c + 1)) 30
    [[ $(count_credentials) == "$before" ]] || fail "the old issue created a credential"
    pass "old admin commands read the new gateway, and an old issue ends unapproved, not carried out"
fi

# Reset with the gateway stopped: the phone and the channel key are
# forgotten, and a new key starts it.
stop_gateway
as "$GW" env CREDENTIALS_DIRECTORY="$CREDS" "$KEEP" --path "$VAULT" gateway approver reset --offline \
    >"$WORK/reset.out" 2>&1 || fail "offline reset: $(cat "$WORK/reset.out")"
grep -q "Removed 1 approver" "$WORK/reset.out" || fail "offline reset: $(cat "$WORK/reset.out")"
[[ -z $(find "$WORK/vault-home" ! -user "$GW") ]] || fail "the reset left files the gateway does not own"
GW_CREDS=$OTHER_KEY
start_gateway
[[ $(status_field approvals.approvers) == 0 ]] || fail "approvers after the reset"
"$KEEP" gateway audit --limit 50 --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >"$WORK/audit2.json" 2>&1
grep -q agent_approver_removed "$WORK/audit2.json" || fail "the reset is not in the audit log"
agent "$WORK/after-reset.out" "$(sign 15 0)"
grep -q "cannot obtain yet" <<<"$(error_text "$WORK/after-reset.out")" \
    || fail "kind 0 after the reset: $(cat "$WORK/after-reset.out")"
stop_gateway
pass "an offline reset forgets the phone and the channel key, recorded in the audit log"

if [[ -n $OLD ]]; then
    # The new bridge against an old gateway, on a vault of its own.
    install -d -m 0700 -o "$GW" -g "$GW" "$WORK/old-home"
    OLD_VAULT=$WORK/old-home/vault
    as "$GW" env KEEP_PASSWORD=$PASS "$OLD" --path "$OLD_VAULT" init --size 10 >/dev/null 2>&1
    OLD_NPUB=$(as "$GW" env KEEP_PASSWORD=$PASS "$OLD" --path "$OLD_VAULT" generate --name agent 2>&1 \
        | grep -o 'npub1[02-9ac-hj-np-z]*' | head -1)
    setpriv --reuid="$GW" --regid="$(id -g "$GW")" --init-groups \
        env -i PATH=/usr/bin:/bin HOME="$WORK" CREDENTIALS_DIRECTORY="$NO_KEY" \
        "$OLD" --path "$OLD_VAULT" gateway serve --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" \
        --admin-uid "$(uid "$ADMIN")" >>"$WORK/old-gateway.log" 2>&1 &
    OLD_GW_PID=$!
    for _ in $(seq 100); do
        "$OLD" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1 && break
        sleep 0.1
    done
    "$OLD" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name e2e --uid "$(uid "$A1")" \
        --key "$OLD_NPUB" --op sign_nostr_event --kind 1 --kind 0 --token-out "$WORK/root-out/old-gw.token" \
        >/dev/null 2>&1 || fail "issue on the old gateway"
    install -m 0600 -o "$A1" "$WORK/root-out/old-gw.token" "$WORK/a1/old-gw.token"
    printf '%s\n' "$init" "$(sign 16 1)" "$(sign 17 0)" | as "$A1" python3 "$WORK/mcp.py" "$KEEP" agent connect \
        --token-file "$WORK/a1/old-gw.token" --socket "$AGENT_SOCK" --gateway-user "$GW" \
        >"$WORK/new-bridge.out" 2>"$WORK/new-bridge.err"
    grep '"id":16' "$WORK/new-bridge.out" >"$WORK/new-bridge.1" || true
    grep '"id":17' "$WORK/new-bridge.out" >"$WORK/new-bridge.0" || true
    is_signed "$WORK/new-bridge.1" || fail "new bridge, old gateway: $(cat "$WORK/new-bridge.out")"
    grep -q "needs approval" "$WORK/new-bridge.0" || fail "new bridge, old gateway, kind 0: $(cat "$WORK/new-bridge.out")"
    stop_pid "$OLD_GW_PID"
    OLD_GW_PID=
    pass "the new bridge is served by an old gateway, which refuses what needs approval"
fi

echo "all approval checks passed"
