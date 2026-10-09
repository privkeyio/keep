#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# End-to-end test of `keep gateway` in strong mode, with real users:
# the gateway runs as its own user, agents as two others in the agents group,
# the owner's admin as a fourth, and an outsider in no group. Every check talks
# to the running daemon over its sockets.
#
# Creates and removes system users and groups, so it runs only as root and
# only when KEEP_GATEWAY_E2E=1:
#
#   sudo KEEP_GATEWAY_E2E=1 scripts/gateway-e2e.sh target/release/keep

set -euo pipefail

if [[ "${KEEP_GATEWAY_E2E:-}" != 1 ]]; then
    echo "refusing to run: this creates system users; set KEEP_GATEWAY_E2E=1" >&2
    exit 2
fi
if [[ $(id -u) -ne 0 ]]; then
    echo "run as root" >&2
    exit 2
fi
BIN_SRC=${1:?usage: gateway-e2e.sh path/to/keep}

P=kgwe2e
GW=${P}gw
ADMIN=${P}admin
A1=${P}a1
A2=${P}a2
OUT=${P}out
AGENTS=${P}agents
ADMINS=${P}admins
RUN=/run/${P}
GW_PID=
PASS=e2e-vault-password
CREATED_USERS=()
CREATED_GROUPS=()

# Never touch accounts or a run directory this script did not create.
for u in $GW $ADMIN $A1 $A2 $OUT; do
    if getent passwd "$u" >/dev/null; then
        echo "refusing to run: user $u already exists" >&2
        exit 2
    fi
done
for g in $AGENTS $ADMINS; do
    if getent group "$g" >/dev/null; then
        echo "refusing to run: group $g already exists" >&2
        exit 2
    fi
done
if [[ -e $RUN ]]; then
    echo "refusing to run: $RUN already exists" >&2
    exit 2
fi
WORK=$(mktemp -d /tmp/${P}.XXXXXX)

fail() {
    echo "FAIL: $*" >&2
    if [[ -f $WORK/gateway.log ]]; then
        echo "--- gateway log ---" >&2
        tail -50 "$WORK/gateway.log" >&2
    fi
    exit 1
}
pass() { echo "ok - $*"; }

# Wait at most 10 seconds for `pid` to exit, then kill it.
reap() {
    local pid=$1 status=0
    for _ in $(seq 100); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || status=$?
    return "$status"
}

cleanup() {
    if [[ -n $GW_PID ]] && kill -0 "$GW_PID" 2>/dev/null; then
        kill "$GW_PID" 2>/dev/null || true
        reap "$GW_PID" || true
    fi
    # Anything left running as these users would keep userdel from removing them.
    for u in "${CREATED_USERS[@]}"; do pkill -KILL -u "$u" 2>/dev/null || true; done
    for u in "${CREATED_USERS[@]}"; do userdel "$u" 2>/dev/null || echo "could not remove user $u" >&2; done
    for g in "${CREATED_GROUPS[@]}"; do groupdel "$g" 2>/dev/null || echo "could not remove group $g" >&2; done
    rm -rf "$WORK" "$RUN"
}
trap cleanup EXIT

for g in $AGENTS $ADMINS; do
    groupadd --system "$g"
    CREATED_GROUPS+=("$g")
done
add_user() {
    useradd --system --no-create-home --shell /usr/sbin/nologin "$@"
    CREATED_USERS+=("${@: -1}")
}
add_user "$GW"
add_user -G "$ADMINS" "$ADMIN"
add_user -G "$AGENTS" "$A1"
add_user -G "$AGENTS" "$A2"
add_user "$OUT"
uid() { id -u "$1"; }

chmod 0755 "$WORK"
install -m 0755 "$BIN_SRC" "$WORK/keep"
KEEP=$WORK/keep
# Run as `user` with its own groups. setpriv execs the command, so a
# backgrounded call's $! is the command itself.
as() {
    local user=$1
    shift
    setpriv --reuid="$user" --regid="$(id -g "$user")" --init-groups \
        env -i PATH=/usr/bin:/bin HOME="$WORK" "$@"
}

# The vault, owned by the gateway's user and closed to everyone else.
install -d -m 0700 -o "$GW" -g "$GW" "$WORK/vault-home"
VAULT=$WORK/vault-home/vault
as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" init --size 10 >/dev/null 2>&1
NPUB=$(as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" generate --name agent 2>&1 \
    | grep -o 'npub1[02-9ac-hj-np-z]*' | head -1)
[[ -n $NPUB ]] || fail "no key generated"
# A fixed key, so the PSBTs below spend its wallet: a 9,900 sat payment plus a
# 100 sat fee (10,000 leaving the wallet), and a 60,000 sat payment.
BTC_NSEC=nsec1qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8qursl6edet
BTC_NPUB=$(as "$GW" env KEEP_PASSWORD=$PASS KEEP_NSEC=$BTC_NSEC "$KEEP" --path "$VAULT" import --name btc 2>&1 \
    | grep -o 'npub1[02-9ac-hj-np-z]*' | head -1)
[[ -n $BTC_NPUB ]] || fail "no key imported"
PSBT_10K=cHNidP8BAIkCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AqwmAAAAAAAAIlEgSDozZGbTHivoWJKTHsZhPKGfmmdiMpaYtMPnFRwBEiuQXwEAAAAAACJRIBdkDVXpEkGdKY8b7CMugitBSCKlL015dMRbbjJfMvDyAAAAAAABASughgEAAAAAACJRINRr8NHDB6I1lP/aFgiyPX+qRronccmpiPC3H6oQJ0qEIRbiZSIirsrwjZtJGRd/9GgjsQH+XrPXYy6Ykdg4jjcyhhkA4oZ7tlYAAIABAACAAAAAgAAAAAAAAAAAARcg4mUiIq7K8I2bSRkXf/RoI7EB/l6z12MumJHYOI43MoYAAAEFIB7t8WA86BP/Kclg28W5Rx+5Lfc7rknIiP3Jvqq1cD6bIQce7fFgPOgT/ynJYNvFuUcfuS33O65JyIj9yb6qtXA+mxkA4oZ7tlYAAIABAACAAAAAgAEAAAAAAAAAAA==
PSBT_60K=cHNidP8BAIkCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9////AmDqAAAAAAAAIlEgSDozZGbTHivoWJKTHsZhPKGfmmdiMpaYtMPnFRwBEivcmwAAAAAAACJRIBdkDVXpEkGdKY8b7CMugitBSCKlL015dMRbbjJfMvDyAAAAAAABASughgEAAAAAACJRINRr8NHDB6I1lP/aFgiyPX+qRronccmpiPC3H6oQJ0qEIRbiZSIirsrwjZtJGRd/9GgjsQH+XrPXYy6Ykdg4jjcyhhkA4oZ7tlYAAIABAACAAAAAgAAAAAAAAAAAARcg4mUiIq7K8I2bSRkXf/RoI7EB/l6z12MumJHYOI43MoYAAAEFIB7t8WA86BP/Kclg28W5Rx+5Lfc7rknIiP3Jvqq1cD6bIQce7fFgPOgT/ynJYNvFuUcfuS33O65JyIj9yb6qtXA+mxkA4oZ7tlYAAIABAACAAAAAgAEAAAAAAAAAAA==
pass "vault created with keys $NPUB and $BTC_NPUB"

# The socket directories: agents reach only theirs, the admin only theirs.
install -d -m 0755 "$RUN"
install -d -m 0750 -o "$GW" -g "$AGENTS" "$RUN/agent"
install -d -m 0750 -o "$GW" -g "$ADMINS" "$RUN/admin"
AGENT_SOCK=$RUN/agent/agent.sock
ADMIN_SOCK=$RUN/admin/admin.sock

start_gateway() {
    setpriv --reuid="$GW" --regid="$(id -g "$GW")" --init-groups \
        env -i PATH=/usr/bin:/bin HOME="$WORK" KEEP_PASSWORD=$PASS RUST_LOG=info \
        "$KEEP" --path "$VAULT" gateway serve \
        --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" \
        --admin-uid "$(uid "$ADMIN")" --wallet-budget-sats 100000 "$@" \
        >>"$WORK/gateway.log" 2>&1 &
    GW_PID=$!
    # Ready once the admin socket answers (a stale socket file does not).
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

# The gateway never runs as root.
if env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" gateway serve \
    --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" >"$WORK/root.log" 2>&1; then
    fail "the gateway ran as root"
fi
grep -q "never root" "$WORK/root.log" || fail "root refusal: $(cat "$WORK/root.log")"
pass "refuses to run as root"

start_gateway
pass "gateway running as $GW (pid $GW_PID)"

# The process cannot be read by its own user: not dumpable.
[[ $(cat "/proc/$GW_PID/comm") == keep ]] || fail "pid $GW_PID is not the gateway"
[[ $(awk '/^Uid:/ {print $3}' "/proc/$GW_PID/status") == "$(uid "$GW")" ]] \
    || fail "the gateway does not run as $GW"
if as "$GW" cat "/proc/$GW_PID/environ" >/dev/null 2>&1; then
    fail "the gateway's environment is readable by its own user"
fi
pass "process runs as $GW and is not dumpable"

# A second gateway cannot take over the sockets.
if as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" gateway serve \
    --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" >"$WORK/second.log" 2>&1; then
    fail "a second gateway started"
fi
grep -q "already opened by another process" "$WORK/second.log" || fail "second gateway: $(cat "$WORK/second.log")"
"$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null || fail "the first gateway lost its socket"
pass "a second gateway is refused by the vault lock and the first keeps serving"

# The agent client: sends one envelope per message and prints each answer.
cat >"$WORK/client.py" <<'PY'
import json, socket, sys
sock_path, token_path = sys.argv[1], sys.argv[2]
token = open(token_path).read().strip() if token_path != "-" else "keep_agt_" + "0" * 64
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
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
        print("CLOSED")
        break
    print(answer.decode().strip())
PY
chmod 0644 "$WORK/client.py"
rpc() { printf '{"jsonrpc":"2.0","id":%s,"method":"%s","params":%s}\n' "$1" "$2" "$3"; }
call() { rpc "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}"; }

gw_admin() { as "$ADMIN" "$KEEP" gateway "$1" --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" "${@:2}" 2>&1; }

# Issue a credential bound to agent 1 through the admin socket.
install -d -m 0700 -o "$ADMIN" "$WORK/admin-out"
as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name e2e --uid "$(uid "$A1")" \
    --key "$NPUB" --op get_public_key --op sign_nostr_event --kind 1 --kind 0 \
    --token-out "$WORK/admin-out/token" >"$WORK/issue.json" 2>"$WORK/issue.err" \
    || fail "issue: $(cat "$WORK/issue.err")"
ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/issue.json")
grep -q keep_agt_ "$WORK/issue.json" && fail "the token was printed with the credential"
[[ $(stat -c %a "$WORK/admin-out/token") == 600 ]] || fail "token file mode"
install -d -m 0700 -o "$A1" "$WORK/a1"
install -m 0600 -o "$A1" "$WORK/admin-out/token" "$WORK/a1/token"
install -d -m 0700 -o "$A2" "$WORK/a2"
install -m 0600 -o "$A2" "$WORK/admin-out/token" "$WORK/a2/stolen"
pass "issued credential $ID"

# A token file that cannot be created stops the issue before a credential exists.
BEFORE=$(gw_admin list | grep -c '"id"')
if as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name lost --uid "$(uid "$A1")" \
    --key "$NPUB" --op get_public_key --token-out "$WORK/admin-out/missing/token" >/dev/null 2>&1; then
    fail "issued with an unwritable token file"
fi
[[ $(gw_admin list | grep -c '"id"') == "$BEFORE" ]] || fail "a credential was issued without its token file"
pass "an unwritable token file issues nothing"

# An issue that never reached the gateway says so, without a false alarm.
if MSG=$(as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$A1" --name x \
    --uid "$(uid "$A1")" --key "$NPUB" --op get_public_key 2>&1); then
    fail "issued through a socket of the wrong user"
fi
echo "$MSG" | grep -q "may have been issued" && fail "false alarm: $MSG"
pass "an issue that was never sent raises no false alarm"

# Issuing to the gateway's or the admin's uid is refused.
for u in "$GW" "$ADMIN"; do
    if as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name bad --uid "$(uid "$u")" \
        --key "$NPUB" --op get_public_key >/dev/null 2>&1; then
        fail "issued a credential bound to $u"
    fi
done
pass "credentials bound to the gateway or admin uid are refused"

# Agent 1 is served what its grant allows.
ANS=$( {
    rpc 1 initialize '{}'
    rpc 2 tools/list '{}'
    call 3 get_nostr_pubkey '{}'
    call 4 sign_nostr_event '{"kind":1,"content":"hello from e2e"}'
    call 5 sign_nostr_event '{"kind":4,"content":"dm"}'
    call 6 sign_nostr_event '{"kind":0,"content":"{}"}'
    call 7 sign_bitcoin_psbt '{"psbt":"cHNidP8="}'
} | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/token")
printf '%s\n' "$ANS" >"$WORK/a1-answers"
python3 - "$NPUB" "$WORK/a1-answers" <<'PY' || fail "agent 1 answers: $ANS"
import json, sys
npub = sys.argv[1]
answers = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
by_id = {a["id"]: a for a in answers}
assert by_id[1]["result"]["serverInfo"]["name"] == "keep-gateway"
tools = sorted(t["name"] for t in by_id[2]["result"]["tools"])
assert tools == ["get_nostr_pubkey", "get_session_info", "sign_nostr_event"], tools
pk = json.loads(by_id[3]["result"]["content"][0]["text"])
assert pk["npub"] == npub, pk
event = json.loads(by_id[4]["result"]["content"][0]["text"])
assert by_id[4]["result"]["isError"] is False
assert event["pubkey"] == pk["hex"] and event["content"] == "hello from e2e" and len(event["sig"]) == 128
assert by_id[5]["result"]["isError"] is True and "not granted" in by_id[5]["result"]["content"][0]["text"]
assert by_id[6]["result"]["isError"] is True and "needs approval" in by_id[6]["result"]["content"][0]["text"]
assert by_id[7]["result"]["isError"] is True, by_id[7]
PY
pass "agent 1 is served its grant: pubkey, kind 1 signed; kind 4 denied, kind 0 needs approval, PSBT denied"

# The same token from agent 2's uid, and an unknown token: one uniform refusal.
REFUSED='{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"request refused"}}'
norm() { python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()), sort_keys=True))'; }
WANT=$(echo "$REFUSED" | norm)
GOT=$(rpc 1 ping '{}' | as "$A2" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a2/stolen" | norm)
[[ $GOT == "$WANT" ]] || fail "stolen token: $GOT"
GOT=$(rpc 1 ping '{}' | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" - | norm)
[[ $GOT == "$WANT" ]] || fail "unknown token: $GOT"
pass "a stolen or unknown token gets the uniform refusal"

# Users outside the agents group cannot reach the agent socket; agents cannot
# reach the admin socket.
if rpc 1 ping '{}' | as "$OUT" python3 "$WORK/client.py" "$AGENT_SOCK" - >/dev/null 2>&1; then
    fail "an outsider reached the agent socket"
fi
if as "$A1" "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1; then
    fail "an agent reached the admin socket"
fi
if as "$GW" "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1; then
    fail "the gateway's own uid was admitted to the admin socket"
fi
"$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null || fail "root was refused"
pass "socket access: outsiders and agents shut out, root and the admin let in"

# The admin client sends nothing to a socket not served by the gateway user.
if OUT_MSG=$("$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$A1" 2>&1); then
    fail "the admin client trusted a socket of another user"
fi
echo "$OUT_MSG" | grep -q "not the gateway's uid" || fail "wrong gateway user: $OUT_MSG"
pass "the admin client checks the socket belongs to the gateway user"

# Freeze, unfreeze and revoke take effect on the next request.
ask_ping() { rpc 1 ping '{}' | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/token" | norm; }
OK=$(echo '{"jsonrpc":"2.0","id":1,"result":{}}' | norm)
[[ $(ask_ping) == "$OK" ]] || fail "ping before freeze"
gw_admin freeze "$ID" >/dev/null || fail "freeze"
[[ $(ask_ping) == "$WANT" ]] || fail "served while frozen"
gw_admin unfreeze "$ID" >/dev/null || fail "unfreeze"
[[ $(ask_ping) == "$OK" ]] || fail "refused after unfreeze"
gw_admin freeze --all >/dev/null || fail "freeze all"
[[ $(ask_ping) == "$WANT" ]] || fail "served while all frozen"
gw_admin unfreeze --all >/dev/null || fail "unfreeze all"
[[ $(ask_ping) == "$OK" ]] || fail "refused after unfreeze all"
pass "freeze and unfreeze apply on the next request"

# The audit log holds the signature, what was served, and the theft signal.
# Refusals of real tokens are written on the gateway's 10 s tick, not before
# the answer, so wait for one.
for _ in $(seq 40); do
    AUDIT=$(gw_admin audit --limit 200)
    echo "$AUDIT" | grep -q "presented by uid $(uid "$A2")" && break
    sleep 0.5
done
echo "$AUDIT" | grep -q "sign_nostr_event kind 1" || fail "no signature entry: $AUDIT"
echo "$AUDIT" | grep -q "agent_served" || fail "no served entry"
echo "$AUDIT" | grep -q "presented by uid $(uid "$A2")" || fail "no theft entry"
echo "$AUDIT" | grep -q "kind 4 is not granted" || fail "no denial entry"
pass "audit log records signatures, served answers, denials and the stolen token"

# Agent 2 may sign PSBTs from the Bitcoin key: 20,000 sats per PSBT, 50,000
# in any 24 hours.
as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name btc --uid "$(uid "$A2")" \
    --key "$BTC_NPUB" --op get_bitcoin_address --op sign_psbt --network testnet \
    --per-psbt-sats 20000 --window-sats 50000 --token-out "$WORK/admin-out/btc" >/dev/null 2>&1 \
    || fail "issue the Bitcoin credential"
install -m 0600 -o "$A2" "$WORK/admin-out/btc" "$WORK/a2/btc"
sign_psbt() {
    call 1 sign_bitcoin_psbt "{\"psbt\":\"$1\"}" \
        | as "$A2" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a2/btc" \
        | python3 -c 'import json,sys; r=json.loads(sys.stdin.read())["result"]; t=r["content"][0]["text"]; print(("ERR " + t) if r["isError"] else ("OK %d %d" % (json.loads(t)["inputs_signed"], json.loads(t)["leaving_wallet_sats"])))'
}
ADDR=$(call 1 get_bitcoin_address '{}' | as "$A2" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a2/btc")
echo "$ADDR" | grep -q '\\"address\\":\\"tb1p' || fail "address: $ADDR"
[[ $(sign_psbt "$PSBT_10K") == "OK 1 10000" ]] || fail "PSBT within the grant was not signed"
GOT=$(sign_psbt "$PSBT_60K")
[[ $GOT == ERR*"over the 20000 sat limit per PSBT"* ]] || fail "over the per-PSBT limit: $GOT"
gw_admin audit --limit 50 | grep -q "sign_bitcoin_psbt txid" || fail "no PSBT signature entry"
pass "agent 2 signs a PSBT within its grant; one over the per-PSBT limit is denied"

# SIGTERM stops it cleanly and removes the sockets; it restarts on the same vault.
stop_gateway
[[ ! -e $AGENT_SOCK && ! -e $ADMIN_SOCK ]] || fail "sockets left behind"
pass "SIGTERM stops the gateway cleanly"
start_gateway
[[ $(ask_ping) == "$OK" ]] || fail "not served after restart"
# The 10,000 sats spent before the restart still count: four more fit the
# 50,000 budget, the fifth does not.
for _ in 1 2 3 4; do
    [[ $(sign_psbt "$PSBT_10K") == "OK 1 10000" ]] || fail "spend within the budget after restart"
done
GOT=$(sign_psbt "$PSBT_10K")
[[ $GOT == ERR*"exceeds the 50000 sat budget"* ]] || fail "budget after restart: $GOT"
pass "the spend budget survives a restart"
gw_admin revoke "$ID" >/dev/null || fail "revoke"
[[ $(ask_ping) == "$WANT" ]] || fail "served after revoke"
pass "restarted; revocation applies on the next request"

# A gateway killed outright leaves a stale socket, which the next one replaces.
# (The group's redirect also silences bash's notice that the job was killed.)
{
    kill -KILL "$GW_PID"
    wait "$GW_PID" || true
} 2>/dev/null
GW_PID=
[[ -S $AGENT_SOCK ]] || fail "expected a stale socket"
start_gateway
gw_admin status >/dev/null || fail "status after a crash"
stop_gateway
pass "a stale socket from a killed gateway is replaced"

echo "all gateway e2e checks passed"
