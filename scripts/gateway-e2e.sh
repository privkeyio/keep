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
#
# It checks SSH signing with the system's OpenSSH (sshd, ssh, ssh-add and
# ssh-keygen; openssh-server must be installed): logins through
# `keep agent ssh-agent` to servers on loopback, and SSHSIG signatures.
#
# With two more arguments it also checks http_request end to end: a build of
# keep made with RUSTFLAGS='--cfg keep_e2e_roots' and KEEP_E2E_CA_DER naming
# the CA in the directory scripts/lib/inject-e2e-pki.sh made, which runs the
# inject workers, and that directory, whose certificate the test server
# presents. The server, its DNS and the workers run in a network namespace
# with no route out.
#
#   sudo KEEP_GATEWAY_E2E=1 scripts/gateway-e2e.sh target/release/keep \
#       target/e2e-roots/release/keep /path/to/pki

set -euo pipefail

if [[ "${KEEP_GATEWAY_E2E:-}" != 1 ]]; then
    echo "refusing to run: this creates system users; set KEEP_GATEWAY_E2E=1" >&2
    exit 2
fi
if [[ $(id -u) -ne 0 ]]; then
    echo "run as root" >&2
    exit 2
fi
BIN_SRC=${1:?usage: gateway-e2e.sh path/to/keep [path/to/e2e-roots-keep pki-dir]}
E2E_BIN_SRC=${2:-}
PKI=${3:-}

P=kgwe2e
GW=${P}gw
ADMIN=${P}admin
A1=${P}a1
A2=${P}a2
OUT=${P}out
AGENTS=${P}agents
ADMINS=${P}admins
INJ=${P}inj
SSH_USER=${P}login
SSH_OTHER=${P}login2
NS=${P}
RUN=/run/${P}
GW_PID=
SSH_AGENT_PID=
GOOD_SSHD_PID=
OTHER_SSHD_PID=
ACTIVATOR_PID=
SERVER_PID=
DNS_PID=
CREATED_NS=
PASS=e2e-vault-password
CREATED_RUN=
. "$(dirname "$0")/lib/gateway-e2e.sh"

refuse_users $GW $ADMIN $A1 $A2 $OUT $INJ $SSH_USER $SSH_OTHER
refuse_groups $AGENTS $ADMINS
refuse_paths "$RUN" "/etc/netns/$NS"
if [[ -n $E2E_BIN_SRC ]] && ip netns list | grep -qw "$NS"; then
    echo "refusing to run: network namespace $NS exists" >&2
    exit 2
fi
WORK=$(mktemp -d /tmp/${P}.XXXXXX)

fail_context() {
    if [[ -f $WORK/gateway.log ]]; then
        echo "--- gateway log ---"
        tail -50 "$WORK/gateway.log"
    fi
}

cleanup() {
    if [[ -n $GW_PID ]] && kill -0 "$GW_PID" 2>/dev/null; then
        kill "$GW_PID" 2>/dev/null || true
        reap "$GW_PID" || true
    fi
    stop_pid "$ACTIVATOR_PID" "$SERVER_PID" "$DNS_PID" "$SSH_AGENT_PID" "$GOOD_SSHD_PID" "$OTHER_SSHD_PID"
    if [[ -n $CREATED_NS ]]; then
        ip netns delete "$NS" 2>/dev/null || true
        rm -rf "/etc/netns/$NS"
    fi
    remove_created_accounts
    rm -rf "$WORK"
    if [[ -n $CREATED_RUN ]]; then rm -rf "$RUN"; fi
}
trap cleanup EXIT

for g in $AGENTS $ADMINS; do
    groupadd --system "$g"
    CREATED_GROUPS+=("$g")
done
add_user "$GW"
add_user -G "$ADMINS" "$ADMIN"
add_user -G "$AGENTS" "$A1"
add_user -G "$AGENTS" "$A2"
add_user "$OUT"

chmod 0755 "$WORK"
install -m 0755 "$BIN_SRC" "$WORK/keep"
KEEP=$WORK/keep

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
CREATED_RUN=1
install -d -m 0750 -o "$GW" -g "$AGENTS" "$RUN/agent"
install -d -m 0750 -o "$GW" -g "$ADMINS" "$RUN/admin"
AGENT_SOCK=$RUN/agent/agent.sock
ADMIN_SOCK=$RUN/admin/admin.sock

# The vault password as systemd hands it to the gateway: a file in a
# directory named by CREDENTIALS_DIRECTORY, readable by the gateway alone.
CREDS=$WORK/creds
make_creds "$CREDS"
chmod 0500 "$CREDS"

start_gateway() {
    setpriv --reuid="$GW" --regid="$(id -g "$GW")" --init-groups \
        env -i PATH=/usr/bin:/bin HOME="$WORK" CREDENTIALS_DIRECTORY="$CREDS" RUST_LOG=info \
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
if timeout 20 env CREDENTIALS_DIRECTORY="$CREDS" "$KEEP" --path "$VAULT" gateway serve \
    --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" >"$WORK/root.log" 2>&1; then
    fail "the gateway ran as root"
fi
grep -q "never root" "$WORK/root.log" || fail "root refusal: $(cat "$WORK/root.log")"
pass "refuses to run as root"

# The password never comes from the environment, nor from a credential others
# could read, and is never printed.
serve_refuses() {
    local why=$1 want=$2 msg
    shift 2
    # Bounded, so a gateway that starts after all fails this check rather
    # than hanging it.
    if msg=$(as "$GW" timeout 20 "$@" "$KEEP" --path "$VAULT" gateway serve \
        --agent-socket "$AGENT_SOCK" --admin-socket "$ADMIN_SOCK" </dev/null 2>&1); then
        fail "the gateway started with $why"
    fi
    grep -q "$want" <<<"$msg" || fail "$why: $msg"
    grep -q "$PASS" <<<"$msg" && fail "$why: the password was printed"
    return 0
}
serve_refuses "KEEP_PASSWORD set" "never reads the vault password from KEEP_PASSWORD" \
    env KEEP_PASSWORD=$PASS CREDENTIALS_DIRECTORY="$CREDS"
serve_refuses "no credential and no terminal" "no vault password"
LOOSE=$WORK/loose-creds
install -d -m 0700 -o "$GW" "$LOOSE"
install -m 0444 -o "$GW" "$CREDS/vault-password" "$LOOSE/vault-password"
serve_refuses "a credential other users can read" "closed to other users" env CREDENTIALS_DIRECTORY="$LOOSE"
[[ ! -e $AGENT_SOCK && ! -e $ADMIN_SOCK ]] || fail "a refused gateway left a socket"
pass "the password comes only from a closed credential, never the environment, and is never printed"

# An admin directory agents can enter is refused before anything is bound.
install -d -m 0750 -o "$GW" -g "$AGENTS" "$RUN/open-admin"
if MSG=$(as "$GW" timeout 20 env CREDENTIALS_DIRECTORY="$CREDS" "$KEEP" --path "$VAULT" gateway serve \
    --agent-socket "$AGENT_SOCK" --admin-socket "$RUN/open-admin/admin.sock" </dev/null 2>&1); then
    fail "the gateway started with an admin directory open to agents"
fi
grep -q "open to the agent socket's group" <<<"$MSG" || fail "admin directory open to agents: $MSG"
[[ ! -e $AGENT_SOCK && ! -e $RUN/open-admin/admin.sock ]] || fail "a refused gateway left a socket"
rmdir "$RUN/open-admin"
pass "an admin directory in the agents' group is refused"

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
if as "$GW" timeout 20 env CREDENTIALS_DIRECTORY="$CREDS" "$KEEP" --path "$VAULT" gateway serve \
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
# An MCP client on stdio, as Claude or Cursor runs one: starts the server
# command given after the plan, follows the plan, prints each answer, then
# closes the server's input and prints its exit status. A plan step is
# {"request": message} (answer printed), {"notify": message},
# {"raw": line} (answer printed), {"touch": path} or {"wait_for": path}.
cat >"$WORK/mcp_client.py" <<'PY'
import json, os, select, subprocess, sys, time
plan = json.load(open(sys.argv[1]))
server = subprocess.Popen(sys.argv[2:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def send(line):
    server.stdin.write((line + "\n").encode())
    server.stdin.flush()
def answer():
    ready, _, _ = select.select([server.stdout], [], [], 30)
    line = server.stdout.readline() if ready else b""
    print(line.decode().strip() if line else "NO ANSWER", flush=True)
for step in plan:
    if "request" in step:
        send(json.dumps(step["request"]))
        answer()
    elif "notify" in step:
        send(json.dumps(step["notify"]))
    elif "raw" in step:
        send(step["raw"])
        answer()
    elif "touch" in step:
        open(step["touch"], "w").close()
    elif "wait_for" in step:
        for _ in range(600):
            if os.path.exists(step["wait_for"]):
                break
            time.sleep(0.1)
server.stdin.close()
try:
    print("EXIT", server.wait(timeout=10), flush=True)
except subprocess.TimeoutExpired:
    server.kill()
    print("EXIT hung", flush=True)
PY
chmod 0644 "$WORK/mcp_client.py"
rpc() { printf '{"jsonrpc":"2.0","id":%s,"method":"%s","params":%s}\n' "$1" "$2" "$3"; }
call() { rpc "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}"; }

gw_admin() { as "$ADMIN" "$KEEP" gateway "$1" --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" "${@:2}" 2>&1; }

# Issue a credential bound to agent 1 through the admin socket.
install -d -m 0700 -o "$ADMIN" "$WORK/admin-out"
as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name e2e --uid "$(uid "$A1")" \
    --key "$NPUB" --op get_public_key --op sign_nostr_event --kind 1 --kind 0 --per-minute 60 \
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
grep -q "may have been issued" <<<"$MSG" && fail "false alarm: $MSG"
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

# A stock MCP client's session through `keep agent connect`, as agent 1.
CONNECT=("$KEEP" agent connect --socket "$AGENT_SOCK" --gateway-user "$GW" --token-file)
mcp() {
    local user=$1 plan=$2
    shift 2
    # Logging everything, so the check below that the log never holds a
    # token covers every message the bridge can write.
    as "$user" env RUST_LOG=trace python3 "$WORK/mcp_client.py" "$plan" "$@" 2>>"$WORK/bridge.log"
}
cat >"$WORK/session.json" <<'JSON'
[
 {"request": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}}}},
 {"notify": {"jsonrpc": "2.0", "method": "notifications/initialized"}},
 {"request": {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}},
 {"request": {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_nostr_pubkey", "arguments": {}}}},
 {"request": {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "sign_nostr_event", "arguments": {"kind": 1, "content": "hello through the bridge"}}}},
 {"request": {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "sign_nostr_event", "arguments": {"kind": 4, "content": "dm"}}}},
 {"raw": "{not json"},
 {"request": {"jsonrpc": "2.0", "id": "last", "method": "ping"}}
]
JSON
chmod 0644 "$WORK/session.json"
mcp "$A1" "$WORK/session.json" "${CONNECT[@]}" "$WORK/a1/token" >"$WORK/bridge-a1" || fail "bridge session: $(cat "$WORK/bridge.log")"
python3 - "$NPUB" "$WORK/bridge-a1" "$WORK/bridge-event" <<'PY' || fail "bridge session answers: $(cat "$WORK/bridge-a1") $(cat "$WORK/bridge.log")"
import json, sys
npub = sys.argv[1]
lines = [l.strip() for l in open(sys.argv[2]) if l.strip()]
assert lines[-1] == "EXIT 0", lines[-1]
answers = [json.loads(l) for l in lines[:-1]]
assert [a["id"] for a in answers] == [1, 2, 3, 4, 5, None, "last"], answers
init, tools, pk, signed, denied, garbled, ping = answers
assert init["result"]["serverInfo"]["name"] == "keep-gateway", init
names = sorted(t["name"] for t in tools["result"]["tools"])
assert names == ["get_nostr_pubkey", "get_session_info", "sign_nostr_event"], names
assert json.loads(pk["result"]["content"][0]["text"])["npub"] == npub, pk
assert signed["result"]["isError"] is False, signed
event = json.loads(signed["result"]["content"][0]["text"])
assert event["content"] == "hello through the bridge" and len(event["sig"]) == 128, event
open(sys.argv[3], "w").write(event["id"])
assert denied["result"]["isError"] is True and "not granted" in denied["result"]["content"][0]["text"], denied
assert garbled["error"]["code"] == -32700, garbled
assert ping["result"] == {}, ping
PY
# Captured first: under pipefail, grep -q closing the pipe early fails the writer.
grep -q "sign_nostr_event kind 1 id $(cat "$WORK/bridge-event")" <<<"$(gw_admin audit --limit 200)" \
    || fail "the bridge's signature was not audited"
pass "an MCP client's session through the bridge: initialize, tools, a signature and a denial"

# The stolen token through the bridge, from agent 2's uid: refused alike.
cat >"$WORK/init.json" <<'JSON'
[{"request": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}}]
JSON
chmod 0644 "$WORK/init.json"
GOT=$(mcp "$A2" "$WORK/init.json" "${CONNECT[@]}" "$WORK/a2/stolen" | sed -n 1p | norm)
[[ $GOT == "$WANT" ]] || fail "stolen token through the bridge: $GOT"
pass "a stolen token through the bridge gets the uniform refusal"

# The bridge refuses what would expose the token or the vault, before
# sending anything.
bridge_refuses() {
    local why=$1 want=$2
    shift 2
    local msg
    # A request ready on its input, so a bridge that ran would send it.
    if msg=$(rpc 1 ping '{}' | "$@" 2>&1); then
        fail "the bridge ran with $why"
    fi
    grep -q "$want" <<<"$msg" || fail "$why: $msg"
    grep -qE 'keep_agt_[0-9a-f]{64}' <<<"$msg" && fail "$why: the token was printed"
    grep -q "$PASS" <<<"$msg" && fail "$why: the password was printed"
    return 0
}
install -m 0640 -o "$A1" "$WORK/a1/token" "$WORK/a1/loose"
bridge_refuses "a token file others can read" "readable by its owner alone" \
    as "$A1" "${CONNECT[@]}" "$WORK/a1/loose"
install -m 0644 -o "$A2" "$WORK/a1/token" "$WORK/a1/foreign"
bridge_refuses "a token file of another user" "is owned by uid" \
    as "$A1" "${CONNECT[@]}" "$WORK/a1/foreign"
bridge_refuses "KEEP_PASSWORD set" "refusing to run with KEEP_PASSWORD" \
    as "$A1" env KEEP_PASSWORD=$PASS "${CONNECT[@]}" "$WORK/a1/token"
bridge_refuses "root" "root can hold no gateway credential" env -i "${CONNECT[@]}" "$WORK/a1/token"
# Agent 2 serves a socket of its own and points agent 1 at it. It records
# every connection, and anything sent on one, in agent 2's own directory.
# (setpriv directly, so $! is the server itself.)
install -d -m 0755 -o "$A2" "$RUN/impostor"
setpriv --reuid="$A2" --regid="$(id -g "$A2")" --init-groups env -i PATH=/usr/bin:/bin python3 -c '
import os, socket, sys
path, conns, got = sys.argv[1:4]
s = socket.socket(socket.AF_UNIX); s.bind(path); os.chmod(path, 0o777); s.listen(4)
while True:
    c, _ = s.accept()
    open(conns, "a").write("connected\n")
    c.settimeout(2)
    try:
        data = c.recv(65536)
    except OSError:
        data = b""
    open(got, "ab").write(data)
    c.close()
' "$RUN/impostor/agent.sock" "$WORK/a2/impostor-connections" "$WORK/a2/impostor-got" &
IMPOSTOR=$!
for _ in $(seq 50); do [[ -S $RUN/impostor/agent.sock ]] && break; sleep 0.1; done
IMPOSTOR_CONNECT=(as "$A1" "$KEEP" agent connect --socket "$RUN/impostor/agent.sock" --gateway-user "$GW"
    --token-file "$WORK/a1/token")
bridge_refuses "an impostor's directory" "its directory is owned by uid $(uid "$A2")" "${IMPOSTOR_CONNECT[@]}"
[[ ! -e $WORK/a2/impostor-connections ]] || fail "the bridge connected to a socket in the impostor's directory"
# Its socket in a directory of the gateway user's: the bridge connects, and
# the server is checked before anything is sent.
chown "$GW" "$RUN/impostor"
bridge_refuses "an impostor's socket" "served by uid $(uid "$A2")" "${IMPOSTOR_CONNECT[@]}"
for _ in $(seq 50); do [[ -s $WORK/a2/impostor-connections ]] && break; sleep 0.1; done
[[ -s $WORK/a2/impostor-connections ]] || fail "the bridge never reached the impostor's socket"
# (The group's redirect also silences bash's notice that the job was killed.)
{
    kill "$IMPOSTOR" || true
    wait "$IMPOSTOR" || true
} 2>/dev/null
pgrep -u "$A2" python3 >/dev/null && fail "the impostor is still running"
[[ ! -s $WORK/a2/impostor-got ]] || fail "the bridge sent something to the impostor"
pass "the bridge refuses a loose or foreign token file, KEEP_PASSWORD, root and an impostor's socket"

# Users outside the agents group cannot reach the agent socket; agents cannot
# reach the admin socket.
if rpc 1 ping '{}' | as "$OUT" python3 "$WORK/client.py" "$AGENT_SOCK" - >/dev/null 2>&1; then
    fail "an outsider reached the agent socket"
fi
if as "$A1" "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1; then
    fail "an agent reached the admin socket"
fi
# The gateway's own uid reaches the admin socket but is turned away unread,
# so its issue is not reported as possibly done.
if MSG=$(as "$GW" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name x \
    --uid "$(uid "$A2")" --key "$NPUB" --op get_public_key 2>&1); then
    fail "the gateway's own uid issued a credential"
fi
grep -q "may have been issued" <<<"$MSG" && fail "false alarm for a refused issue: $MSG"
grep -q "run as root or the gateway's admin uid" <<<"$MSG" || fail "refused issue: $MSG"
if as "$GW" "$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null 2>&1; then
    fail "the gateway's own uid was admitted to the admin socket"
fi
"$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" >/dev/null || fail "root was refused"
pass "socket access: outsiders and agents shut out, root and the admin let in"

# The admin client sends nothing to a socket not served by the gateway user.
if OUT_MSG=$("$KEEP" gateway status --admin-socket "$ADMIN_SOCK" --gateway-user "$A1" 2>&1); then
    fail "the admin client trusted a socket of another user"
fi
grep -q "not the gateway's uid" <<<"$OUT_MSG" || fail "wrong gateway user: $OUT_MSG"
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
    grep -q "presented by uid $(uid "$A2")" <<<"$AUDIT" && break
    sleep 0.5
done
grep -q "sign_nostr_event kind 1" <<<"$AUDIT" || fail "no signature entry: $AUDIT"
grep -q "agent_served" <<<"$AUDIT" || fail "no served entry"
grep -q "presented by uid $(uid "$A2")" <<<"$AUDIT" || fail "no theft entry"
grep -q "kind 4 is not granted" <<<"$AUDIT" || fail "no denial entry"
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
grep -q '\\"address\\":\\"tb1p' <<<"$ADDR" || fail "address: $ADDR"
[[ $(sign_psbt "$PSBT_10K") == "OK 1 10000" ]] || fail "PSBT within the grant was not signed"
GOT=$(sign_psbt "$PSBT_60K")
[[ $GOT == ERR*"over the 20000 sat limit per PSBT"* ]] || fail "over the per-PSBT limit: $GOT"
grep -q "sign_bitcoin_psbt txid" <<<"$(gw_admin audit --limit 50)" || fail "no PSBT signature entry"
pass "agent 2 signs a PSBT within its grant; one over the per-PSBT limit is denied"

# A bridge left running across the restart below: refused nothing, sent
# nothing while the gateway is down, and served again once it is back.
SYNC=$WORK/a1/sync
cat >"$WORK/restart.json" <<JSON
[
 {"request": {"jsonrpc": "2.0", "id": 1, "method": "ping"}},
 {"touch": "$SYNC-up"},
 {"wait_for": "$SYNC-down"},
 {"request": {"jsonrpc": "2.0", "id": 2, "method": "ping"}},
 {"touch": "$SYNC-asked"},
 {"wait_for": "$SYNC-back"},
 {"request": {"jsonrpc": "2.0", "id": 3, "method": "ping"}}
]
JSON
chmod 0644 "$WORK/restart.json"
mcp "$A1" "$WORK/restart.json" "${CONNECT[@]}" "$WORK/a1/token" >"$WORK/bridge-restart" &
BRIDGE_CLIENT=$!
wait_file() { for _ in $(seq 300); do [[ -e $1 ]] && return 0; sleep 0.1; done; fail "timed out waiting for $1"; }
wait_file "$SYNC-up"
# SIGTERM stops it cleanly and removes the sockets; it restarts on the same vault.
stop_gateway
touch "$SYNC-down"
wait_file "$SYNC-asked"
# A bridge started while the gateway is down runs anyway, and is served once
# the gateway is back.
cat >"$WORK/late.json" <<JSON
[
 {"request": {"jsonrpc": "2.0", "id": 1, "method": "ping"}},
 {"touch": "$SYNC-late"},
 {"wait_for": "$SYNC-back"},
 {"request": {"jsonrpc": "2.0", "id": 2, "method": "ping"}}
]
JSON
chmod 0644 "$WORK/late.json"
mcp "$A1" "$WORK/late.json" "${CONNECT[@]}" "$WORK/a1/token" >"$WORK/bridge-late" &
LATE_CLIENT=$!
wait_file "$SYNC-late"
# Both bridges are waiting, and neither can be read by the agent's own user.
BRIDGES=$(pgrep -u "$A1" -f -- "^$KEEP agent connect" || true)
[[ $(wc -w <<<"$BRIDGES") == 2 ]] || fail "expected two bridges running as $A1: $BRIDGES"
as "$A1" cat /proc/self/environ >/dev/null || fail "$A1 cannot read its own dumpable process"
for pid in $BRIDGES; do
    if as "$A1" cat "/proc/$pid/environ" >/dev/null 2>&1; then
        fail "a bridge's environment is readable by its own user"
    fi
done
pass "bridges run as the agent's user and are not dumpable"
[[ ! -e $AGENT_SOCK && ! -e $ADMIN_SOCK ]] || fail "sockets left behind"
pass "SIGTERM stops the gateway cleanly"
start_gateway
[[ $(ask_ping) == "$OK" ]] || fail "not served after restart"
touch "$SYNC-back"
wait "$BRIDGE_CLIENT" || fail "bridge client across the restart"
python3 - "$WORK/bridge-restart" <<'PY' || fail "bridge across the restart: $(cat "$WORK/bridge-restart") $(cat "$WORK/bridge.log")"
import json, sys
lines = [l.strip() for l in open(sys.argv[1]) if l.strip()]
assert lines[-1] == "EXIT 0", lines
up, down, back = (json.loads(l) for l in lines[:-1])
assert up == {"jsonrpc": "2.0", "id": 1, "result": {}}, up
assert down["id"] == 2 and down["error"]["code"] == -32010, down
assert back == {"jsonrpc": "2.0", "id": 3, "result": {}}, back
PY
pass "a bridge left running reports the stopped gateway and reconnects to the restarted one"
wait "$LATE_CLIENT" || fail "bridge client started while the gateway was down"
python3 - "$WORK/bridge-late" <<'PY' || fail "bridge started early: $(cat "$WORK/bridge-late") $(cat "$WORK/bridge.log")"
import json, sys
lines = [l.strip() for l in open(sys.argv[1]) if l.strip()]
assert lines[-1] == "EXIT 0", lines
down, back = (json.loads(l) for l in lines[:-1])
assert down["id"] == 1 and down["error"]["code"] == -32010, down
assert back == {"jsonrpc": "2.0", "id": 2, "result": {}}, back
PY
grep -q "is not reachable yet" "$WORK/bridge.log" || fail "the bridge did not say the gateway was down"
pass "a bridge started while the gateway is down is served once it is back"
grep -qE 'keep_agt_[0-9a-f]{64}' "$WORK/bridge.log" && fail "a token is in the bridge's log"
grep -q "connected to the gateway" "$WORK/bridge.log" || fail "the bridge's log was not captured"
pass "the bridge's log, at trace level, holds no token"
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

# SSH keys. The gateway is stopped, so the owner generates the key.
SSH_PUB=$(as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" secret ssh-keygen --name "deploy key" 2>&1 \
    | grep '^ssh-ed25519 ') || fail "secret ssh-keygen"
[[ $(as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" secret ssh-pubkey "deploy key" 2>&1 | grep '^ssh-ed25519 ') == "$SSH_PUB" ]] \
    || fail "secret ssh-pubkey differs from what ssh-keygen printed"
pass "the vault generated an SSH key and prints its public key again"

# Two SSH servers on loopback, each with its own host key; the grant names
# only the first, and only the first of two users both servers let in. The
# users have a shell, so a session runs.
[[ -x /usr/sbin/sshd ]] || fail "the SSH checks need openssh-server"
for u in "$SSH_USER" "$SSH_OTHER"; do
    useradd --system --no-create-home --shell /bin/sh "$u"
    CREATED_USERS+=("$u")
    # No password, without the lock sshd refuses outside PAM.
    usermod -p '*' "$u"
done
install -d -m 0755 /run/sshd
# sshd reads authorized_keys as the login user; the host keys stay 0600.
install -d -m 0755 "$WORK/sshd"
printf '%s\n' "$SSH_PUB" >"$WORK/sshd/authorized_keys"
chmod 0644 "$WORK/sshd/authorized_keys"
start_sshd() {
    local name=$1 port=$2
    ssh-keygen -q -t ed25519 -N '' -C '' -f "$WORK/sshd/$name-host" || fail "ssh-keygen host key"
    cat >"$WORK/sshd/$name.conf" <<CONF
Port $port
ListenAddress 127.0.0.1
HostKey $WORK/sshd/$name-host
PidFile $WORK/sshd/$name.pid
AuthorizedKeysFile $WORK/sshd/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $SSH_USER $SSH_OTHER
AllowAgentForwarding no
LogLevel VERBOSE
CONF
    /usr/sbin/sshd -D -e -f "$WORK/sshd/$name.conf" >>"$WORK/sshd/$name.log" 2>&1 &
    eval "${name^^}_SSHD_PID=\$!"
    for _ in $(seq 50); do
        ss -ltnH "sport = :$port" | grep -q 127.0.0.1 && return 0
        sleep 0.1
    done
    fail "sshd $name: $(cat "$WORK/sshd/$name.log")"
}
GOOD_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
OTHER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
start_sshd good "$GOOD_PORT"
start_sshd other "$OTHER_PORT"
GOOD_HOST=$(cut -d' ' -f1,2 "$WORK/sshd/good-host.pub")
OTHER_HOST=$(cut -d' ' -f1,2 "$WORK/sshd/other-host.pub")

start_gateway
cat >"$WORK/admin-out/ssh.json" <<JSON
[{"secret": {"name": "deploy key"},
  "ssh": {"users": ["$SSH_USER"], "host_keys": ["$GOOD_HOST"], "sshsig_namespaces": ["git"]}}]
JSON
chmod 0644 "$WORK/admin-out/ssh.json"
as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name ssh \
    --uid "$(uid "$A1")" --op ssh_sign --secrets-file "$WORK/admin-out/ssh.json" \
    --per-minute 60 --token-out "$WORK/admin-out/ssh-token" >"$WORK/ssh-issue.json" 2>"$WORK/ssh-issue.err" \
    || fail "issue with an SSH key: $(cat "$WORK/ssh-issue.err")"
install -m 0600 -o "$A1" "$WORK/admin-out/ssh-token" "$WORK/a1/ssh-token"
pass "issued a credential granted the SSH key by name"

# The agent's SSH agent, as agent 1, in a directory only it can enter.
install -d -m 0700 -o "$A1" "$WORK/a1/ssh"
SSH_SOCK=$WORK/a1/ssh/agent.sock
as "$A1" "$KEEP" agent ssh-agent --token-file "$WORK/a1/ssh-token" --listen "$SSH_SOCK" \
    --socket "$AGENT_SOCK" --gateway-user "$GW" >>"$WORK/ssh-agent.log" 2>&1 &
SSH_AGENT_PID=$!
for _ in $(seq 50); do [[ -S $SSH_SOCK ]] && break; sleep 0.1; done
[[ -S $SSH_SOCK ]] || fail "ssh-agent socket: $(cat "$WORK/ssh-agent.log")"
[[ $(stat -c %a "$SSH_SOCK") == 600 ]] || fail "ssh-agent socket mode $(stat -c %a "$SSH_SOCK")"
as "$A1" env SSH_AUTH_SOCK="$SSH_SOCK" ssh-add -L >"$WORK/ssh-add" 2>&1 || fail "ssh-add -L: $(cat "$WORK/ssh-add")"
[[ $(cut -d' ' -f1,2 "$WORK/ssh-add") == "$SSH_PUB" ]] || fail "ssh-add -L listed $(cat "$WORK/ssh-add")"
# Root can enter the directory, but the agent serves only its own user.
env SSH_AUTH_SOCK="$SSH_SOCK" ssh-add -L >/dev/null 2>&1 && fail "the SSH agent served root"
pass "the agent's SSH agent lists the granted key, to its own user alone"

printf '[127.0.0.1]:%s %s\n[127.0.0.1]:%s %s\n' "$GOOD_PORT" "$GOOD_HOST" "$OTHER_PORT" "$OTHER_HOST" >"$WORK/a1/known_hosts"
chown "$A1" "$WORK/a1/known_hosts"
ssh_as_agent() {
    local port=$1 user=$2
    shift 2
    as "$A1" env SSH_AUTH_SOCK="$SSH_SOCK" ssh -F /dev/null -o BatchMode=yes \
        -o UserKnownHostsFile="$WORK/a1/known_hosts" -o StrictHostKeyChecking=yes \
        -o ConnectTimeout=10 -p "$port" "$@" "$user@127.0.0.1" echo logged-in
}
OUT_SSH=$(ssh_as_agent "$GOOD_PORT" "$SSH_USER" 2>&1) || fail "ssh login: $OUT_SSH $(tail -5 "$WORK/sshd/good.log")"
[[ $OUT_SSH == *logged-in* ]] || fail "ssh login output: $OUT_SSH"
pass "an SSH client logs in through the agent's SSH agent with the vault's key"

ssh_as_agent "$GOOD_PORT" "$SSH_OTHER" >/dev/null 2>&1 && fail "logged in as a user the rule does not name"
ssh_as_agent "$OTHER_PORT" "$SSH_USER" >/dev/null 2>&1 && fail "logged in to a host the rule does not name"
REFUSALS=$(gw_admin audit --limit 40)
grep -q "a user the rule does not name" <<<"$REFUSALS" || fail "no refusal for the other user: $REFUSALS"
grep -q "a host key the rule does not name" <<<"$REFUSALS" || fail "no refusal for the other host: $REFUSALS"
grep -q "ssh_sign.*login $SSH_USER host SHA256:" <<<"$REFUSALS" || fail "no record of the login: $REFUSALS"
pass "logins as another user or to another host are refused, and every one is recorded"

# SSHSIG, as git signs commits: in the granted namespace only.
printf 'commit\n' >"$WORK/a1/message"
printf '%s\n' "$SSH_PUB" >"$WORK/a1/key.pub"
chown "$A1" "$WORK/a1/message" "$WORK/a1/key.pub"
as "$A1" env SSH_AUTH_SOCK="$SSH_SOCK" ssh-keygen -Y sign -f "$WORK/a1/key.pub" -n git "$WORK/a1/message" \
    >"$WORK/sshsig.out" 2>&1 || fail "ssh-keygen -Y sign: $(cat "$WORK/sshsig.out")"
printf 'agent@e2e namespaces="git" %s\n' "$SSH_PUB" >"$WORK/allowed_signers"
ssh-keygen -Y verify -f "$WORK/allowed_signers" -I agent@e2e -n git -s "$WORK/a1/message.sig" \
    <"$WORK/a1/message" >"$WORK/verify.out" 2>&1 || fail "ssh-keygen -Y verify: $(cat "$WORK/verify.out")"
grep -q "Good" "$WORK/verify.out" || fail "verify output: $(cat "$WORK/verify.out")"
rm -f "$WORK/a1/message.sig"
as "$A1" env SSH_AUTH_SOCK="$SSH_SOCK" ssh-keygen -Y sign -f "$WORK/a1/key.pub" -n file "$WORK/a1/message" \
    >/dev/null 2>&1 && fail "signed in a namespace the rule does not name"
pass "SSHSIG signatures in the granted namespace verify with ssh-keygen; other namespaces are refused"

stop_pid "$SSH_AGENT_PID" "$GOOD_SSHD_PID" "$OTHER_SSHD_PID"
SSH_AGENT_PID= GOOD_SSHD_PID= OTHER_SSHD_PID=
stop_gateway

if [[ -z $E2E_BIN_SRC ]]; then
    echo "all gateway e2e checks passed (http_request not checked: no e2e build given)"
    exit 0
fi

# http_request. The gateway is stopped, so the owner adds the secret.
SECRET_VALUE=sk_e2e_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
printf '%s' "$SECRET_VALUE" | as "$GW" env KEEP_PASSWORD=$PASS "$KEEP" --path "$VAULT" \
    secret add --name "deploy token" --kind api-token >/dev/null 2>&1 || fail "secret add"
install -m 0755 "$E2E_BIN_SRC" "$WORK/keep-e2e"
grep -q keep-e2e-roots-build "$WORK/keep-e2e" || fail "the e2e build lacks its marker"
grep -q keep-e2e-roots-build "$KEEP" && fail "the release build carries the e2e marker"
pass "only the e2e build carries the e2e root"

# A namespace with one globally reachable address and no route out: the test
# server and its DNS answer there, and the workers run in it.
ip netns add "$NS"
CREATED_NS=1
ip -n "$NS" link set lo up
ip -n "$NS" link add d0 type dummy
ip -n "$NS" addr add 11.22.33.44/32 dev d0
ip -n "$NS" link set d0 up
install -d -m 0755 "/etc/netns/$NS"
echo "nameserver 11.22.33.44" >"/etc/netns/$NS/resolv.conf"
echo "hosts: files dns" >"/etc/netns/$NS/nsswitch.conf"
printf '127.0.0.1 localhost\n' >"/etc/netns/$NS/hosts"
cat >"$WORK/dns.py" <<'PY'
import socket, struct
names = {b"echo.keep.test": "11.22.33.44", b"evil.keep.test": "10.0.0.1"}
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("11.22.33.44", 53))
while True:
    q, addr = s.recvfrom(512)
    qid, _, qd = struct.unpack(">HHH", q[:6])[0], 0, 1
    labels, i = [], 12
    while q[i]:
        labels.append(q[i + 1:i + 1 + q[i]])
        i += q[i] + 1
    qtype = struct.unpack(">H", q[i + 1:i + 3])[0]
    question = q[12:i + 5]
    name = b".".join(labels).lower()
    ip = names.get(name)
    answers = b""
    if ip and qtype == 1:
        answers = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    rcode = 0 if ip else 3
    header = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, 1 if answers else 0, 0, 0)
    s.sendto(header + question + answers, addr)
PY
cat >"$WORK/server.py" <<'PY'
import http.server, json, ssl, sys
pki, log = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(log, "a") as f:
            f.write(json.dumps({"path": self.path, "headers": dict(self.headers)}) + "\n")
        if self.path == "/v1/ok":
            body, extra = b'{"ok":true}', [("Set-Cookie", "session=abc"), ("Content-Type", "application/json")]
        elif self.path == "/v1/echo":
            body, extra = str(self.headers).encode(), [("Content-Type", "text/plain")]
        elif self.path == "/v1/gzip":
            body, extra = b"\x1f\x8b\x08\x00", [("Content-Encoding", "gzip")]
        elif self.path == "/v1/cut":
            # The secret straddling the 256 KiB the agent is given.
            body = b"x" * (256 * 1024 - 5) + self.headers["Authorization"].encode() + b"y" * 100
            extra = [("Content-Type", "text/plain")]
        elif self.path == "/v1/slow":
            import time
            time.sleep(4)
            body, extra = b"slow", []
        elif self.path == "/v1/redirect":
            self.send_response(302)
            self.send_header("Location", "https://echo.keep.test/v1/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:
            body, extra = b"not found", []
        self.send_response(200)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(pki + "/leaf.pem", pki + "/leaf.key")
srv = http.server.HTTPServer(("11.22.33.44", 443), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
ip netns exec "$NS" python3 -I "$WORK/dns.py" >>"$WORK/dns.log" 2>&1 &
DNS_PID=$!
ip netns exec "$NS" python3 -I "$WORK/server.py" "$PKI" "$WORK/server-requests" >>"$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$DNS_PID" "$SERVER_PID" || fail "test server: $(cat "$WORK/server.log" "$WORK/dns.log")"

# The workers, one per connection, as systemd's socket unit starts them: as
# their own user, in the namespace, the connection as their standard input
# and output. The socket is root's, in a root directory, open to the
# gateway's group.
add_user --user-group "$INJ"
install -d -m 0755 "$RUN/inject"
WORKER_SOCK=$RUN/inject/worker.sock
start_workers() {
    local bin=$1
    rm -f "$WORKER_SOCK"
    systemd-socket-activate --accept --inetd -l "$WORKER_SOCK" -- \
        ip netns exec "$NS" setpriv --reuid="$INJ" --regid="$INJ" --clear-groups \
        env -i PATH=/usr/bin:/bin "$bin" gateway inject-worker >>"$WORK/worker.log" 2>&1 &
    ACTIVATOR_PID=$!
    for _ in $(seq 50); do [[ -S $WORKER_SOCK ]] && break; sleep 0.1; done
    [[ -S $WORKER_SOCK ]] || fail "worker socket"
    chgrp "$GW" "$WORKER_SOCK"
    chmod 0660 "$WORKER_SOCK"
}
start_workers "$WORK/keep-e2e"
start_gateway --inject-socket "$WORKER_SOCK"

cat >"$WORK/admin-out/secrets.json" <<'JSON'
[{"secret": {"name": "deploy token"}, "http": [
  {"host": "echo.keep.test", "port": 443, "methods": ["GET"], "path_prefix": "/v1",
   "header": "authorization", "format": "Bearer {}"},
  {"host": "evil.keep.test", "port": 443, "methods": ["GET"], "path_prefix": "/v1",
   "header": "authorization", "format": "Bearer {}"}
]}]
JSON
chmod 0644 "$WORK/admin-out/secrets.json"
as "$ADMIN" "$KEEP" gateway issue --admin-socket "$ADMIN_SOCK" --gateway-user "$GW" --name http \
    --uid "$(uid "$A1")" --op http_request --secrets-file "$WORK/admin-out/secrets.json" \
    --per-minute 60 --token-out "$WORK/admin-out/http-token" >"$WORK/http-issue.json" 2>"$WORK/http-issue.err" \
    || fail "issue with secrets: $(cat "$WORK/http-issue.err")"
install -m 0600 -o "$A1" "$WORK/admin-out/http-token" "$WORK/a1/http-token"
SECRET_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["grant"]["secrets"][0]["secret"])' "$WORK/http-issue.json")
HTTP_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/http-issue.json")
pass "issued a credential granted the secret by name ($SECRET_ID)"

req() { call "$1" http_request "{\"secret\":\"$SECRET_ID\",\"method\":\"${3:-GET}\",\"url\":\"$2\"${4:-}}"; }
ANS=$( {
    call 1 list_secrets '{}'
    req 2 https://echo.keep.test/v1/ok
    req 4 https://echo.keep.test/v1/gzip
    req 5 https://echo.keep.test/v1/redirect
    req 6 https://echo.keep.test/v2/ok
    req 7 https://evil.keep.test/v1/ok
    req 8 https://echo.keep.test:443/v1/ok
    req 9 https://echo.keep.test/v1/ok POST
    req 10 https://echo.keep.test/v1/ok GET ',"headers":{"X-Other":"y"}'
} | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/http-token")
printf '%s\n' "$ANS" >"$WORK/http-answers"
python3 - "$WORK/http-answers" "$SECRET_ID" <<'PY' || fail "http_request answers: $ANS"
import json, sys
by_id = {a["id"]: a["result"] for a in map(json.loads, filter(str.strip, open(sys.argv[1])))}
text = lambda i: by_id[i]["content"][0]["text"]
listed = json.loads(text(1))["secrets"]
assert listed[0]["id"] == sys.argv[2] and listed[0]["name"] == "deploy token" and listed[0]["usable"], listed
ok = json.loads(text(2))
assert not by_id[2]["isError"] and ok["status"] == 200 and ok["body"] == '{"ok":true}', ok
assert ok["headers"] == {"content-type": "application/json"}, ok
assert by_id[4]["isError"] and text(4) == "encoded response", text(4)
redirect = json.loads(text(5))
assert redirect["status"] == 302 and redirect["headers"]["location"] == "https://echo.keep.test/v1/ok", redirect
refused = "denied: request not allowed"
for i in (6, 8, 9, 10):
    assert by_id[i]["isError"] and text(i) == refused, (i, text(i))
assert by_id[7]["isError"] and text(7) == "address refused", text(7)
PY
pass "http_request: answered within the rule; gzip, other paths, methods and headers, internal addresses and unnormalized URLs refused; redirects returned"

# An echo of the secret is refused and freezes the credential.
echoed() {
    local out
    out=$(req "$1" "$2" | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/http-token")
    python3 -c 'import json,sys; r=json.loads(sys.argv[1])["result"]; assert r["isError"] and r["content"][0]["text"] == "secret in response", r' "$out" \
        || fail "echo $2: $out"
    gw_admin list | python3 -c 'import json,sys; c=[c for c in json.load(sys.stdin) if c["id"]==sys.argv[1]]; assert c and c[0]["frozen"], c' "$HTTP_ID" \
        || fail "not frozen after an echo of $2"
    gw_admin unfreeze "$HTTP_ID" >/dev/null || fail "unfreeze after an echo"
}
echoed 3 https://echo.keep.test/v1/echo
echoed 11 https://echo.keep.test/v1/cut
pass "an echo of the secret, one split across the cut, is refused and freezes the credential"

python3 - "$WORK/server-requests" "$SECRET_VALUE" <<'PY' || fail "server saw: $(cat "$WORK/server-requests")"
import json, sys
reqs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
paths = [r["path"] for r in reqs]
assert paths == ["/v1/ok", "/v1/gzip", "/v1/redirect", "/v1/echo", "/v1/cut"], paths
for r in reqs:
    h = {k.lower(): v for k, v in r["headers"].items()}
    assert h["authorization"] == "Bearer " + sys.argv[2], h
    assert h["accept-encoding"] == "identity" and h["host"] == "echo.keep.test", h
PY
pass "the server got the secret in the rule's header, and nothing outside the rule reached it"

for f in "$WORK/http-answers" "$WORK/gateway.log" "$WORK/worker.log"; do
    grep -qF "$SECRET_VALUE" "$f" && fail "the secret is in $(basename "$f")"
done
# While a request is in flight (the server holds it for 4 seconds), no
# process's arguments or environment hold the secret.
req 12 https://echo.keep.test/v1/slow | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/http-token" >"$WORK/slow" &
SLOW_PID=$!
sleep 2
pgrep -f "inject-worker" >/dev/null || fail "no worker running during the held request"
for c in /proc/[0-9]*/cmdline /proc/[0-9]*/environ; do
    grep -qaF "$SECRET_VALUE" "$c" 2>/dev/null && fail "the secret is in $c"
done
wait "$SLOW_PID" || fail "held request: $(cat "$WORK/slow")"
grep -qF 'body\":\"slow' "$WORK/slow" || fail "held request answer: $(cat "$WORK/slow")"
AUDIT=$(gw_admin audit --limit 40)
grep -q "http_request" <<<"$AUDIT" || fail "no http_request in the audit log"
grep -qF "$SECRET_VALUE" <<<"$AUDIT" && fail "the secret is in the audit log"
pass "the secret is in no answer, log, audit entry, process argument or environment"

# The release build trusts only the bundled roots: the same server fails TLS.
stop_pid "$ACTIVATOR_PID"
start_workers "$KEEP"
ANS=$(req 9 https://echo.keep.test/v1/ok | as "$A1" python3 "$WORK/client.py" "$AGENT_SOCK" "$WORK/a1/http-token")
python3 -c 'import json,sys; r=json.loads(sys.argv[1])["result"]; assert r["isError"] and r["content"][0]["text"] == "tls", r' "$ANS" \
    || fail "release worker against the test root: $ANS"
pass "the release worker refuses a server only the e2e root vouches for"
stop_gateway
stop_pid "$ACTIVATOR_PID"
ACTIVATOR_PID=

echo "all gateway e2e checks passed"
