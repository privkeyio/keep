#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# End-to-end test of the shipped systemd unit, contrib/systemd/keep-gateway.service,
# on a machine booted with systemd: the gateway starts as the `keep-gateway`
# user, unlocks from an encrypted credential, reports ready only once it
# serves, serves an MCP client through `keep agent connect`, restarts
# unattended, and refuses to start, and stops retrying, when misconfigured.
# It also runs http_request under the shipped inject socket and worker
# units: the socket's permissions, a worker per connection under a dynamic
# uid of its own, and a request carried from an agent to a worker.
# Given keep-agent's approval_peer example as well, it also runs approvals
# under the shipped units: the approvals drop-in, the relay helper's unit, a
# phone paired over a local relay, and the refusal to start without the
# channel key once a phone is paired.
#
# It installs the unit and the binary as documented and creates the
# `keep-gateway` user and the `keep-agents` and `keep-admins` groups, so it
# runs only as root, only when KEEP_GATEWAY_SYSTEMD_E2E=1, and only where none
# of them exist yet (a disposable VM, container or CI runner):
#
#   sudo KEEP_GATEWAY_SYSTEMD_E2E=1 scripts/gateway-systemd-e2e.sh target/release/keep \
#     [target/release/examples/approval_peer]
#
# The credential is encrypted with the host key, since test machines have no
# TPM; the documented setup seals it to the TPM as well. The checks of the
# loaded unit's properties match how systemd 255 prints them.

set -euo pipefail

if [[ "${KEEP_GATEWAY_SYSTEMD_E2E:-}" != 1 ]]; then
    echo "refusing to run: this installs a systemd unit and creates users; set KEEP_GATEWAY_SYSTEMD_E2E=1" >&2
    exit 2
fi
if [[ $(id -u) -ne 0 ]]; then
    echo "run as root" >&2
    exit 2
fi
if [[ ! -d /run/systemd/system ]]; then
    echo "refusing to run: this machine was not booted with systemd" >&2
    exit 2
fi
BIN_SRC=${1:?usage: gateway-systemd-e2e.sh path/to/keep [path/to/approval_peer [path/to/e2e-roots-keep pki-dir]]}
PEER_SRC=${2:-}
E2E_SRC=${3:-}
PKI=${4:-}
CONTRIB=$(cd "$(dirname "$0")/.." && pwd)/contrib/systemd
UNIT_SRC=$CONTRIB/keep-gateway.service
[[ -f $UNIT_SRC ]] || { echo "no unit at $UNIT_SRC" >&2; exit 2; }

UNIT=keep-gateway.service
UNIT_FILE=/etc/systemd/system/$UNIT
DROPIN=/etc/systemd/system/$UNIT.d
BIN=/usr/local/bin/keep
CRED_DIR=/etc/keep/gateway
CRED=$CRED_DIR/vault-password.cred
HOST_SECRET=/var/lib/systemd/credential.secret
STATE=/var/lib/keep-gateway
VAULT=$STATE/vault
GW=keep-gateway
AGENT=kgsdagent
ADMIN=kgsdadmin
OUT=kgsdout
RELAY_USER=keep-gateway-relay
RELAY_UNIT=keep-gateway-relay.service
RELAY_UNIT_FILE=/etc/systemd/system/$RELAY_UNIT
INJECT_SOCKET_UNIT=keep-gateway-inject.socket
INJECT_UNITS=(/etc/systemd/system/$INJECT_SOCKET_UNIT /etc/systemd/system/keep-gateway-inject@.service)
INJECT_DROPIN=/etc/systemd/system/keep-gateway-inject@.service.d
E2E_BIN=/usr/local/bin/keep-e2e
TEST_LINK=kgsd0
HOLD_PID=
SERVER_PID=
DNS_PID=
RELAY_PID=
PAIR_PID=
PHONE_PID=
PASS=systemd-e2e-vault-password
CREATED=()
UNIT_INSTALLED=
. "$(dirname "$0")/lib/gateway-e2e.sh"

refuse_users $GW $AGENT $ADMIN $OUT $RELAY_USER
refuse_groups $GW keep-agents keep-admins $AGENT $ADMIN $OUT $RELAY_USER
refuse_paths "$UNIT_FILE" "$DROPIN" "$RELAY_UNIT_FILE" "$BIN" /etc/keep "$STATE" /run/keep-gateway \
    /run/keep-gateway-admin /run/keep-gateway-relay /run/keep-gateway-inject "${INJECT_UNITS[@]}" \
    "$INJECT_DROPIN" "$E2E_BIN" "/sys/class/net/$TEST_LINK"
for u in "$UNIT" "$RELAY_UNIT" "$INJECT_SOCKET_UNIT"; do
    if systemctl cat "$u" >/dev/null 2>&1; then
        echo "refusing to run: a $u unit is already installed" >&2
        exit 2
    fi
done
# systemd-creds makes the host key on first use; it is removed afterwards
# only if this script made it.
[[ -e $HOST_SECRET ]] || CREATED+=("$HOST_SECRET")
WORK=$(mktemp -d /var/tmp/kgsd.XXXXXX)

fail_context() {
    echo "--- journal ---"
    journalctl -u "$UNIT" --no-pager -n 40 -o cat
}

cleanup() {
    stop_pid "$HOLD_PID" "$SERVER_PID" "$DNS_PID"
    ip link delete "$TEST_LINK" 2>/dev/null || true
    rm -rf "$INJECT_DROPIN" "$E2E_BIN"
    systemctl stop "$INJECT_SOCKET_UNIT" 'keep-gateway-inject@*' >/dev/null 2>&1 || true
    systemctl reset-failed 'keep-gateway-inject@*' >/dev/null 2>&1 || true
    rm -f "${INJECT_UNITS[@]}"
    systemctl stop "$RELAY_UNIT" >/dev/null 2>&1 || true
    systemctl reset-failed "$RELAY_UNIT" >/dev/null 2>&1 || true
    rm -f "$RELAY_UNIT_FILE"
    stop_pid "$PAIR_PID" "$PHONE_PID" "$RELAY_PID"
    if [[ -n $UNIT_INSTALLED ]]; then
        systemctl stop "$UNIT" >/dev/null 2>&1 || true
        systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
    fi
    rm -rf "$DROPIN"
    rm -f "$UNIT_FILE"
    systemctl daemon-reload || true
    remove_created_accounts
    for p in "${CREATED[@]}"; do rm -rf "$p"; done
    rm -rf /run/keep-gateway /run/keep-gateway-admin /run/keep-gateway-relay /run/keep-gateway-inject
    rm -rf "$WORK"
}
trap cleanup EXIT

# Users and groups as documented.
groupadd --system keep-agents
CREATED_GROUPS+=(keep-agents)
groupadd --system keep-admins
CREATED_GROUPS+=(keep-admins)
useradd --system --user-group --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin $GW
CREATED_USERS+=($GW)
CREATED_GROUPS+=($GW)
add_user -G keep-agents "$AGENT"
add_user -G keep-admins "$ADMIN"
add_user "$OUT"

install -m 0755 "$BIN_SRC" "$BIN"
CREATED+=("$BIN")

# The vault, created as the gateway's user (the password comes from the
# environment only for this setup step; the gateway never reads it there).
install -d -m 0700 -o $GW -g $GW "$STATE"
CREATED+=("$STATE")
MSG=$(as $GW env KEEP_PASSWORD=$PASS "$BIN" --path "$VAULT" init --size 10 2>&1) || fail "vault init: $MSG"
MSG=$(as $GW env KEEP_PASSWORD=$PASS "$BIN" --path "$VAULT" generate --name agent 2>&1) || fail "generate: $MSG"
NPUB=$(grep -o -m1 'npub1[02-9ac-hj-np-z]*' <<<"$MSG") || fail "no key generated: $MSG"
NPUB=${NPUB%%$'\n'*}
pass "vault created as $GW with key $NPUB"

# The password, encrypted. Nothing in the file reads as the password.
install -d -m 0700 /etc/keep
CREATED+=(/etc/keep)
install -d -m 0700 "$CRED_DIR"
seal() {
    local out
    out=$(printf '%s' "$1" | systemd-creds encrypt --name=vault-password --with-key=host - "$CRED" 2>&1) \
        || fail "systemd-creds encrypt: $out"
}
seal "$PASS"
[[ -s $CRED ]] || fail "no credential written"
if grep -qaF "$PASS" "$CRED"; then fail "the credential holds the password in plaintext"; fi
pass "vault password encrypted to $CRED"

install -m 0644 "$UNIT_SRC" "$UNIT_FILE"
UNIT_INSTALLED=1
systemctl daemon-reload
VERIFY=$(systemd-analyze verify "$UNIT_FILE" 2>&1) || fail "systemd-analyze verify: $VERIFY"
# Only what it says about this unit counts; other units' warnings vary by host.
if grep -qF "$UNIT" <<<"$VERIFY"; then fail "systemd-analyze verify warns: $VERIFY"; fi
pass "the unit passes systemd-analyze verify"
# The unit as systemd loaded it.
PROPS=$(systemctl show --all "$UNIT")
for want in User=$GW Group=$GW Type=notify NotifyAccess=main StartLimitBurst=5 StartLimitIntervalUSec=10min \
    NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes \
    PrivateTmp=yes PrivateDevices=yes PrivateIPC=yes PrivateNetwork=yes ProtectProc=invisible \
    ProtectKernelTunables=yes ProtectKernelModules=yes ProtectKernelLogs=yes ProtectControlGroups=yes \
    ProtectClock=yes ProtectHostname=yes RestrictRealtime=yes RestrictSUIDSGID=yes \
    MemoryDenyWriteExecute=yes LockPersonality=yes RemoveIPC=yes KeyringMode=private \
    DevicePolicy=closed CapabilityBoundingSet= AmbientCapabilities= RestrictAddressFamilies=AF_UNIX \
    RestrictNamespaces=yes SystemCallArchitectures=native SystemCallErrorNumber=1 LimitCORE=0 \
    UMask=0077 PrivateUsers=no IPAddressAllow= \
    'ReadWritePaths=-/run/keep-gateway -/run/keep-gateway-admin'; do
    grep -qxF "$want" <<<"$PROPS" || fail "the unit does not set $want: $(grep "^${want%%=*}=" <<<"$PROPS")"
done
# systemd prints the denied prefixes in no fixed order.
DENY=$(grep '^IPAddressDeny=' <<<"$PROPS") || fail "no IPAddressDeny"
for prefix in 0.0.0.0/0 ::/0; do
    grep -qF " $prefix" <<<" ${DENY#IPAddressDeny=}" || fail "the unit does not deny $prefix: $DENY"
done
grep -qx 'LoadCredentialEncrypted=vault-password:/etc/keep/gateway/vault-password.cred' <<<"$(systemctl cat "$UNIT")" \
    || fail "the unit does not load the encrypted credential"
# An allow list (a deny list shows as `~...`) that leaves out what the unit
# denies, and what no service it allows would need.
FILTER=$(grep '^SystemCallFilter=' <<<"$PROPS") || fail "no system call filter"
[[ $FILTER != SystemCallFilter=~* ]] || fail "not an allow list: ${FILTER:0:80}"
for call in accept4 bind mlock read sendto; do
    grep -qw "$call" <<<"$FILTER" || fail "the filter denies $call"
done
for call in mount reboot setrlimit init_module ptrace kexec_load; do
    if grep -qw "$call" <<<"$FILTER"; then fail "the filter allows $call"; fi
done
pass "the unit sets every hardening option as loaded by systemd"
SECURITY=$(systemd-analyze security "$UNIT" --no-pager 2>/dev/null || true)
EXPOSURE=$(grep -o 'Overall exposure level.*' <<<"$SECURITY" | grep -oE '[0-9]+\.[0-9]+ [A-Z]+' || true)
echo "   systemd-analyze security: exposure ${EXPOSURE:-unknown}"

# Type=notify: once `systemctl start` returns, the gateway already answers.
systemctl start "$UNIT" || fail "the unit did not start"
MSG=$("$BIN" gateway status 2>&1) || fail "started, but not answering: $MSG"
pass "the unit is ready only once the gateway answers on its default admin socket"

PID=$(systemctl show -p MainPID --value "$UNIT")
[[ $PID -gt 0 ]] || fail "no main pid"
status() { awk -v k="$1:" '$1 == k {print $2}' "/proc/$PID/status"; }
[[ $(awk '/^Uid:/ {print $3}' "/proc/$PID/status") == "$(uid $GW)" ]] || fail "not running as $GW"
[[ $(status NoNewPrivs) == 1 ]] || fail "NoNewPrivs is not set"
[[ $(status Seccomp) == 2 ]] || fail "no seccomp filter"
[[ $(status CapEff) == 0000000000000000 ]] || fail "capabilities: $(status CapEff)"
[[ $(status CapBnd) == 0000000000000000 ]] || fail "bounding set: $(status CapBnd)"
grep -q '^Max core file size *0 *0' "/proc/$PID/limits" || fail "core dumps are not off"
ENVIRON=$(tr '\0' '\n' <"/proc/$PID/environ")
if grep -q '^KEEP_PASSWORD=' <<<"$ENVIRON"; then fail "KEEP_PASSWORD in the environment"; fi
grep -q '^CREDENTIALS_DIRECTORY=' <<<"$ENVIRON" || fail "no credentials directory"
SHOW=$(systemctl show "$UNIT")
if grep -qF "$PASS" <<<"$SHOW"; then fail "the password shows in systemctl show"; fi
if as $GW cat "/proc/$PID/environ" >/dev/null 2>&1; then fail "the gateway is dumpable"; fi
pass "runs as $GW: no new privileges, seccomp, no capabilities, no core dumps, not dumpable, no password in its environment"

dir_is() {
    local got
    got=$(stat -c '%U:%G %a' "$1")
    [[ $got == "$2" ]] || fail "$1 is $got, not $2"
}
dir_is /run/keep-gateway "$GW:keep-agents 750"
dir_is /run/keep-gateway-admin "$GW:keep-admins 750"
dir_is "$STATE" "$GW:$GW 700"
pass "socket directories: $GW:keep-agents and $GW:keep-admins, mode 0750; the vault's 0700"

CREDS=/run/credentials/$UNIT
[[ -f $CREDS/vault-password ]] || fail "no decrypted credential at $CREDS"
if as "$AGENT" cat "$CREDS/vault-password" >/dev/null 2>&1; then fail "an agent read the credential"; fi
if as $GW cat "$CRED" >/dev/null 2>&1; then fail "$GW read the encrypted credential file"; fi
JOURNAL=$(journalctl -u "$UNIT" --no-pager -o cat)
if grep -qF "$PASS" <<<"$JOURNAL"; then fail "the password is in the journal"; fi
pass "the decrypted password is closed to agents and absent from the journal"

# A credential for the agent, issued by root over the admin socket.
install -d -m 0700 "$WORK/root"
MSG=$("$BIN" gateway issue --name systemd --uid "$(uid "$AGENT")" --key "$NPUB" \
    --op get_public_key --op sign_nostr_event --kind 1 --token-out "$WORK/root/token" 2>&1) \
    || fail "issue: $MSG"
chmod 0755 "$WORK"
install -d -m 0700 -o "$AGENT" "$WORK/agent"
install -m 0600 -o "$AGENT" "$WORK/root/token" "$WORK/agent/token"

# A stock MCP client's session through the bridge, with every default.
cat >"$WORK/session.py" <<'PY'
import json, select, subprocess, sys
server = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def ask(message):
    server.stdin.write((json.dumps(message) + "\n").encode())
    server.stdin.flush()
    ready, _, _ = select.select([server.stdout], [], [], 30)
    return json.loads(server.stdout.readline()) if ready else None
init = ask({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "systemd-e2e", "version": "1"}}})
assert init["result"]["serverInfo"]["name"] == "keep-gateway", init
server.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
tools = ask({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
assert "sign_nostr_event" in [t["name"] for t in tools["result"]["tools"]], tools
signed = ask({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "sign_nostr_event", "arguments": {"kind": 1, "content": "under systemd"}}})
assert signed["result"]["isError"] is False, signed
event = json.loads(signed["result"]["content"][0]["text"])
denied = ask({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "sign_nostr_event", "arguments": {"kind": 4, "content": "dm"}}})
assert denied["result"]["isError"] is True, denied
server.stdin.close()
assert server.wait(timeout=10) == 0
print(event["id"])
PY
chmod 0644 "$WORK/session.py"
session() {
    as "$AGENT" python3 "$WORK/session.py" "$BIN" agent connect --token-file "$WORK/agent/token" 2>>"$WORK/bridge.log"
}
EVENT=$(session) || fail "bridge session: $(cat "$WORK/bridge.log")"
AUDIT=$("$BIN" gateway audit --limit 50 2>&1) || fail "audit: $AUDIT"
grep -qF "sign_nostr_event kind 1 id $EVENT" <<<"$AUDIT" || fail "the signature was not audited"
pass "an MCP client signs through the bridge with the default socket and gateway user, audited"

# Who reaches which socket. The outsider holds a copy of the token, so only
# the socket's directory keeps it out.
install -d -m 0700 -o "$OUT" "$WORK/out"
install -m 0600 -o "$OUT" "$WORK/root/token" "$WORK/out/token"
MSG=$(as "$OUT" "$BIN" agent connect --token-file "$WORK/out/token" </dev/null 2>&1) \
    && fail "an outsider reached the agent socket"
grep -q "Permission denied" <<<"$MSG" || fail "outsider: $MSG"
MSG=$(as "$AGENT" "$BIN" gateway status 2>&1) && fail "an agent reached the admin socket"
grep -q "Permission denied" <<<"$MSG" || fail "agent at the admin socket: $MSG"
MSG=$(as "$ADMIN" "$BIN" gateway status 2>&1) && fail "the admin was let in before --admin-uid was set"
grep -q "run as root or the gateway's admin uid" <<<"$MSG" || fail "admin before --admin-uid: $MSG"
pass "outsiders are shut out of the agent socket, agents out of the admin socket"

# Settings go in a drop-in, as documented.
install -d -m 0755 "$DROPIN"
cat >"$DROPIN/admin.conf" <<EOF
[Service]
ExecStart=
ExecStart=$BIN --path $VAULT gateway serve --admin-uid $(uid "$ADMIN")
EOF
systemctl daemon-reload
systemctl restart "$UNIT" || fail "restart"
MSG=$(as "$ADMIN" "$BIN" gateway status 2>&1) || fail "the admin uid was refused: $MSG"
EVENT=$(session) || fail "bridge session after restart: $(cat "$WORK/bridge.log")"
pass "restarted unattended from the credential; the admin uid set in a drop-in manages it"

# Misconfigured: the gateway refuses to start, says why in its own journal,
# and never logs the password.
INVOCATION=
refuses_to_start() {
    local why=$1 want=$2 log=
    systemctl daemon-reload
    if systemctl restart "$UNIT" 2>/dev/null; then fail "started with $why"; fi
    INVOCATION=$(systemctl show -p InvocationID --value "$UNIT")
    for _ in $(seq 50); do
        log=$(journalctl _SYSTEMD_INVOCATION_ID="$INVOCATION" --no-pager -o cat)
        grep -qF "$want" <<<"$log" && break
        sleep 0.1
    done
    grep -qF "$want" <<<"$log" || fail "$why: $log"
    if grep -qF "$PASS" <<<"$log"; then fail "$why: the password is in the journal"; fi
    return 0
}
cat >"$DROPIN/password.conf" <<EOF
[Service]
Environment=KEEP_PASSWORD=$PASS
EOF
refuses_to_start "KEEP_PASSWORD in its environment" "never reads the vault password from KEEP_PASSWORD"
systemctl stop "$UNIT" >/dev/null 2>&1 || true
systemctl reset-failed "$UNIT" 2>/dev/null || true
rm "$DROPIN/password.conf"
mv "$CRED" "$WORK/root/saved.cred"
seal "not-the-password"
CURSOR=$(journalctl -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
refuses_to_start "the wrong password" "Decryption failed - wrong password"
# It tries again, five starts in all, then gives up rather than loop.
for _ in $(seq 600); do
    LOG=$(journalctl -u "$UNIT" --after-cursor="$CURSOR" --no-pager -o cat)
    grep -q "Start request repeated too quickly" <<<"$LOG" && break
    sleep 0.1
done
grep -q "Start request repeated too quickly" <<<"$LOG" \
    || fail "still retrying: $(systemctl show -p ActiveState -p SubState -p NRestarts "$UNIT" | tr '\n' ' ')"
RESTARTS=$(systemctl show -p NRestarts --value "$UNIT")
sleep 7
[[ $(systemctl show -p ActiveState --value "$UNIT") == failed ]] || fail "not failed after the start limit"
[[ $(systemctl show -p NRestarts --value "$UNIT") == "$RESTARTS" ]] || fail "it went on restarting"
pass "it refuses to start with KEEP_PASSWORD set or the wrong password, gives up after five starts, and never logs the password"

mv "$WORK/root/saved.cred" "$CRED"
systemctl reset-failed "$UNIT" 2>/dev/null || true
systemctl daemon-reload
# A wrong password slows further unlocks for a while: wait it out.
for _ in $(seq 60); do
    systemctl start "$UNIT" 2>/dev/null && break
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    sleep 5
done
systemctl is-active --quiet "$UNIT" || fail "did not start again with the right password"
MSG=$("$BIN" gateway status 2>&1) || fail "not answering after the fix: $MSG"
pass "sealed again with the right password, it starts after reset-failed"

# http_request under the shipped units. The secret is added with the gateway
# stopped, as documented.
systemctl stop "$UNIT"
SECRET_VALUE=sk_sd_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
printf '%s' "$SECRET_VALUE" | as $GW env KEEP_PASSWORD=$PASS "$BIN" --path "$VAULT" \
    secret add --name "deploy token" --kind api-token >/dev/null 2>&1 || fail "secret add"
install -m 0644 "$CONTRIB/keep-gateway-inject.socket" "${INJECT_UNITS[0]}"
install -m 0644 "$CONTRIB/keep-gateway-inject@.service" "${INJECT_UNITS[1]}"
install -m 0644 "$CONTRIB/keep-gateway-inject.conf" "$DROPIN/inject.conf"
sed -i 's|^ExecStart=\(.\+ gateway serve .*\)$|ExecStart=\1 --inject-socket|' "$DROPIN/admin.conf"
grep -q -- '--inject-socket$' "$DROPIN/admin.conf" || fail "drop-in: $(cat "$DROPIN/admin.conf")"
systemctl daemon-reload
for f in "${INJECT_UNITS[@]}"; do
    VERIFY=$(systemd-analyze verify "$f" 2>&1) || fail "systemd-analyze verify $f: $VERIFY"
    if grep -qF "$(basename "$f")" <<<"$VERIFY"; then fail "systemd-analyze verify warns: $VERIFY"; fi
done
PROPS=$(systemctl show --all keep-gateway-inject@probe.service)
for want in DynamicUser=yes NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes \
    PrivateDevices=yes ProtectProc=invisible ProcSubset=pid CapabilityBoundingSet= MemoryDenyWriteExecute=yes \
    RestrictNamespaces=yes LimitCORE=0 UMask=0077 RuntimeMaxUSec=40s StandardInput=socket Type=exec \
    SocketBindDeny=any; do
    grep -qxF "$want" <<<"$PROPS" || fail "the worker unit does not set $want: $(grep "^${want%%=*}=" <<<"$PROPS")"
done
systemctl start "$INJECT_SOCKET_UNIT" || fail "the inject socket did not start"
systemctl start "$UNIT" || fail "the gateway did not start with --inject-socket"
dir_is /run/keep-gateway-inject "root:root 755"
[[ $(stat -c '%U:%G %a' /run/keep-gateway-inject/worker.sock) == "root:$GW 660" ]] \
    || fail "worker socket: $(stat -c '%U:%G %a' /run/keep-gateway-inject/worker.sock)"
pass "the inject socket is root's, open to the gateway's group alone, and the gateway starts with it"

# Two connections at once: two workers, each under a dynamic uid of its own.
python3 -c '
import socket, time
held = [socket.socket(socket.AF_UNIX) for _ in range(2)]
for s in held:
    s.connect("/run/keep-gateway-inject/worker.sock")
time.sleep(20)
' &
HOLD_PID=$!
for _ in $(seq 100); do
    [[ $(systemctl list-units 'keep-gateway-inject@*' --state=running --no-legend | wc -l) -ge 2 ]] && break
    sleep 0.1
done
UIDS=()
for u in $(systemctl list-units 'keep-gateway-inject@*' --state=running --no-legend --plain | awk '{print $1}'); do
    PIDW=$(systemctl show -p MainPID --value "$u")
    UIDS+=("$(awk '/^Uid:/ {print $3}' "/proc/$PIDW/status")")
done
[[ ${#UIDS[@]} -eq 2 ]] || fail "expected two workers, saw ${#UIDS[@]}"
[[ ${UIDS[0]} != "${UIDS[1]}" ]] || fail "two workers share uid ${UIDS[0]}"
for w in "${UIDS[@]}"; do
    [[ $w -ge 61184 && $w -le 65519 ]] || fail "worker uid $w is not a dynamic one"
done
stop_pid "$HOLD_PID"
HOLD_PID=
pass "each worker runs under a dynamic uid of its own (${UIDS[*]})"

# A credential is never bound to a dynamic uid while injection is on.
if MSG=$("$BIN" gateway issue --name dyn --uid 61200 --op get_public_key --key "$NPUB" 2>&1); then
    fail "issued a credential bound to a dynamic uid"
fi
grep -q "dynamic services" <<<"$MSG" || fail "dynamic uid refused for another reason: $MSG"

# An agent's request reaches a worker through the socket unit and back.
cat >"$WORK/secrets.json" <<'JSON'
[{"secret": {"name": "deploy token"}, "http": [{"host": "echo.keep.test", "port": 443,
  "methods": ["GET"], "path_prefix": "/v1", "header": "authorization", "format": "Bearer {}"}]}]
JSON
"$BIN" gateway issue --name http --uid "$(uid "$AGENT")" --op http_request --secrets-file "$WORK/secrets.json" \
    --token-out "$WORK/root/http-token" >"$WORK/http-issue.json" 2>"$WORK/http-issue.err" \
    || fail "issue with secrets: $(cat "$WORK/http-issue.err")"
install -m 0600 -o "$AGENT" "$WORK/root/http-token" "$WORK/agent/http-token"
SECRET_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["grant"]["secrets"][0]["secret"])' "$WORK/http-issue.json")
HTTP_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/http-issue.json")
# One http_request through the bridge; prints the tool result.
cat >"$WORK/call_http.py" <<'PY'
import json, select, subprocess, sys
secret, url, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]
server = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def ask(message):
    server.stdin.write((json.dumps(message) + "\n").encode())
    server.stdin.flush()
    ready, _, _ = select.select([server.stdout], [], [], 60)
    return json.loads(server.stdout.readline()) if ready else None
ask({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
r = ask({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "http_request",
    "arguments": {"secret": secret, "method": "GET", "url": url}}})
server.stdin.close()
server.wait(timeout=10)
print(json.dumps(r["result"]))
PY
chmod 0644 "$WORK/call_http.py"
http() {
    as "$AGENT" python3 "$WORK/call_http.py" "$SECRET_ID" "$1" "$BIN" agent connect --token-file "$WORK/agent/http-token" \
        2>>"$WORK/bridge.log"
}
# The text of a tool result, and whether it is an error.
result_is() {
    python3 -c 'import json,sys; r=json.loads(sys.argv[1]); assert r["isError"] == (sys.argv[2] == "error") and sys.argv[3] in r["content"][0]["text"], r' "$@"
}
if [[ -z $E2E_SRC ]]; then
    # The test machine resolves no name under .test, so the worker answers dns.
    OUT_HTTP=$(http https://echo.keep.test/v1/ok) || fail "http_request: $OUT_HTTP"
    result_is "$OUT_HTTP" error dns || fail "http_request through the units: $OUT_HTTP"
    pass "an agent's http_request reaches a worker started by the socket unit (resolving under its sandbox)"
else
    # The whole path under the shipped sandbox: a test server on a globally
    # reachable address on a dummy link, its name answered by a DNS server
    # there that systemd-resolved routes keep.test to, and the workers run
    # from the e2e build, which trusts the test root.
    ip link add "$TEST_LINK" type dummy
    ip addr add 11.22.33.44/32 dev "$TEST_LINK"
    ip link set "$TEST_LINK" up
    resolvectl dns "$TEST_LINK" 11.22.33.44
    resolvectl domain "$TEST_LINK" '~keep.test'
    cat >"$WORK/dns.py" <<'PY'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("11.22.33.44", 53))
while True:
    q, addr = s.recvfrom(512)
    qid = struct.unpack(">H", q[:2])[0]
    labels, i = [], 12
    while q[i]:
        labels.append(q[i + 1:i + 1 + q[i]])
        i += q[i] + 1
    qtype = struct.unpack(">H", q[i + 1:i + 3])[0]
    known = b".".join(labels).lower() == b"echo.keep.test"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("11.22.33.44") if known and qtype == 1 else b""
    s.sendto(struct.pack(">HHHHHH", qid, 0x8180 | (0 if known else 3), 1, 1 if answer else 0, 0, 0) + q[12:i + 5] + answer, addr)
PY
    cat >"$WORK/server.py" <<'PY'
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok":true}' if self.path == "/v1/ok" else str(self.headers).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1] + "/leaf.pem", sys.argv[1] + "/leaf.key")
srv = http.server.HTTPServer(("11.22.33.44", 443), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
    python3 -I "$WORK/dns.py" >>"$WORK/dns.log" 2>&1 &
    DNS_PID=$!
    python3 -I "$WORK/server.py" "$PKI" >>"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    install -m 0755 "$E2E_SRC" "$E2E_BIN"
    install -d -m 0755 "$INJECT_DROPIN"
    printf '[Service]\nExecStart=\nExecStart=%s gateway inject-worker\n' "$E2E_BIN" >"$INJECT_DROPIN/e2e.conf"
    systemctl daemon-reload
    for _ in $(seq 50); do
        ss -ltnH 'sport = :443' | grep -q 11.22.33.44 && ss -lunH 'sport = :53' | grep -q 11.22.33.44 && break
        sleep 0.1
    done
    kill -0 "$SERVER_PID" "$DNS_PID" || fail "test servers: $(cat "$WORK/server.log" "$WORK/dns.log")"
    [[ $(resolvectl query --legend=no echo.keep.test 2>&1) == *11.22.33.44* ]] \
        || fail "resolved does not route keep.test: $(resolvectl query echo.keep.test 2>&1)"
    OUT_HTTP=$(http https://echo.keep.test/v1/ok) || fail "http_request: $OUT_HTTP"
    result_is "$OUT_HTTP" ok '"status":200' || fail "http_request under the sandbox: $OUT_HTTP $(cat "$WORK/server.log" "$WORK/dns.log") $(ss -ltn) $(journalctl -u 'keep-gateway-inject@*' --no-pager -o cat | tail -5)"
    OUT_HTTP=$(http https://echo.keep.test/v1/echo) || fail "http_request: $OUT_HTTP"
    result_is "$OUT_HTTP" error "secret in response" || fail "echo under the sandbox: $OUT_HTTP"
    "$BIN" gateway list | python3 -c 'import json,sys; c=[c for c in json.load(sys.stdin) if c["id"]==sys.argv[1]]; assert c and c[0]["frozen"], c' "$HTTP_ID" \
        || fail "not frozen after an echo"
    pass "under the shipped sandbox a worker resolves, connects, verifies and answers, and refuses an echo of the secret, freezing the credential"
fi
JOURNAL=$(journalctl -u "$UNIT" -u 'keep-gateway-inject@*' --no-pager -o cat)
grep -qF "$SECRET_VALUE" <<<"$JOURNAL" && fail "the secret is in the journal"
pass "the journal never holds the secret"
systemctl stop "$INJECT_SOCKET_UNIT"
rm -f "$DROPIN/inject.conf"
sed -i 's| --inject-socket$||' "$DROPIN/admin.conf"
systemctl daemon-reload
systemctl restart "$UNIT" || fail "restart without injection"

if [[ -n $PEER_SRC ]]; then
    # Approvals under the shipped units, set up as documented.
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin $RELAY_USER
    CREATED_USERS+=($RELAY_USER)
    CREATED_GROUPS+=($RELAY_USER)
    install -m 0755 "$PEER_SRC" "$WORK/approval_peer"
    PEER=$WORK/approval_peer
    PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    "$PEER" relay "$PORT" >"$WORK/relay.log" 2>&1 &
    RELAY_PID=$!
    for _ in $(seq 100); do grep -q '^relay ' "$WORK/relay.log" && break; sleep 0.1; done
    grep -q '^relay ' "$WORK/relay.log" || fail "no local relay: $(cat "$WORK/relay.log")"

    # The channel key, sealed straight from the pipe.
    MSG=$(as $GW "$BIN" gateway channel-key new 2>"$WORK/channel-key.err" \
        | systemd-creds encrypt --name=channel-key --with-key=host - "$CRED_DIR/channel-key.cred" 2>&1) \
        || fail "channel key: $MSG $(cat "$WORK/channel-key.err")"
    grep -q "channel key npub1" "$WORK/channel-key.err" || fail "no public key: $(cat "$WORK/channel-key.err")"
    install -m 0644 "$CONTRIB/keep-gateway-relay.service" "$RELAY_UNIT_FILE"
    install -m 0644 "$CONTRIB/keep-gateway-approvals.conf" "$DROPIN/approvals.conf"
    cat >"$DROPIN/admin.conf" <<EOF
[Service]
ExecStart=
ExecStart=$BIN --path $VAULT gateway serve --admin-uid $(uid "$ADMIN") --approval-relay ws://127.0.0.1:$PORT
EOF
    systemctl daemon-reload
    VERIFY=$(systemd-analyze verify "$RELAY_UNIT_FILE" 2>&1) || fail "systemd-analyze verify: $VERIFY"
    if grep -qF "$RELAY_UNIT" <<<"$VERIFY"; then fail "systemd-analyze verify warns: $VERIFY"; fi
    PROPS=$(systemctl show --all "$RELAY_UNIT")
    for want in User=$RELAY_USER Group=$RELAY_USER NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes \
        PrivateTmp=yes PrivateDevices=yes ProtectProc=invisible ProcSubset=pid CapabilityBoundingSet= \
        MemoryDenyWriteExecute=yes RestrictNamespaces=yes LimitCORE=0 UMask=0077 PrivateUsers=no; do
        grep -qxF "$want" <<<"$PROPS" || fail "the relay unit does not set $want: $(grep "^${want%%=*}=" <<<"$PROPS")"
    done
    # The relays and the gateway's socket, and no other family; systemd
    # prints them in its own order.
    FAMILIES=$(grep '^RestrictAddressFamilies=' <<<"$PROPS") || fail "no RestrictAddressFamilies"
    [[ $(tr ' ' '\n' <<<"${FAMILIES#*=}" | sort | tr '\n' ' ') == "AF_INET AF_INET6 AF_UNIX " ]] \
        || fail "the relay unit allows $FAMILIES"
    systemctl restart "$UNIT" || fail "the gateway did not start with approvals"
    systemctl start "$RELAY_UNIT" || fail "the relay helper did not start"
    dir_is /run/keep-gateway-relay "$GW:$RELAY_USER 750"
    [[ $("$BIN" gateway status | python3 -c 'import json,sys; print(json.load(sys.stdin)["approvals"]["configured"])') == True ]] \
        || fail "approvals not configured"
    [[ -f /run/credentials/$UNIT/channel-key ]] || fail "no channel key credential"
    for _ in $(seq 100); do
        grep -q "connected to the gateway's relay socket" <<<"$(journalctl -u "$RELAY_UNIT" --no-pager -o cat)" && break
        sleep 0.1
    done
    LOG=$(journalctl -u "$RELAY_UNIT" --no-pager -o cat)
    grep -q "connected to the gateway's relay socket" <<<"$LOG" || fail "the helper did not connect: $LOG"
    HELPER=$(systemctl show -p MainPID --value "$RELAY_UNIT")
    [[ $(awk '/^Uid:/ {print $3}' "/proc/$HELPER/status") == "$(uid $RELAY_USER)" ]] || fail "the helper is not $RELAY_USER"
    pass "the gateway runs with the approvals drop-in and the helper's unit connects as $RELAY_USER"

    # Pair a phone on a terminal, as root does the first time.
    write_pair_driver "$WORK/pair.py"
    python3 "$WORK/pair.py" "$WORK/uri" "$WORK/phone.fp" "$WORK/pair.answer" "$BIN" gateway approver pair \
        --label Phone >"$WORK/pair.out" 2>&1 &
    PAIR_PID=$!
    for _ in $(seq 300); do [[ -s $WORK/uri ]] && break; sleep 0.1; done
    [[ -s $WORK/uri ]] || fail "no pairing code: $(cat "$WORK/pair.out")"
    "$PEER" phone "$(cat "$WORK/uri")" </dev/null >"$WORK/phone.log" 2>&1 &
    PHONE_PID=$!
    for _ in $(seq 300); do grep -q '^fingerprint ' "$WORK/phone.log" && break; sleep 0.1; done
    awk '/^fingerprint / {sub(/^fingerprint /, ""); print; exit}' "$WORK/phone.log" >"$WORK/phone.fp.tmp"
    mv "$WORK/phone.fp.tmp" "$WORK/phone.fp"
    wait "$PAIR_PID" || fail "pairing: $(cat "$WORK/pair.out")"
    PAIR_PID=
    [[ $(cat "$WORK/pair.answer") == same ]] || fail "the fingerprints differ"
    for _ in $(seq 300); do grep -q '^paired$' "$WORK/phone.log" && break; sleep 0.1; done
    grep -q '^paired$' "$WORK/phone.log" || fail "the phone was not told it is paired: $(cat "$WORK/phone.log")"
    stop_pid "$PHONE_PID"
    PHONE_PID=
    [[ $("$BIN" gateway status | python3 -c 'import json,sys; print(json.load(sys.stdin)["approvals"]["approvers"])') == 1 ]] \
        || fail "no approver registered"
    pass "a phone paired through the gateway in its sandbox, with no network of its own, and the helper"

    # Once a phone is paired, the gateway needs its channel key.
    # The approvals set-up taken out: the drop-in and the relays.
    mv "$DROPIN/approvals.conf" "$WORK/approvals.conf"
    mv "$DROPIN/admin.conf" "$WORK/admin.conf"
    cat >"$DROPIN/admin.conf" <<EOF
[Service]
ExecStart=
ExecStart=$BIN --path $VAULT gateway serve --admin-uid $(uid "$ADMIN")
EOF
    refuses_to_start "no channel key" "needs its channel-key credential"
    systemctl stop "$UNIT" >/dev/null 2>&1 || true
    systemctl reset-failed "$UNIT" 2>/dev/null || true
    mv "$WORK/admin.conf" "$DROPIN/admin.conf"
    mv "$WORK/approvals.conf" "$DROPIN/approvals.conf"
    systemctl daemon-reload
    systemctl start "$UNIT" || fail "did not start again with the channel key"
    pass "with a phone paired, it refuses to start without its channel key, and starts again with it"
    systemctl stop "$RELAY_UNIT"
fi


systemctl stop "$UNIT"
[[ $(systemctl show -p ExecMainStatus --value "$UNIT") == 0 ]] || fail "stopped with status $(systemctl show -p ExecMainStatus --value "$UNIT")"
LEFT=$(find /run/keep-gateway /run/keep-gateway-admin -mindepth 1; [[ -d /run/keep-gateway-relay ]] && find /run/keep-gateway-relay -mindepth 1 || true)
[[ -z $LEFT ]] || fail "sockets left behind: $LEFT"
[[ $(systemctl show -p Result --value "$UNIT") == success ]] || fail "stop result: $(systemctl show -p Result --value "$UNIT")"
pass "stops cleanly and removes its sockets"

echo "all gateway systemd e2e checks passed"
