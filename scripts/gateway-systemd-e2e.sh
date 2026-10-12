#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# End-to-end test of the shipped systemd unit, contrib/systemd/keep-gateway.service,
# on a machine booted with systemd: the gateway starts as the `keep-gateway`
# user, unlocks from an encrypted credential, reports ready only once it
# serves, serves an MCP client through `keep agent connect`, restarts
# unattended, and refuses to start, and stops retrying, when misconfigured.
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
BIN_SRC=${1:?usage: gateway-systemd-e2e.sh path/to/keep [path/to/approval_peer]}
PEER_SRC=${2:-}
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
RELAY_PID=
PASS=systemd-e2e-vault-password
CREATED_USERS=()
CREATED_GROUPS=()
CREATED=()
UNIT_INSTALLED=

# Never touch what this script did not create.
for u in $GW $AGENT $ADMIN $OUT $RELAY_USER; do
    if getent passwd "$u" >/dev/null; then
        echo "refusing to run: user $u already exists" >&2
        exit 2
    fi
done
for g in $GW keep-agents keep-admins $RELAY_USER; do
    if getent group "$g" >/dev/null; then
        echo "refusing to run: group $g already exists" >&2
        exit 2
    fi
done
for p in "$UNIT_FILE" "$DROPIN" "$RELAY_UNIT_FILE" "$BIN" /etc/keep "$STATE" /run/keep-gateway \
    /run/keep-gateway-admin /run/keep-gateway-relay; do
    if [[ -e $p ]]; then
        echo "refusing to run: $p already exists" >&2
        exit 2
    fi
done
for u in "$UNIT" "$RELAY_UNIT"; do
    if systemctl cat "$u" >/dev/null 2>&1; then
        echo "refusing to run: a $u unit is already installed" >&2
        exit 2
    fi
done
# systemd-creds makes the host key on first use; it is removed afterwards
# only if this script made it.
[[ -e $HOST_SECRET ]] || CREATED+=("$HOST_SECRET")
WORK=$(mktemp -d /var/tmp/kgsd.XXXXXX)

fail() {
    echo "FAIL: $*" >&2
    echo "--- journal ---" >&2
    journalctl -u "$UNIT" --no-pager -n 40 -o cat >&2 || true
    exit 1
}
pass() { echo "ok - $*"; }

cleanup() {
    systemctl stop "$RELAY_UNIT" >/dev/null 2>&1 || true
    systemctl reset-failed "$RELAY_UNIT" >/dev/null 2>&1 || true
    rm -f "$RELAY_UNIT_FILE"
    if [[ -n $RELAY_PID ]]; then kill "$RELAY_PID" 2>/dev/null || true; fi
    if [[ -n $UNIT_INSTALLED ]]; then
        systemctl stop "$UNIT" >/dev/null 2>&1 || true
        systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
    fi
    rm -rf "$DROPIN"
    rm -f "$UNIT_FILE"
    systemctl daemon-reload || true
    for u in "${CREATED_USERS[@]}"; do pkill -KILL -u "$u" 2>/dev/null || true; done
    for u in "${CREATED_USERS[@]}"; do userdel "$u" 2>/dev/null || echo "could not remove user $u" >&2; done
    for g in "${CREATED_GROUPS[@]}"; do
        # userdel may have removed a user's own group already.
        getent group "$g" >/dev/null || continue
        groupdel "$g" 2>/dev/null || echo "could not remove group $g" >&2
    done
    for p in "${CREATED[@]}"; do rm -rf "$p"; done
    rm -rf /run/keep-gateway /run/keep-gateway-admin /run/keep-gateway-relay
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
add_user() {
    useradd --system --no-create-home --shell /usr/sbin/nologin "$@"
    CREATED_USERS+=("${@: -1}")
}
add_user -G keep-agents "$AGENT"
add_user -G keep-admins "$ADMIN"
add_user "$OUT"
uid() { id -u "$1"; }
as() {
    local user=$1
    shift
    setpriv --reuid="$user" --regid="$(id -g "$user")" --init-groups \
        env -i PATH=/usr/bin:/bin HOME="$WORK" "$@"
}

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
        journalctl -u "$RELAY_UNIT" --no-pager -o cat | grep -q "connected to the gateway's relay socket" && break
        sleep 0.1
    done
    LOG=$(journalctl -u "$RELAY_UNIT" --no-pager -o cat)
    grep -q "connected to the gateway's relay socket" <<<"$LOG" || fail "the helper did not connect: $LOG"
    HELPER=$(systemctl show -p MainPID --value "$RELAY_UNIT")
    [[ $(awk '/^Uid:/ {print $3}' "/proc/$HELPER/status") == "$(uid $RELAY_USER)" ]] || fail "the helper is not $RELAY_USER"
    pass "the gateway runs with the approvals drop-in and the helper's unit connects as $RELAY_USER"

    # Pair a phone on a terminal, as root does the first time.
    cat >"$WORK/pair.py" <<'PY'
import os, pty, re, sys, time
uri_out, phone_fp = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[3], sys.argv[3:])
buf = b""
def until(pattern, secs):
    global buf
    deadline = time.time() + secs
    while time.time() < deadline:
        m = re.search(pattern, buf)
        if m:
            return m
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    sys.exit("timed out waiting for %r; got %r" % (pattern, buf[-2000:]))
open(uri_out, "w").write(until(rb"(keep-approver:v1\?[^\s]+)", 30).group(1).decode())
shown = until(rb"shows fingerprint:\s+([0-9a-f]{4}(?: [0-9a-f]{4})+)", 120).group(1).decode()
for _ in range(600):
    if os.path.exists(phone_fp) and os.path.getsize(phone_fp):
        break
    time.sleep(0.1)
os.write(fd, b"y\n" if open(phone_fp).read().strip() == shown else b"n\n")
while True:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
PY
    python3 "$WORK/pair.py" "$WORK/uri" "$WORK/phone.fp" "$BIN" gateway approver pair --label Phone \
        >"$WORK/pair.out" 2>&1 &
    PAIR=$!
    for _ in $(seq 300); do [[ -s $WORK/uri ]] && break; sleep 0.1; done
    [[ -s $WORK/uri ]] || fail "no pairing code: $(cat "$WORK/pair.out")"
    "$PEER" phone "$(cat "$WORK/uri")" </dev/null >"$WORK/phone.log" 2>&1 &
    PHONE=$!
    for _ in $(seq 300); do grep -q '^fingerprint ' "$WORK/phone.log" && break; sleep 0.1; done
    awk '/^fingerprint / {sub(/^fingerprint /, ""); print; exit}' "$WORK/phone.log" >"$WORK/phone.fp.tmp"
    mv "$WORK/phone.fp.tmp" "$WORK/phone.fp"
    wait "$PAIR" || fail "pairing: $(cat "$WORK/pair.out")"
    for _ in $(seq 300); do grep -q '^paired$' "$WORK/phone.log" && break; sleep 0.1; done
    grep -q '^paired$' "$WORK/phone.log" || fail "the phone was not told it is paired: $(cat "$WORK/phone.log")"
    kill "$PHONE" 2>/dev/null || true
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
