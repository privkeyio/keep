# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# Helpers shared by the gateway end-to-end scripts, which source this file.
# Each script defines fail_context (what to show when a check fails) and
# its own cleanup, and sets WORK before calling as or write_pair_driver.

CREATED_USERS=()
CREATED_GROUPS=()

pass() { echo "ok - $*"; }

fail() {
    echo "FAIL: $*" >&2
    fail_context >&2 || true
    exit 1
}

# Never touch accounts, groups or paths a script did not create.
refuse_users() {
    local u
    for u in "$@"; do
        if getent passwd "$u" >/dev/null; then
            echo "refusing to run: user $u already exists" >&2
            exit 2
        fi
    done
}
refuse_groups() {
    local g
    for g in "$@"; do
        if getent group "$g" >/dev/null; then
            echo "refusing to run: group $g already exists" >&2
            exit 2
        fi
    done
}
refuse_paths() {
    local p
    for p in "$@"; do
        if [[ -e $p ]]; then
            echo "refusing to run: $p already exists" >&2
            exit 2
        fi
    done
}

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

stop_pid() {
    local pid
    for pid in "$@"; do
        if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            reap "$pid" || true
        fi
    done
}

add_user() {
    useradd --system --no-create-home --shell /usr/sbin/nologin "$@"
    CREATED_USERS+=("${@: -1}")
    if [[ " $* " == *" --user-group "* ]]; then CREATED_GROUPS+=("${@: -1}"); fi
}

# Anything left running as these users would keep userdel from removing
# them; userdel may already have removed a user's own group.
remove_created_accounts() {
    local u g
    for u in "${CREATED_USERS[@]}"; do pkill -KILL -u "$u" 2>/dev/null || true; done
    for u in "${CREATED_USERS[@]}"; do userdel "$u" 2>/dev/null || echo "could not remove user $u" >&2; done
    for g in "${CREATED_GROUPS[@]}"; do
        getent group "$g" >/dev/null || continue
        groupdel "$g" 2>/dev/null || echo "could not remove group $g" >&2
    done
}

uid() { id -u "$1"; }

# A credentials directory as systemd hands one to the gateway, holding the
# vault password ($PASS) and readable by the gateway's user ($GW) alone.
make_creds() {
    local dir=$1
    install -d -m 0700 -o "$GW" "$dir"
    printf '%s\n' "$PASS" >"$dir/vault-password"
    chown "$GW" "$dir/vault-password"
    chmod 0400 "$dir/vault-password"
}

# Run as `user` with its own groups. A backgrounded call's $! is a subshell
# of this script, not the command: whatever it started runs as a created
# user, and remove_created_accounts kills it.
as() {
    local user=$1
    shift
    setpriv --reuid="$user" --regid="$(id -g "$user")" --init-groups \
        env -i PATH=/usr/bin:/bin HOME="$WORK" "$@"
}

# Pairing on a terminal: the driver runs `keep gateway approver pair` on a
# pty, writes the pairing code to <uri>, waits for the phone's fingerprint
# in <phone fp>, answers the question with whether the two match, writes
# "same" or "different" to <answer>, and prints what the command printed.
#
#   python3 <driver> <uri> <phone fp> <answer> keep gateway approver pair ...
write_pair_driver() {
    cat >"$1" <<'PY'
import os, pty, re, select, sys, time
uri_out, phone_fp, answer_out = sys.argv[1], sys.argv[2], sys.argv[3]
argv = sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
buf = b""
def until(pattern, secs):
    global buf
    deadline = time.time() + secs
    while True:
        m = re.search(pattern, buf)
        if m:
            return m
        left = deadline - time.time()
        # Wait for output no longer than the deadline, so a command that
        # stops printing cannot hang the driver.
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    sys.exit("timed out waiting for %r; got %r" % (pattern, buf[-2000:]))
uri = until(rb"(keep-approver:v1\?[^\s]+)\r?\n", 30).group(1).decode()
open(uri_out + ".tmp", "w").write(uri)
os.rename(uri_out + ".tmp", uri_out)
shown = until(rb"shows fingerprint:\s+([0-9a-f]{4}(?: [0-9a-f]{4})+)\r?\n", 120).group(1).decode()
for _ in range(600):
    if os.path.exists(phone_fp) and os.path.getsize(phone_fp):
        break
    time.sleep(0.1)
same = open(phone_fp).read().strip() == shown
open(answer_out, "w").write("same" if same else "different")
os.write(fd, b"y\n" if same else b"n\n")
while True:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
_, status = os.waitpid(pid, 0)
sys.stdout.write(buf.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
PY
    chmod 0644 "$1"
}
