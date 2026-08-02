#!/usr/bin/env bash
# Self-test for check-rng-hygiene.sh.
#
# This guard keeps unhandled RNG errors, swallowed RNG failures and seeded PRNGs
# out of production Rust, and asserts the entropy health gate still runs. A
# scanner that quietly stops scanning reports a clean tree exactly like a clean
# tree does, so the rules are asserted rather than trusted.
#
# Probes go under keep-core/src: the guard skips tests, benches, examples,
# vendor, target and fuzz, so a probe placed there passes and looks like a
# bypass when it is only misplaced. The positive control catches that.
#
# Note the two-pattern rules. A bare fill_bytes() is legitimate; it is a finding
# only together with a swallow such as .ok() or .unwrap_or_default(). Probes are
# written to the real rule, not to a simpler one that would pass regardless.
#
# Each reject case requires the guard to NAME the probe file. Without that, a
# guard aborting for an unrelated reason would be credited as a detection and
# every case below would pass while detecting nothing.
#
# Probes are staged into a throwaway GIT_INDEX_FILE, so the real index is never
# touched. The file itself must exist on disk while the guard runs, because the
# scanner reads bytes; it is removed on every path including the EXIT trap.
set -uo pipefail

cd "$(dirname "$0")/.." || { echo "FAIL: cannot cd to the repo root"; exit 1; }
GUARD=scripts/check-rng-hygiene.sh
[ -x "$GUARD" ] || { echo "FAIL: $GUARD not found or not executable"; exit 1; }

TMPD=$(mktemp -d)
PROBE=""
cleanup() { rm -rf "$TMPD"; [ -n "$PROBE" ] && rm -f "$PROBE"; }
trap cleanup EXIT

fails=0

# run_probe <path> <content> <pass|fail> <description>
run_probe() {
    local name="$1" content="$2" expect="$3" desc="$4"

    if [ -e "$name" ]; then
        echo "  HARNESS BROKEN: $name exists; refusing to overwrite a real file"
        fails=$((fails + 1)); return
    fi
    PROBE="$name"
    printf '%s' "$content" > "$name"

    rm -f "$TMPD/index"
    GIT_INDEX_FILE="$TMPD/index" git read-tree HEAD 2>/dev/null
    GIT_INDEX_FILE="$TMPD/index" git add -f "$name" 2>/dev/null

    local staged
    staged=$(GIT_INDEX_FILE="$TMPD/index" git ls-files | wc -l)
    if [ "$staged" -lt 10 ]; then
        echo "  HARNESS BROKEN: only $staged file(s) staged; the guard would scan almost nothing"
        fails=$((fails + 1)); rm -f "$name"; PROBE=""; return
    fi

    local rc=0 out
    out=$(GIT_INDEX_FILE="$TMPD/index" "$GUARD" 2>&1) || rc=$?
    rm -f "$name"; PROBE=""

    if [ "$expect" = fail ]; then
        if [ "$rc" -eq 0 ]; then
            echo "  BYPASS: $desc"; fails=$((fails + 1))
        elif ! printf '%s' "$out" | grep -qF "$name"; then
            echo "  WRONG REASON: $desc (guard failed without naming $name)"; fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
    else
        if [ "$rc" -ne 0 ]; then
            echo "  FALSE POSITIVE: $desc"
            printf '%s\n' "$out" | sed 's/^/      /' | head -4
            fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
    fi
}

echo "== rejects what it must reject =="

SRC=keep-core/src

run_probe $SRC/probe_ctl.rs 'fn f(){ let mut b=[0u8;32]; getrandom::getrandom(&mut b); }
' fail "unhandled RNG error (positive control: if this passes, nothing below means anything)"

run_probe $SRC/probe_swallow.rs 'fn f(){ let mut b=[0u8;32]; getrandom::getrandom(&mut b).ok(); }
' fail "RNG failure collapsed with .ok()"

# The evasion that defeated the guards in keep-node, keep-esp32 and keep-android:
# splitting the tokens across lines. This scanner already buffers, and this case
# is here so that stays true.
run_probe $SRC/probe_split.rs 'fn f(){ let mut b=[0u8;32]; getrandom::getrandom(&mut b)
    .ok(); }
' fail "swallow split onto the next line"

run_probe $SRC/probe_split2.rs 'fn f(){ let mut b=[0u8;32]; getrandom::getrandom(&mut b)
    .unwrap_or_default(); }
' fail "unwrap_or_default split onto the next line"

run_probe $SRC/probe_seeded.rs 'fn f(){ let r = SmallRng::seed_from_u64(1); let _ = r; }
' fail "seeded PRNG in production code"

echo "== accepts what it must accept =="

run_probe $SRC/probe_ok.rs 'fn f()->Result<(),getrandom::Error>{ let mut b=[0u8;32]; getrandom::getrandom(&mut b)?; Ok(()) }
' pass "RNG error propagated with ?"

run_probe $SRC/probe_comment.rs '// getrandom(&mut b).ok() named in prose only
fn f(){ let x=1; let _=x; }
' pass "a banned shape inside a comment is not code"

run_probe $SRC/probe_cfgtest.rs '#[cfg(test)]
mod t { fn f(){ let mut b=[0u8;32]; getrandom::getrandom(&mut b).ok(); } }
' pass "test code is out of scope"

echo
if [ "$fails" -ne 0 ]; then
    echo "FAIL: $fails case(s) did not behave as required"
    exit 1
fi
echo "OK: check-rng-hygiene.sh rejects every known bypass and accepts sanctioned use"
