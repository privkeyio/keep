#!/usr/bin/env bash
# Fail if production code can silently fall back to predictable randomness.
#
# Motivated by the COLDCARD firmware disclosure (Block, 2026-07):
# https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware
# A guard that checked only whether a macro was *defined* -- not whether it was
# *enabled* -- silently bound wallet seed generation to a non-cryptographic
# fallback PRNG. Nothing crashed, nothing logged, and the firmware shipped that
# way for years. The lesson is not "use a CSPRNG"; every codebase already
# intends to. The lesson is that a degraded RNG path must not be able to succeed
# quietly, and that only a mechanical check keeps it that way.
#
# The shapes that bug takes in this workspace:
#
#   1. An unhandled getrandom error leaves the destination array zeroed, because
#      every caller here starts from `[0u8; N]`. The statement must propagate
#      with `?` or panic loudly.
#   2. The same for a discarded fill_bytes/try_fill_bytes result, and for the
#      `.ok()` / `unwrap_or(..)` / `unwrap_or_default()` shape, which turns an
#      RNG failure into a fixed value rather than an error.
#   3. A seeded, reproducible PRNG (`seed_from_u64`, `from_seed`, `SmallRng`)
#      standing in for the OS RNG. Fine in tests, never in production.
#   4. keep-core's entropy gate. `random_bytes_mixed_internal()` mixes OS
#      randomness with timing jitter and process context, so its output looks
#      random even when a source has degraded -- the health check is what makes
#      the degradation visible, and every public entry point must run it.
#
# Deliberate non-crypto randomness (backoff jitter, sampling, test fixtures) is
# allowed with an inline opt-out on the same line or in the comment block above:
#
#     let jitter = rng.gen_range(0..500);   // rng-hygiene: ok - backoff jitter
#
# Scope: TRACKED files only (git ls-files), so target/ and vendored trees can
# never trip a rule or hide one. Test trees, benches, and fuzz targets are
# excluded -- fixtures are deterministic on purpose.
#
# What this does NOT cover, stated so nobody reads a green run as more than it
# is: it is a grep. It catches the shape, not the intent -- it cannot tell
# whether a checked draw is used correctly once generated, nor whether a value
# reaches the right place. It does not inspect dependencies, so a crate that
# degrades its own RNG internally is invisible here. Rule 4 checks that the gate
# is called, not that the health check itself is sound.
#
# Run from anywhere. Exits non-zero with the offending lines.

set -uo pipefail
cd "$(dirname "$0")/.."

status=0
fail() { printf '\n\033[31mFAIL\033[0m %s\n' "$1"; status=1; }

OPT_OUT='rng-hygiene: ok'
ENTROPY_MODULE='keep-core/src/entropy.rs'

# Tracked Rust sources, minus test trees, benches, and fuzz targets. Vendored
# and generated trees are excluded by path.
list_sources() {
  git ls-files '*.rs' \
    | grep -vE '(^|/)(tests|benches|examples|vendor|target)/' \
    | grep -vE '^fuzz/' \
    || true
}

# ------------------------------------------------------------------ Rust ----
# Statement-scoped, so a call that wraps onto the next line (`getrandom::fill(..)`
# then `.map_err(..)?;`) is judged whole. Handled == propagates with `?` or
# panics with expect/unwrap. Everything else -- `let _ =`, `let _res =`,
# `.ok()`, a bare `is_err()` test -- leaves the buffer zeroed and is flagged.
#
# `#[cfg(test)]` bodies are skipped by brace depth rather than by filename: unit
# tests live inline in src/ throughout this workspace, so a filename filter would
# either miss them or exclude the production code around them.
#
# One awk per file so the whole file can be slurped and looked at forward: an
# `if let Err(e) = rng(..) { return Err(..) }` handles the failure just as well
# as a `?`, and a rule that only knows `?` would push people to rewrite correct
# code. Deciding that needs the block body, not just the call line.
scan_rust() { # $1 = call-site ERE
  local f
  list_sources | while IFS= read -r f; do
    [ -n "$f" ] || continue
    awk -v pat="$1" -v optout="$OPT_OUT" -v fname="$f" '
      function count(s, ch,   n, tmp) { tmp = s; n = gsub(ch, ch, tmp); return n }

      # A construct that exits the enclosing scope on the error branch has
      # handled it. Scan from the call line until brace depth returns to where
      # it started, and look for an exit inside.
      function block_exits(from,   i, d, seen) {
        d = 0; seen = 0
        for (i = from; i <= n; i++) {
          d += count(L[i], "{") - count(L[i], "}")
          if (i > from || index(L[i], "{"))
            if (L[i] ~ /(return|panic!|unreachable!|todo!|\?;|continue|break|process::exit)/) seen = 1
          if (i > from && d <= 0) break
        }
        return seen
      }

      function judge(text, where, blockstart, isctrl,   t) {
        t = text
        sub(/;.*$/, "", t)                     # statement ends at the first ;
        if (t ~ /\?/ || t ~ /\.expect\(/ || t ~ /\.unwrap\(/) return
        if (isctrl && block_exits(blockstart)) return
        printf "%s:%d:%s\n", fname, where, t
      }

      { L[FNR] = $0; n = FNR }

      END {
        instmt = 0; buf = ""; start = 0; testdepth = -1; depth = 0
        blockopt = 0; pending = 0
        for (i = 1; i <= n; i++) {
          raw = L[i]
          line = raw
          sub(/^[[:space:]]*/, "", line)

          # Track brace depth so a #[cfg(test)] module is skipped whole. Unit
          # tests live inline in src/ across this workspace, so a filename
          # filter would either miss them or exclude the production code beside
          # them.
          if (pending && index(raw, "{")) { testdepth = depth; pending = 0 }
          else if (line ~ /^#\[cfg\(test\)\]/) { pending = 1 }
          depth += count(raw, "{") - count(raw, "}")
          if (testdepth >= 0) {
            if (depth <= testdepth) testdepth = -1
            continue
          }

          if (instmt) {
            buf = buf " " raw
            if (index(buf, ";")) { judge(buf, start, start, ctrl); instmt = 0 }
            continue
          }
          if (line ~ /^(\/\/|\*|\/\*)/) { if (index(raw, optout)) blockopt = 1; continue }
          # Only `use` lines are skipped outright -- a `use getrandom::fill;`
          # is an import, not a draw. Function signatures are NOT skipped: a
          # one-line `fn f() { getrandom(..); }` is still a call site.
          if (line ~ /^use /) { blockopt = 0; continue }
          if (index(raw, optout) || blockopt) { blockopt = 0; continue }
          blockopt = 0
          if (match(raw, pat) == 0) continue
          # `fn getrandom(..)` declares the wrapper, it does not call it. Judged
          # by what precedes the match, so a call on the same line as a one-line
          # fn body is still seen.
          pre = substr(raw, 1, RSTART - 1)
          if (pre ~ /(^|[^a-zA-Z0-9_])fn[[:space:]]+$/) continue
          # Decided from the whole line: substr() below cuts off the
          # `if let Err(e) = ` that makes this an error-handling construct.
          # A control construct ends at its opening brace, not at a semicolon --
          # `if rng(..).is_err() {}` has no semicolon at all, and waiting for one
          # would swallow the finding entirely.
          ctrl = (line ~ /^(if[[:space:]]|match[[:space:]]|while[[:space:]]|\}[[:space:]]*else[[:space:]])/)
          buf = substr(raw, RSTART)
          if (index(buf, ";") || (ctrl && index(raw, "{"))) { judge(buf, i, i, ctrl) }
          else { instmt = 1; start = i }
        }
      }
    ' "$f" 2>/dev/null || true
  done
}

# ------------------------------------------------- 1. getrandom / fill_bytes --
# Only real calls: `getrandom(` / `getrandom::fill(` -- never a type position
# like `getrandom::Error`, which has no open paren after the name.
rng_bad=$(scan_rust 'getrandom[a-z_:]*[[:space:]]*\(|try_fill_bytes[[:space:]]*\(')
if [ -n "$rng_bad" ]; then
  fail "RNG error not handled (leaves the buffer zeroed):"
  printf '%s\n' "$rng_bad" | sed 's/^/  /'
  echo "  → propagate with ? / map_err(..)?, or .expect(\"OS RNG available\")"
fi

# ---------------------------------------------- 2. RNG failure as a value ----
# `.ok()`, `unwrap_or(..)`, `unwrap_or_default()` on an RNG call substitute a
# fixed value for an error. For a [u8; N] that fixed value is all zeros.
swallow_bad=$(
  list_sources | tr '\n' '\0' | xargs -0 -r grep -nHE \
    '(getrandom|fill_bytes|try_fill|random_bytes)[^;]*\.(ok\(\)|unwrap_or\(|unwrap_or_default\(|unwrap_or_else\()' 2>/dev/null \
    | grep -vE ':[[:space:]]*(///|//|\*)' \
    | grep -vF "$OPT_OUT" \
    || true
)
if [ -n "$swallow_bad" ]; then
  fail "RNG failure collapsed into a value instead of an error:"
  printf '%s\n' "$swallow_bad" | sed 's/^/  /'
  echo "  → propagate the error; a default [u8; N] is all zeros"
fi

# ------------------------------------------------------- 3. seeded PRNGs ----
seeded_bad=$(scan_rust 'seed_from_u64[[:space:]]*\(|from_seed[[:space:]]*\(|SmallRng')
if [ -n "$seeded_bad" ]; then
  fail "seeded/reproducible PRNG in production code:"
  printf '%s\n' "$seeded_bad" | sed 's/^/  /'
  echo "  → use the OS RNG (OsRng / rand::rng() / getrandom),"
  echo "    or mark a deliberate non-crypto use: // $OPT_OUT - <reason>"
fi

# ------------------------------------------------ 4. the entropy gate holds --
# Every public entry point in the entropy module that reaches the unchecked
# mixer must run the health gate first. Checked structurally rather than by
# grepping for a string, so deleting the `?` is caught too.
if [ ! -f "$ENTROPY_MODULE" ]; then
  fail "$ENTROPY_MODULE not found; rule 4 cannot run (was the module moved?)"
else
  gate_bad=$(awk '
    /^pub fn /            { fn = $0; sub(/^pub fn /, "", fn); sub(/[(<].*$/, "", fn); gated = 0; uses = 0 }
    /ensure_entropy_health\(\)\?/ { if (fn != "") gated = 1 }
    /random_bytes_mixed_internal\(\)/ { if (fn != "") uses = 1 }
    /^\}/ { if (fn != "" && uses && !gated) print fn; fn = "" }
  ' "$ENTROPY_MODULE")
  if [ -n "$gate_bad" ]; then
    fail "public entropy entry point reaches the mixer without ensure_entropy_health()?:"
    printf '%s\n' "$gate_bad" | sed 's/^/  /'
    echo "  → the mixer folds in timing jitter and process context, so its output looks"
    echo "    random even when a source has degraded. The gate is what makes that visible."
  fi
fi

if [ "$status" -eq 0 ]; then
  echo "RNG hygiene: OK (getrandom errors handled, no swallowed failures, no seeded PRNGs, entropy gate intact)"
fi
exit "$status"
