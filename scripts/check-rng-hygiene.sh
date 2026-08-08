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
#      with `?`, panic loudly, or take a branch that exits.
#   2. The same failure collapsed into a value -- `.ok()`, `unwrap_or(..)`,
#      `unwrap_or_default()` -- which for a `[u8; N]` means all zeros.
#   3. A seeded, reproducible PRNG (`seed_from_u64`, `from_seed`, `SmallRng`)
#      standing in for the OS RNG. Fine in tests, never in production.
#   5. The panicking draw (`crypto::random_bytes`) used where the caller could
#      have propagated instead. It aborts the process on a health-check failure,
#      which is fail-closed but ungraceful: uniffi catches the unwind and
#      surfaces an untyped internal exception, losing the error's identity, and
#      in a long-running signer it takes down whichever task drew. Prefer
#      `try_random_bytes`; opt out where the signature genuinely cannot carry a
#      `Result`.
#   4. keep-core's entropy gate. `random_bytes_mixed_internal()` mixes OS
#      randomness with timing jitter and process context, so its output looks
#      random even when a source has degraded -- the health check is what makes
#      the degradation visible, and every public entry point must run it.
#
# Deliberate non-crypto randomness (backoff jitter, sampling) is allowed with an
# inline opt-out on the same line, in the comment block directly above, or on any
# continuation line of the same statement:
#
#     let jitter = rng.gen_range(0..500);   // rng-hygiene: ok - backoff jitter
#
# This guard fails CLOSED. An awk error, a missing repo, or an empty file list is
# reported as a failure rather than silently passing: a guard that reports "OK"
# when it scanned nothing is worse than no guard, because it is trusted.
#
# Scope: TRACKED files only (git ls-files), so target/ and vendored trees can
# never trip a rule or hide one. Test trees, benches, and fuzz targets are
# excluded by path, and inline `#[cfg(test)]` items are excluded by brace depth
# -- unit tests live inline in src/ throughout this workspace, so a filename
# filter would either miss them or exclude the production code beside them.
#
# What this does NOT cover, stated so nobody reads a green run as more than it
# is: it is a grep. It catches the shape, not the intent -- it cannot tell
# whether a checked draw is used correctly once generated, nor whether a value
# reaches the right place. It does not inspect dependencies, so a crate that
# degrades its own RNG internally is invisible here. Rule 4 checks that the gate
# is called, not that the health check itself is sound.
#
# Portable to BSD awk and BSD xargs (developers run this on macOS), so: no gawk
# extensions, and no `xargs -r`.
#
# Run from anywhere. Exits non-zero with the offending lines.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

status=0
fail() { printf '\n\033[31mFAIL\033[0m %s\n' "$1"; status=1; }

OPT_OUT='rng-hygiene: ok'
# Overridable so the probe suite can point rules 4 and 6 at a fixture. Those two
# read a fixed path rather than the scanned file list, so without this they were
# the only rules that could not be proven to still fail.
ENTROPY_MODULE="${ENTROPY_MODULE:-keep-core/src/entropy.rs}"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  printf '\n\033[31mFAIL\033[0m not inside a git work tree; this guard scans tracked files only\n'
  exit 1
}

# Tracked Rust sources, minus test trees, benches, examples, and fuzz targets.
list_sources() {
  git ls-files '*.rs' \
    | grep -vE '(^|/)(tests|benches|examples|vendor|target)/' \
    | grep -vE '^fuzz/'
}

SOURCES=$(list_sources)
if [ -z "$SOURCES" ]; then
  printf '\n\033[31mFAIL\033[0m no Rust sources found to scan; the file list is broken\n'
  exit 1
fi

# ------------------------------------------------------------------ Rust ----
# Statement-scoped, so a call that wraps onto the next line (`getrandom::fill(..)`
# then `.map_err(..)?;`) is judged whole.
#
# "Handled" is deliberately broader than `?`: an `if let Err(e) = rng(..) { return
# Err(..) }` or a `match` whose Err arm exits handles the failure just as well,
# and a rule that only knows `?` pushes people to rewrite correct code to satisfy
# a grep. Deciding that needs the block body, so each file is slurped and scanned
# forward for an exit before judging.
#
# One awk per file, and its exit status is checked -- an earlier version piped
# awk's stderr to /dev/null behind `|| true`, which meant a broken awk reported a
# clean tree.
scan_rust() { # $1 = call-site ERE, $2 = optional verdict ERE, $3 = strict (no ?/expect suppression)
  local f rc out
  rc=0
  for f in $SOURCES; do
    out=$(awk -v pat="$1" -v vpat="${2:-}" -v strict="${3:-}" -v optout="$OPT_OUT" -v fname="$f" '
      function count(s, ch,   i, n) {
        # Literal character count: gsub()/split() would treat ch as a regex,
        # and "(" alone is not a valid one -- BSD awk aborts on it.
        n = 0
        for (i = length(s); i > 0; i--) if (substr(s, i, 1) == ch) n++
        return n
      }

      # A construct that exits the enclosing scope on the ERROR branch has
      # handled it. Only the error branch counts: an earlier version scanned the
      # whole block, so `match rng() { Ok(()) => return k, Err(_) => {} }` was
      # read as handled. Strings are stripped first, so a log message containing
      # the word "return" does not count as an exit either. Both were working
      # bypasses.
      # Text following an `Err ... =>` match arm on this line, or "" if there is
      # no such arm. Used so a one-line `match r { Ok(()) => return k, Err(_) =>
      # {} }` is judged on its error arm alone.
      function err_arm_text(c,   p, q, t) {
        p = index(c, "Err")
        if (p == 0) return ""
        t = substr(c, p)
        q = index(t, "=>")
        if (q == 0) return ""
        return substr(t, q + 2)
      }
      function is_exit(t) {
        return (t ~ /(return|panic!|unreachable!|todo!|\?;|continue|break|process::exit)/)
      }

      # A construct that exits the enclosing scope on the ERROR branch has
      # handled it. Only the error branch counts: an earlier version scanned the
      # whole block, so `match r { Ok(()) => return k, Err(_) => {} }` read as
      # handled. Strings are stripped first (code_of), so a log message
      # containing the word "return" is not an exit either. Both were working
      # bypasses.
      function block_exits(from,   i, d, seen, inerr, c, arm) {
        d = 0; seen = 0; inerr = 0
        for (i = from; i <= n; i++) {
          c = code_of(L[i])
          if (i == from && c ~ /if[ \t]+let[ \t]+Err/) inerr = 1
          arm = err_arm_text(c)
          if (arm != "") {
            if (is_exit(arm)) seen = 1
            inerr = 1                       # a multi-line Err arm continues below
          } else if (c ~ /(^|[^a-zA-Z0-9_])Ok[ \t]*(\(|=>)/ && i > from && c ~ /=>/) {
            inerr = 0
          } else if (inerr && is_exit(c)) {
            seen = 1
          }
          # Stripped text, not raw: a brace inside a string literal would end the
          # block early and the exit search would stop before the real handler.
          d += count(c, "{") - count(c, "}")
          if (i > from && d <= 0) break
        }
        return seen
      }

      function judge(text, where, blockstart, isctrl,   t) {
        if (index(text, optout)) return          # marker on any continuation line
        t = code_of(text)
        sub(/;.*$/, "", t)                       # statement ends at the first ;
        # A verdict pattern means "detect on the call name, decide on the whole
        # assembled statement". Rule 2 needs that: rustfmt puts
        # `.unwrap_or_default()` on its own line, so a single-line rule never
        # sees the call and the discard together.
        if (vpat != "") {
          if (t ~ vpat) printf "%s:%d:%s\n", fname, where, t
          return
        }
        # The `?` / expect / unwrap has to belong to THIS call, not to something
        # nested inside its arguments: `let _ = rng(&mut k).map_err(|e| f(n)?);`
        # discards the RNG result while carrying a `?`, and used to pass.
        # Strict rules skip this. The suppression below reads a `?` or an
        # `.expect(..)` as "the error was handled", which is the right reading
        # for a call that returns a Result. A panicking draw returns an array,
        # so a `?` in the same statement belongs to something else entirely and
        # says nothing about the draw. Without this gate,
        # `f(crypto::random_bytes::<32>())?` was silently skipped.
        if (strict == "" && (outer(t) ~ /\?/ || t ~ /\)[ \t]*\.expect\(/ || t ~ /\)[ \t]*\.unwrap\(/)) return
        if (isctrl && block_exits(blockstart)) return
        printf "%s:%d:%s\n", fname, where, t
      }

      # Drop a trailing // comment and blank every string literal before
      # matching, keeping the original text so the opt-out marker stays visible.
      # Without this, prose mentioning a banned name trips its own rule, and a
      # log message containing the word "return" counts as an error branch that
      # exits -- which was a working bypass.
      function code_of(s,   p, out, i, c, instr, q) {
        p = index(s, "//")
        if (p > 0) s = substr(s, 1, p - 1)
        out = ""; instr = 0
        for (i = 1; i <= length(s); i++) {
          c = substr(s, i, 1)
          if (instr) { if (c == "\\") { i++; continue }
                       if (c == q) { instr = 0; out = out "\"\"" }
                       continue }
          if (c == "\"") { instr = 1; q = c; continue }
          out = out c
        }
        return out
      }

      # Remove balanced parenthesised groups, so a `?` belonging to a nested call
      # (`map_err(|e| other(n)?)`) is not mistaken for the RNG call propagating.
      function outer(s,   out, i, c, d) {
        out = ""; d = 0
        for (i = 1; i <= length(s); i++) {
          c = substr(s, i, 1)
          if (c == "(") { d++; continue }
          if (c == ")") { if (d > 0) d--; continue }
          if (d == 0) out = out c
        }
        return out
      }

      { L[FNR] = $0; n = FNR }

      END {
        instmt = 0; buf = ""; start = 0; testdepth = -1; depth = 0
        blockopt = 0; pending = 0; ctrl = 0
        for (i = 1; i <= n; i++) {
          raw = L[i]
          line = raw
          sub(/^[ \t]*/, "", line)
          code = code_of(raw)

          # #[cfg(test)] arms only for the item that follows, and only while that
          # item is still an attribute or a brace-opening line. An earlier version
          # left it armed until the next `{` anywhere, so a braceless
          # `#[cfg(test)] use ..;` swallowed the next real block -- and that exact
          # shape exists in keep-enclave/host/src/mock.rs.
          if (pending) {
            if (index(raw, "{")) { testdepth = depth; pending = 0 }
            else if (line !~ /^#\[/ && line != "") { pending = 0 }
          }
          if (line ~ /^#\[cfg\(test\)\]/) pending = 1
          # Stripped text, not raw. An unbalanced brace inside a string literal
          # in a test block left `testdepth` armed to end-of-file, so every rule
          # silently stopped scanning the rest of that file and still reported a
          # clean tree. `write_store(dir.path(), "{ this is not json")` in
          # keep-desktop is exactly this shape, harmless only because its test
          # module ends the file. Fourteen files have production code after a
          # mid-file test block, so the next one would be a total miss.
          depth += count(code, "{") - count(code, "}")
          if (testdepth >= 0) {
            if (depth <= testdepth) testdepth = -1
            continue
          }

          if (instmt) {
            buf = buf " " raw
            # Terminate at the statement semicolon, or at the end of the
            # enclosing block for a tail expression that has none. Without the
            # second case the buffer runs on past the function and the reported
            # text is unreadable.
            if (index(buf, ";") || line ~ /^\}/) { judge(buf, start, start, ctrl); instmt = 0 }
            continue
          }
          if (line ~ /^(\/\/|\*|\/\*)/) { if (index(raw, optout)) blockopt = 1; continue }
          # Only `use` lines are skipped outright: `use getrandom::fill;` is an
          # import, not a draw. Function signatures are NOT skipped, so a one-line
          # `fn f() { getrandom(..); }` is still a call site.
          if (line ~ /^use /) { blockopt = 0; continue }
          if (index(raw, optout) || blockopt) { blockopt = 0; continue }
          blockopt = 0
          # `fn getrandom(..)` declares the wrapper, it does not call it -- but a
          # one-line `fn f() { let _ = rng(..); }` puts a real call on the same
          # line, so skip past the declaration and keep searching rather than
          # dropping the whole line, which was a working bypass.
          rest = code; base = 0
          while (1) {
            if (match(rest, pat) == 0) { base = -1; break }
            pre = substr(rest, 1, RSTART - 1)
            if (pre !~ /(^|[^a-zA-Z0-9_])fn[ \t]+$/) { base += RSTART; break }
            base += RSTART + RLENGTH - 1
            rest = substr(rest, RSTART + RLENGTH)
          }
          if (base < 0) continue
          # A control construct ends at its opening brace, not at a semicolon:
          # `if rng(..).is_err() {}` has no semicolon at all. Decided from the
          # whole line, since substr() below cuts off the `if let Err(e) = `.
          ctrl = (line ~ /^(if[ \t]|match[ \t]|while[ \t]|\}[ \t]*else[ \t])/)
          buf = substr(code, base)
          if (index(buf, ";") || (ctrl && index(raw, "{"))) { judge(buf, i, i, ctrl) }
          else { instmt = 1; start = i }
        }
        # A statement still being assembled at end of file was never judged.
        # `pub fn x() -> T { draw() }` as the last line has no semicolon and no
        # following `}` line to terminate it, so the buffer was simply dropped
        # and the call inside it never scanned.
        if (instmt) judge(buf, start, start, ctrl)
        # Fail closed if the test-block tracker never disarmed: the brace
        # accounting lost sync, so an unknown tail of this file went unscanned.
        # Reporting that clean is the one outcome this guard must never produce.
        # Goes to stderr so it survives the command substitution the caller reads.
        if (testdepth >= 0) print "rng-hygiene: brace tracking stuck in " fname > "/dev/stderr"
        if (testdepth >= 0) print "SCANNER-STUCK"
      }
    ' "$f") || rc=2
    case $out in
      *SCANNER-STUCK*) rc=2 ;;
      *) [ -n "$out" ] && printf '%s\n' "$out" ;;
    esac
  done
  return "$rc"
}

report() { # $1 = findings, $2 = headline, $3.. = hints
  [ -z "$1" ] && return 0
  fail "$2"
  printf '%s\n' "$1" | sed 's/^/  /'
  shift 2
  for hint in "$@"; do echo "  → $hint"; done
}

# ------------------------------------------------- 1. getrandom / fill_bytes --
# Only real calls: `getrandom(` / `getrandom::fill(` -- never a type position
# like `getrandom::Error`, which has no open paren after the name.
rng_bad=$(scan_rust 'getrandom[a-z_:]*[ \t]*[(]|try_fill_bytes[ \t]*[(]') || {
  fail "the scanner itself failed; refusing to report a clean tree"
  exit 1
}
report "$rng_bad" "RNG error not handled (leaves the buffer zeroed):" \
  'propagate with ? / map_err(..)?, .expect("OS RNG available"), or return on the Err branch'

# ---------------------------------------------- 2. RNG failure as a value ----
# Routed through the same scanner as rule 1 rather than a bare grep, so it
# inherits the #[cfg(test)] and comment handling instead of crying wolf on test
# code.
swallow_bad=$(scan_rust '(getrandom|fill_bytes|try_fill|random_bytes)[a-z_:]*[ \t]*[(<]' \
  '\\.(ok\\(\\)|unwrap_or\\(|unwrap_or_default\\(|unwrap_or_else\\()') || {
  fail "the scanner itself failed; refusing to report a clean tree"
  exit 1
}
report "$swallow_bad" "RNG failure collapsed into a value instead of an error:" \
  'propagate the error; a default [u8; N] is all zeros'

# ------------------------------------------------------- 3. seeded PRNGs ----
seeded_bad=$(scan_rust 'seed_from_u64[ \t]*[(]|from_seed[ \t]*[(]|SmallRng') || {
  fail "the scanner itself failed; refusing to report a clean tree"
  exit 1
}
report "$seeded_bad" "seeded/reproducible PRNG in production code:" \
  'use the OS RNG (OsRng / rand::rng() / getrandom)' \
  "or mark a deliberate non-crypto use: // $OPT_OUT - <reason>"

# ------------------------------------------------ 4. the entropy gate holds --
# Every public entry point in the entropy module that reaches the unchecked mixer
# must run the health gate first. Structural, not a string grep, so deleting the
# `?` is caught too. Fails closed if it finds no gated entry point at all: that
# means the module was reshaped (moved into an impl, gate renamed) and the rule
# has quietly stopped meaning anything.
if [ ! -f "$ENTROPY_MODULE" ]; then
  fail "$ENTROPY_MODULE not found; rule 4 cannot run (was the module moved?)"
else
  gate_out=$(awk '
    # Comments stripped first: the gate named only in a doc comment used to
    # satisfy this rule while the call was gone.
    { p = index($0, "//"); if (p > 0) $0 = substr($0, 1, p - 1) }
    /(^|[^a-zA-Z0-9_])pub fn /  { fn = $0; sub(/^.*pub fn /, "", fn); sub(/[(<].*$/, "", fn); gated = 0; uses = 0 }
    /ensure_entropy_health\(\)\?/     { if (fn != "") gated = 1 }
    /random_bytes_mixed_internal\(\)/ { if (fn != "") uses = 1 }
    /^[ \t]*\}[ \t]*$/ {
      if (fn != "" && uses) { if (gated) ok++; else print "UNGATED " fn }
      fn = ""
    }
    END { print "GATED " (ok + 0) }
  ' "$ENTROPY_MODULE") || { fail "rule 4 scanner failed on $ENTROPY_MODULE"; exit 1; }
  gate_bad=$(printf '%s\n' "$gate_out" | sed -n 's/^UNGATED //p')
  gate_ok=$(printf '%s\n' "$gate_out" | sed -n 's/^GATED //p')
  report "$gate_bad" "public entropy entry point reaches the mixer without ensure_entropy_health()?:" \
    'the mixer folds in timing jitter and process context, so its output looks' \
    'random even when a source has degraded. The gate is what makes that visible.'
  if [ "${gate_ok:-0}" -lt 1 ]; then
    fail "rule 4 found no gated entry point in $ENTROPY_MODULE; the rule has stopped checking anything"
    echo "  → the entropy API was probably reshaped (moved into an impl, or the gate renamed)."
    echo "    Update this rule deliberately rather than leaving it vacuous."
  fi
fi

# --------------------------------------------- 5. the panicking draw ---------
# `random_bytes` is `try_random_bytes().expect(..)`. Panicking on a degraded RNG
# is the right direction -- it refuses to hand out a key rather than hand out a
# predictable one -- but it is the blunt version of it. uniffi catches the
# unwind and reports an untyped internal exception, and in the bunker the panic
# lands on whichever task drew, so a caller that can return an error should.
#
# Single-pattern like rule 3: there is no "handled" spelling of this call, only
# the fallible sibling or a deliberate opt-out. `crypto::try_random_bytes` does
# not contain the literal `crypto::random_bytes`, so the fallible form is not
# matched.
#
# The optional `::` is load-bearing. Nearly every call here is a turbofish
# (`random_bytes::<32>()`), where the next character after the name is a colon,
# so without it this rule matched only the bare-parenthesis spelling and sailed
# straight past the sites it exists to find. The left identifier boundary keeps
# a module merely ending in those names (`not_crypto::random_bytes`) from being
# reported, and `strict` turns off the shared `?`/`.expect` suppression, which
# would otherwise excuse the draw because of error handling belonging to another
# call in the same statement.
panicking_bad=$(scan_rust '(^|[^A-Za-z0-9_])(crypto|entropy)::random_bytes(::)?[ \t]*[(<]' '' strict) || {
  fail "the scanner itself failed; refusing to report a clean tree"
  exit 1
}
report "$panicking_bad" "panicking RNG draw where the error could have propagated:" \
  'use keep_core::crypto::try_random_bytes::<N>()? and let the caller decide' \
  "or, where the signature cannot carry a Result: // $OPT_OUT - <reason>"

# ------------------------------------ 6. the health check samples the OS -----
# The check is only worth running if it looks at the source the keys actually
# come from. `gather_os_entropy` fed it `rand::rng()` for a long time, which is
# a thread-local ChaCha12 seeded once from the OS: a kernel stuck on a constant
# was expanded into a keystream that passes every criterion the check applies,
# while FROST nonces, drawn from `getrandom` via OsRng, came out identical. The
# check certified the expansion rather than the source.
#
# Structural rather than a grep for the bad call, so replacing it with any other
# userspace generator is caught too: the sampler must name the OS interface.
if [ -f "$ENTROPY_MODULE" ]; then
  os_src=$(awk '
    /^[ \t]*fn gather_os_entropy/ { inside = 1; found = 0; next }
    inside && /^[ \t]*\}/ { print (found ? "OK" : "NOT-OS"); inside = 0 }
    inside {
      p = index($0, "//"); if (p > 0) $0 = substr($0, 1, p - 1)
      if ($0 ~ /SysRng|getrandom/) found = 1
    }
    END { if (inside) print "UNTERMINATED" }
  ' "$ENTROPY_MODULE") || { fail "rule 6 scanner failed on $ENTROPY_MODULE"; exit 1; }
  case $os_src in
    OK) ;;
    NOT-OS)
      fail "the entropy health check does not sample the OS:"
      echo "  gather_os_entropy() in $ENTROPY_MODULE names no OS interface."
      echo "  → it must draw through SysRng/getrandom. A seeded userspace"
      echo "    generator expands a degraded source into output that passes"
      echo "    every check here, which certifies the expansion, not the source." ;;
    *)
      fail "rule 6 could not find gather_os_entropy() in $ENTROPY_MODULE"
      echo "  → the sampler was renamed or moved; update this rule deliberately"
      echo "    rather than leaving it vacuous." ;;
  esac
fi

if [ "$status" -eq 0 ]; then
  echo "RNG hygiene: OK (getrandom errors handled, no swallowed failures, no seeded PRNGs, no unpropagated panicking draws, health check samples the OS, entropy gate intact on $gate_ok entry points)"
fi
exit "$status"
