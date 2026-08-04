# Invariants

Rules this codebase has broken more than once. Each one below was violated in
code that had been reviewed, compiled, and passed CI, and each was caught by an
adversarial reader or a failing test rather than by anyone re-reading the change.
That is the reason they are written down: they are not obvious at the point of
writing, and inspection does not catch them.

They are ordered by what happens when you get them wrong, worst first.

## Never destroy a source until the copy reads back

Not "until the write returned success". A commit reports that bytes reached
disk, not that they can be retrieved.

The share migration copied a share into per-group storage and then erased the
original. Encrypted preferences return the default when a value cannot be
decrypted, and writing that default *removes* the destination key rather than
storing nothing, so a failed read produced a commit that reported success having
written no share, after which the source was erased. The share was then
unrecoverable, with no error anywhere.

The fix attempt then repeated the mistake one level up: it guarded on whether the
destination *contained* the key, which resolves a name and never decrypts. Both
are the same error, which is the next invariant.

## Distinguish absence from failure, everywhere it crosses a boundary

A value that is not there and a value that could not be read are different
facts, and a type that cannot express the difference forces every caller to
guess. Callers guess wrong in the unsafe direction.

The signer's rate-limiter storage returned an optional string, so an unreadable
counter was indistinguishable from a package with no history. Auto-signing
treated that as "no usage yet", which restarted the window on every request and
removed the ceiling entirely. Fixing it meant changing the trait to report
found, absent, or unavailable, and changing the caller to refuse rather than
assume.

If you are adding a storage or FFI method that can fail, make failure
representable. If you are implementing one that cannot, say so at the
implementation rather than returning a default.

## Name resolution is not value retrievability

`contains(key)` proves a name resolves. It does not prove the value decrypts,
that a companion value exists, or that anything is readable. Guarding a
destructive action on presence is guarding on the wrong thing.

Registry membership is the same trap one level further out: a list of which
groups exist does not record whether their data survived.

## Bounding cost must not relax a guard

These are different changes and it is easy to write the second while intending
the first.

An unreadable audit registry caused a re-fold on every commit, which is a real
cost on a hot path. The bound added to stop that also forced the "safe to
rewrite" flag true, which authorized the truncating rewrite the guard existed to
prevent. Three transient faults would have destroyed a valid key list with no
attacker involved. The correct bound stops the retrying and leaves the refusal
in place.

## A search that finds things cannot prove absence

`grep -c` returning zero means your pattern did not match. It does not mean the
thing is not there.

Four claims in the hardening backlogs were wrong because of one search:
looking for lines containing both a symbol and the word "test". A test
function's name line contains neither the attribute nor that word, so every
tested symbol reported as untested. The same class of error found "cert pinning
is absent" for a path that pins through a helper, because the low-level function
name did not appear in that file.

Before writing "X does not exist", open the file.

## Assert the property, not the artifact

Write the assertion about what must remain true, not about the specific state
you happen to be looking at.

Two migration tests asserted "the legacy copy survives". The invariant is "the
share survives somewhere". Those agree only when the fix *fails*: once the
migration correctly recovers the share into its new home, clearing the old copy
is the right outcome, so both tests failed on working code. A test that fails
when the fix works and passes when it is broken is worse than no test.

## Identify a target by what an operation changed

Not by a filter you assume is selective.

Tests that needed to corrupt one stored entry picked it with predicates like
"the first entry whose value starts with the version marker", which also matches
the derivation key and the registry. Corrupting the derivation key throws out of
the read path and produces a failure unrelated to the thing under test. The
reliable method is to snapshot, perform the write, and diff, asserting that
exactly one entry changed.

## A test that has never failed proves nothing

Run it against the broken code before trusting it. Roughly eight tests written
in one session passed for reasons unrelated to their names, including several
that would have passed with the fix reverted.

Two failure modes are worth knowing by name. A test can be vacuous because its
setup never reaches the code under test, and it can be *masked* by a later fix:
one clear-path test became meaningless when a bound was added elsewhere, because
the bound rejected the staged input before the behaviour under test ran.

## Green CI is not correctness

CI here has passed defective code repeatedly, including a change carrying two
critical findings, and a test asserting the broken behaviour as correct.

Know what your signals do not cover:

- macOS, Windows, Debian and reproducibility jobs do not run on pull requests.
  A merge that is fully green as a PR can turn `main` red.
- Draft pull requests skip instrumented tests entirely, so a draft's green
  checks say nothing about the Android test suite.
- keep-android cannot be compiled locally without the full cross-compile,
  because the generated bindings are not checked in.

A queued or skipped run reads as passing in a snapshot. Match runs by commit
SHA and wait for a conclusion.
