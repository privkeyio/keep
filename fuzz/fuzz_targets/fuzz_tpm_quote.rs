#![no_main]

// Fuzz the TPM-quote byte parser with arbitrary input. `pcr_selection_from_attest` reaches the
// low-level `parse_quote`, which byte-slices a marshaled `TPMS_ATTEST` blob taken verbatim from a
// peer's announce -- fully attacker-controlled, untrusted input on the boot/discovery gate. The
// parser must NEVER panic (slice out-of-bounds, length overflow) on malformed/truncated/oversized
// input; a panic here is a remote DoS on the gate. Any `Err` is a correct outcome; only a crash is
// a bug. Complements `fuzz_frost_messages`, which stops at `KfpMessage::validate()` and never
// reaches the quote parser.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keep_frost_net::tpm_quote::pcr_selection_from_attest(data);
});
