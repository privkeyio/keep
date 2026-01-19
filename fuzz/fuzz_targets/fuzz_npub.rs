#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = keep_core::keys::npub_to_bytes(data);
});
