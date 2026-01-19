#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keep_core::crypto::EncryptedData::from_bytes(data);
});
