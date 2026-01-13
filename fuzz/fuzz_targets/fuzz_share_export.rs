#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = keep_core::frost::ShareExport::from_json(data);
    let _ = keep_core::frost::ShareExport::from_bech32(data);
});
