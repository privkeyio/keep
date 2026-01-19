#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(arr) = <[u8; 512]>::try_from(data) {
        let _ = keep_core::hidden::header::OuterHeader::from_bytes(&arr);
        let _ = keep_core::hidden::header::HiddenHeader::from_bytes(&arr);
    }
    if !data.is_empty() {
        let _ = keep_core::hidden::header::HiddenHeader::from_bytes_compact(data);
    }
});
