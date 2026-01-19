#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if let Ok(msg) = keep_frost_net::KfpMessage::from_json(data) {
        let _ = msg.validate();
        let _ = msg.to_json();
    }
});
