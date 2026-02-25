//! Fuzz target for config parsing (#101).
//! Feeds arbitrary strings to TOML config parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try parsing as aikido config — should never panic
        let _ = toml::from_str::<aikido_core::config::AikidoConfig>(s);
    }
});
