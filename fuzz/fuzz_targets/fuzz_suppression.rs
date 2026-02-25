//! Fuzz target for suppression comment parsing (#101).
//! Feeds arbitrary source strings to the suppression parser.

#![no_main]

use libfuzzer_sys::fuzz_target;

use aikido_core::ast_walker::{ModuleInfo, ModuleKind};
use aikido_core::detector::{Confidence, Finding, Severity, SourceLocation};
use aikido_core::suppression::filter_suppressed;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        // Create a module with the fuzzed source code
        let modules = vec![ModuleInfo {
            name: "test/fuzz".to_string(),
            path: "validators/fuzz.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: Some(source.to_string()),
            test_function_names: vec![],
        }];

        // Create findings that reference various lines
        let line_count = source.lines().count();
        if line_count > 0 {
            let findings: Vec<Finding> = (1..=line_count.min(5))
                .map(|line| {
                    let mut loc = SourceLocation::from_bytes("validators/fuzz.ak", 0, 1);
                    loc.line_start = Some(line);
                    Finding {
                        detector_name: "test-detector".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Likely,
                        title: "Test".to_string(),
                        description: "Test finding".to_string(),
                        module: "test/fuzz".to_string(),
                        location: Some(loc),
                        suggestion: None,
                        related_findings: vec![],
                        semantic_group: None,
                    }
                })
                .collect();

            // Should never panic
            let _ = filter_suppressed(findings, &modules);
        }
    }
});
