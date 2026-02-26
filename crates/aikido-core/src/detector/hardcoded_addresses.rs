use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Suspicious ByteArray literal sizes that match Cardano address components:
/// - 28 bytes: key hash (payment or stake)
/// - 29 bytes: key hash + network tag
/// - 57 bytes: full address payload (payment key hash + stake key hash + overhead)
const SUSPICIOUS_BYTE_LENGTHS: &[usize] = &[28, 29, 57];

pub struct HardcodedAddresses;

impl Detector for HardcodedAddresses {
    fn name(&self) -> &str {
        "hardcoded-addresses"
    }

    fn description(&self) -> &str {
        "Detects ByteArray literals with lengths matching Cardano key hashes or addresses"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "ByteArray literals of 28, 29, or 57 bytes match common Cardano address component sizes \
        (key hashes, addresses). Hardcoding these values makes the contract inflexible and may \
        indicate addresses that should be validator parameters instead.\n\n\
        Note: This detector uses size-based heuristics and may produce false positives for \
        ByteArrays that happen to match these sizes but are not addresses.\n\n\
        Fix: Pass addresses/key hashes as validator parameters."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-798")
    }

    fn category(&self) -> &str {
        "configuration"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    let suspicious: Vec<usize> = handler
                        .body_signals
                        .bytearray_literal_lengths
                        .iter()
                        .filter(|len| SUSPICIOUS_BYTE_LENGTHS.contains(len))
                        .copied()
                        .collect();

                    if suspicious.is_empty() {
                        continue;
                    }

                    let size_desc: Vec<String> = suspicious
                        .iter()
                        .map(|&len| match len {
                            28 => "28 bytes (key hash)".to_string(),
                            29 => "29 bytes (key hash + network tag)".to_string(),
                            57 => "57 bytes (full address payload)".to_string(),
                            _ => format!("{len} bytes"),
                        })
                        .collect();

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Hardcoded address-like literal in {}.{}",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler body contains ByteArray literal(s) of suspicious size: {}. \
                            These may be hardcoded addresses or key hashes that should be parameterized.",
                            size_desc.join(", ")
                        ),
                        module: module.name.clone(),
                        location: handler.location.map(|(s, e)| {
                            SourceLocation::from_bytes(&module.path, s, e)
                        }),
                        suggestion: Some(
                            "Pass addresses/key hashes as validator parameters instead of hardcoding them."
                                .to_string(),
                        ),
                        related_findings: vec![],
                        semantic_group: None,

                        evidence: None,
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    fn make_validator_module(bytearray_lengths: Vec<usize>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![ParamInfo {
                        name: "self".to_string(),
                        type_name: "Transaction".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        bytearray_literal_lengths: bytearray_lengths,
                        ..Default::default()
                    },
                }],
                summary: None,
            }],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }]
    }

    #[test]
    fn test_detects_28_byte_key_hash() {
        let modules = make_validator_module(vec![28]);
        let findings = HardcodedAddresses.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("key hash"));
    }

    #[test]
    fn test_detects_57_byte_address() {
        let modules = make_validator_module(vec![57]);
        let findings = HardcodedAddresses.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("address payload"));
    }

    #[test]
    fn test_no_finding_for_safe_sizes() {
        let modules = make_validator_module(vec![4, 8, 16, 32, 64]);
        let findings = HardcodedAddresses.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_for_empty() {
        let modules = make_validator_module(vec![]);
        let findings = HardcodedAddresses.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_skips_lib_modules() {
        let modules = vec![ModuleInfo {
            name: "test/lib".to_string(),
            path: "lib.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];
        let findings = HardcodedAddresses.detect(&modules);
        assert!(findings.is_empty());
    }
}
