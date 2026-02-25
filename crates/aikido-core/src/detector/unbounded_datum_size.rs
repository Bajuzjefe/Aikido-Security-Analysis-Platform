use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects datum types with unbounded fields that could grow beyond processing limits.
pub struct UnboundedDatumSize;

const UNBOUNDED_TYPE_PATTERNS: &[&str] = &["List<", "ByteArray", "Dict<"];

/// Field names or type names that indicate a fixed-size ByteArray (not truly unbounded).
/// PolicyId, ScriptHash, VerificationKey, etc. are always 28 or 32 bytes on Cardano.
const FIXED_SIZE_BYTEARRAY_NAMES: &[&str] = &[
    "policy_id",
    "policyid",
    "policy",
    "script_hash",
    "scripthash",
    "key_hash",
    "keyhash",
    "verification_key",
    "verificationkey",
    "pub_key",
    "pubkey",
    "credential",
    "tx_hash",
    "txhash",
    "asset_name",
    "assetname",
    "currency_symbol",
    "nft",
    "token",
    "datum_hash",
    "datumhash",
    "owner_ref",
];

/// Type names that represent fixed-size Cardano primitives even though they're ByteArray underneath.
const FIXED_SIZE_TYPE_NAMES: &[&str] = &[
    "PolicyId",
    "ScriptHash",
    "VerificationKey",
    "VerificationKeyHash",
    "Credential",
    "AssetName",
    "Hash<",
    "aiken/crypto.ScriptHash",
    "aiken/crypto.VerificationKey",
    "aiken/crypto.VerificationKeyHash",
    "cardano/assets.PolicyId",
    "cardano/assets.AssetName",
    "cardano/address.Credential",
];

impl Detector for UnboundedDatumSize {
    fn name(&self) -> &str {
        "unbounded-datum-size"
    }

    fn description(&self) -> &str {
        "Detects datum types with unbounded fields (List, ByteArray) that could exceed processing limits"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Datum types that contain unbounded collections (List, ByteArray, Dict) can grow \
        arbitrarily large. Processing large datums consumes excessive CPU/memory budget, \
        potentially making the UTXO unspendable if the cost exceeds Plutus limits.\n\n\
        Example (vulnerable):\n  type Datum {\n    owners: List<ByteArray>\n    \
        history: List<Action>\n  }\n\n\
        Fix: Use bounded alternatives or enforce size limits in the validator logic."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-400")
    }

    fn category(&self) -> &str {
        "resource"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            // Find datum types used by validators
            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }
                    // First param of spend handler is the datum
                    if let Some(datum_param) = handler.params.first() {
                        let datum_type_name =
                            crate::detector::type_base_name(&datum_param.type_name);
                        // Find the datum type definition
                        find_unbounded_fields(
                            module,
                            datum_type_name,
                            &validator.name,
                            &handler.name,
                            &mut findings,
                            self,
                            handler.location,
                        );
                    }
                }
            }
        }

        // Also check across lib modules for the same datum types
        let lib_modules: Vec<_> = modules
            .iter()
            .filter(|m| m.kind == ModuleKind::Lib)
            .collect();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }
            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }
                    if let Some(datum_param) = handler.params.first() {
                        let datum_type_name =
                            crate::detector::type_base_name(&datum_param.type_name);
                        for lib_mod in &lib_modules {
                            find_unbounded_fields(
                                lib_mod,
                                datum_type_name,
                                &validator.name,
                                &handler.name,
                                &mut findings,
                                self,
                                handler.location,
                            );
                        }
                    }
                }
            }
        }

        findings
    }
}

fn find_unbounded_fields(
    module: &ModuleInfo,
    datum_type_name: &str,
    validator_name: &str,
    handler_name: &str,
    findings: &mut Vec<Finding>,
    detector: &UnboundedDatumSize,
    handler_location: Option<(usize, usize)>,
) {
    for dt in &module.data_types {
        if dt.name != datum_type_name {
            continue;
        }
        for constructor in &dt.constructors {
            for field in &constructor.fields {
                let type_is_unbounded = UNBOUNDED_TYPE_PATTERNS
                    .iter()
                    .any(|p| field.type_name.contains(p));
                if type_is_unbounded && !is_fixed_size_bytearray(field) {
                    let field_label = field.label.as_deref().unwrap_or("<unnamed>").to_string();
                    findings.push(Finding {
                        detector_name: detector.name().to_string(),
                        severity: detector.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Datum field '{field_label}' in {validator_name}.{handler_name} has unbounded type"
                        ),
                        description: format!(
                            "Field '{}' has type '{}' which can grow unboundedly. \
                            Processing a large datum may exceed Plutus execution budget.",
                            field_label, field.type_name
                        ),
                        module: module.name.clone(),
                        location: handler_location.map(|(s, e)| {
                            SourceLocation::from_bytes(&module.path, s, e)
                        }),
                        suggestion: Some(
                            "Consider using bounded alternatives or enforcing size limits in validator logic."
                                .to_string(),
                        ),
                        related_findings: vec![],
                        semantic_group: None,

                        evidence: None,
                    });
                }
            }
        }
    }
}

/// Check if a ByteArray field is actually fixed-size based on its name or type context.
fn is_fixed_size_bytearray(field: &crate::ast_walker::FieldInfo) -> bool {
    // Only applies to plain ByteArray (not List<ByteArray>, Dict<..., ByteArray>)
    if field.type_name != "ByteArray" {
        return false;
    }

    // Check if the field name suggests a fixed-size Cardano primitive
    if let Some(ref label) = field.label {
        let lower = label.to_lowercase();
        if FIXED_SIZE_BYTEARRAY_NAMES.iter().any(|p| lower.contains(p)) {
            return true;
        }
    }

    // Check if the resolved type name is a known fixed-size type
    if FIXED_SIZE_TYPE_NAMES
        .iter()
        .any(|t| field.type_name.contains(t))
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    fn make_modules_with_datum(fields: Vec<FieldInfo>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![ParamInfo {
                        name: "datum".to_string(),
                        type_name: "MyDatum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals::default(),
                }],
                summary: None,
            }],
            data_types: vec![DataTypeInfo {
                name: "MyDatum".to_string(),
                public: true,
                constructors: vec![ConstructorInfo {
                    name: "MyDatum".to_string(),
                    fields,
                }],
            }],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }]
    }

    #[test]
    fn test_detects_unbounded_list_field() {
        let fields = vec![
            FieldInfo {
                label: Some("owner".to_string()),
                type_name: "ByteArray".to_string(),
            },
            FieldInfo {
                label: Some("history".to_string()),
                type_name: "List<Action>".to_string(),
            },
        ];
        let modules = make_modules_with_datum(fields);
        let findings = UnboundedDatumSize.detect(&modules);
        // Both fields flagged: "owner" ByteArray is generic (not a known fixed-size pattern),
        // and "history" List<Action> is unbounded
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.title.contains("history")));
        assert!(findings.iter().any(|f| f.title.contains("owner")));
    }

    #[test]
    fn test_skips_fixed_size_bytearray_fields() {
        let fields = vec![
            FieldInfo {
                label: Some("poolPolicyId".to_string()),
                type_name: "ByteArray".to_string(),
            },
            FieldInfo {
                label: Some("script_hash".to_string()),
                type_name: "ByteArray".to_string(),
            },
            FieldInfo {
                label: Some("loanPolicyId".to_string()),
                type_name: "ByteArray".to_string(),
            },
        ];
        let modules = make_modules_with_datum(fields);
        let findings = UnboundedDatumSize.detect(&modules);
        assert!(
            findings.is_empty(),
            "Fixed-size ByteArray fields should not be flagged"
        );
    }

    #[test]
    fn test_still_flags_generic_bytearray() {
        let fields = vec![FieldInfo {
            label: Some("payload".to_string()),
            type_name: "ByteArray".to_string(),
        }];
        let modules = make_modules_with_datum(fields);
        let findings = UnboundedDatumSize.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "Generic ByteArray fields should still be flagged"
        );
    }

    #[test]
    fn test_no_finding_for_fixed_fields() {
        let fields = vec![
            FieldInfo {
                label: Some("owner".to_string()),
                type_name: "VerificationKeyHash".to_string(),
            },
            FieldInfo {
                label: Some("amount".to_string()),
                type_name: "Int".to_string(),
            },
        ];
        let modules = make_modules_with_datum(fields);
        let findings = UnboundedDatumSize.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_bytearray_field() {
        let fields = vec![FieldInfo {
            label: Some("data".to_string()),
            type_name: "ByteArray".to_string(),
        }];
        let modules = make_modules_with_datum(fields);
        let findings = UnboundedDatumSize.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("data"));
    }
}
