use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{
    matches_field_pattern, Confidence, Detector, Finding, Severity, SourceLocation,
};

/// Check if a type name represents a VerificationKeyHash.
/// Aiken stores this as `aiken/hash.Hash<Blake2b_224, VerificationKey>`.
fn is_verification_key_hash_type(type_name: &str) -> bool {
    let lower = type_name.to_lowercase();
    (lower.contains("hash") && lower.contains("verificationkey"))
        || lower.contains("verificationkeyhash")
}

/// Check if a field has a user-identifying name or type (direct check).
fn is_user_identifying_field(
    field: &crate::ast_walker::FieldInfo,
    user_fields: &[&str],
    user_types: &[&str],
) -> bool {
    // Check field name with word-boundary matching
    let name_match = field
        .label
        .as_ref()
        .is_some_and(|label| matches_field_pattern(label, user_fields));
    // Check field type (Credential, VerificationKeyHash, etc.)
    let type_match = user_types.iter().any(|t| {
        let base = crate::detector::type_base_name(&field.type_name);
        base == *t || field.type_name.contains(t)
    });
    // Check Hash<..., VerificationKey> pattern
    let hash_match = is_verification_key_hash_type(&field.type_name);

    name_match || type_match || hash_match
}

pub struct UtxoContentionRisk;

impl Detector for UtxoContentionRisk {
    fn name(&self) -> &str {
        "utxo-contention-risk"
    }

    fn description(&self) -> &str {
        "Detects validators with single global UTXO contention patterns"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a validator uses a single shared UTXO (global state) that multiple users \
        must spend and recreate, contention arises: only one transaction can succeed per \
        block. This limits throughput to ~1 tx/20s and causes most user transactions to \
        fail with 'UTxO already spent' errors.\n\n\
        Indicators: spend handler with no user-specific datum fields (no owner, beneficiary, \
        or unique ID), suggesting a single global state UTXO.\n\n\
        Fix: Use a UTXO-per-user pattern (each user has their own UTXO at the script address) \
        or use a batching/aggregation approach."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-400")
    }

    fn category(&self) -> &str {
        "resource"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // User-identifying datum field name patterns (word-boundary matched)
        const USER_FIELDS: &[&str] = &[
            "owner",
            "beneficiary",
            "creator",
            "user",
            "sender",
            "recipient",
            "address",
            "pkh",
            "credential",
            "position_id",
            "order_id",
            "nft_id",
            "id",
            "seller",
            "buyer",
            "borrower",
            "lender",
            "delegator",
            "bidder",
            "issuer",
            "obligee",
            "minter",
            "trader",
            "depositor",
            "position_owner",
            "key_hash",
            "pub_key_hash",
            "signer",
        ];

        // Datum type names that indicate intentional singleton patterns (case-insensitive)
        const SINGLETON_PATTERNS: &[&str] = &[
            "settings",
            "config",
            "parameters",
            "protocol",
            "global",
            "pool",
            "registry",
            "factory",
            "oracle",
            "treasury",
        ];

        // Types that imply per-user identification
        const USER_TYPES: &[&str] = &[
            "Credential",
            "VerificationKeyHash",
            "VerificationKey",
            "Address",
            "PaymentCredential",
        ];

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                // Only check validators with spend handlers
                let spend_handler = validator.handlers.iter().find(|h| h.name == "spend");
                let Some(spend) = spend_handler else {
                    continue;
                };

                // Get the datum type from the first param
                let datum_param = spend.params.first();
                let Some(datum_p) = datum_param else {
                    continue;
                };

                // Skip if datum is Void/Data (no structured datum = likely not a state machine)
                if datum_p.type_name == "Void"
                    || datum_p.type_name == "Data"
                    || datum_p.type_name == "Int"
                    || datum_p.type_name == "ByteArray"
                {
                    continue;
                }

                // Skip single-handler validators (only 1 handler total = simple lock/unlock)
                if validator.handlers.len() == 1 {
                    continue;
                }

                // Skip when spend handler delegates to a withdrawal script.
                // Withdrawal delegation means the real logic lives elsewhere.
                let signals = &spend.body_signals;
                if signals.tx_field_accesses.contains("withdrawals")
                    && signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("has_key") || c.contains("is_withdrawal"))
                {
                    continue;
                }

                // Skip singleton-pattern datums by type name — these are intentionally
                // single-UTXO by design (e.g. ProtocolSettings, PoolConfig, GlobalRegistry)
                let datum_lower = datum_p.type_name.to_lowercase();
                if SINGLETON_PATTERNS
                    .iter()
                    .any(|pat| datum_lower.contains(pat))
                {
                    continue;
                }

                // Find the datum type definition
                let datum_base = crate::detector::type_base_name(&datum_p.type_name);
                let datum_type = modules.iter().flat_map(|m| &m.data_types).find(|dt| {
                    dt.name == datum_base
                        || dt.name.ends_with(&format!(".{datum_base}"))
                        || datum_base.ends_with(&format!(".{}", dt.name))
                });

                let Some(dt) = datum_type else {
                    continue;
                };

                // Check if the datum has any user-identifying fields (by name or type)
                let has_user_field = dt.constructors.iter().any(|c| {
                    c.fields.iter().any(|f| {
                        if is_user_identifying_field(f, USER_FIELDS, USER_TYPES) {
                            return true;
                        }

                        // One-level nested type resolution: if this field is a custom type,
                        // resolve it and check its fields too.
                        let field_base = crate::detector::type_base_name(&f.type_name);
                        // Skip primitive / well-known types
                        if matches!(
                            field_base,
                            "Int"
                                | "Bool"
                                | "ByteArray"
                                | "String"
                                | "Void"
                                | "Data"
                                | "List"
                                | "Option"
                                | "Pairs"
                        ) {
                            return false;
                        }

                        // Look up the nested type definition
                        let nested_type = modules.iter().flat_map(|m| &m.data_types).find(|ndt| {
                            ndt.name == field_base
                                || ndt.name.ends_with(&format!(".{field_base}"))
                                || field_base.ends_with(&format!(".{}", ndt.name))
                        });

                        if let Some(nested_dt) = nested_type {
                            nested_dt.constructors.iter().any(|nc| {
                                nc.fields.iter().any(|nf| {
                                    is_user_identifying_field(nf, USER_FIELDS, USER_TYPES)
                                })
                            })
                        } else {
                            false
                        }
                    })
                });

                // If the datum has no user-specific fields, flag contention risk
                if !has_user_field {
                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Potential UTXO contention in validator '{}'",
                            validator.name
                        ),
                        description: format!(
                            "Datum type '{datum_base}' has no user-identifying fields (owner, id, etc.). \
                            If this validator uses a single global UTXO, multiple users will \
                            contend for it, limiting throughput to ~1 tx per block.",
                        ),
                        module: module.name.clone(),
                        location: spend
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Consider a per-user UTXO pattern or add user-identifying \
                            fields to the datum."
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

    /// Helper to build a module with a multi-handler validator (spend + mint).
    /// The single-handler skip means we need >=2 handlers to trigger.
    fn make_module(
        datum_type_name: &str,
        datum_fields: Vec<(Option<&str>, &str)>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![
                    HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![ParamInfo {
                            name: "datum".to_string(),
                            type_name: datum_type_name.to_string(),
                        }],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals::default(),
                    },
                    HandlerInfo {
                        name: "mint".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals::default(),
                    },
                ],
                summary: None,
            }],
            data_types: vec![DataTypeInfo {
                name: datum_type_name.to_string(),
                public: true,
                constructors: vec![ConstructorInfo {
                    name: datum_type_name.to_string(),
                    fields: datum_fields
                        .into_iter()
                        .map(|(label, typ)| FieldInfo {
                            label: label.map(|l| l.to_string()),
                            type_name: typ.to_string(),
                        })
                        .collect(),
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

    /// Helper for single-handler validator (spend only)
    fn make_single_handler_module(
        datum_type_name: &str,
        datum_fields: Vec<(Option<&str>, &str)>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![ParamInfo {
                        name: "datum".to_string(),
                        type_name: datum_type_name.to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals::default(),
                }],
                summary: None,
            }],
            data_types: vec![DataTypeInfo {
                name: datum_type_name.to_string(),
                public: true,
                constructors: vec![ConstructorInfo {
                    name: datum_type_name.to_string(),
                    fields: datum_fields
                        .into_iter()
                        .map(|(label, typ)| FieldInfo {
                            label: label.map(|l| l.to_string()),
                            type_name: typ.to_string(),
                        })
                        .collect(),
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
    fn test_detects_global_state_datum() {
        let modules = make_module(
            "AuctionState",
            vec![(Some("total_locked"), "Int"), (Some("last_update"), "Int")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("contention"));
    }

    #[test]
    fn test_no_finding_with_owner_field() {
        let modules = make_module(
            "Position",
            vec![(Some("owner"), "ByteArray"), (Some("amount"), "Int")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_credential_type() {
        let modules = make_module(
            "Position",
            vec![(Some("amount"), "Int"), (Some("party"), "Credential")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "Credential type should indicate per-user"
        );
    }

    #[test]
    fn test_no_finding_with_hash_verification_key_type() {
        // Aiken represents VerificationKeyHash as Hash<Blake2b_224, VerificationKey>
        let modules = make_module(
            "Position",
            vec![
                (Some("amount"), "Int"),
                (
                    Some("signer"),
                    "aiken/hash.Hash<Blake2b_224, VerificationKey>",
                ),
            ],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "Hash<..., VerificationKey> should indicate per-user"
        );
    }

    #[test]
    fn test_no_finding_with_nested_user_field() {
        // Datum has a field of custom type "Config" which contains an "owner" field
        let mut modules = make_module(
            "VaultState",
            vec![(Some("total_locked"), "Int"), (Some("config"), "Config")],
        );
        // Add the nested Config type definition
        modules[0].data_types.push(DataTypeInfo {
            name: "Config".to_string(),
            public: true,
            constructors: vec![ConstructorInfo {
                name: "Config".to_string(),
                fields: vec![
                    FieldInfo {
                        label: Some("owner".to_string()),
                        type_name: "ByteArray".to_string(),
                    },
                    FieldInfo {
                        label: Some("threshold".to_string()),
                        type_name: "Int".to_string(),
                    },
                ],
            }],
        });
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "nested type with owner field should indicate per-user"
        );
    }

    #[test]
    fn test_no_finding_with_void_datum() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "v".to_string(),
                params: vec![],
                handlers: vec![
                    HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![ParamInfo {
                            name: "datum".to_string(),
                            type_name: "Void".to_string(),
                        }],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals::default(),
                    },
                    HandlerInfo {
                        name: "mint".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals::default(),
                    },
                ],
                summary: None,
            }],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];
        assert!(UtxoContentionRisk.detect(&modules).is_empty());
    }

    #[test]
    fn test_no_finding_for_single_handler_validator() {
        // Single-handler (spend only) = simple lock/unlock, not a contention risk
        let modules = make_single_handler_module(
            "AuctionState",
            vec![(Some("total_locked"), "Int"), (Some("last_update"), "Int")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "single-handler validators should be skipped"
        );
    }

    #[test]
    fn test_no_finding_for_singleton_datum_type() {
        // Datum named ProtocolSettings = intentional singleton by design
        let modules = make_module(
            "ProtocolSettings",
            vec![(Some("fee_percent"), "Int"), (Some("treasury"), "Int")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "singleton-pattern datum types should be skipped"
        );
    }

    #[test]
    fn test_no_finding_for_config_datum_type() {
        // Datum named GlobalConfig = intentional singleton by design
        let modules = make_module(
            "GlobalConfig",
            vec![(Some("threshold"), "Int"), (Some("enabled"), "Bool")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(findings.is_empty(), "config datum types should be skipped");
    }

    #[test]
    fn test_no_finding_for_oracle_datum_type() {
        // OracleDatum is a singleton by design (like ProtocolSettings)
        let modules = make_module(
            "OracleDatum",
            vec![(Some("pool_a_qty"), "Int"), (Some("pool_b_qty"), "Int")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "oracle datum types should be skipped as singletons"
        );
    }

    #[test]
    fn test_no_finding_for_treasury_datum_type() {
        let modules = make_module(
            "TreasuryState",
            vec![(Some("balance"), "Int"), (Some("fee"), "Int")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "treasury datum types should be skipped as singletons"
        );
    }

    #[test]
    fn test_no_finding_with_new_user_fields() {
        // Expanded USER_FIELDS: seller, buyer, borrower, etc.
        let modules = make_module(
            "Offer",
            vec![(Some("amount"), "Int"), (Some("seller"), "ByteArray")],
        );
        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "seller should be a user-identifying field"
        );
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut modules = make_module(
            "AuctionState",
            vec![(Some("total_locked"), "Int"), (Some("last_update"), "Int")],
        );
        // Add withdrawal delegation signals to spend handler
        let spend = &mut modules[0].validators[0].handlers[0];
        spend
            .body_signals
            .tx_field_accesses
            .insert("withdrawals".to_string());
        spend
            .body_signals
            .function_calls
            .insert("pairs.has_key".to_string());

        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "withdrawal delegation should suppress contention risk"
        );
    }

    #[test]
    fn test_type_resolution_does_not_match_suffix() {
        // ForwardsDatum should NOT resolve to Datum type via suffix matching.
        // This tests the fix for the "ForwardsDatum".ends_with("Datum") bug.
        let mut modules = make_module(
            "ForwardsDatum",
            vec![
                (Some("issuer_address_hash"), "VerificationKeyHash"),
                (Some("amount"), "Int"),
            ],
        );
        // Add a Datum type (from stdlib) that could be incorrectly matched
        modules[0].data_types.push(DataTypeInfo {
            name: "Datum".to_string(),
            public: true,
            constructors: vec![ConstructorInfo {
                name: "Datum".to_string(),
                fields: vec![FieldInfo {
                    label: Some("raw".to_string()),
                    type_name: "Data".to_string(),
                }],
            }],
        });

        let findings = UtxoContentionRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "ForwardsDatum with issuer field should not fire, must not resolve to Datum"
        );
    }
}
