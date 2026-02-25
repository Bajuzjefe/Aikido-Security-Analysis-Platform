//! Transaction composition model (Phase 3).
//!
//! Infers transaction templates from code patterns: which validators participate,
//! what data flows between them, and what coordination patterns are used.

use std::collections::HashSet;

use crate::ast_walker::{ModuleInfo, ModuleKind};

/// A transaction template inferred from validator code.
#[derive(Debug, Clone)]
pub struct TransactionTemplate {
    /// Module where this template was inferred from.
    pub source_module: String,
    /// Validator name.
    pub source_validator: String,
    /// Handler name.
    pub source_handler: String,
    /// Participants in this transaction.
    pub participants: Vec<TxParticipant>,
    /// Data flows between participants.
    pub data_flows: Vec<DataFlow>,
}

/// A participant in a transaction.
#[derive(Debug, Clone)]
pub struct TxParticipant {
    /// Role in the transaction.
    pub role: ParticipantRole,
    /// What this participant validates.
    pub validates: HashSet<String>,
}

/// The role a validator plays in a transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum ParticipantRole {
    /// Spending a UTxO at a script address.
    SpendScript,
    /// Minting or burning tokens.
    MintBurn,
    /// Withdrawal (staking/delegation check).
    Withdrawal,
    /// External signer (wallet).
    Signer,
}

/// Data flow between transaction participants.
#[derive(Debug, Clone)]
pub struct DataFlow {
    pub from: ParticipantRole,
    pub to: ParticipantRole,
    pub data_type: FlowType,
}

/// Type of data flowing between participants.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowType {
    /// Value (ADA + native tokens) transfer.
    ValueTransfer,
    /// Datum continuity (input datum → output datum).
    DatumContinuity,
    /// Mint/burn coordination.
    MintBurnCoordination,
    /// Signature requirement.
    SignatureRequirement,
}

/// Infer transaction templates from analyzed modules.
pub fn infer_transaction_templates(modules: &[ModuleInfo]) -> Vec<TransactionTemplate> {
    let mut templates = Vec::new();

    for module in modules {
        if module.kind != ModuleKind::Validator {
            continue;
        }

        for validator in &module.validators {
            for handler in &validator.handlers {
                let signals = &handler.body_signals;
                let mut participants = Vec::new();
                let mut data_flows = Vec::new();

                // The handler itself is a participant
                let self_role = match handler.name.as_str() {
                    "spend" => ParticipantRole::SpendScript,
                    "mint" => ParticipantRole::MintBurn,
                    "withdraw" => ParticipantRole::Withdrawal,
                    _ => ParticipantRole::SpendScript,
                };
                participants.push(TxParticipant {
                    role: self_role.clone(),
                    validates: signals.tx_field_accesses.clone(),
                });

                // If spend handler accesses `mint`, there's a minting participant
                if handler.name == "spend" && signals.tx_field_accesses.contains("mint") {
                    participants.push(TxParticipant {
                        role: ParticipantRole::MintBurn,
                        validates: HashSet::from(["mint".to_string()]),
                    });
                    data_flows.push(DataFlow {
                        from: ParticipantRole::SpendScript,
                        to: ParticipantRole::MintBurn,
                        data_type: FlowType::MintBurnCoordination,
                    });
                }

                // If handler accesses `withdrawals`, there's a withdrawal participant
                if signals.tx_field_accesses.contains("withdrawals") {
                    participants.push(TxParticipant {
                        role: ParticipantRole::Withdrawal,
                        validates: HashSet::from(["withdrawals".to_string()]),
                    });
                }

                // If handler accesses `extra_signatories`, there's a signer
                if signals.tx_field_accesses.contains("extra_signatories") {
                    participants.push(TxParticipant {
                        role: ParticipantRole::Signer,
                        validates: HashSet::from(["extra_signatories".to_string()]),
                    });
                    data_flows.push(DataFlow {
                        from: ParticipantRole::Signer,
                        to: self_role.clone(),
                        data_type: FlowType::SignatureRequirement,
                    });
                }

                // Datum continuity (spend with outputs)
                if handler.name == "spend"
                    && signals.tx_field_accesses.contains("outputs")
                    && (signals.has_datum_continuity_assertion
                        || signals.all_record_labels.contains("datum"))
                {
                    data_flows.push(DataFlow {
                        from: ParticipantRole::SpendScript,
                        to: ParticipantRole::SpendScript,
                        data_type: FlowType::DatumContinuity,
                    });
                }

                // Value transfer (spend with outputs and value access)
                if handler.name == "spend"
                    && signals.tx_field_accesses.contains("outputs")
                    && signals.all_record_labels.contains("value")
                {
                    data_flows.push(DataFlow {
                        from: ParticipantRole::SpendScript,
                        to: ParticipantRole::SpendScript,
                        data_type: FlowType::ValueTransfer,
                    });
                }

                let has_state_transfer_hint =
                    handler.name == "spend" && signals.tx_field_accesses.contains("outputs");

                if participants.len() > 1 || !data_flows.is_empty() || has_state_transfer_hint {
                    templates.push(TransactionTemplate {
                        source_module: module.name.clone(),
                        source_validator: validator.name.clone(),
                        source_handler: handler.name.clone(),
                        participants,
                        data_flows,
                    });
                }
            }
        }
    }

    templates
}

/// Check for coordination gaps: patterns where participants should coordinate
/// but appear to be missing checks.
pub fn find_coordination_gaps(templates: &[TransactionTemplate]) -> Vec<CoordinationGap> {
    let mut gaps = Vec::new();

    for template in templates {
        // Gap 1: Mint coordination without checking minted quantity
        let has_mint_participant = template
            .participants
            .iter()
            .any(|p| p.role == ParticipantRole::MintBurn);
        let has_mint_flow = template
            .data_flows
            .iter()
            .any(|f| f.data_type == FlowType::MintBurnCoordination);

        if has_mint_participant && !has_mint_flow {
            gaps.push(CoordinationGap {
                module: template.source_module.clone(),
                validator: template.source_validator.clone(),
                handler: template.source_handler.clone(),
                gap_type: GapType::UncoordinatedMint,
                description: "Minting participant present but no coordination flow detected"
                    .to_string(),
            });
        }

        // Gap 2: Datum continuity expected but not verified
        let spend_produces_output = template
            .participants
            .iter()
            .any(|p| p.role == ParticipantRole::SpendScript && p.validates.contains("outputs"));
        let has_datum_flow = template
            .data_flows
            .iter()
            .any(|f| f.data_type == FlowType::DatumContinuity);

        if spend_produces_output && !has_datum_flow {
            gaps.push(CoordinationGap {
                module: template.source_module.clone(),
                validator: template.source_validator.clone(),
                handler: template.source_handler.clone(),
                gap_type: GapType::MissingDatumContinuity,
                description: "Spend produces outputs but no datum continuity verified".to_string(),
            });
        }
    }

    gaps
}

/// A coordination gap between transaction participants.
#[derive(Debug, Clone)]
pub struct CoordinationGap {
    pub module: String,
    pub validator: String,
    pub handler: String,
    pub gap_type: GapType,
    pub description: String,
}

/// Types of coordination gaps.
#[derive(Debug, Clone, PartialEq)]
pub enum GapType {
    /// Mint participant without coordination.
    UncoordinatedMint,
    /// Missing datum continuity.
    MissingDatumContinuity,
    /// Missing burn flow in destructive operation.
    MissingBurnFlow,
    /// Delegation without delegate validation.
    UnverifiedDelegation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    fn make_module_with_handler(
        name: &str,
        handler_name: &str,
        tx_accesses: &[&str],
    ) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: handler_name.to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses.iter().map(|s| s.to_string()).collect(),
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
        }
    }

    #[test]
    fn test_infer_mint_coordination() {
        let modules = vec![make_module_with_handler(
            "test/pool",
            "spend",
            &["outputs", "mint"],
        )];
        let templates = infer_transaction_templates(&modules);
        assert!(!templates.is_empty());
        assert!(templates[0]
            .participants
            .iter()
            .any(|p| p.role == ParticipantRole::MintBurn));
    }

    #[test]
    fn test_infer_withdrawal_participant() {
        let modules = vec![make_module_with_handler(
            "test/pool",
            "spend",
            &["outputs", "withdrawals"],
        )];
        let templates = infer_transaction_templates(&modules);
        assert!(!templates.is_empty());
        assert!(templates[0]
            .participants
            .iter()
            .any(|p| p.role == ParticipantRole::Withdrawal));
    }

    #[test]
    fn test_coordination_gap_missing_datum() {
        // Spend handler with outputs + extra_signatories (creates a multi-participant
        // template) but no datum continuity — should detect the gap.
        let modules = vec![make_module_with_handler(
            "test/pool",
            "spend",
            &["outputs", "inputs", "extra_signatories"],
        )];
        let templates = infer_transaction_templates(&modules);
        let gaps = find_coordination_gaps(&templates);
        assert!(
            gaps.iter()
                .any(|g| g.gap_type == GapType::MissingDatumContinuity),
            "should detect missing datum continuity"
        );
    }
}
