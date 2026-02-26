//! Transaction simulation lane for Aikido.
//!
//! This module provides the framework for transaction simulation — building
//! simulated transactions from static analysis findings to verify whether
//! detected vulnerabilities are actually exploitable.
//!
//! The actual UPLC execution will require pallas integration later, but the
//! scaffolding, types, builders, and exploit scenario generation are complete.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::detector::Finding;
use crate::evidence::{compute_effective_confidence, Evidence, EvidenceLevel};
use uplc::ast::{Data, DeBruijn, Program};
use uplc::machine::cost_model::ExBudget;

// ---------------------------------------------------------------------------
// Core simulation types
// ---------------------------------------------------------------------------

/// A simulated transaction context for testing validator behavior.
#[derive(Debug, Clone, Serialize)]
pub struct SimulatedTx {
    /// Transaction inputs (simplified).
    pub inputs: Vec<SimInput>,
    /// Transaction outputs.
    pub outputs: Vec<SimOutput>,
    /// Required signatories (public key hashes as hex strings).
    pub signatories: Vec<String>,
    /// Validity range.
    pub validity_range: SimValidityRange,
    /// Mint field (policy_id -> asset_name -> quantity).
    pub mint: HashMap<String, HashMap<String, i64>>,
    /// Redeemer for the validator being tested.
    pub redeemer: SimPlutusData,
    /// Datum for the input being spent.
    pub datum: Option<SimPlutusData>,
}

/// A simulated transaction input.
#[derive(Debug, Clone, Serialize)]
pub struct SimInput {
    /// Transaction hash (hex).
    pub tx_hash: String,
    /// Output index within the referenced transaction.
    pub output_index: u32,
    /// Bech32-style address (simplified as string for simulation).
    pub address: String,
    /// Value held by this input.
    pub value: SimValue,
    /// Datum attached to this input, if any.
    pub datum: Option<SimPlutusData>,
}

/// A simulated transaction output.
#[derive(Debug, Clone, Serialize)]
pub struct SimOutput {
    /// Destination address.
    pub address: String,
    /// Value sent to this output.
    pub value: SimValue,
    /// Datum attached to this output, if any.
    pub datum: Option<SimPlutusData>,
}

/// A value bundle (ADA + native assets).
#[derive(Debug, Clone, Serialize)]
pub struct SimValue {
    /// Lovelace amount (1 ADA = 1,000,000 lovelace).
    pub lovelace: u64,
    /// Native assets: policy_id -> asset_name -> quantity.
    pub native_assets: HashMap<String, HashMap<String, u64>>,
}

impl SimValue {
    /// Create a value with only ADA.
    pub fn lovelace_only(lovelace: u64) -> Self {
        Self {
            lovelace,
            native_assets: HashMap::new(),
        }
    }

    /// Create a value with ADA and a single native asset.
    pub fn with_asset(lovelace: u64, policy: &str, name: &str, qty: u64) -> Self {
        let mut native_assets = HashMap::new();
        let mut assets = HashMap::new();
        assets.insert(name.to_string(), qty);
        native_assets.insert(policy.to_string(), assets);
        Self {
            lovelace,
            native_assets,
        }
    }
}

/// Transaction validity range (POSIX milliseconds).
#[derive(Debug, Clone, Serialize)]
pub struct SimValidityRange {
    /// Earliest POSIX time (ms) the transaction is valid.
    pub start: Option<u64>,
    /// Latest POSIX time (ms) the transaction is valid.
    pub end: Option<u64>,
}

impl SimValidityRange {
    /// Create an unbounded validity range (always valid).
    pub fn unbounded() -> Self {
        Self {
            start: None,
            end: None,
        }
    }

    /// Create a finite validity range.
    pub fn finite(start: u64, end: u64) -> Self {
        Self {
            start: Some(start),
            end: Some(end),
        }
    }
}

/// Simplified PlutusData for simulation.
///
/// Mirrors the Plutus data model without requiring full CBOR encoding.
/// Used to construct redeemers, datums, and witness values for exploit scenarios.
#[derive(Debug, Clone, Serialize)]
pub enum SimPlutusData {
    /// An integer value.
    Integer(i64),
    /// A byte string (raw bytes).
    ByteString(Vec<u8>),
    /// A list of PlutusData values.
    List(Vec<SimPlutusData>),
    /// A map of key-value pairs.
    Map(Vec<(SimPlutusData, SimPlutusData)>),
    /// A constructor with a tag and fields (Constr in Plutus).
    Constructor {
        tag: u64,
        fields: Vec<SimPlutusData>,
    },
}

impl SimPlutusData {
    /// Create a Constr(0, []) — commonly used as a "unit" or simple redeemer variant.
    pub fn unit_constructor() -> Self {
        SimPlutusData::Constructor {
            tag: 0,
            fields: vec![],
        }
    }

    /// Create a constructor with a tag and fields.
    pub fn constr(tag: u64, fields: Vec<SimPlutusData>) -> Self {
        SimPlutusData::Constructor { tag, fields }
    }

    /// Create a ByteString from a hex string.
    pub fn from_hex(hex: &str) -> Self {
        let bytes = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        SimPlutusData::ByteString(bytes)
    }
}

// ---------------------------------------------------------------------------
// Simulation result types
// ---------------------------------------------------------------------------

/// Result of a simulation run.
#[derive(Debug, Clone, Serialize)]
pub enum SimulationResult {
    /// Validator accepted the transaction.
    Accepted {
        /// CPU units consumed.
        cpu_units: u64,
        /// Memory units consumed.
        mem_units: u64,
        /// Execution trace steps.
        trace: Vec<SimTraceStep>,
    },
    /// Validator rejected the transaction.
    Rejected {
        /// Error message from the validator.
        error: String,
        /// Execution trace up to the error.
        trace: Vec<SimTraceStep>,
    },
    /// Simulation could not be run (e.g., missing compiled code).
    NotAvailable {
        /// Reason simulation was not possible.
        reason: String,
    },
}

impl SimulationResult {
    /// Returns true if the validator accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, SimulationResult::Accepted { .. })
    }

    /// Returns true if the validator rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, SimulationResult::Rejected { .. })
    }

    /// Returns true if simulation was not available.
    pub fn is_not_available(&self) -> bool {
        matches!(self, SimulationResult::NotAvailable { .. })
    }
}

/// A step in the execution trace.
#[derive(Debug, Clone, Serialize)]
pub struct SimTraceStep {
    /// Step number (1-indexed).
    pub step: usize,
    /// Human-readable description of what happened.
    pub description: String,
    /// The kind of trace event.
    pub kind: TraceStepKind,
}

/// Classification of a trace step.
#[derive(Debug, Clone, Serialize)]
pub enum TraceStepKind {
    /// Entering a named function.
    FunctionEntry(String),
    /// Binding a value to a variable.
    VariableBinding { name: String, value: String },
    /// A conditional branch was taken.
    BranchTaken { condition: String, result: bool },
    /// A comparison was evaluated.
    Comparison {
        left: String,
        op: String,
        right: String,
        result: bool,
    },
    /// A value was returned.
    Return(String),
    /// An error occurred.
    Error(String),
}

// ---------------------------------------------------------------------------
// Transaction builder
// ---------------------------------------------------------------------------

/// Builder for creating simulated transactions.
///
/// Provides a fluent API for constructing `SimulatedTx` instances
/// for testing validator behavior against specific scenarios.
pub struct SimTxBuilder {
    tx: SimulatedTx,
}

impl Default for SimTxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SimTxBuilder {
    /// Create a new builder with an empty transaction.
    pub fn new() -> Self {
        Self {
            tx: SimulatedTx {
                inputs: Vec::new(),
                outputs: Vec::new(),
                signatories: Vec::new(),
                validity_range: SimValidityRange::unbounded(),
                mint: HashMap::new(),
                redeemer: SimPlutusData::unit_constructor(),
                datum: None,
            },
        }
    }

    /// Add an input to the transaction.
    pub fn add_input(mut self, input: SimInput) -> Self {
        self.tx.inputs.push(input);
        self
    }

    /// Add an output to the transaction.
    pub fn add_output(mut self, output: SimOutput) -> Self {
        self.tx.outputs.push(output);
        self
    }

    /// Add a required signatory (public key hash as hex).
    pub fn add_signatory(mut self, pkh: &str) -> Self {
        self.tx.signatories.push(pkh.to_string());
        self
    }

    /// Set the transaction validity range.
    pub fn set_validity_range(mut self, start: Option<u64>, end: Option<u64>) -> Self {
        self.tx.validity_range = SimValidityRange { start, end };
        self
    }

    /// Add a minted asset to the transaction.
    pub fn set_mint(mut self, policy: &str, name: &str, qty: i64) -> Self {
        self.tx
            .mint
            .entry(policy.to_string())
            .or_default()
            .insert(name.to_string(), qty);
        self
    }

    /// Set the redeemer for the validator being tested.
    pub fn set_redeemer(mut self, redeemer: SimPlutusData) -> Self {
        self.tx.redeemer = redeemer;
        self
    }

    /// Set the datum for the input being spent.
    pub fn set_datum(mut self, datum: SimPlutusData) -> Self {
        self.tx.datum = Some(datum);
        self
    }

    /// Build the simulated transaction.
    pub fn build(self) -> SimulatedTx {
        self.tx
    }
}

// ---------------------------------------------------------------------------
// Exploit scenario types
// ---------------------------------------------------------------------------

/// An exploit scenario describes how a vulnerability could be exploited.
///
/// Generated from static analysis findings, these scenarios describe the
/// attack step by step and optionally include a simulated transaction
/// that demonstrates the exploit.
#[derive(Debug, Clone, Serialize)]
pub struct ExploitScenario {
    /// The detector that produced the finding.
    pub finding_detector: String,
    /// Human-readable description of the exploit.
    pub description: String,
    /// Step-by-step description of the attack.
    pub attack_steps: Vec<AttackStep>,
    /// A simulated transaction that would exploit the vulnerability (if constructible).
    pub simulated_tx: Option<SimulatedTx>,
    /// What we expect the validator to do with this transaction.
    pub expected_result: ExpectedResult,
}

/// A single step in an attack scenario.
#[derive(Debug, Clone, Serialize)]
pub struct AttackStep {
    /// Step number (1-indexed).
    pub step: usize,
    /// What the attacker does at this step.
    pub action: String,
    /// Why this step is necessary for the exploit.
    pub rationale: String,
}

/// Expected outcome of running the exploit transaction through the validator.
#[derive(Debug, Clone, Serialize)]
pub enum ExpectedResult {
    /// The validator should accept — confirming the vulnerability is real.
    ValidatorAccepts,
    /// The validator should reject — suggesting a false positive.
    ValidatorRejects,
    /// Cannot determine the expected outcome without simulation.
    Unknown,
}

// ---------------------------------------------------------------------------
// Exploit scenario generation
// ---------------------------------------------------------------------------

/// Generate an exploit scenario from a finding.
///
/// Maps known detector patterns to concrete attack scenarios with
/// simulated transactions. Returns `None` for detectors that don't
/// have a well-defined exploit pattern.
pub fn generate_exploit_scenario(finding: &Finding) -> Option<ExploitScenario> {
    match finding.detector_name.as_str() {
        "missing-signature-check" => Some(generate_missing_signature_scenario(finding)),
        "unrestricted-minting" => Some(generate_unrestricted_minting_scenario(finding)),
        "double-satisfaction" => Some(generate_double_satisfaction_scenario(finding)),
        "missing-redeemer-validation" => {
            Some(generate_missing_redeemer_validation_scenario(finding))
        }
        "missing-validity-range" => Some(generate_missing_validity_range_scenario(finding)),
        "missing-datum-in-script-output" => {
            Some(generate_missing_datum_in_output_scenario(finding))
        }
        _ => None,
    }
}

fn generate_missing_signature_scenario(finding: &Finding) -> ExploitScenario {
    let dummy_pkh = "deadbeef".repeat(7);
    let attacker_pkh = "cafebabe".repeat(7);

    let tx = SimTxBuilder::new()
        .add_input(SimInput {
            tx_hash: "a".repeat(64),
            output_index: 0,
            address: format!("addr_test1qz{dummy_pkh}"),
            value: SimValue::lovelace_only(10_000_000),
            datum: Some(SimPlutusData::constr(0, vec![])),
        })
        .add_output(SimOutput {
            address: format!("addr_test1qz{attacker_pkh}"),
            value: SimValue::lovelace_only(10_000_000),
            datum: None,
        })
        // Deliberately omit adding the required signatory
        .set_redeemer(SimPlutusData::unit_constructor())
        .set_datum(SimPlutusData::constr(0, vec![]))
        .build();

    ExploitScenario {
        finding_detector: "missing-signature-check".to_string(),
        description: format!(
            "Exploit for missing signature check in module '{}': \
             An attacker constructs a transaction that spends from the script \
             without providing the required signatory, draining funds to their own address.",
            finding.module
        ),
        attack_steps: vec![
            AttackStep {
                step: 1,
                action: "Identify the script UTxO holding funds".to_string(),
                rationale: "The attacker locates a UTxO at the vulnerable script address."
                    .to_string(),
            },
            AttackStep {
                step: 2,
                action: "Build a transaction spending the UTxO without a valid signature"
                    .to_string(),
                rationale: "Since the validator does not check signatories, \
                            the transaction can be signed by anyone."
                    .to_string(),
            },
            AttackStep {
                step: 3,
                action: "Send the output to the attacker's address".to_string(),
                rationale: "Funds are redirected without authorization.".to_string(),
            },
        ],
        simulated_tx: Some(tx),
        expected_result: ExpectedResult::ValidatorAccepts,
    }
}

fn generate_unrestricted_minting_scenario(finding: &Finding) -> ExploitScenario {
    let attacker_pkh = "cafebabe".repeat(7);
    let fake_policy = "ff".repeat(28);

    let tx = SimTxBuilder::new()
        .add_input(SimInput {
            tx_hash: "b".repeat(64),
            output_index: 0,
            address: format!("addr_test1qz{attacker_pkh}"),
            value: SimValue::lovelace_only(5_000_000),
            datum: None,
        })
        .add_output(SimOutput {
            address: format!("addr_test1qz{attacker_pkh}"),
            value: SimValue::with_asset(2_000_000, &fake_policy, "exploit_token", 1_000_000),
            datum: None,
        })
        .set_mint(&fake_policy, "exploit_token", 1_000_000)
        .set_redeemer(SimPlutusData::unit_constructor())
        .build();

    ExploitScenario {
        finding_detector: "unrestricted-minting".to_string(),
        description: format!(
            "Exploit for unrestricted minting in module '{}': \
             An attacker can mint an arbitrary amount of tokens because the minting \
             policy does not validate the minted quantity or authorized minter.",
            finding.module
        ),
        attack_steps: vec![
            AttackStep {
                step: 1,
                action: "Construct a minting transaction with a large token quantity".to_string(),
                rationale: "The minting policy does not restrict who can mint or how much."
                    .to_string(),
            },
            AttackStep {
                step: 2,
                action: "Send the minted tokens to the attacker's address".to_string(),
                rationale: "The attacker now holds tokens they should not be able to create."
                    .to_string(),
            },
            AttackStep {
                step: 3,
                action: "Sell or use the illicitly minted tokens".to_string(),
                rationale: "Inflates supply or grants unauthorized access via token gating."
                    .to_string(),
            },
        ],
        simulated_tx: Some(tx),
        expected_result: ExpectedResult::ValidatorAccepts,
    }
}

fn generate_double_satisfaction_scenario(finding: &Finding) -> ExploitScenario {
    let script_addr = format!("addr_test1wz{}", "aa".repeat(28));
    let attacker_addr = format!("addr_test1qz{}", "cafebabe".repeat(7));

    let tx = SimTxBuilder::new()
        .add_input(SimInput {
            tx_hash: "c".repeat(64),
            output_index: 0,
            address: script_addr.clone(),
            value: SimValue::lovelace_only(50_000_000),
            datum: Some(SimPlutusData::constr(0, vec![SimPlutusData::Integer(100)])),
        })
        .add_input(SimInput {
            tx_hash: "d".repeat(64),
            output_index: 0,
            address: script_addr.clone(),
            value: SimValue::lovelace_only(50_000_000),
            datum: Some(SimPlutusData::constr(0, vec![SimPlutusData::Integer(100)])),
        })
        // Only one output satisfies both inputs — double satisfaction
        .add_output(SimOutput {
            address: script_addr,
            value: SimValue::lovelace_only(50_000_000),
            datum: Some(SimPlutusData::constr(0, vec![SimPlutusData::Integer(100)])),
        })
        .add_output(SimOutput {
            address: attacker_addr,
            value: SimValue::lovelace_only(50_000_000),
            datum: None,
        })
        .set_redeemer(SimPlutusData::unit_constructor())
        .set_datum(SimPlutusData::constr(0, vec![SimPlutusData::Integer(100)]))
        .build();

    ExploitScenario {
        finding_detector: "double-satisfaction".to_string(),
        description: format!(
            "Exploit for double satisfaction in module '{}': \
             An attacker spends two script inputs in the same transaction, \
             but only one output satisfies the validator's conditions. \
             The attacker steals the value from the second input.",
            finding.module
        ),
        attack_steps: vec![
            AttackStep {
                step: 1,
                action: "Find two UTxOs at the same script address".to_string(),
                rationale: "Both UTxOs are governed by the same validator.".to_string(),
            },
            AttackStep {
                step: 2,
                action: "Construct a transaction spending both UTxOs with a single valid output"
                    .to_string(),
                rationale:
                    "The validator checks that 'some' output satisfies conditions, not 'each' input."
                        .to_string(),
            },
            AttackStep {
                step: 3,
                action: "Redirect the extra funds to the attacker's address".to_string(),
                rationale: "The validator is satisfied by one output, the rest are unchecked."
                    .to_string(),
            },
        ],
        simulated_tx: Some(tx),
        expected_result: ExpectedResult::ValidatorAccepts,
    }
}

fn generate_missing_redeemer_validation_scenario(finding: &Finding) -> ExploitScenario {
    let script_addr = format!("addr_test1wz{}", "bb".repeat(28));
    let attacker_addr = format!("addr_test1qz{}", "cafebabe".repeat(7));

    let tx = SimTxBuilder::new()
        .add_input(SimInput {
            tx_hash: "e".repeat(64),
            output_index: 0,
            address: script_addr,
            value: SimValue::lovelace_only(20_000_000),
            datum: Some(SimPlutusData::constr(0, vec![])),
        })
        .add_output(SimOutput {
            address: attacker_addr,
            value: SimValue::lovelace_only(20_000_000),
            datum: None,
        })
        // Use a garbage redeemer — if the validator doesn't check it, it will still pass
        .set_redeemer(SimPlutusData::constr(
            999,
            vec![SimPlutusData::Integer(0xDEAD)],
        ))
        .set_datum(SimPlutusData::constr(0, vec![]))
        .build();

    ExploitScenario {
        finding_detector: "missing-redeemer-validation".to_string(),
        description: format!(
            "Exploit for missing redeemer validation in module '{}': \
             An attacker supplies a malformed or unexpected redeemer value. \
             Since the validator does not pattern-match on the redeemer, \
             any constructor tag is accepted.",
            finding.module
        ),
        attack_steps: vec![
            AttackStep {
                step: 1,
                action: "Craft a transaction with an unexpected redeemer constructor".to_string(),
                rationale: "The validator does not discriminate on redeemer shape.".to_string(),
            },
            AttackStep {
                step: 2,
                action: "Spend the script UTxO with the malformed redeemer".to_string(),
                rationale: "If the redeemer is not validated, any value is accepted.".to_string(),
            },
        ],
        simulated_tx: Some(tx),
        expected_result: ExpectedResult::ValidatorAccepts,
    }
}

fn generate_missing_validity_range_scenario(finding: &Finding) -> ExploitScenario {
    let script_addr = format!("addr_test1wz{}", "cc".repeat(28));
    let attacker_addr = format!("addr_test1qz{}", "cafebabe".repeat(7));

    // Build a transaction with no validity range — can be submitted at any time
    let tx = SimTxBuilder::new()
        .add_input(SimInput {
            tx_hash: "f".repeat(64),
            output_index: 0,
            address: script_addr,
            value: SimValue::lovelace_only(15_000_000),
            datum: Some(SimPlutusData::constr(
                0,
                vec![
                    // Simulated deadline field in datum
                    SimPlutusData::Integer(1_700_000_000_000),
                ],
            )),
        })
        .add_output(SimOutput {
            address: attacker_addr,
            value: SimValue::lovelace_only(15_000_000),
            datum: None,
        })
        // No validity range — transaction can be submitted at any time
        .set_validity_range(None, None)
        .set_redeemer(SimPlutusData::unit_constructor())
        .set_datum(SimPlutusData::constr(
            0,
            vec![SimPlutusData::Integer(1_700_000_000_000)],
        ))
        .build();

    ExploitScenario {
        finding_detector: "missing-validity-range".to_string(),
        description: format!(
            "Exploit for missing validity range in module '{}': \
             An attacker submits a time-sensitive transaction without a validity \
             interval, allowing it to be processed at any time regardless of \
             intended deadlines.",
            finding.module
        ),
        attack_steps: vec![
            AttackStep {
                step: 1,
                action:
                    "Build a transaction without setting validity_range_start or validity_range_end"
                        .to_string(),
                rationale: "The validator does not assert on the transaction validity range."
                    .to_string(),
            },
            AttackStep {
                step: 2,
                action: "Submit the transaction after the intended deadline has passed".to_string(),
                rationale: "Without validity range checks, time-dependent logic is bypassable."
                    .to_string(),
            },
        ],
        simulated_tx: Some(tx),
        expected_result: ExpectedResult::ValidatorAccepts,
    }
}

fn generate_missing_datum_in_output_scenario(finding: &Finding) -> ExploitScenario {
    let script_addr = format!("addr_test1wz{}", "dd".repeat(28));

    // Build a transaction that sends to a script address without attaching a datum
    let tx = SimTxBuilder::new()
        .add_input(SimInput {
            tx_hash: "a1".repeat(32),
            output_index: 0,
            address: script_addr.clone(),
            value: SimValue::lovelace_only(30_000_000),
            datum: Some(SimPlutusData::constr(0, vec![SimPlutusData::Integer(42)])),
        })
        .add_output(SimOutput {
            address: script_addr,
            value: SimValue::lovelace_only(30_000_000),
            // No datum — funds become locked forever
            datum: None,
        })
        .set_redeemer(SimPlutusData::unit_constructor())
        .set_datum(SimPlutusData::constr(0, vec![SimPlutusData::Integer(42)]))
        .build();

    ExploitScenario {
        finding_detector: "missing-datum-in-script-output".to_string(),
        description: format!(
            "Exploit for missing datum in script output in module '{}': \
             An attacker (or buggy off-chain code) sends funds to the script address \
             without attaching a datum, permanently locking the funds since no \
             valid datum exists to satisfy the spending condition.",
            finding.module
        ),
        attack_steps: vec![
            AttackStep {
                step: 1,
                action: "Construct a continuation output to the script address without a datum"
                    .to_string(),
                rationale:
                    "The validator does not enforce that outputs to its own address carry a datum."
                        .to_string(),
            },
            AttackStep {
                step: 2,
                action: "Submit the transaction".to_string(),
                rationale: "Funds are now locked at the script address with no way to spend them."
                    .to_string(),
            },
        ],
        simulated_tx: Some(tx),
        expected_result: ExpectedResult::ValidatorAccepts,
    }
}

// ---------------------------------------------------------------------------
// Simulation-based evidence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct BlueprintValidatorCode {
    title: String,
    compiled_code: String,
}

/// Execute exploit scenarios against compiled UPLC validators from `plutus.json`
/// and attach simulation evidence to findings.
pub fn enrich_findings_with_uplc_simulation(
    findings: &mut [Finding],
    project_root: &Path,
) -> usize {
    enrich_findings_with_uplc_simulation_with_context_builder(findings, project_root, None)
}

/// Same as `enrich_findings_with_uplc_simulation`, but allows plugging an
/// external context builder command (e.g., Anvil workflow bridge) to provide
/// richer ScriptContext data for UPLC execution.
pub fn enrich_findings_with_uplc_simulation_with_context_builder(
    findings: &mut [Finding],
    project_root: &Path,
    context_builder_command: Option<&str>,
) -> usize {
    let validators = load_blueprint_validators(project_root);
    if validators.is_empty() {
        return 0;
    }

    let mut enriched = 0usize;

    for finding in findings.iter_mut() {
        let Some(scenario) = generate_exploit_scenario(finding) else {
            continue;
        };

        let result = run_uplc_simulation(
            &scenario,
            finding,
            &validators,
            context_builder_command,
            project_root,
        );
        let Some(sim_evidence) = simulation_to_evidence(&result, &scenario) else {
            continue;
        };

        let merged = merge_evidence(finding.evidence.clone(), sim_evidence);
        finding.confidence = compute_effective_confidence(&finding.confidence, &merged);
        finding.evidence = Some(merged);
        enriched += 1;
    }

    enriched
}

fn load_blueprint_validators(project_root: &Path) -> Vec<BlueprintValidatorCode> {
    let blueprint_path = project_root.join("plutus.json");
    let Ok(content) = std::fs::read_to_string(&blueprint_path) else {
        return vec![];
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };
    let Some(validators) = json.get("validators").and_then(|v| v.as_array()) else {
        return vec![];
    };

    validators
        .iter()
        .filter_map(|v| {
            let title = v.get("title")?.as_str()?.to_string();
            let compiled_code = v.get("compiledCode")?.as_str()?.to_string();
            if compiled_code.is_empty() {
                None
            } else {
                Some(BlueprintValidatorCode {
                    title,
                    compiled_code,
                })
            }
        })
        .collect()
}

fn run_uplc_simulation(
    scenario: &ExploitScenario,
    finding: &Finding,
    validators: &[BlueprintValidatorCode],
    context_builder_command: Option<&str>,
    project_root: &Path,
) -> SimulationResult {
    let Some(tx) = scenario.simulated_tx.as_ref() else {
        return SimulationResult::NotAvailable {
            reason: "scenario has no simulated transaction".to_string(),
        };
    };

    let Some(validator) = match_validator_for_finding(finding, validators) else {
        return SimulationResult::NotAvailable {
            reason: "no matching validator in plutus.json".to_string(),
        };
    };

    let mut decoder_logs = Vec::new();
    let mut decoder_errs = Vec::new();
    let Ok(program) = Program::<DeBruijn>::from_hex(
        &validator.compiled_code,
        &mut decoder_logs,
        &mut decoder_errs,
    ) else {
        return SimulationResult::NotAvailable {
            reason: format!("failed to decode validator '{}'", validator.title),
        };
    };

    let datum = tx
        .datum
        .clone()
        .or_else(|| tx.inputs.first().and_then(|i| i.datum.clone()))
        .unwrap_or_else(SimPlutusData::unit_constructor);
    let redeemer = tx.redeemer.clone();
    let context = build_context_data_with_override(
        tx,
        context_builder_command,
        finding,
        scenario,
        project_root,
    );

    let applied = program
        .apply_data(sim_plutus_to_data(&datum))
        .apply_data(sim_plutus_to_data(&redeemer))
        .apply_data(context);

    let eval = applied.eval(ExBudget::default());
    let cost = eval.cost();
    let trace = eval
        .logs()
        .into_iter()
        .enumerate()
        .map(|(i, log)| SimTraceStep {
            step: i + 1,
            description: log.clone(),
            kind: TraceStepKind::VariableBinding {
                name: "trace".to_string(),
                value: log,
            },
        })
        .collect::<Vec<_>>();

    if eval.failed(false) {
        let msg = match eval.result() {
            Ok(term) => format!("validator returned non-accept result: {term}"),
            Err(err) => format!("UPLC evaluation failed: {err:?}"),
        };
        SimulationResult::Rejected { error: msg, trace }
    } else {
        SimulationResult::Accepted {
            cpu_units: cost.cpu.max(0) as u64,
            mem_units: cost.mem.max(0) as u64,
            trace,
        }
    }
}

fn match_validator_for_finding<'a>(
    finding: &Finding,
    validators: &'a [BlueprintValidatorCode],
) -> Option<&'a BlueprintValidatorCode> {
    let mut candidates = vec![normalize_key(&finding.module)];
    if let Some(loc) = &finding.location {
        candidates.push(normalize_key(&loc.module_path));
    }

    validators.iter().find(|validator| {
        let key = normalize_key(&validator.title);
        candidates
            .iter()
            .any(|cand| !cand.is_empty() && key.contains(cand))
    })
}

fn normalize_key(value: &str) -> String {
    let mut lowered = value.to_ascii_lowercase();
    if let Some(stripped) = lowered.rsplit('/').next() {
        lowered = stripped.to_string();
    }
    lowered.trim_end_matches(".ak").to_string()
}

fn build_context_data(tx: &SimulatedTx) -> uplc::PlutusData {
    let signatories = tx
        .signatories
        .iter()
        .map(|s| Data::bytestring(hex_or_utf8_bytes(s)))
        .collect::<Vec<_>>();

    Data::constr(
        0,
        vec![
            Data::list(vec![]),      // inputs (placeholder)
            Data::list(vec![]),      // outputs (placeholder)
            Data::list(signatories), // signatories
            Data::list(vec![]),      // certificates/withdrawals placeholder
            Data::map(vec![]),       // mint placeholder
            Data::constr(0, vec![]), // validity range placeholder
        ],
    )
}

#[derive(Debug, Serialize)]
struct ContextBuilderRequest<'a> {
    detector: &'a str,
    module: &'a str,
    scenario: &'a str,
    tx: &'a SimulatedTx,
    project_root: String,
}

#[derive(Debug, Deserialize)]
struct ContextBuilderResponse {
    context: ExternalPlutusData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ExternalPlutusData {
    Integer {
        value: i64,
    },
    ByteString {
        hex: String,
    },
    List {
        values: Vec<ExternalPlutusData>,
    },
    Map {
        entries: Vec<ExternalMapEntry>,
    },
    Constructor {
        tag: u64,
        fields: Vec<ExternalPlutusData>,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalMapEntry {
    key: ExternalPlutusData,
    value: ExternalPlutusData,
}

fn build_context_data_with_override(
    tx: &SimulatedTx,
    context_builder_command: Option<&str>,
    finding: &Finding,
    scenario: &ExploitScenario,
    project_root: &Path,
) -> uplc::PlutusData {
    let Some(cmd) = context_builder_command else {
        return build_context_data(tx);
    };

    let request = ContextBuilderRequest {
        detector: &finding.detector_name,
        module: &finding.module,
        scenario: &scenario.finding_detector,
        tx,
        project_root: project_root.to_string_lossy().into_owned(),
    };

    let Ok(req_json) = serde_json::to_string(&request) else {
        return build_context_data(tx);
    };

    let Ok(output) = Command::new("sh")
        .arg("-lc")
        .arg(cmd)
        .current_dir(project_root)
        .env("AIKIDO_SIM_CONTEXT_REQUEST", req_json)
        .output()
    else {
        return build_context_data(tx);
    };

    if !output.status.success() {
        return build_context_data(tx);
    }

    let Ok(response) = serde_json::from_slice::<ContextBuilderResponse>(&output.stdout) else {
        return build_context_data(tx);
    };

    external_plutus_to_data(&response.context)
}

fn external_plutus_to_data(value: &ExternalPlutusData) -> uplc::PlutusData {
    match value {
        ExternalPlutusData::Integer { value } => Data::integer((*value).into()),
        ExternalPlutusData::ByteString { hex } => Data::bytestring(hex_or_utf8_bytes(hex)),
        ExternalPlutusData::List { values } => {
            Data::list(values.iter().map(external_plutus_to_data).collect())
        }
        ExternalPlutusData::Map { entries } => Data::map(
            entries
                .iter()
                .map(|e| {
                    (
                        external_plutus_to_data(&e.key),
                        external_plutus_to_data(&e.value),
                    )
                })
                .collect(),
        ),
        ExternalPlutusData::Constructor { tag, fields } => {
            Data::constr(*tag, fields.iter().map(external_plutus_to_data).collect())
        }
    }
}

fn sim_plutus_to_data(value: &SimPlutusData) -> uplc::PlutusData {
    match value {
        SimPlutusData::Integer(i) => Data::integer((*i).into()),
        SimPlutusData::ByteString(bytes) => Data::bytestring(bytes.clone()),
        SimPlutusData::List(values) => Data::list(values.iter().map(sim_plutus_to_data).collect()),
        SimPlutusData::Map(entries) => Data::map(
            entries
                .iter()
                .map(|(k, v)| (sim_plutus_to_data(k), sim_plutus_to_data(v)))
                .collect(),
        ),
        SimPlutusData::Constructor { tag, fields } => {
            Data::constr(*tag, fields.iter().map(sim_plutus_to_data).collect())
        }
    }
}

fn hex_or_utf8_bytes(s: &str) -> Vec<u8> {
    let cleaned = s.strip_prefix("0x").unwrap_or(s);
    if cleaned.len() >= 2
        && cleaned.len() % 2 == 0
        && cleaned.chars().all(|c| c.is_ascii_hexdigit())
    {
        (0..cleaned.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
            .collect()
    } else {
        cleaned.as_bytes().to_vec()
    }
}

fn merge_evidence(existing: Option<Evidence>, incoming: Evidence) -> Evidence {
    match existing {
        None => incoming,
        Some(prev) => Evidence {
            level: if prev.level == incoming.level {
                incoming.level
            } else {
                EvidenceLevel::Corroborated
            },
            method: format!("{},{}", prev.method, incoming.method),
            details: match (prev.details, incoming.details) {
                (Some(a), Some(b)) => Some(format!("{a}; {b}")),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            code_flow: if prev.code_flow.is_empty() {
                incoming.code_flow
            } else if incoming.code_flow.is_empty() {
                prev.code_flow
            } else {
                let mut flow = prev.code_flow;
                flow.extend(incoming.code_flow);
                flow
            },
            witness: incoming.witness.or(prev.witness),
            confidence_boost: prev.confidence_boost.max(incoming.confidence_boost),
        },
    }
}

/// Convert a simulation result into evidence for the evidence framework.
///
/// When a simulation confirms that an exploit transaction is accepted by the
/// validator, this produces `SimulationConfirmed` level evidence with a high
/// confidence boost.
// TODO: integrate with evidence.rs when available — currently returns a
// standalone Evidence struct. The caller is responsible for attaching it
// to the Finding.
pub fn simulation_to_evidence(
    result: &SimulationResult,
    scenario: &ExploitScenario,
) -> Option<Evidence> {
    match result {
        SimulationResult::Accepted {
            cpu_units,
            mem_units,
            trace,
        } => {
            let witness = serde_json::json!({
                "cpu_units": cpu_units,
                "mem_units": mem_units,
                "trace_steps": trace.len(),
                "detector": scenario.finding_detector,
            });

            Some(Evidence {
                level: EvidenceLevel::SimulationConfirmed,
                method: "tx-simulation".to_string(),
                details: Some(format!(
                    "Exploit transaction accepted by validator (CPU: {}, MEM: {}). {}",
                    cpu_units, mem_units, scenario.description
                )),
                code_flow: vec![],
                witness: Some(witness),
                confidence_boost: 0.8,
            })
        }
        SimulationResult::Rejected { error, .. } => {
            let witness = serde_json::json!({
                "rejection_error": error,
                "detector": scenario.finding_detector,
            });

            Some(Evidence {
                level: EvidenceLevel::PatternMatch,
                method: "tx-simulation-rejected".to_string(),
                details: Some(format!(
                    "Exploit transaction rejected by validator: {}. \
                     This may indicate a false positive for {}.",
                    error, scenario.finding_detector
                )),
                code_flow: vec![],
                witness: Some(witness),
                // Negative confidence boost — the simulation contradicts the finding
                confidence_boost: -0.3,
            })
        }
        SimulationResult::NotAvailable { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Format functions
// ---------------------------------------------------------------------------

/// Format a report of multiple exploit scenarios.
pub fn format_simulation_report(scenarios: &[ExploitScenario]) -> String {
    if scenarios.is_empty() {
        return "No exploit scenarios generated.".to_string();
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "TRANSACTION SIMULATION REPORT ({} scenarios)",
        scenarios.len()
    ));
    lines.push("=".repeat(60));

    for (i, scenario) in scenarios.iter().enumerate() {
        if i > 0 {
            lines.push(String::new());
            lines.push("-".repeat(60));
        }
        lines.push(format_exploit_scenario(scenario));
    }

    lines.push(String::new());
    lines.push("=".repeat(60));

    let accepted_count = scenarios
        .iter()
        .filter(|s| matches!(s.expected_result, ExpectedResult::ValidatorAccepts))
        .count();
    let rejected_count = scenarios
        .iter()
        .filter(|s| matches!(s.expected_result, ExpectedResult::ValidatorRejects))
        .count();
    let unknown_count = scenarios
        .iter()
        .filter(|s| matches!(s.expected_result, ExpectedResult::Unknown))
        .count();

    lines.push(format!(
        "Summary: {} exploitable, {} rejected, {} unknown",
        accepted_count, rejected_count, unknown_count
    ));

    lines.join("\n")
}

/// Format a single exploit scenario for display.
pub fn format_exploit_scenario(scenario: &ExploitScenario) -> String {
    let mut lines = Vec::new();

    lines.push(format!("Detector: {}", scenario.finding_detector));
    lines.push(format!("Description: {}", scenario.description));

    let expected = match &scenario.expected_result {
        ExpectedResult::ValidatorAccepts => "EXPLOITABLE (validator accepts)",
        ExpectedResult::ValidatorRejects => "NOT EXPLOITABLE (validator rejects)",
        ExpectedResult::Unknown => "UNKNOWN (simulation required)",
    };
    lines.push(format!("Expected: {expected}"));

    lines.push(String::new());
    lines.push("Attack Steps:".to_string());
    for step in &scenario.attack_steps {
        lines.push(format!("  {}. {}", step.step, step.action));
        lines.push(format!("     Rationale: {}", step.rationale));
    }

    if let Some(ref tx) = scenario.simulated_tx {
        lines.push(String::new());
        lines.push("Simulated Transaction:".to_string());
        lines.push(format!("  Inputs:      {}", tx.inputs.len()));
        lines.push(format!("  Outputs:     {}", tx.outputs.len()));
        lines.push(format!("  Signatories: {}", tx.signatories.len()));
        lines.push(format!(
            "  Mint:        {} policies",
            tx.mint.keys().count()
        ));
        lines.push(format!(
            "  Validity:    {}",
            format_validity_range(&tx.validity_range)
        ));

        // Summarize input values
        let total_input_lovelace: u64 = tx.inputs.iter().map(|i| i.value.lovelace).sum();
        let total_output_lovelace: u64 = tx.outputs.iter().map(|o| o.value.lovelace).sum();
        lines.push(format!(
            "  Input ADA:   {:.6}",
            total_input_lovelace as f64 / 1_000_000.0
        ));
        lines.push(format!(
            "  Output ADA:  {:.6}",
            total_output_lovelace as f64 / 1_000_000.0
        ));
    }

    lines.join("\n")
}

fn format_validity_range(range: &SimValidityRange) -> String {
    match (range.start, range.end) {
        (None, None) => "unbounded (always valid)".to_string(),
        (Some(s), None) => format!("from {s} (no upper bound)"),
        (None, Some(e)) => format!("until {e} (no lower bound)"),
        (Some(s), Some(e)) => format!("{s} to {e}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Finding, Severity, SourceLocation};

    /// Helper: create a minimal Finding for testing.
    fn make_finding(detector: &str, module: &str) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("{detector} finding"),
            description: format!("Test finding for {detector}"),
            module: module.to_string(),
            location: Some(SourceLocation::from_bytes(module, 0, 50)),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,
            evidence: None,
        }
    }

    // --- SimTxBuilder tests ---

    #[test]
    fn test_builder_default_produces_empty_tx() {
        let tx = SimTxBuilder::new().build();
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
        assert!(tx.signatories.is_empty());
        assert!(tx.validity_range.start.is_none());
        assert!(tx.validity_range.end.is_none());
        assert!(tx.mint.is_empty());
        assert!(tx.datum.is_none());
    }

    #[test]
    fn test_builder_add_input() {
        let tx = SimTxBuilder::new()
            .add_input(SimInput {
                tx_hash: "abc".to_string(),
                output_index: 0,
                address: "addr_test1".to_string(),
                value: SimValue::lovelace_only(5_000_000),
                datum: None,
            })
            .build();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].tx_hash, "abc");
        assert_eq!(tx.inputs[0].value.lovelace, 5_000_000);
    }

    #[test]
    fn test_builder_add_output() {
        let tx = SimTxBuilder::new()
            .add_output(SimOutput {
                address: "addr_test1_recipient".to_string(),
                value: SimValue::lovelace_only(3_000_000),
                datum: Some(SimPlutusData::Integer(42)),
            })
            .build();
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].address, "addr_test1_recipient");
        assert!(tx.outputs[0].datum.is_some());
    }

    #[test]
    fn test_builder_add_signatory() {
        let tx = SimTxBuilder::new()
            .add_signatory("deadbeef1234")
            .add_signatory("cafebabe5678")
            .build();
        assert_eq!(tx.signatories.len(), 2);
        assert_eq!(tx.signatories[0], "deadbeef1234");
        assert_eq!(tx.signatories[1], "cafebabe5678");
    }

    #[test]
    fn test_builder_set_validity_range() {
        let tx = SimTxBuilder::new()
            .set_validity_range(Some(1000), Some(2000))
            .build();
        assert_eq!(tx.validity_range.start, Some(1000));
        assert_eq!(tx.validity_range.end, Some(2000));
    }

    #[test]
    fn test_builder_set_mint() {
        let tx = SimTxBuilder::new()
            .set_mint("policy_abc", "token_x", 100)
            .set_mint("policy_abc", "token_y", -50)
            .set_mint("policy_def", "token_z", 1)
            .build();
        assert_eq!(tx.mint.len(), 2);
        assert_eq!(tx.mint["policy_abc"]["token_x"], 100);
        assert_eq!(tx.mint["policy_abc"]["token_y"], -50);
        assert_eq!(tx.mint["policy_def"]["token_z"], 1);
    }

    #[test]
    fn test_builder_set_redeemer() {
        let tx = SimTxBuilder::new()
            .set_redeemer(SimPlutusData::constr(1, vec![SimPlutusData::Integer(42)]))
            .build();
        match tx.redeemer {
            SimPlutusData::Constructor { tag, ref fields } => {
                assert_eq!(tag, 1);
                assert_eq!(fields.len(), 1);
            }
            _ => panic!("Expected Constructor redeemer"),
        }
    }

    #[test]
    fn test_builder_set_datum() {
        let tx = SimTxBuilder::new()
            .set_datum(SimPlutusData::Integer(99))
            .build();
        assert!(tx.datum.is_some());
        match tx.datum.unwrap() {
            SimPlutusData::Integer(v) => assert_eq!(v, 99),
            _ => panic!("Expected Integer datum"),
        }
    }

    #[test]
    fn test_builder_full_chain() {
        let tx = SimTxBuilder::new()
            .add_input(SimInput {
                tx_hash: "tx1".to_string(),
                output_index: 0,
                address: "addr1".to_string(),
                value: SimValue::lovelace_only(10_000_000),
                datum: None,
            })
            .add_output(SimOutput {
                address: "addr2".to_string(),
                value: SimValue::lovelace_only(10_000_000),
                datum: None,
            })
            .add_signatory("pkh1")
            .set_validity_range(Some(100), Some(200))
            .set_mint("policy", "token", 1)
            .set_redeemer(SimPlutusData::Integer(0))
            .set_datum(SimPlutusData::ByteString(vec![1, 2, 3]))
            .build();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.signatories.len(), 1);
        assert_eq!(tx.validity_range.start, Some(100));
        assert!(!tx.mint.is_empty());
        assert!(tx.datum.is_some());
    }

    // --- SimPlutusData tests ---

    #[test]
    fn test_plutus_data_unit_constructor() {
        let data = SimPlutusData::unit_constructor();
        match data {
            SimPlutusData::Constructor { tag, fields } => {
                assert_eq!(tag, 0);
                assert!(fields.is_empty());
            }
            _ => panic!("Expected Constructor"),
        }
    }

    #[test]
    fn test_plutus_data_constr() {
        let data = SimPlutusData::constr(
            3,
            vec![
                SimPlutusData::Integer(1),
                SimPlutusData::ByteString(vec![0xff]),
            ],
        );
        match data {
            SimPlutusData::Constructor { tag, fields } => {
                assert_eq!(tag, 3);
                assert_eq!(fields.len(), 2);
            }
            _ => panic!("Expected Constructor"),
        }
    }

    #[test]
    fn test_plutus_data_from_hex() {
        let data = SimPlutusData::from_hex("deadbeef");
        match data {
            SimPlutusData::ByteString(bytes) => {
                assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            _ => panic!("Expected ByteString"),
        }
    }

    #[test]
    fn test_plutus_data_list() {
        let data = SimPlutusData::List(vec![
            SimPlutusData::Integer(1),
            SimPlutusData::Integer(2),
            SimPlutusData::Integer(3),
        ]);
        match data {
            SimPlutusData::List(items) => assert_eq!(items.len(), 3),
            _ => panic!("Expected List"),
        }
    }

    #[test]
    fn test_plutus_data_map() {
        let data = SimPlutusData::Map(vec![(
            SimPlutusData::ByteString(b"key".to_vec()),
            SimPlutusData::Integer(42),
        )]);
        match data {
            SimPlutusData::Map(pairs) => {
                assert_eq!(pairs.len(), 1);
            }
            _ => panic!("Expected Map"),
        }
    }

    // --- SimValue tests ---

    #[test]
    fn test_sim_value_lovelace_only() {
        let v = SimValue::lovelace_only(2_000_000);
        assert_eq!(v.lovelace, 2_000_000);
        assert!(v.native_assets.is_empty());
    }

    #[test]
    fn test_sim_value_with_asset() {
        let v = SimValue::with_asset(5_000_000, "policy_abc", "MyToken", 100);
        assert_eq!(v.lovelace, 5_000_000);
        assert_eq!(v.native_assets["policy_abc"]["MyToken"], 100);
    }

    // --- SimValidityRange tests ---

    #[test]
    fn test_validity_range_unbounded() {
        let r = SimValidityRange::unbounded();
        assert!(r.start.is_none());
        assert!(r.end.is_none());
    }

    #[test]
    fn test_validity_range_finite() {
        let r = SimValidityRange::finite(1000, 2000);
        assert_eq!(r.start, Some(1000));
        assert_eq!(r.end, Some(2000));
    }

    // --- SimulationResult tests ---

    #[test]
    fn test_simulation_result_accepted() {
        let result = SimulationResult::Accepted {
            cpu_units: 1_000_000,
            mem_units: 50_000,
            trace: vec![],
        };
        assert!(result.is_accepted());
        assert!(!result.is_rejected());
        assert!(!result.is_not_available());
    }

    #[test]
    fn test_simulation_result_rejected() {
        let result = SimulationResult::Rejected {
            error: "validator returned False".to_string(),
            trace: vec![],
        };
        assert!(!result.is_accepted());
        assert!(result.is_rejected());
        assert!(!result.is_not_available());
    }

    #[test]
    fn test_simulation_result_not_available() {
        let result = SimulationResult::NotAvailable {
            reason: "No compiled code found".to_string(),
        };
        assert!(!result.is_accepted());
        assert!(!result.is_rejected());
        assert!(result.is_not_available());
    }

    // --- Exploit scenario generation tests ---

    #[test]
    fn test_generate_missing_signature_scenario() {
        let finding = make_finding("missing-signature-check", "validators/treasury.ak");
        let scenario = generate_exploit_scenario(&finding).expect("should generate scenario");

        assert_eq!(scenario.finding_detector, "missing-signature-check");
        assert!(scenario.description.contains("treasury.ak"));
        assert!(!scenario.attack_steps.is_empty());
        assert!(scenario.simulated_tx.is_some());
        assert!(matches!(
            scenario.expected_result,
            ExpectedResult::ValidatorAccepts
        ));

        // The exploit TX should NOT have signatories (that's the exploit)
        let tx = scenario.simulated_tx.as_ref().unwrap();
        assert!(tx.signatories.is_empty());
        assert!(!tx.inputs.is_empty());
        assert!(!tx.outputs.is_empty());
    }

    #[test]
    fn test_generate_unrestricted_minting_scenario() {
        let finding = make_finding("unrestricted-minting", "validators/mint.ak");
        let scenario = generate_exploit_scenario(&finding).expect("should generate scenario");

        assert_eq!(scenario.finding_detector, "unrestricted-minting");
        assert!(scenario.description.contains("mint.ak"));
        assert!(scenario.simulated_tx.is_some());
        assert!(matches!(
            scenario.expected_result,
            ExpectedResult::ValidatorAccepts
        ));

        // The exploit TX should have a mint field
        let tx = scenario.simulated_tx.as_ref().unwrap();
        assert!(!tx.mint.is_empty());
    }

    #[test]
    fn test_generate_double_satisfaction_scenario() {
        let finding = make_finding("double-satisfaction", "validators/swap.ak");
        let scenario = generate_exploit_scenario(&finding).expect("should generate scenario");

        assert_eq!(scenario.finding_detector, "double-satisfaction");
        assert!(scenario.description.contains("swap.ak"));
        assert!(scenario.simulated_tx.is_some());
        assert!(matches!(
            scenario.expected_result,
            ExpectedResult::ValidatorAccepts
        ));

        // The exploit TX should have two inputs but only two outputs (one goes to attacker)
        let tx = scenario.simulated_tx.as_ref().unwrap();
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
    }

    #[test]
    fn test_generate_missing_redeemer_validation_scenario() {
        let finding = make_finding("missing-redeemer-validation", "validators/lend.ak");
        let scenario = generate_exploit_scenario(&finding).expect("should generate scenario");

        assert_eq!(scenario.finding_detector, "missing-redeemer-validation");
        assert!(scenario.description.contains("lend.ak"));
        assert!(scenario.simulated_tx.is_some());

        // The exploit TX should have a garbage redeemer (tag 999)
        let tx = scenario.simulated_tx.as_ref().unwrap();
        match &tx.redeemer {
            SimPlutusData::Constructor { tag, .. } => assert_eq!(*tag, 999),
            _ => panic!("Expected garbage constructor redeemer"),
        }
    }

    #[test]
    fn test_generate_missing_validity_range_scenario() {
        let finding = make_finding("missing-validity-range", "validators/escrow.ak");
        let scenario = generate_exploit_scenario(&finding).expect("should generate scenario");

        assert_eq!(scenario.finding_detector, "missing-validity-range");
        assert!(scenario.simulated_tx.is_some());

        let tx = scenario.simulated_tx.as_ref().unwrap();
        assert!(tx.validity_range.start.is_none());
        assert!(tx.validity_range.end.is_none());
    }

    #[test]
    fn test_generate_missing_datum_in_output_scenario() {
        let finding = make_finding("missing-datum-in-script-output", "validators/pool.ak");
        let scenario = generate_exploit_scenario(&finding).expect("should generate scenario");

        assert_eq!(scenario.finding_detector, "missing-datum-in-script-output");
        assert!(scenario.simulated_tx.is_some());

        // The exploit TX output to the script should have no datum
        let tx = scenario.simulated_tx.as_ref().unwrap();
        assert!(tx.outputs[0].datum.is_none());
    }

    #[test]
    fn test_generate_unknown_detector_returns_none() {
        let finding = make_finding("some-unknown-detector", "validators/test.ak");
        assert!(generate_exploit_scenario(&finding).is_none());
    }

    // --- Simulation to evidence tests ---

    #[test]
    fn test_simulation_to_evidence_accepted() {
        let result = SimulationResult::Accepted {
            cpu_units: 5_000_000,
            mem_units: 200_000,
            trace: vec![SimTraceStep {
                step: 1,
                description: "Entered validator".to_string(),
                kind: TraceStepKind::FunctionEntry("spend".to_string()),
            }],
        };
        let scenario = ExploitScenario {
            finding_detector: "missing-signature-check".to_string(),
            description: "Test scenario".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::ValidatorAccepts,
        };

        let evidence = simulation_to_evidence(&result, &scenario).expect("should produce evidence");
        assert_eq!(evidence.level, EvidenceLevel::SimulationConfirmed);
        assert_eq!(evidence.method, "tx-simulation");
        assert_eq!(evidence.confidence_boost, 0.8);
        assert!(evidence.details.as_ref().unwrap().contains("5000000"));
        assert!(evidence.witness.is_some());
    }

    #[test]
    fn test_simulation_to_evidence_rejected() {
        let result = SimulationResult::Rejected {
            error: "validator returned False".to_string(),
            trace: vec![],
        };
        let scenario = ExploitScenario {
            finding_detector: "unrestricted-minting".to_string(),
            description: "Test scenario".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::ValidatorAccepts,
        };

        let evidence = simulation_to_evidence(&result, &scenario).expect("should produce evidence");
        assert_eq!(evidence.level, EvidenceLevel::PatternMatch);
        assert_eq!(evidence.method, "tx-simulation-rejected");
        assert_eq!(evidence.confidence_boost, -0.3);
        assert!(evidence
            .details
            .as_ref()
            .unwrap()
            .contains("false positive"));
    }

    #[test]
    fn test_simulation_to_evidence_not_available() {
        let result = SimulationResult::NotAvailable {
            reason: "No compiled code".to_string(),
        };
        let scenario = ExploitScenario {
            finding_detector: "test".to_string(),
            description: "Test".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::Unknown,
        };

        assert!(simulation_to_evidence(&result, &scenario).is_none());
    }

    // --- Format function tests ---

    #[test]
    fn test_format_exploit_scenario() {
        let scenario = ExploitScenario {
            finding_detector: "missing-signature-check".to_string(),
            description: "Funds can be drained without authorization.".to_string(),
            attack_steps: vec![
                AttackStep {
                    step: 1,
                    action: "Find script UTxO".to_string(),
                    rationale: "Locate target funds".to_string(),
                },
                AttackStep {
                    step: 2,
                    action: "Spend without signature".to_string(),
                    rationale: "No auth check".to_string(),
                },
            ],
            simulated_tx: Some(
                SimTxBuilder::new()
                    .add_input(SimInput {
                        tx_hash: "aaa".to_string(),
                        output_index: 0,
                        address: "addr1".to_string(),
                        value: SimValue::lovelace_only(10_000_000),
                        datum: None,
                    })
                    .add_output(SimOutput {
                        address: "addr2".to_string(),
                        value: SimValue::lovelace_only(10_000_000),
                        datum: None,
                    })
                    .build(),
            ),
            expected_result: ExpectedResult::ValidatorAccepts,
        };

        let formatted = format_exploit_scenario(&scenario);
        assert!(formatted.contains("Detector: missing-signature-check"));
        assert!(formatted.contains("EXPLOITABLE"));
        assert!(formatted.contains("Attack Steps:"));
        assert!(formatted.contains("1. Find script UTxO"));
        assert!(formatted.contains("Simulated Transaction:"));
        assert!(formatted.contains("Inputs:      1"));
        assert!(formatted.contains("Outputs:     1"));
        assert!(formatted.contains("10.000000"));
    }

    #[test]
    fn test_format_simulation_report_empty() {
        let report = format_simulation_report(&[]);
        assert_eq!(report, "No exploit scenarios generated.");
    }

    #[test]
    fn test_format_simulation_report_multiple() {
        let scenarios = vec![
            ExploitScenario {
                finding_detector: "missing-signature-check".to_string(),
                description: "Exploit 1".to_string(),
                attack_steps: vec![],
                simulated_tx: None,
                expected_result: ExpectedResult::ValidatorAccepts,
            },
            ExploitScenario {
                finding_detector: "unrestricted-minting".to_string(),
                description: "Exploit 2".to_string(),
                attack_steps: vec![],
                simulated_tx: None,
                expected_result: ExpectedResult::ValidatorRejects,
            },
            ExploitScenario {
                finding_detector: "double-satisfaction".to_string(),
                description: "Exploit 3".to_string(),
                attack_steps: vec![],
                simulated_tx: None,
                expected_result: ExpectedResult::Unknown,
            },
        ];

        let report = format_simulation_report(&scenarios);
        assert!(report.contains("TRANSACTION SIMULATION REPORT (3 scenarios)"));
        assert!(report.contains("missing-signature-check"));
        assert!(report.contains("unrestricted-minting"));
        assert!(report.contains("double-satisfaction"));
        assert!(report.contains("1 exploitable, 1 rejected, 1 unknown"));
    }

    #[test]
    fn test_format_validity_range_unbounded() {
        let range = SimValidityRange::unbounded();
        let formatted = format_validity_range(&range);
        assert_eq!(formatted, "unbounded (always valid)");
    }

    #[test]
    fn test_format_validity_range_finite() {
        let range = SimValidityRange::finite(1000, 2000);
        let formatted = format_validity_range(&range);
        assert_eq!(formatted, "1000 to 2000");
    }

    #[test]
    fn test_format_validity_range_start_only() {
        let range = SimValidityRange {
            start: Some(1000),
            end: None,
        };
        let formatted = format_validity_range(&range);
        assert_eq!(formatted, "from 1000 (no upper bound)");
    }

    #[test]
    fn test_format_validity_range_end_only() {
        let range = SimValidityRange {
            start: None,
            end: Some(2000),
        };
        let formatted = format_validity_range(&range);
        assert_eq!(formatted, "until 2000 (no lower bound)");
    }

    #[test]
    fn test_format_expected_result_display() {
        let scenario_accept = ExploitScenario {
            finding_detector: "test".to_string(),
            description: "test".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::ValidatorAccepts,
        };
        let formatted = format_exploit_scenario(&scenario_accept);
        assert!(formatted.contains("EXPLOITABLE (validator accepts)"));

        let scenario_reject = ExploitScenario {
            finding_detector: "test".to_string(),
            description: "test".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::ValidatorRejects,
        };
        let formatted = format_exploit_scenario(&scenario_reject);
        assert!(formatted.contains("NOT EXPLOITABLE (validator rejects)"));

        let scenario_unknown = ExploitScenario {
            finding_detector: "test".to_string(),
            description: "test".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::Unknown,
        };
        let formatted = format_exploit_scenario(&scenario_unknown);
        assert!(formatted.contains("UNKNOWN (simulation required)"));
    }

    // --- Serialization tests ---

    #[test]
    fn test_simulated_tx_serializes() {
        let tx = SimTxBuilder::new()
            .add_input(SimInput {
                tx_hash: "abc123".to_string(),
                output_index: 0,
                address: "addr_test1".to_string(),
                value: SimValue::lovelace_only(5_000_000),
                datum: Some(SimPlutusData::Integer(1)),
            })
            .add_output(SimOutput {
                address: "addr_test2".to_string(),
                value: SimValue::lovelace_only(5_000_000),
                datum: None,
            })
            .set_redeemer(SimPlutusData::constr(0, vec![]))
            .build();

        let json = serde_json::to_string(&tx).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");
        assert!(parsed["inputs"].is_array());
        assert!(parsed["outputs"].is_array());
        assert!(parsed["mint"].is_object());
    }

    #[test]
    fn test_simulation_result_serializes() {
        let result = SimulationResult::Accepted {
            cpu_units: 1_000,
            mem_units: 500,
            trace: vec![SimTraceStep {
                step: 1,
                description: "test step".to_string(),
                kind: TraceStepKind::FunctionEntry("main".to_string()),
            }],
        };
        let json = serde_json::to_string(&result).expect("should serialize");
        assert!(json.contains("Accepted"));
        assert!(json.contains("1000"));
    }

    #[test]
    fn test_exploit_scenario_serializes() {
        let scenario = ExploitScenario {
            finding_detector: "test-detector".to_string(),
            description: "test desc".to_string(),
            attack_steps: vec![AttackStep {
                step: 1,
                action: "do something".to_string(),
                rationale: "because".to_string(),
            }],
            simulated_tx: None,
            expected_result: ExpectedResult::Unknown,
        };
        let json = serde_json::to_string(&scenario).expect("should serialize");
        assert!(json.contains("test-detector"));
        assert!(json.contains("Unknown"));
    }

    // --- Edge case tests ---

    #[test]
    fn test_builder_default_trait() {
        let builder: SimTxBuilder = Default::default();
        let tx = builder.build();
        assert!(tx.inputs.is_empty());
    }

    #[test]
    fn test_plutus_data_from_hex_empty() {
        let data = SimPlutusData::from_hex("");
        match data {
            SimPlutusData::ByteString(bytes) => assert!(bytes.is_empty()),
            _ => panic!("Expected empty ByteString"),
        }
    }

    #[test]
    fn test_attack_step_ordering() {
        let finding = make_finding("missing-signature-check", "validators/test.ak");
        let scenario = generate_exploit_scenario(&finding).unwrap();
        for (i, step) in scenario.attack_steps.iter().enumerate() {
            assert_eq!(step.step, i + 1, "Attack steps should be 1-indexed");
        }
    }

    #[test]
    fn test_exploit_scenario_has_consistent_detector_name() {
        let detectors = [
            "missing-signature-check",
            "unrestricted-minting",
            "double-satisfaction",
            "missing-redeemer-validation",
            "missing-validity-range",
            "missing-datum-in-script-output",
        ];

        for detector in detectors {
            let finding = make_finding(detector, "validators/test.ak");
            let scenario = generate_exploit_scenario(&finding).unwrap();
            assert_eq!(
                scenario.finding_detector, detector,
                "Scenario detector should match input finding"
            );
        }
    }

    #[test]
    fn test_trace_step_kinds() {
        // Ensure all TraceStepKind variants can be constructed and serialized
        let steps = vec![
            SimTraceStep {
                step: 1,
                description: "enter".to_string(),
                kind: TraceStepKind::FunctionEntry("validate".to_string()),
            },
            SimTraceStep {
                step: 2,
                description: "bind".to_string(),
                kind: TraceStepKind::VariableBinding {
                    name: "x".to_string(),
                    value: "42".to_string(),
                },
            },
            SimTraceStep {
                step: 3,
                description: "branch".to_string(),
                kind: TraceStepKind::BranchTaken {
                    condition: "x > 0".to_string(),
                    result: true,
                },
            },
            SimTraceStep {
                step: 4,
                description: "compare".to_string(),
                kind: TraceStepKind::Comparison {
                    left: "x".to_string(),
                    op: "==".to_string(),
                    right: "42".to_string(),
                    result: true,
                },
            },
            SimTraceStep {
                step: 5,
                description: "return".to_string(),
                kind: TraceStepKind::Return("True".to_string()),
            },
            SimTraceStep {
                step: 6,
                description: "error".to_string(),
                kind: TraceStepKind::Error("validator failed".to_string()),
            },
        ];

        for step in &steps {
            let json = serde_json::to_string(step).expect("should serialize");
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_context_builder_override_uses_external_context() {
        let finding = make_finding("missing-signature-check", "validators/test.ak");
        let scenario = ExploitScenario {
            finding_detector: "missing-signature-check".to_string(),
            description: "test".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::Unknown,
        };
        let tx = SimTxBuilder::new().add_signatory("abc").build();
        let cmd = "printf '%s' '{\"context\":{\"type\":\"constructor\",\"tag\":0,\"fields\":[{\"type\":\"list\",\"values\":[]},{\"type\":\"list\",\"values\":[]},{\"type\":\"list\",\"values\":[{\"type\":\"byte_string\",\"hex\":\"deadbeef\"}]},{\"type\":\"list\",\"values\":[]},{\"type\":\"map\",\"entries\":[]},{\"type\":\"constructor\",\"tag\":0,\"fields\":[{\"type\":\"integer\",\"value\":10},{\"type\":\"integer\",\"value\":20}]}]}}'";

        let actual =
            build_context_data_with_override(&tx, Some(cmd), &finding, &scenario, Path::new("."));
        let expected = Data::constr(
            0,
            vec![
                Data::list(vec![]),
                Data::list(vec![]),
                Data::list(vec![Data::bytestring(vec![0xde, 0xad, 0xbe, 0xef])]),
                Data::list(vec![]),
                Data::map(vec![]),
                Data::constr(0, vec![Data::integer(10.into()), Data::integer(20.into())]),
            ],
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_context_builder_override_falls_back_on_invalid_json() {
        let finding = make_finding("missing-signature-check", "validators/test.ak");
        let scenario = ExploitScenario {
            finding_detector: "missing-signature-check".to_string(),
            description: "test".to_string(),
            attack_steps: vec![],
            simulated_tx: None,
            expected_result: ExpectedResult::Unknown,
        };
        let tx = SimTxBuilder::new().add_signatory("deadbeef").build();
        let fallback = build_context_data(&tx);
        let actual = build_context_data_with_override(
            &tx,
            Some("printf '%s' 'not-json'"),
            &finding,
            &scenario,
            Path::new("."),
        );
        assert_eq!(actual, fallback);
    }
}
