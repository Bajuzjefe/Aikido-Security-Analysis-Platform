//! Grammar-aware fuzzing framework for Cardano transactions.
//!
//! Provides Cardano-specific type generators, transaction template fuzzing,
//! stateful protocol fuzzing (Echidna-style), and reporting utilities.
//! The actual UPLC execution integration comes later; this module defines
//! the complete types and generators.

use serde::Serialize;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64* — no external rand dependency)
// ---------------------------------------------------------------------------

/// Simple deterministic PRNG so the module has no dependency on `rand`.
/// Seeded from [`FuzzCampaign::seed`] for reproducibility.
#[derive(Debug, Clone)]
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid zero-state (xorshift fixpoint)
        Self {
            state: if seed == 0 {
                0xDEAD_BEEF_CAFE_1234
            } else {
                seed
            },
        }
    }

    /// xorshift64* step — returns a pseudo-random u64.
    fn next_u64(&mut self) -> u64 {
        let mut s = self.state;
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        self.state = s;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform u64 in `[lo, hi)`.
    fn range_u64(&mut self, lo: u64, hi: u64) -> u64 {
        if lo >= hi {
            return lo;
        }
        lo + self.next_u64() % (hi - lo)
    }

    /// Uniform usize in `[lo, hi)`.
    fn range_usize(&mut self, lo: usize, hi: usize) -> usize {
        self.range_u64(lo as u64, hi as u64) as usize
    }

    /// Generate a random hex string of `byte_len` bytes (2 * byte_len hex chars).
    fn hex_bytes(&mut self, byte_len: usize) -> String {
        let mut out = String::with_capacity(byte_len * 2);
        let mut remaining = byte_len;
        while remaining > 0 {
            let val = self.next_u64();
            let take = remaining.min(8);
            for i in 0..take {
                let byte = ((val >> (i * 8)) & 0xFF) as u8;
                out.push_str(&format!("{byte:02x}"));
            }
            remaining -= take;
        }
        out
    }

    /// Pick a random element from a slice.
    /// Pick a random element from a non-empty slice.
    /// Will be used by UPLC execution integration.
    #[allow(dead_code)]
    fn choose<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let idx = self.range_usize(0, items.len());
        &items[idx]
    }

    /// Fair coin flip.
    /// Will be used by UPLC execution integration.
    #[allow(dead_code)]
    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }
}

// ---------------------------------------------------------------------------
// Cardano constraints
// ---------------------------------------------------------------------------

/// Cardano-specific generation constraints.
#[derive(Debug, Clone, Serialize)]
pub struct CardanoConstraints {
    /// Minimum ADA per UTxO (usually 1_000_000 lovelace = 1 ADA).
    pub min_lovelace: u64,
    /// Maximum ADA per output.
    pub max_lovelace: u64,
    /// Maximum number of native assets in a single output.
    pub max_assets_per_output: usize,
    /// Maximum transaction inputs.
    pub max_inputs: usize,
    /// Maximum transaction outputs.
    pub max_outputs: usize,
    /// Maximum extra signatories.
    pub max_signatories: usize,
    /// Public-key hash length in bytes (28).
    pub pkh_length: usize,
    /// Transaction hash length in bytes (32).
    pub tx_hash_length: usize,
    /// Minting policy ID length in bytes (28).
    pub policy_id_length: usize,
}

impl Default for CardanoConstraints {
    fn default() -> Self {
        Self {
            min_lovelace: 1_000_000,
            max_lovelace: 1_000_000_000_000, // 1M ADA
            max_assets_per_output: 10,
            max_inputs: 20,
            max_outputs: 20,
            max_signatories: 5,
            pkh_length: 28,
            tx_hash_length: 32,
            policy_id_length: 28,
        }
    }
}

// ---------------------------------------------------------------------------
// Cardano-aware random generators
// ---------------------------------------------------------------------------

/// Generate a random 28-byte public-key hash as a hex string.
pub fn random_pkh() -> String {
    random_pkh_seeded(now_seed())
}

/// Seeded variant of [`random_pkh`].
pub fn random_pkh_seeded(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    rng.hex_bytes(CardanoConstraints::default().pkh_length)
}

/// Generate a random 32-byte transaction hash as a hex string.
pub fn random_tx_hash() -> String {
    random_tx_hash_seeded(now_seed())
}

/// Seeded variant of [`random_tx_hash`].
pub fn random_tx_hash_seeded(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    rng.hex_bytes(CardanoConstraints::default().tx_hash_length)
}

/// Generate a random 28-byte policy ID as a hex string.
pub fn random_policy_id() -> String {
    random_policy_id_seeded(now_seed())
}

/// Seeded variant of [`random_policy_id`].
pub fn random_policy_id_seeded(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    rng.hex_bytes(CardanoConstraints::default().policy_id_length)
}

/// Generate a random lovelace amount within `constraints`.
pub fn random_lovelace(constraints: &CardanoConstraints) -> u64 {
    random_lovelace_seeded(constraints, now_seed())
}

/// Seeded variant of [`random_lovelace`].
pub fn random_lovelace_seeded(constraints: &CardanoConstraints, seed: u64) -> u64 {
    let mut rng = Rng::new(seed);
    rng.range_u64(constraints.min_lovelace, constraints.max_lovelace)
}

/// Generate a random human-readable asset name (4-12 lowercase ASCII chars).
pub fn random_asset_name() -> String {
    random_asset_name_seeded(now_seed())
}

/// Seeded variant of [`random_asset_name`].
pub fn random_asset_name_seeded(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    let len = rng.range_usize(4, 13);
    (0..len)
        .map(|_| (b'a' + (rng.next_u64() % 26) as u8) as char)
        .collect()
}

/// Derive a unique-ish seed from a counter. Only used by the unseeded public
/// API so callers that don't care about reproducibility get distinct values.
fn now_seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0xCAFE_0001);
    CTR.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Fuzz campaign types
// ---------------------------------------------------------------------------

/// A fuzz campaign configuration.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzCampaign {
    pub name: String,
    pub target_validator: String,
    pub target_handler: String,
    pub constraints: CardanoConstraints,
    pub seed: u64,
    pub max_iterations: usize,
    pub timeout_ms: u64,
    pub strategy: FuzzStrategy,
}

/// The fuzzing strategy to use.
#[derive(Debug, Clone, Serialize)]
pub enum FuzzStrategy {
    /// Fully random transaction generation.
    Random,
    /// Mutation-based: start from a template and mutate.
    Mutation { template: FuzzTemplate },
    /// Stateful: generate sequences of transactions (Echidna-style).
    Stateful { max_steps: usize },
}

/// A template transaction to mutate.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzTemplate {
    pub description: String,
    pub base_inputs: usize,
    pub base_outputs: usize,
    pub has_mint: bool,
    pub has_signatories: bool,
    pub has_validity_range: bool,
}

/// Result of a fuzz campaign.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzResult {
    pub campaign_name: String,
    pub iterations_run: usize,
    pub crashes: Vec<FuzzCrash>,
    pub coverage_estimate: f64,
    pub duration_ms: u64,
}

/// A crash/finding from fuzzing.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzCrash {
    pub iteration: usize,
    pub description: String,
    pub crash_type: CrashType,
    pub minimized_input: Option<String>,
}

/// Classification of a fuzz crash.
#[derive(Debug, Clone, Serialize)]
pub enum CrashType {
    /// Validator accepted a malicious transaction.
    UnexpectedAccept,
    /// Validator panicked/errored unexpectedly.
    UnexpectedError(String),
    /// Invariant violation detected.
    InvariantViolation(String),
    /// Budget exceeded.
    BudgetExceeded { cpu: u64, mem: u64 },
}

// ---------------------------------------------------------------------------
// Stateful protocol fuzzing (Echidna-style)
// ---------------------------------------------------------------------------

/// State machine for protocol fuzzing.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolState {
    pub utxos: Vec<FuzzUtxo>,
    pub step: usize,
    pub history: Vec<FuzzAction>,
}

impl ProtocolState {
    /// Create an empty initial state.
    pub fn new() -> Self {
        Self {
            utxos: Vec::new(),
            step: 0,
            history: Vec::new(),
        }
    }

    /// Total lovelace across all UTxOs.
    pub fn total_value(&self) -> u64 {
        self.utxos.iter().map(|u| u.value_lovelace).sum()
    }
}

impl Default for ProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

/// A UTxO in the fuzz state.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzUtxo {
    pub address: String,
    pub value_lovelace: u64,
    pub datum: Option<String>,
}

/// An action the protocol fuzzer can take.
#[derive(Debug, Clone, Serialize)]
pub enum FuzzAction {
    Deposit { amount: u64 },
    Withdraw { amount: u64 },
    Swap { input_amount: u64 },
    Mint { quantity: i64 },
    Burn { quantity: i64 },
    UpdateDatum,
    AddSignatory(String),
    SetValidityRange(u64, u64),
}

/// Generate a random sequence of protocol actions.
pub fn generate_action_sequence(max_steps: usize, seed: u64) -> Vec<FuzzAction> {
    let mut rng = Rng::new(seed);
    let count = rng.range_usize(1, max_steps.max(2));
    (0..count).map(|_| random_action(&mut rng)).collect()
}

fn random_action(rng: &mut Rng) -> FuzzAction {
    let variant = rng.range_usize(0, 8);
    match variant {
        0 => FuzzAction::Deposit {
            amount: rng.range_u64(1_000_000, 100_000_000_000),
        },
        1 => FuzzAction::Withdraw {
            amount: rng.range_u64(1_000_000, 100_000_000_000),
        },
        2 => FuzzAction::Swap {
            input_amount: rng.range_u64(1_000_000, 50_000_000_000),
        },
        3 => FuzzAction::Mint {
            quantity: rng.range_u64(1, 1_000_000) as i64,
        },
        4 => FuzzAction::Burn {
            quantity: -(rng.range_u64(1, 1_000_000) as i64),
        },
        5 => FuzzAction::UpdateDatum,
        6 => FuzzAction::AddSignatory(rng.hex_bytes(28)),
        _ => {
            let lo = rng.range_u64(0, 100_000);
            let hi = lo + rng.range_u64(1, 200_000);
            FuzzAction::SetValidityRange(lo, hi)
        }
    }
}

// ---------------------------------------------------------------------------
// State invariants
// ---------------------------------------------------------------------------

/// A protocol-state invariant.
#[derive(Clone)]
pub struct ProtocolStateInvariant {
    pub name: String,
    pub check: fn(&ProtocolState) -> bool,
    pub description: String,
}

impl std::fmt::Debug for ProtocolStateInvariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolStateInvariant")
            .field("name", &self.name)
            .field("description", &self.description)
            .finish()
    }
}

/// Check protocol invariants against current state.
/// Returns a list of violation descriptions (empty = all OK).
pub fn check_state_invariants(
    state: &ProtocolState,
    invariants: &[ProtocolStateInvariant],
) -> Vec<String> {
    invariants
        .iter()
        .filter(|inv| !(inv.check)(state))
        .map(|inv| format!("{}: {}", inv.name, inv.description))
        .collect()
}

/// Built-in protocol invariants.
pub fn default_protocol_invariants() -> Vec<ProtocolStateInvariant> {
    vec![
        ProtocolStateInvariant {
            name: "no-negative-values".to_string(),
            check: |state| state.utxos.iter().all(|u| u.value_lovelace > 0),
            description: "All UTxO values must be strictly positive".to_string(),
        },
        ProtocolStateInvariant {
            name: "minimum-ada".to_string(),
            check: |state| state.utxos.iter().all(|u| u.value_lovelace >= 1_000_000),
            description: "Every UTxO must hold at least 1 ADA (1_000_000 lovelace)".to_string(),
        },
        ProtocolStateInvariant {
            name: "value-conservation".to_string(),
            check: |state| {
                // Value must never exceed the sum of all deposits in history.
                let total_deposited: u64 = state
                    .history
                    .iter()
                    .filter_map(|a| match a {
                        FuzzAction::Deposit { amount } => Some(*amount),
                        _ => None,
                    })
                    .sum();
                state.total_value() <= total_deposited
            },
            description:
                "Total UTxO value must not exceed total deposited (no value from thin air)"
                    .to_string(),
        },
    ]
}

/// Apply a [`FuzzAction`] to the [`ProtocolState`], mutating it in place.
/// Returns `Ok(())` on success or `Err(description)` if the action is invalid
/// (e.g. withdrawing from an empty set of UTxOs).
pub fn apply_action(state: &mut ProtocolState, action: &FuzzAction) -> Result<(), String> {
    match action {
        FuzzAction::Deposit { amount } => {
            let mut rng = Rng::new(*amount ^ (state.step as u64));
            state.utxos.push(FuzzUtxo {
                address: rng.hex_bytes(28),
                value_lovelace: *amount,
                datum: None,
            });
        }
        FuzzAction::Withdraw { amount } => {
            if state.utxos.is_empty() {
                return Err("withdraw from empty UTxO set".to_string());
            }
            // Remove value from the first UTxO that has enough.
            let mut removed = false;
            for utxo in &mut state.utxos {
                if utxo.value_lovelace >= *amount {
                    utxo.value_lovelace -= amount;
                    removed = true;
                    break;
                }
            }
            if !removed {
                return Err(format!("no UTxO has enough lovelace to withdraw {amount}"));
            }
            // Remove zero-value UTxOs.
            state.utxos.retain(|u| u.value_lovelace > 0);
        }
        FuzzAction::Swap { input_amount } => {
            // Simplified: swap consumes one UTxO and produces another.
            if state.utxos.is_empty() {
                return Err("swap with no UTxOs".to_string());
            }
            let mut rng = Rng::new(*input_amount ^ (state.step as u64));
            state.utxos.push(FuzzUtxo {
                address: rng.hex_bytes(28),
                value_lovelace: *input_amount,
                datum: None,
            });
        }
        FuzzAction::Mint { quantity } => {
            if *quantity > 0 {
                let mut rng = Rng::new(*quantity as u64 ^ (state.step as u64));
                state.utxos.push(FuzzUtxo {
                    address: rng.hex_bytes(28),
                    value_lovelace: 1_500_000, // min ADA for token-bearing UTxO
                    datum: Some(format!("minted:{quantity}")),
                });
            }
        }
        FuzzAction::Burn { quantity } => {
            if *quantity < 0 {
                // Remove a token-bearing UTxO if any.
                if let Some(idx) = state
                    .utxos
                    .iter()
                    .position(|u| u.datum.as_deref().is_some_and(|d| d.starts_with("minted:")))
                {
                    state.utxos.remove(idx);
                }
            }
        }
        FuzzAction::UpdateDatum => {
            if let Some(utxo) = state.utxos.first_mut() {
                utxo.datum = Some(format!("updated_at_step_{}", state.step));
            }
        }
        FuzzAction::AddSignatory(_) | FuzzAction::SetValidityRange(_, _) => {
            // These don't modify UTxO state — they're tx-level metadata.
        }
    }

    state.step += 1;
    state.history.push(action.clone());
    Ok(())
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Format a detailed fuzz report from multiple campaign results.
pub fn format_fuzz_report(results: &[FuzzResult]) -> String {
    let mut out = String::new();

    out.push_str("=== Aikido Fuzz Report ===\n\n");

    for result in results {
        out.push_str(&format!(
            "Campaign: {}\n  Iterations: {}\n  Duration: {} ms\n  Coverage estimate: {:.1}%\n  Crashes: {}\n",
            result.campaign_name,
            result.iterations_run,
            result.duration_ms,
            result.coverage_estimate * 100.0,
            result.crashes.len(),
        ));

        for (i, crash) in result.crashes.iter().enumerate() {
            out.push_str(&format!(
                "  [{i}] iteration={}, type={}, desc=\"{}\"\n",
                crash.iteration,
                crash_type_label(&crash.crash_type),
                crash.description,
            ));
            if let Some(ref minimized) = crash.minimized_input {
                out.push_str(&format!("      minimized: {minimized}\n"));
            }
        }
        out.push('\n');
    }

    out
}

/// Format a compact summary of fuzz results.
pub fn format_fuzz_summary(results: &[FuzzResult]) -> String {
    let total_iterations: usize = results.iter().map(|r| r.iterations_run).sum();
    let total_crashes: usize = results.iter().map(|r| r.crashes.len()).sum();
    let total_duration: u64 = results.iter().map(|r| r.duration_ms).sum();

    let mut crash_counts: HashMap<&str, usize> = HashMap::new();
    for result in results {
        for crash in &result.crashes {
            let label = crash_type_label(&crash.crash_type);
            *crash_counts.entry(label).or_default() += 1;
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "Fuzz summary: {} campaigns, {} iterations, {} crashes, {} ms\n",
        results.len(),
        total_iterations,
        total_crashes,
        total_duration,
    ));
    if !crash_counts.is_empty() {
        out.push_str("Crash breakdown:\n");
        let mut sorted: Vec<_> = crash_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (label, count) in sorted {
            out.push_str(&format!("  {label}: {count}\n"));
        }
    }
    out
}

fn crash_type_label(ct: &CrashType) -> &'static str {
    match ct {
        CrashType::UnexpectedAccept => "unexpected-accept",
        CrashType::UnexpectedError(_) => "unexpected-error",
        CrashType::InvariantViolation(_) => "invariant-violation",
        CrashType::BudgetExceeded { .. } => "budget-exceeded",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- CardanoConstraints defaults ---

    #[test]
    fn default_constraints_are_sane() {
        let c = CardanoConstraints::default();
        assert_eq!(c.min_lovelace, 1_000_000);
        assert_eq!(c.max_lovelace, 1_000_000_000_000);
        assert_eq!(c.max_assets_per_output, 10);
        assert_eq!(c.max_inputs, 20);
        assert_eq!(c.max_outputs, 20);
        assert_eq!(c.max_signatories, 5);
        assert_eq!(c.pkh_length, 28);
        assert_eq!(c.tx_hash_length, 32);
        assert_eq!(c.policy_id_length, 28);
    }

    #[test]
    fn constraints_serialize_to_json() {
        let c = CardanoConstraints::default();
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["pkh_length"], 28);
        assert_eq!(json["tx_hash_length"], 32);
    }

    // --- Random generators produce valid-length values ---

    #[test]
    fn random_pkh_length() {
        let pkh = random_pkh_seeded(42);
        assert_eq!(pkh.len(), 56, "28 bytes = 56 hex chars");
        assert!(
            pkh.chars().all(|c| c.is_ascii_hexdigit()),
            "must be valid hex"
        );
    }

    #[test]
    fn random_tx_hash_length() {
        let h = random_tx_hash_seeded(42);
        assert_eq!(h.len(), 64, "32 bytes = 64 hex chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_policy_id_length() {
        let p = random_policy_id_seeded(42);
        assert_eq!(p.len(), 56, "28 bytes = 56 hex chars");
        assert!(p.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_lovelace_in_range() {
        let c = CardanoConstraints::default();
        for seed in 1..100 {
            let v = random_lovelace_seeded(&c, seed);
            assert!(v >= c.min_lovelace, "lovelace must be >= min");
            assert!(v < c.max_lovelace, "lovelace must be < max");
        }
    }

    #[test]
    fn random_asset_name_valid() {
        for seed in 1..50 {
            let name = random_asset_name_seeded(seed);
            assert!(name.len() >= 4 && name.len() <= 12);
            assert!(name.chars().all(|c| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn different_seeds_different_values() {
        let a = random_pkh_seeded(1);
        let b = random_pkh_seeded(2);
        assert_ne!(a, b, "different seeds should produce different pkhs");
    }

    #[test]
    fn same_seed_same_values() {
        let a = random_pkh_seeded(42);
        let b = random_pkh_seeded(42);
        assert_eq!(a, b, "same seed must reproduce identical values");
    }

    // --- FuzzTemplate creation ---

    #[test]
    fn fuzz_template_defaults() {
        let t = FuzzTemplate {
            description: "simple spend".to_string(),
            base_inputs: 1,
            base_outputs: 2,
            has_mint: false,
            has_signatories: true,
            has_validity_range: false,
        };
        assert_eq!(t.base_inputs, 1);
        assert_eq!(t.base_outputs, 2);
        assert!(!t.has_mint);
        assert!(t.has_signatories);
    }

    #[test]
    fn fuzz_template_serializes() {
        let t = FuzzTemplate {
            description: "mint test".to_string(),
            base_inputs: 2,
            base_outputs: 3,
            has_mint: true,
            has_signatories: false,
            has_validity_range: true,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["has_mint"], true);
        assert_eq!(json["base_inputs"], 2);
    }

    #[test]
    fn fuzz_campaign_serializes() {
        let campaign = FuzzCampaign {
            name: "test-campaign".to_string(),
            target_validator: "my_validator".to_string(),
            target_handler: "spend".to_string(),
            constraints: CardanoConstraints::default(),
            seed: 42,
            max_iterations: 1000,
            timeout_ms: 30_000,
            strategy: FuzzStrategy::Random,
        };
        let json = serde_json::to_string(&campaign).unwrap();
        assert!(json.contains("test-campaign"));
        assert!(json.contains("Random"));
    }

    #[test]
    fn fuzz_strategy_mutation_serializes() {
        let strategy = FuzzStrategy::Mutation {
            template: FuzzTemplate {
                description: "base".to_string(),
                base_inputs: 1,
                base_outputs: 1,
                has_mint: false,
                has_signatories: false,
                has_validity_range: false,
            },
        };
        let json = serde_json::to_value(&strategy).unwrap();
        assert!(json.get("Mutation").is_some());
    }

    #[test]
    fn fuzz_strategy_stateful_serializes() {
        let strategy = FuzzStrategy::Stateful { max_steps: 50 };
        let json = serde_json::to_value(&strategy).unwrap();
        assert!(json.get("Stateful").is_some());
        assert_eq!(json["Stateful"]["max_steps"], 50);
    }

    // --- Action sequence generation ---

    #[test]
    fn action_sequence_nonempty() {
        let actions = generate_action_sequence(10, 42);
        assert!(!actions.is_empty());
        assert!(actions.len() <= 10);
    }

    #[test]
    fn action_sequence_respects_max_steps() {
        for seed in 1..50 {
            let actions = generate_action_sequence(5, seed);
            assert!(actions.len() < 5, "must be strictly less than max_steps");
        }
    }

    #[test]
    fn action_sequence_deterministic() {
        let a = generate_action_sequence(20, 99);
        let b = generate_action_sequence(20, 99);
        assert_eq!(a.len(), b.len());
        // Serialized forms must match for determinism.
        let ja = serde_json::to_string(&a).unwrap();
        let jb = serde_json::to_string(&b).unwrap();
        assert_eq!(ja, jb);
    }

    #[test]
    fn action_sequence_covers_multiple_variants() {
        // With enough steps and seeds, we should see diverse action types.
        let mut seen = std::collections::HashSet::new();
        for seed in 0..200 {
            for action in generate_action_sequence(50, seed) {
                let label = match action {
                    FuzzAction::Deposit { .. } => "deposit",
                    FuzzAction::Withdraw { .. } => "withdraw",
                    FuzzAction::Swap { .. } => "swap",
                    FuzzAction::Mint { .. } => "mint",
                    FuzzAction::Burn { .. } => "burn",
                    FuzzAction::UpdateDatum => "update_datum",
                    FuzzAction::AddSignatory(_) => "add_signatory",
                    FuzzAction::SetValidityRange(_, _) => "set_validity_range",
                };
                seen.insert(label);
            }
        }
        assert!(
            seen.len() >= 6,
            "should see at least 6 of 8 action types, got {}",
            seen.len()
        );
    }

    // --- State invariant checking ---

    #[test]
    fn empty_state_passes_default_invariants() {
        let state = ProtocolState::new();
        let invariants = default_protocol_invariants();
        let violations = check_state_invariants(&state, &invariants);
        assert!(
            violations.is_empty(),
            "empty state should have no violations"
        );
    }

    #[test]
    fn deposit_then_no_violations() {
        let mut state = ProtocolState::new();
        apply_action(&mut state, &FuzzAction::Deposit { amount: 5_000_000 }).unwrap();
        let invariants = default_protocol_invariants();
        let violations = check_state_invariants(&state, &invariants);
        assert!(
            violations.is_empty(),
            "single deposit should not violate invariants"
        );
    }

    #[test]
    fn withdraw_from_empty_fails() {
        let mut state = ProtocolState::new();
        let result = apply_action(&mut state, &FuzzAction::Withdraw { amount: 1_000_000 });
        assert!(result.is_err());
    }

    #[test]
    fn zero_value_utxo_detected() {
        let state = ProtocolState {
            utxos: vec![FuzzUtxo {
                address: "deadbeef".to_string(),
                value_lovelace: 0,
                datum: None,
            }],
            step: 0,
            history: vec![],
        };
        let invariants = default_protocol_invariants();
        let violations = check_state_invariants(&state, &invariants);
        assert!(
            violations.iter().any(|v| v.contains("no-negative-values")),
            "zero-value UTxO should violate the positive-value invariant"
        );
    }

    #[test]
    fn sub_min_ada_detected() {
        let state = ProtocolState {
            utxos: vec![FuzzUtxo {
                address: "abc123".to_string(),
                value_lovelace: 500_000, // below 1 ADA
                datum: None,
            }],
            step: 0,
            history: vec![],
        };
        let invariants = default_protocol_invariants();
        let violations = check_state_invariants(&state, &invariants);
        assert!(
            violations.iter().any(|v| v.contains("minimum-ada")),
            "sub-min-ADA UTxO should violate the minimum-ada invariant"
        );
    }

    #[test]
    fn value_conservation_violated() {
        // Manually craft a state where value exceeds deposits.
        let state = ProtocolState {
            utxos: vec![FuzzUtxo {
                address: "abc".to_string(),
                value_lovelace: 100_000_000,
                datum: None,
            }],
            step: 1,
            history: vec![FuzzAction::Deposit { amount: 10_000_000 }],
        };
        let invariants = default_protocol_invariants();
        let violations = check_state_invariants(&state, &invariants);
        assert!(
            violations.iter().any(|v| v.contains("value-conservation")),
            "inflated value should violate conservation"
        );
    }

    #[test]
    fn custom_invariant_works() {
        let custom = ProtocolStateInvariant {
            name: "max-utxos".to_string(),
            check: |state| state.utxos.len() <= 2,
            description: "Protocol should never have more than 2 UTxOs".to_string(),
        };
        let state = ProtocolState {
            utxos: vec![
                FuzzUtxo {
                    address: "a".to_string(),
                    value_lovelace: 2_000_000,
                    datum: None,
                },
                FuzzUtxo {
                    address: "b".to_string(),
                    value_lovelace: 2_000_000,
                    datum: None,
                },
                FuzzUtxo {
                    address: "c".to_string(),
                    value_lovelace: 2_000_000,
                    datum: None,
                },
            ],
            step: 0,
            history: vec![],
        };
        let violations = check_state_invariants(&state, &[custom]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("max-utxos"));
    }

    // --- apply_action state transitions ---

    #[test]
    fn deposit_adds_utxo() {
        let mut state = ProtocolState::new();
        apply_action(&mut state, &FuzzAction::Deposit { amount: 3_000_000 }).unwrap();
        assert_eq!(state.utxos.len(), 1);
        assert_eq!(state.utxos[0].value_lovelace, 3_000_000);
        assert_eq!(state.step, 1);
        assert_eq!(state.history.len(), 1);
    }

    #[test]
    fn withdraw_reduces_value() {
        let mut state = ProtocolState::new();
        apply_action(&mut state, &FuzzAction::Deposit { amount: 10_000_000 }).unwrap();
        apply_action(&mut state, &FuzzAction::Withdraw { amount: 3_000_000 }).unwrap();
        assert_eq!(state.utxos[0].value_lovelace, 7_000_000);
    }

    #[test]
    fn mint_adds_token_utxo() {
        let mut state = ProtocolState::new();
        apply_action(&mut state, &FuzzAction::Mint { quantity: 100 }).unwrap();
        assert_eq!(state.utxos.len(), 1);
        assert!(state.utxos[0]
            .datum
            .as_ref()
            .unwrap()
            .starts_with("minted:"));
    }

    #[test]
    fn burn_removes_minted_utxo() {
        let mut state = ProtocolState::new();
        apply_action(&mut state, &FuzzAction::Mint { quantity: 50 }).unwrap();
        assert_eq!(state.utxos.len(), 1);
        apply_action(&mut state, &FuzzAction::Burn { quantity: -50 }).unwrap();
        assert!(state.utxos.is_empty());
    }

    #[test]
    fn update_datum_modifies_first_utxo() {
        let mut state = ProtocolState::new();
        apply_action(&mut state, &FuzzAction::Deposit { amount: 2_000_000 }).unwrap();
        assert!(state.utxos[0].datum.is_none());
        apply_action(&mut state, &FuzzAction::UpdateDatum).unwrap();
        assert!(state.utxos[0].datum.is_some());
        assert!(state.utxos[0]
            .datum
            .as_ref()
            .unwrap()
            .contains("updated_at_step_"));
    }

    #[test]
    fn signatory_and_validity_dont_change_utxos() {
        let mut state = ProtocolState::new();
        apply_action(&mut state, &FuzzAction::Deposit { amount: 5_000_000 }).unwrap();
        let utxo_count = state.utxos.len();
        let value = state.total_value();
        apply_action(&mut state, &FuzzAction::AddSignatory("abc".to_string())).unwrap();
        apply_action(&mut state, &FuzzAction::SetValidityRange(100, 200)).unwrap();
        assert_eq!(state.utxos.len(), utxo_count);
        assert_eq!(state.total_value(), value);
    }

    // --- FuzzResult / FuzzCrash types ---

    #[test]
    fn crash_types_serialize() {
        let crashes = vec![
            CrashType::UnexpectedAccept,
            CrashType::UnexpectedError("oops".to_string()),
            CrashType::InvariantViolation("bad".to_string()),
            CrashType::BudgetExceeded {
                cpu: 10_000_000,
                mem: 5_000,
            },
        ];
        for ct in &crashes {
            let json = serde_json::to_string(ct).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn fuzz_result_serializes() {
        let result = FuzzResult {
            campaign_name: "test".to_string(),
            iterations_run: 100,
            crashes: vec![FuzzCrash {
                iteration: 42,
                description: "bad accept".to_string(),
                crash_type: CrashType::UnexpectedAccept,
                minimized_input: Some("{\"inputs\": []}".to_string()),
            }],
            coverage_estimate: 0.75,
            duration_ms: 1234,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("bad accept"));
    }

    // --- Report formatting ---

    #[test]
    fn format_report_empty() {
        let report = format_fuzz_report(&[]);
        assert!(report.contains("Aikido Fuzz Report"));
    }

    #[test]
    fn format_report_with_crashes() {
        let results = vec![FuzzResult {
            campaign_name: "spend-fuzz".to_string(),
            iterations_run: 500,
            crashes: vec![
                FuzzCrash {
                    iteration: 10,
                    description: "accepted bad tx".to_string(),
                    crash_type: CrashType::UnexpectedAccept,
                    minimized_input: None,
                },
                FuzzCrash {
                    iteration: 42,
                    description: "budget boom".to_string(),
                    crash_type: CrashType::BudgetExceeded {
                        cpu: 999_999,
                        mem: 888,
                    },
                    minimized_input: Some("{\"min\": true}".to_string()),
                },
            ],
            coverage_estimate: 0.42,
            duration_ms: 2500,
        }];
        let report = format_fuzz_report(&results);
        assert!(report.contains("spend-fuzz"));
        assert!(report.contains("500"));
        assert!(report.contains("42.0%"));
        assert!(report.contains("Crashes: 2"));
        assert!(report.contains("unexpected-accept"));
        assert!(report.contains("budget-exceeded"));
        assert!(report.contains("minimized:"));
    }

    #[test]
    fn format_summary_aggregates() {
        let results = vec![
            FuzzResult {
                campaign_name: "a".to_string(),
                iterations_run: 100,
                crashes: vec![FuzzCrash {
                    iteration: 1,
                    description: "x".to_string(),
                    crash_type: CrashType::UnexpectedAccept,
                    minimized_input: None,
                }],
                coverage_estimate: 0.5,
                duration_ms: 1000,
            },
            FuzzResult {
                campaign_name: "b".to_string(),
                iterations_run: 200,
                crashes: vec![
                    FuzzCrash {
                        iteration: 2,
                        description: "y".to_string(),
                        crash_type: CrashType::UnexpectedAccept,
                        minimized_input: None,
                    },
                    FuzzCrash {
                        iteration: 3,
                        description: "z".to_string(),
                        crash_type: CrashType::InvariantViolation("v".to_string()),
                        minimized_input: None,
                    },
                ],
                coverage_estimate: 0.6,
                duration_ms: 2000,
            },
        ];
        let summary = format_fuzz_summary(&results);
        assert!(summary.contains("2 campaigns"));
        assert!(summary.contains("300 iterations"));
        assert!(summary.contains("3 crashes"));
        assert!(summary.contains("3000 ms"));
        assert!(summary.contains("unexpected-accept: 2"));
        assert!(summary.contains("invariant-violation: 1"));
    }

    #[test]
    fn format_summary_no_crashes() {
        let results = vec![FuzzResult {
            campaign_name: "clean".to_string(),
            iterations_run: 1000,
            crashes: vec![],
            coverage_estimate: 0.99,
            duration_ms: 5000,
        }];
        let summary = format_fuzz_summary(&results);
        assert!(summary.contains("0 crashes"));
        assert!(!summary.contains("Crash breakdown"));
    }

    // --- ProtocolState basics ---

    #[test]
    fn protocol_state_default() {
        let state = ProtocolState::default();
        assert!(state.utxos.is_empty());
        assert_eq!(state.step, 0);
        assert!(state.history.is_empty());
        assert_eq!(state.total_value(), 0);
    }

    #[test]
    fn protocol_state_total_value() {
        let state = ProtocolState {
            utxos: vec![
                FuzzUtxo {
                    address: "a".to_string(),
                    value_lovelace: 3_000_000,
                    datum: None,
                },
                FuzzUtxo {
                    address: "b".to_string(),
                    value_lovelace: 7_000_000,
                    datum: None,
                },
            ],
            step: 0,
            history: vec![],
        };
        assert_eq!(state.total_value(), 10_000_000);
    }

    // --- Rng internals ---

    #[test]
    fn rng_zero_seed_handled() {
        let mut rng = Rng::new(0);
        // Should not get stuck (zero is special-cased).
        let v = rng.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn rng_deterministic() {
        let mut a = Rng::new(123);
        let mut b = Rng::new(123);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn rng_range_bounds() {
        let mut rng = Rng::new(77);
        for _ in 0..200 {
            let v = rng.range_u64(10, 20);
            assert!((10..20).contains(&v));
        }
    }

    #[test]
    fn rng_hex_bytes_length() {
        let mut rng = Rng::new(55);
        for len in [1, 7, 16, 28, 32, 64] {
            let hex = rng.hex_bytes(len);
            assert_eq!(
                hex.len(),
                len * 2,
                "hex_bytes({len}) should produce {}",
                len * 2
            );
        }
    }

    // --- Invariant Debug impl ---

    #[test]
    fn invariant_debug_does_not_panic() {
        let inv = default_protocol_invariants();
        let dbg = format!("{:?}", inv[0]);
        assert!(dbg.contains("no-negative-values"));
    }
}
