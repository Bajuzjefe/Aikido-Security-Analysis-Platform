//! Cardano Weakness Classification (CWC) Registry
//!
//! A standardized classification system for Cardano smart contract weaknesses,
//! analogous to CWE (Common Weakness Enumeration) but specific to the Cardano
//! blockchain ecosystem. Each CWC entry groups related detectors under a
//! common weakness category with severity, remediation guidance, and references.

use crate::detector::Severity;

/// A single entry in the Cardano Weakness Classification registry.
#[derive(Debug, Clone)]
pub struct CwcEntry {
    /// Identifier in the format "CWC-NNN".
    pub id: &'static str,
    /// Human-readable weakness name.
    pub name: &'static str,
    /// Detailed description of the weakness category.
    pub description: &'static str,
    /// Base severity for this weakness class.
    pub severity: Severity,
    /// Detector names that map to this weakness.
    pub detectors: &'static [&'static str],
    /// Brief guidance on how to remediate the weakness.
    pub remediation: &'static str,
    /// Related CWE identifiers or external references.
    pub references: &'static [&'static str],
}

/// Complete CWC registry. Each entry groups one or more detectors under a
/// weakness category. The ordering follows severity: Critical first, then
/// High, Medium, and Low/Info.
static CWC_REGISTRY: &[CwcEntry] = &[
    // -----------------------------------------------------------------------
    // Critical (CWC-001 to CWC-005)
    // -----------------------------------------------------------------------
    CwcEntry {
        id: "CWC-001",
        name: "Missing Signature Verification",
        description: "The validator does not verify that the transaction is signed by the \
            expected party (e.g., the asset owner, admin, or oracle). An attacker can submit \
            transactions that manipulate protocol state or drain funds without authorization. \
            This is the most common vulnerability in Cardano smart contracts and the root \
            cause of many exploits.",
        severity: Severity::Critical,
        detectors: &["missing-signature-check"],
        remediation: "Require that the transaction's extra_signatories list contains the \
            expected public key hash. Use a dedicated authorization helper that checks \
            list.has(ctx.transaction.extra_signatories, owner_pkh) in every redeemer branch.",
        references: &["CWE-862", "CWE-285"],
    },
    CwcEntry {
        id: "CWC-002",
        name: "Unrestricted Token Minting",
        description: "The minting policy does not adequately restrict who can mint or how \
            many tokens can be created. Without proper checks on the minting redeemer, \
            transaction signatories, or token quantities, an attacker can mint arbitrary \
            amounts of protocol tokens, diluting value or forging authentication tokens.",
        severity: Severity::Critical,
        detectors: &["unrestricted-minting", "missing-minting-policy-check"],
        remediation: "Ensure the minting policy validates the transaction signer, enforces \
            maximum mint quantities, and verifies token names. For one-shot minting, consume \
            a specific UTxO to guarantee uniqueness.",
        references: &["CWE-770", "CWE-284"],
    },
    CwcEntry {
        id: "CWC-003",
        name: "Datum Integrity Violation",
        description: "The validator does not ensure that the datum attached to continuing \
            outputs is correct or present. An attacker can replace the datum with arbitrary \
            data, corrupt protocol state, or omit the datum entirely, causing the UTxO to \
            become unspendable or the state machine to enter an invalid state.",
        severity: Severity::Critical,
        detectors: &[
            "arbitrary-datum-in-output",
            "missing-datum-in-script-output",
            "state-transition-integrity",
        ],
        remediation: "Validate that continuing outputs carry an inline datum that matches \
            the expected state transition. Compare old and new datum fields explicitly and \
            ensure that only authorized fields change according to the redeemer action.",
        references: &["CWE-20", "CWE-345"],
    },
    CwcEntry {
        id: "CWC-004",
        name: "Value Not Preserved",
        description: "The validator does not verify that the value (ADA and native assets) \
            in continuing outputs matches expectations. An attacker can siphon funds by \
            constructing transactions where the continuing UTxO holds less value than \
            required, using semantic comparison gaps to bypass checks.",
        severity: Severity::Critical,
        detectors: &[
            "value-not-preserved",
            "value-preservation-gap",
            "value-comparison-semantics",
        ],
        remediation: "Explicitly check that the continuing output value is greater than or \
            equal to the expected amount. Use value arithmetic that accounts for all native \
            assets, not just ADA. Prefer exact equality checks where possible.",
        references: &["CWE-682", "CWE-697"],
    },
    CwcEntry {
        id: "CWC-005",
        name: "Missing UTxO Authentication",
        description: "The validator does not authenticate the UTxO being spent, allowing an \
            attacker to satisfy the script with a different UTxO than intended. In double \
            satisfaction attacks, a single UTxO can satisfy multiple script inputs, causing \
            one to execute without proper validation.",
        severity: Severity::Critical,
        detectors: &["missing-utxo-authentication", "double-satisfaction"],
        remediation: "Authenticate inputs by checking for a protocol token (NFT) in the \
            spent UTxO. Each script input should verify its own authentication token is \
            present. For multi-input transactions, ensure each validator checks a unique \
            token.",
        references: &["CWE-287", "CWE-345"],
    },
    // -----------------------------------------------------------------------
    // High (CWC-006 to CWC-015)
    // -----------------------------------------------------------------------
    CwcEntry {
        id: "CWC-006",
        name: "Time Lock Bypass",
        description: "The validator does not check the transaction's validity interval, \
            allowing time-sensitive operations to be executed outside their intended window. \
            Attackers can submit transactions with wide or absent validity ranges to bypass \
            deadlines, lock periods, or vesting schedules.",
        severity: Severity::High,
        detectors: &["missing-validity-range"],
        remediation: "Access tx.validity_range and assert that the interval falls within \
            the expected bounds. For deadlines, check that the upper bound is before the \
            cutoff. For lock periods, check that the lower bound is after the unlock time.",
        references: &["CWE-367", "CWE-613"],
    },
    CwcEntry {
        id: "CWC-007",
        name: "Oracle Manipulation",
        description: "The validator uses oracle data without verifying its authenticity or \
            freshness. An attacker can provide stale or forged oracle data to manipulate \
            price feeds, exchange rates, or other external inputs, causing the protocol to \
            make decisions based on incorrect information.",
        severity: Severity::High,
        detectors: &["oracle-manipulation-risk", "oracle-freshness-not-checked"],
        remediation: "Verify that oracle data is signed by the trusted oracle provider and \
            that its timestamp falls within an acceptable freshness window. Cross-reference \
            the oracle datum's last-updated field against the transaction validity range.",
        references: &["CWE-345", "CWE-829"],
    },
    CwcEntry {
        id: "CWC-008",
        name: "Integer Arithmetic Vulnerability",
        description: "The validator performs arithmetic operations without guarding against \
            underflow, overflow, division by zero, or rounding errors. Since Plutus uses \
            arbitrary-precision integers, underflow below zero can produce unexpected \
            negative values, division by zero causes script failure, and rounding can leak \
            value over many transactions.",
        severity: Severity::High,
        detectors: &[
            "integer-underflow-risk",
            "division-by-zero-risk",
            "rounding-error-risk",
        ],
        remediation: "Add explicit guards before arithmetic: check divisors are non-zero, \
            ensure subtraction operands do not underflow, and use truncation-safe rounding \
            that favors the protocol (round against the user). Consider using safe math \
            helper functions.",
        references: &["CWE-190", "CWE-191", "CWE-369"],
    },
    CwcEntry {
        id: "CWC-009",
        name: "Redeemer Validation Failure",
        description: "The validator does not properly validate or handle all redeemer \
            variants. Missing pattern matches can cause unexpected behavior, and performing \
            arithmetic directly on redeemer-supplied values without bounds checking allows \
            attackers to inject malicious inputs.",
        severity: Severity::High,
        detectors: &[
            "missing-redeemer-validation",
            "non-exhaustive-redeemer",
            "unsafe-redeemer-arithmetic",
        ],
        remediation: "Pattern-match exhaustively on all redeemer constructors with an \
            explicit fail branch for unrecognized variants. Validate redeemer-supplied \
            numeric values (amounts, indices) against expected bounds before using them \
            in computation.",
        references: &["CWE-20", "CWE-129"],
    },
    CwcEntry {
        id: "CWC-010",
        name: "Unsafe Datum Handling",
        description: "The validator destructures or accesses datum fields unsafely, fails \
            to validate expected datum fields, or is vulnerable to datum tampering. Unsafe \
            pattern matching on datum constructors can cause script failures, while missing \
            field validation allows attackers to inject crafted datums that pass structural \
            checks but contain malicious values.",
        severity: Severity::High,
        detectors: &[
            "unsafe-datum-deconstruction",
            "missing-datum-field-validation",
            "datum-tampering-risk",
        ],
        remediation: "Use safe datum deconstruction with expect or when clauses. Validate \
            all security-critical datum fields (owner, deadline, amounts) after extraction. \
            Compare datum fields against expected values derived from the redeemer and \
            protocol state.",
        references: &["CWE-20", "CWE-502"],
    },
    CwcEntry {
        id: "CWC-011",
        name: "Token Name Confusion",
        description: "The validator does not validate token names in minting or spending \
            logic, allowing an attacker to mint tokens with unexpected names, duplicate \
            existing asset names, or mint tokens under policies they should not control. \
            This can break protocol invariants that depend on token name uniqueness.",
        severity: Severity::High,
        detectors: &[
            "token-name-not-validated",
            "duplicate-asset-name-risk",
            "other-token-minting",
        ],
        remediation: "Explicitly check that minted token names match the expected value \
            derived from the redeemer or datum. Verify that the flattened mint list contains \
            only the expected policy and asset name pairs. Reject any unexpected token names.",
        references: &["CWE-20", "CWE-290"],
    },
    CwcEntry {
        id: "CWC-012",
        name: "Output Address Manipulation",
        description: "The validator does not verify the destination address of transaction \
            outputs. An attacker can redirect funds to an address they control by \
            constructing a transaction where the continuing output goes to a different \
            script or wallet address than the protocol expects.",
        severity: Severity::High,
        detectors: &["output-address-not-validated"],
        remediation: "Check that continuing outputs are sent to the validator's own script \
            address (for state continuity) or to the expected recipient address (for \
            payouts). Compare the full address including the payment and staking credentials.",
        references: &["CWE-601", "CWE-862"],
    },
    CwcEntry {
        id: "CWC-013",
        name: "Withdrawal Vulnerability",
        description: "The validator is susceptible to the withdraw-zero trick, where an \
            attacker registers a staking credential and submits a zero-ADA withdrawal to \
            force script execution as a side effect, or the validator does not properly \
            check withdrawal amounts, allowing unauthorized fund extraction.",
        severity: Severity::High,
        detectors: &["withdraw-zero-trick", "withdraw-amount-check"],
        remediation: "If using the withdraw-zero pattern intentionally for delegation, \
            ensure the validator recognizes it and applies appropriate authorization. \
            Otherwise, validate that withdrawal amounts match expected values and that \
            the withdrawer is authorized.",
        references: &["CWE-862", "CWE-20"],
    },
    CwcEntry {
        id: "CWC-014",
        name: "Burn Verification Failure",
        description: "The validator does not verify that tokens are properly burned when \
            protocol logic requires it. Missing burn verification allows tokens to persist \
            after they should have been destroyed, potentially allowing replay attacks or \
            inconsistent protocol state. Incomplete burn flows leave orphaned tokens.",
        severity: Severity::High,
        detectors: &[
            "missing-burn-verification",
            "missing-token-burn",
            "incomplete-burn-flow",
        ],
        remediation: "When protocol actions require token burning (e.g., closing a position, \
            redeeming a receipt), verify that the flattened mint list contains a negative \
            quantity for the expected policy ID and asset name. Ensure all related tokens \
            are burned together.",
        references: &["CWE-672", "CWE-404"],
    },
    CwcEntry {
        id: "CWC-015",
        name: "State Transition Violation",
        description: "The validator does not enforce valid state transitions or fails to \
            update state when required. Missing state updates can leave the protocol in an \
            inconsistent state, while missing state machine validation allows arbitrary \
            transitions that bypass intended protocol flow.",
        severity: Severity::High,
        detectors: &["missing-state-update", "state-machine-violation"],
        remediation: "Define the valid state machine transitions explicitly and check that \
            each redeemer action produces a valid next state. Verify that the output datum \
            reflects the expected state change and that no intermediate states are skipped.",
        references: &["CWE-372", "CWE-841"],
    },
    // -----------------------------------------------------------------------
    // Medium (CWC-016 to CWC-025)
    // -----------------------------------------------------------------------
    CwcEntry {
        id: "CWC-016",
        name: "Resource Exhaustion",
        description: "The validator processes unbounded data structures (lists, maps, datum \
            fields, or value entries) without size limits, or uses unconstrained recursion. \
            An attacker can craft inputs that cause the validator to exceed execution unit \
            limits, making the UTxO unspendable, or causing denial-of-service by bloating \
            protocol operations.",
        severity: Severity::Medium,
        detectors: &[
            "unbounded-list-iteration",
            "unbounded-datum-size",
            "unbounded-value-size",
            "unconstrained-recursion",
            "unbounded-protocol-operations",
        ],
        remediation: "Impose explicit bounds on list lengths, datum sizes, and recursion \
            depth. Use pagination or batching for operations that process variable-length \
            data. Set maximum limits in the datum or parameterize the validator with bounds.",
        references: &["CWE-400", "CWE-674", "CWE-770"],
    },
    CwcEntry {
        id: "CWC-017",
        name: "Denial of Service",
        description: "The protocol design allows UTxO contention (multiple users competing \
            for the same UTxO) or cheap spam (low-cost transactions that degrade protocol \
            performance). These patterns can be exploited to block legitimate users from \
            interacting with the protocol.",
        severity: Severity::Medium,
        detectors: &["utxo-contention-risk", "cheap-spam-vulnerability"],
        remediation: "Use UTxO-per-user patterns instead of a single global UTxO. Add \
            minimum deposit or fee requirements to make spam uneconomical. Consider \
            batching or off-chain aggregation for high-throughput operations.",
        references: &["CWE-400", "CWE-770"],
    },
    CwcEntry {
        id: "CWC-018",
        name: "Insufficient Access Control",
        description: "The validator does not properly control access to staking operations \
            or fails to verify input credentials. Missing staking control allows unauthorized \
            delegation changes, while missing input credential checks allow attackers to \
            spend inputs they should not have access to.",
        severity: Severity::Medium,
        detectors: &[
            "insufficient-staking-control",
            "missing-input-credential-check",
        ],
        remediation: "Verify the transaction signer matches the expected credential for \
            staking operations. Check that inputs consumed by the transaction belong to \
            the expected addresses or carry the required authentication tokens.",
        references: &["CWE-862", "CWE-863"],
    },
    CwcEntry {
        id: "CWC-019",
        name: "Unsafe Pattern Matching",
        description: "The validator uses unsafe pattern matching that can fail at runtime, \
            partial patterns that do not cover all constructors, or unsafe list head access \
            on potentially empty lists. These patterns cause unintended script failures that \
            can lock funds or enable denial-of-service.",
        severity: Severity::Medium,
        detectors: &[
            "unsafe-match-comparison",
            "unsafe-partial-pattern",
            "unsafe-list-head",
        ],
        remediation: "Use exhaustive pattern matching with explicit handling for all \
            constructors. Guard list head access with is_empty checks or use safe \
            alternatives like list.head() with a default. Use when clauses for conditional \
            matching.",
        references: &["CWE-252", "CWE-476"],
    },
    CwcEntry {
        id: "CWC-020",
        name: "Hardcoded Configuration",
        description: "The validator contains hardcoded addresses, key hashes, or magic \
            numbers that should be parameterized. Hardcoded values make the contract \
            inflexible, error-prone during deployment, and difficult to audit. Magic \
            numbers obscure business logic intent.",
        severity: Severity::Medium,
        detectors: &["hardcoded-addresses", "magic-numbers"],
        remediation: "Parameterize the validator with configuration values passed as \
            constructor parameters. Use named constants for magic numbers and document \
            their purpose. Store mutable configuration in a datum-based config UTxO.",
        references: &["CWE-547", "CWE-798"],
    },
    CwcEntry {
        id: "CWC-021",
        name: "Reference Script Vulnerability",
        description: "The validator does not prevent reference scripts from being attached \
            to its UTxOs. An attacker can attach a reference script to a protocol UTxO, \
            increasing its minimum ADA requirement and potentially making it unspendable \
            if the protocol does not account for the additional overhead.",
        severity: Severity::Medium,
        detectors: &["reference-script-injection"],
        remediation: "Check that continuing outputs do not carry a reference script unless \
            the protocol explicitly requires it. Verify output.reference_script == None for \
            state-carrying UTxOs.",
        references: &["CWE-400", "CWE-20"],
    },
    CwcEntry {
        id: "CWC-022",
        name: "Fee Manipulation",
        description: "The validator computes fees or charges without proper validation, \
            allowing attackers to manipulate fee calculations to extract extra value or \
            pay less than required. Unchecked fee arithmetic can lead to rounding exploits \
            or fee-skipping attacks.",
        severity: Severity::Medium,
        detectors: &["fee-calculation-unchecked"],
        remediation: "Validate fee calculations against expected bounds. Use protocol-defined \
            fee schedules stored in a config datum. Ensure fee rounding favors the protocol \
            (round up fees, round down rewards).",
        references: &["CWE-682", "CWE-20"],
    },
    CwcEntry {
        id: "CWC-023",
        name: "Cross-Validator Incoherence",
        description: "Multiple validators in the protocol do not coordinate their checks, \
            creating gaps where an action validated by one script is not properly constrained \
            by another. Uncoordinated multi-validator designs can allow state inconsistencies \
            across UTxOs managed by different scripts.",
        severity: Severity::Medium,
        detectors: &[
            "cross-validator-gap",
            "uncoordinated-multi-validator",
            "uncoordinated-state-transfer",
        ],
        remediation: "Use a shared protocol token that all validators check to ensure \
            coordinated execution. Define clear validator interaction protocols and verify \
            cross-validator invariants in each script. Consider using a single coordinating \
            validator with forwarding logic.",
        references: &["CWE-362", "CWE-367"],
    },
    CwcEntry {
        id: "CWC-024",
        name: "Quantity Tracking",
        description: "The validator incorrectly counts token quantities (e.g., double-counting \
            from repeated quantity_of calls), uses insufficient multi-asset comparison that \
            misses assets, or incompletely extracts value components. These flaws allow \
            attackers to manipulate perceived balances.",
        severity: Severity::Medium,
        detectors: &[
            "quantity-of-double-counting",
            "multi-asset-comparison-bypass",
            "incomplete-value-extraction",
        ],
        remediation: "Use a single quantity_of call per asset per handler and store the \
            result. Compare full Value objects rather than individual token quantities. \
            When extracting value components, ensure all policy IDs and asset names are \
            accounted for.",
        references: &["CWE-682", "CWE-131"],
    },
    CwcEntry {
        id: "CWC-025",
        name: "Identity Forgery",
        description: "The validator's identity token mechanism can be forged or bypassed. \
            If the protocol uses an NFT as an authentication token but does not properly \
            validate its provenance (policy ID, asset name, uniqueness), an attacker can \
            mint a counterfeit token and use it to impersonate the protocol.",
        severity: Severity::Medium,
        detectors: &["identity-token-forgery"],
        remediation: "Verify identity tokens by their full asset ID (policy ID + asset \
            name), not just by name. Ensure the minting policy guarantees uniqueness \
            (e.g., one-shot minting). Check that exactly one identity token exists in \
            the transaction inputs.",
        references: &["CWE-290", "CWE-287"],
    },
    CwcEntry {
        id: "CWC-026",
        name: "Path-Sensitive Vulnerability",
        description: "Advanced analysis detects potential vulnerabilities that are only \
            exploitable along specific execution paths. Path-sensitive guard checks \
            identify conditions where security-critical checks are bypassed on certain \
            branches, and taint analysis tracks untrusted data flowing to sensitive sinks.",
        severity: Severity::Medium,
        detectors: &["path-sensitive-guard-check", "precise-taint-to-sink"],
        remediation: "Ensure that security checks (signature verification, value \
            validation, datum integrity) are present on ALL execution paths, not just \
            the happy path. Review branch conditions that gate security-critical logic.",
        references: &["CWE-691", "CWE-807"],
    },
    // -----------------------------------------------------------------------
    // Low / Info (CWC-027 to CWC-030)
    // -----------------------------------------------------------------------
    CwcEntry {
        id: "CWC-027",
        name: "Dead Code",
        description: "The validator contains unreachable code paths, dead branches that \
            can never execute, or empty handler bodies. While not directly exploitable, \
            dead code increases the attack surface, wastes execution budget, and may \
            indicate incomplete implementation or logic errors.",
        severity: Severity::Low,
        detectors: &[
            "dead-code-path",
            "dead-branch-detection",
            "empty-handler-body",
        ],
        remediation: "Remove unreachable code paths and dead branches. If an empty handler \
            is intentional (e.g., a no-op redeemer), add an explicit comment. Use the Aiken \
            compiler's warnings to identify unused code.",
        references: &["CWE-561"],
    },
    CwcEntry {
        id: "CWC-028",
        name: "Missing Protocol Enforcement",
        description: "The validator does not enforce protocol-level constraints such as \
            requiring a protocol token in transactions, validating output counts to prevent \
            UTxO splitting or duplication, or ensuring minimum ADA requirements are met. \
            These missing checks can allow protocol invariant violations.",
        severity: Severity::Low,
        detectors: &[
            "missing-protocol-token",
            "output-count-validation",
            "missing-min-ada-check",
        ],
        remediation: "Require a protocol authentication token (NFT) in all protocol \
            transactions. Validate that the number of continuing outputs matches the \
            expected count. Check that outputs meet the minimum ADA requirement to \
            prevent dust UTxOs.",
        references: &["CWE-284", "CWE-20"],
    },
    CwcEntry {
        id: "CWC-029",
        name: "Tautological Logic",
        description: "The validator contains comparisons that are always true or always \
            false, invariant conditions that can never be violated, or datum field bounds \
            that are trivially satisfied. These indicate logic errors where the intended \
            check has been rendered meaningless by the implementation.",
        severity: Severity::Low,
        detectors: &[
            "tautological-comparison",
            "invariant-violation",
            "datum-field-bounds",
        ],
        remediation: "Review tautological conditions and replace them with meaningful \
            checks. Verify that invariants are actually constraining and that datum field \
            bounds reflect real business requirements. Remove or fix always-true guards.",
        references: &["CWE-570", "CWE-571"],
    },
    CwcEntry {
        id: "CWC-030",
        name: "Code Quality",
        description: "The validator contains code quality issues such as redundant checks, \
            shadowed variables, unused parameters, unused imports, unused library modules, \
            excessive parameter counts, or redeemer branches that always fail. These issues \
            do not directly cause vulnerabilities but degrade readability and may mask \
            real bugs.",
        severity: Severity::Info,
        detectors: &[
            "redundant-check",
            "shadowed-variable",
            "unused-validator-parameter",
            "unused-import",
            "unused-library-module",
            "excessive-validator-params",
            "fail-only-redeemer-branch",
        ],
        remediation: "Remove redundant checks and unused code. Rename shadowed variables \
            for clarity. Reduce validator parameter count by grouping related values into \
            a configuration struct. Investigate fail-only branches for missing logic.",
        references: &["CWE-561", "CWE-563"],
    },
];

/// Look up the CWC entry for a given detector name.
///
/// Returns `None` if the detector is not mapped to any CWC entry. Every
/// detector registered in `all_detectors()` should have a CWC mapping.
pub fn cwc_for_detector(detector_name: &str) -> Option<&'static CwcEntry> {
    CWC_REGISTRY
        .iter()
        .find(|entry| entry.detectors.contains(&detector_name))
}

/// Return all CWC entries in registry order (Critical first, then descending).
pub fn all_cwc_entries() -> Vec<&'static CwcEntry> {
    CWC_REGISTRY.iter().collect()
}

/// Format the full CWC registry for CLI output (`--list-cwc`).
///
/// Produces a human-readable table with ID, severity, name, and mapped detectors.
pub fn format_cwc_registry() -> String {
    let mut output = String::new();
    output.push_str("Cardano Weakness Classification (CWC) Registry\n");
    output.push_str(&"=".repeat(72));
    output.push('\n');
    output.push('\n');

    let mut current_severity: Option<&str> = None;

    for entry in CWC_REGISTRY.iter() {
        let sev_label = match entry.severity {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        };

        // Print severity group header when it changes
        if current_severity != Some(sev_label) {
            if current_severity.is_some() {
                output.push('\n');
            }
            output.push_str(&format!("--- {sev_label} ---\n\n"));
            current_severity = Some(sev_label);
        }

        output.push_str(&format!("{:<8} {}\n", entry.id, entry.name));
        output.push_str(&format!("         Severity: {sev_label}\n"));
        output.push_str(&format!(
            "         Detectors: {}\n",
            entry.detectors.join(", ")
        ));

        // Wrap description at ~68 chars with 9-space indent
        let desc_lines = wrap_text(entry.description, 63);
        for line in &desc_lines {
            output.push_str(&format!("         {line}\n"));
        }

        if !entry.references.is_empty() {
            output.push_str(&format!(
                "         References: {}\n",
                entry.references.join(", ")
            ));
        }

        output.push('\n');
    }

    // Summary
    let total_detectors: usize = CWC_REGISTRY.iter().map(|e| e.detectors.len()).sum();
    output.push_str(&format!(
        "Total: {} CWC entries covering {} detectors\n",
        CWC_REGISTRY.len(),
        total_detectors
    ));

    output
}

/// Simple word-wrap that breaks text at word boundaries to fit within `max_width`.
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line.push_str(word);
        } else if current_line.len() + 1 + word.len() > max_width {
            lines.push(current_line);
            current_line = word.to_string();
        } else {
            current_line.push(' ');
            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_cwc_entries_returns_30() {
        let entries = all_cwc_entries();
        assert_eq!(entries.len(), 30, "Expected 30 CWC entries");
    }

    #[test]
    fn test_cwc_ids_are_sequential() {
        let entries = all_cwc_entries();
        for (i, entry) in entries.iter().enumerate() {
            let expected_id = format!("CWC-{:03}", i + 1);
            assert_eq!(
                entry.id, expected_id,
                "Entry at index {i} has id {} but expected {expected_id}",
                entry.id
            );
        }
    }

    #[test]
    fn test_cwc_ids_are_unique() {
        let entries = all_cwc_entries();
        let mut seen = std::collections::HashSet::new();
        for entry in &entries {
            assert!(seen.insert(entry.id), "Duplicate CWC id: {}", entry.id);
        }
    }

    #[test]
    fn test_no_detector_in_multiple_cwc_entries() {
        let entries = all_cwc_entries();
        let mut detector_to_cwc: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for entry in &entries {
            for det in entry.detectors {
                if let Some(existing) = detector_to_cwc.insert(det, entry.id) {
                    panic!(
                        "Detector '{}' is in both {} and {}",
                        det, existing, entry.id
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_registered_detectors_have_cwc_mapping() {
        let all_dets = crate::detector::all_detectors();
        let mut unmapped = Vec::new();
        for det in &all_dets {
            if cwc_for_detector(det.name()).is_none() {
                unmapped.push(det.name().to_string());
            }
        }
        assert!(
            unmapped.is_empty(),
            "The following detectors have no CWC mapping: {:?}",
            unmapped
        );
    }

    #[test]
    fn test_all_cwc_detectors_exist_in_registry() {
        let all_dets = crate::detector::all_detectors();
        let det_names: std::collections::HashSet<&str> =
            all_dets.iter().map(|d| d.name()).collect();
        let entries = all_cwc_entries();
        let mut phantom = Vec::new();
        for entry in &entries {
            for det in entry.detectors {
                if !det_names.contains(det) {
                    phantom.push(format!("{}: {}", entry.id, det));
                }
            }
        }
        assert!(
            phantom.is_empty(),
            "CWC entries reference non-existent detectors: {:?}",
            phantom
        );
    }

    #[test]
    fn test_cwc_for_detector_critical() {
        let entry = cwc_for_detector("missing-signature-check").unwrap();
        assert_eq!(entry.id, "CWC-001");
        assert_eq!(entry.severity, Severity::Critical);
    }

    #[test]
    fn test_cwc_for_detector_high() {
        let entry = cwc_for_detector("missing-validity-range").unwrap();
        assert_eq!(entry.id, "CWC-006");
        assert_eq!(entry.severity, Severity::High);
    }

    #[test]
    fn test_cwc_for_detector_medium() {
        let entry = cwc_for_detector("unbounded-list-iteration").unwrap();
        assert_eq!(entry.id, "CWC-016");
        assert_eq!(entry.severity, Severity::Medium);
    }

    #[test]
    fn test_cwc_for_detector_low() {
        let entry = cwc_for_detector("dead-code-path").unwrap();
        assert_eq!(entry.id, "CWC-027");
        assert_eq!(entry.severity, Severity::Low);
    }

    #[test]
    fn test_cwc_for_detector_info() {
        let entry = cwc_for_detector("redundant-check").unwrap();
        assert_eq!(entry.id, "CWC-030");
        assert_eq!(entry.severity, Severity::Info);
    }

    #[test]
    fn test_cwc_for_unknown_detector_returns_none() {
        assert!(cwc_for_detector("nonexistent-detector").is_none());
    }

    #[test]
    fn test_cwc_entry_fields_not_empty() {
        for entry in all_cwc_entries() {
            assert!(!entry.id.is_empty(), "Empty id");
            assert!(!entry.name.is_empty(), "Empty name for {}", entry.id);
            assert!(
                !entry.description.is_empty(),
                "Empty description for {}",
                entry.id
            );
            assert!(!entry.detectors.is_empty(), "No detectors for {}", entry.id);
            assert!(
                !entry.remediation.is_empty(),
                "Empty remediation for {}",
                entry.id
            );
        }
    }

    #[test]
    fn test_cwc_severity_ordering() {
        let entries = all_cwc_entries();
        let mut last_order = 100u8;
        for entry in &entries {
            let order = match entry.severity {
                Severity::Critical => 5,
                Severity::High => 4,
                Severity::Medium => 3,
                Severity::Low => 2,
                Severity::Info => 1,
            };
            assert!(
                order <= last_order,
                "{} has severity {:?} which is higher than the previous entry",
                entry.id,
                entry.severity
            );
            last_order = order;
        }
    }

    #[test]
    fn test_critical_entries_count() {
        let count = all_cwc_entries()
            .iter()
            .filter(|e| e.severity == Severity::Critical)
            .count();
        assert_eq!(count, 5, "Expected 5 Critical CWC entries");
    }

    #[test]
    fn test_high_entries_count() {
        let count = all_cwc_entries()
            .iter()
            .filter(|e| e.severity == Severity::High)
            .count();
        assert_eq!(count, 10, "Expected 10 High CWC entries");
    }

    #[test]
    fn test_medium_entries_count() {
        let count = all_cwc_entries()
            .iter()
            .filter(|e| e.severity == Severity::Medium)
            .count();
        assert_eq!(count, 11, "Expected 11 Medium CWC entries");
    }

    #[test]
    fn test_low_and_info_entries_count() {
        let count = all_cwc_entries()
            .iter()
            .filter(|e| e.severity == Severity::Low || e.severity == Severity::Info)
            .count();
        assert_eq!(count, 4, "Expected 4 Low/Info CWC entries");
    }

    #[test]
    fn test_format_cwc_registry_contains_all_ids() {
        let output = format_cwc_registry();
        for entry in all_cwc_entries() {
            assert!(
                output.contains(entry.id),
                "Registry output missing {}",
                entry.id
            );
        }
    }

    #[test]
    fn test_format_cwc_registry_contains_header() {
        let output = format_cwc_registry();
        assert!(output.contains("Cardano Weakness Classification (CWC) Registry"));
    }

    #[test]
    fn test_format_cwc_registry_contains_severity_sections() {
        let output = format_cwc_registry();
        assert!(output.contains("--- Critical ---"));
        assert!(output.contains("--- High ---"));
        assert!(output.contains("--- Medium ---"));
        assert!(output.contains("--- Low ---"));
        assert!(output.contains("--- Info ---"));
    }

    #[test]
    fn test_format_cwc_registry_contains_summary() {
        let output = format_cwc_registry();
        assert!(output.contains("Total: 30 CWC entries covering"));
    }

    #[test]
    fn test_specific_detector_mappings() {
        // Spot-check several detectors across different CWC entries
        let cases = vec![
            ("double-satisfaction", "CWC-005"),
            ("unrestricted-minting", "CWC-002"),
            ("state-transition-integrity", "CWC-003"),
            ("value-not-preserved", "CWC-004"),
            ("oracle-manipulation-risk", "CWC-007"),
            ("integer-underflow-risk", "CWC-008"),
            ("withdraw-zero-trick", "CWC-013"),
            ("reference-script-injection", "CWC-021"),
            ("identity-token-forgery", "CWC-025"),
            ("tautological-comparison", "CWC-029"),
            ("path-sensitive-guard-check", "CWC-026"),
        ];
        for (detector, expected_cwc) in cases {
            let entry = cwc_for_detector(detector)
                .unwrap_or_else(|| panic!("No CWC entry for detector: {detector}"));
            assert_eq!(
                entry.id, expected_cwc,
                "Detector '{detector}' mapped to {} but expected {expected_cwc}",
                entry.id
            );
        }
    }

    #[test]
    fn test_cwc_references_format() {
        for entry in all_cwc_entries() {
            for reference in entry.references {
                assert!(
                    reference.starts_with("CWE-"),
                    "{}: reference '{}' should start with 'CWE-'",
                    entry.id,
                    reference
                );
            }
        }
    }

    #[test]
    fn test_total_detector_count() {
        let total: usize = all_cwc_entries().iter().map(|e| e.detectors.len()).sum();
        let all_dets = crate::detector::all_detectors();
        assert_eq!(
            total,
            all_dets.len(),
            "CWC total detector slots ({total}) should match all_detectors() count ({})",
            all_dets.len()
        );
    }

    #[test]
    fn test_wrap_text_basic() {
        let lines = wrap_text("hello world foo bar baz", 11);
        assert_eq!(lines, vec!["hello world", "foo bar baz"]);
    }

    #[test]
    fn test_wrap_text_single_long_word() {
        let lines = wrap_text("superlongword", 5);
        assert_eq!(lines, vec!["superlongword"]);
    }

    #[test]
    fn test_wrap_text_empty() {
        let lines = wrap_text("", 10);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_cwc_names_are_unique() {
        let entries = all_cwc_entries();
        let mut seen = std::collections::HashSet::new();
        for entry in &entries {
            assert!(
                seen.insert(entry.name),
                "Duplicate CWC name: {}",
                entry.name
            );
        }
    }
}
