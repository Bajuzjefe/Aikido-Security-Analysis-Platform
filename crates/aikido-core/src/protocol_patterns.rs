//! Cross-validator protocol pattern analysis.
//!
//! Detects which DeFi protocol pattern a set of validators implements (DEX, lending,
//! staking, etc.), analyzes token flows between validators, tracks authority
//! propagation, and generates a protocol-level analysis report.

use serde::Serialize;
use std::collections::HashMap;

use crate::ast_walker::ModuleInfo;
use crate::detector::Severity;

// ---------------------------------------------------------------------------
// Protocol pattern types
// ---------------------------------------------------------------------------

/// A recognized DeFi protocol pattern.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolPattern {
    pub name: String,
    pub category: ProtocolCategory,
    pub validators: Vec<ValidatorRole>,
    pub invariants: Vec<ProtocolInvariant>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum ProtocolCategory {
    Dex,
    Lending,
    Staking,
    Dao,
    NftMarketplace,
    Options,
    Escrow,
    Unknown,
}

impl std::fmt::Display for ProtocolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolCategory::Dex => write!(f, "DEX"),
            ProtocolCategory::Lending => write!(f, "Lending"),
            ProtocolCategory::Staking => write!(f, "Staking"),
            ProtocolCategory::Dao => write!(f, "DAO"),
            ProtocolCategory::NftMarketplace => write!(f, "NFT Marketplace"),
            ProtocolCategory::Options => write!(f, "Options"),
            ProtocolCategory::Escrow => write!(f, "Escrow"),
            ProtocolCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorRole {
    /// Role name, e.g. "pool", "lp_mint", "factory".
    pub role: String,
    /// Handler types present, e.g. ["spend", "mint"].
    pub handler_types: Vec<String>,
    /// Expected signals for this role, e.g. ["checks_outputs", "checks_mint"].
    pub expected_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolInvariant {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub check_type: InvariantCheckType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum InvariantCheckType {
    /// All minted tokens must have corresponding burn paths.
    TokenLifecycle,
    /// Value flowing in must equal value flowing out (minus fees).
    ValueConservation,
    /// Authority must propagate correctly through validators.
    AuthorityChain,
    /// Datum state must be consistent across validators.
    DatumConsistency,
    /// Time constraints must be coordinated.
    TemporalCoordination,
}

impl std::fmt::Display for InvariantCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvariantCheckType::TokenLifecycle => write!(f, "Token Lifecycle"),
            InvariantCheckType::ValueConservation => write!(f, "Value Conservation"),
            InvariantCheckType::AuthorityChain => write!(f, "Authority Chain"),
            InvariantCheckType::DatumConsistency => write!(f, "Datum Consistency"),
            InvariantCheckType::TemporalCoordination => write!(f, "Temporal Coordination"),
        }
    }
}

// ---------------------------------------------------------------------------
// Token flow types
// ---------------------------------------------------------------------------

/// A token flow between validators.
#[derive(Debug, Clone, Serialize)]
pub struct TokenFlow {
    pub source_validator: String,
    pub dest_validator: String,
    pub token_type: TokenFlowType,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum TokenFlowType {
    Mint,
    Transfer,
    Burn,
    Reference,
}

impl std::fmt::Display for TokenFlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenFlowType::Mint => write!(f, "Mint"),
            TokenFlowType::Transfer => write!(f, "Transfer"),
            TokenFlowType::Burn => write!(f, "Burn"),
            TokenFlowType::Reference => write!(f, "Reference"),
        }
    }
}

// ---------------------------------------------------------------------------
// Authority flow types
// ---------------------------------------------------------------------------

/// How authorization requirements flow through the protocol.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorityFlow {
    /// Source of the authority, e.g. "admin_pkh in config datum".
    pub source: String,
    /// Validators that correctly check this authority.
    pub validators: Vec<String>,
    /// Validators that should check but don't.
    pub missing_checks: Vec<String>,
}

// ---------------------------------------------------------------------------
// Built-in protocol pattern library
// ---------------------------------------------------------------------------

/// Build the built-in library of known DeFi protocol patterns.
pub fn builtin_protocol_patterns() -> Vec<ProtocolPattern> {
    vec![
        dex_pattern(),
        lending_pattern(),
        staking_pattern(),
        dao_pattern(),
        nft_marketplace_pattern(),
        options_pattern(),
        escrow_pattern(),
    ]
}

fn dex_pattern() -> ProtocolPattern {
    ProtocolPattern {
        name: "Decentralized Exchange (AMM)".to_string(),
        category: ProtocolCategory::Dex,
        description: "Automated market maker with liquidity pools and LP token minting."
            .to_string(),
        validators: vec![
            ValidatorRole {
                role: "pool".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_mint".to_string(),
                    "checks_value".to_string(),
                ],
            },
            ValidatorRole {
                role: "lp_mint".to_string(),
                handler_types: vec!["mint".to_string()],
                expected_signals: vec!["checks_inputs".to_string()],
            },
            ValidatorRole {
                role: "factory".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_signatories".to_string(),
                ],
            },
        ],
        invariants: vec![
            ProtocolInvariant {
                name: "LP token lifecycle".to_string(),
                description: "LP tokens must be mintable and burnable; burn path must exist."
                    .to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::TokenLifecycle,
            },
            ProtocolInvariant {
                name: "Constant product conservation".to_string(),
                description:
                    "Pool reserves must satisfy the constant-product invariant after swaps."
                        .to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::ValueConservation,
            },
            ProtocolInvariant {
                name: "Pool datum consistency".to_string(),
                description: "Pool datum must be carried forward correctly on state transitions."
                    .to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::DatumConsistency,
            },
        ],
    }
}

fn lending_pattern() -> ProtocolPattern {
    ProtocolPattern {
        name: "Lending Protocol".to_string(),
        category: ProtocolCategory::Lending,
        description: "Collateralized lending with liquidation and interest accrual.".to_string(),
        validators: vec![
            ValidatorRole {
                role: "pool".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_value".to_string(),
                    "checks_datum".to_string(),
                ],
            },
            ValidatorRole {
                role: "collateral".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_signatories".to_string(),
                ],
            },
            ValidatorRole {
                role: "oracle".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec!["checks_validity_range".to_string()],
            },
        ],
        invariants: vec![
            ProtocolInvariant {
                name: "Collateral ratio".to_string(),
                description: "Collateral must maintain the required ratio; undercollateralized positions trigger liquidation."
                    .to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::ValueConservation,
            },
            ProtocolInvariant {
                name: "Oracle freshness".to_string(),
                description: "Price oracle data must be validated for freshness via validity range."
                    .to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::TemporalCoordination,
            },
            ProtocolInvariant {
                name: "Interest accrual consistency".to_string(),
                description: "Loan datum must correctly reflect accumulated interest."
                    .to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::DatumConsistency,
            },
        ],
    }
}

fn staking_pattern() -> ProtocolPattern {
    ProtocolPattern {
        name: "Staking Protocol".to_string(),
        category: ProtocolCategory::Staking,
        description: "Token staking with reward distribution and epoch-based accounting."
            .to_string(),
        validators: vec![
            ValidatorRole {
                role: "staking_pool".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_validity_range".to_string(),
                ],
            },
            ValidatorRole {
                role: "reward_mint".to_string(),
                handler_types: vec!["mint".to_string()],
                expected_signals: vec!["checks_inputs".to_string()],
            },
        ],
        invariants: vec![
            ProtocolInvariant {
                name: "Reward token lifecycle".to_string(),
                description: "Reward tokens minted per epoch must not exceed the defined rate."
                    .to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::TokenLifecycle,
            },
            ProtocolInvariant {
                name: "Stake value conservation".to_string(),
                description:
                    "Staked value must be preserved or only reduced by authorized withdrawals."
                        .to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::ValueConservation,
            },
            ProtocolInvariant {
                name: "Epoch time coordination".to_string(),
                description:
                    "Reward distribution must respect epoch boundaries via validity range."
                        .to_string(),
                severity: Severity::Medium,
                check_type: InvariantCheckType::TemporalCoordination,
            },
        ],
    }
}

fn dao_pattern() -> ProtocolPattern {
    ProtocolPattern {
        name: "DAO Governance".to_string(),
        category: ProtocolCategory::Dao,
        description: "Decentralized governance with proposal creation, voting, and execution."
            .to_string(),
        validators: vec![
            ValidatorRole {
                role: "treasury".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_signatories".to_string(),
                ],
            },
            ValidatorRole {
                role: "governance_token".to_string(),
                handler_types: vec!["mint".to_string()],
                expected_signals: vec!["checks_inputs".to_string()],
            },
            ValidatorRole {
                role: "proposal".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_validity_range".to_string(),
                ],
            },
        ],
        invariants: vec![
            ProtocolInvariant {
                name: "Quorum enforcement".to_string(),
                description: "Proposals must reach the quorum threshold before execution."
                    .to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::AuthorityChain,
            },
            ProtocolInvariant {
                name: "Voting period enforcement".to_string(),
                description: "Votes must only be cast within the defined voting period."
                    .to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::TemporalCoordination,
            },
            ProtocolInvariant {
                name: "Treasury authorization".to_string(),
                description: "Treasury spends must be authorized by passed proposals.".to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::AuthorityChain,
            },
        ],
    }
}

fn nft_marketplace_pattern() -> ProtocolPattern {
    ProtocolPattern {
        name: "NFT Marketplace".to_string(),
        category: ProtocolCategory::NftMarketplace,
        description: "NFT listing, bidding, and sale with royalty enforcement.".to_string(),
        validators: vec![
            ValidatorRole {
                role: "listing".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_signatories".to_string(),
                    "checks_value".to_string(),
                ],
            },
            ValidatorRole {
                role: "bid".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_signatories".to_string(),
                ],
            },
        ],
        invariants: vec![
            ProtocolInvariant {
                name: "Royalty enforcement".to_string(),
                description: "Sales must include royalty payments to the original creator."
                    .to_string(),
                severity: Severity::Medium,
                check_type: InvariantCheckType::ValueConservation,
            },
            ProtocolInvariant {
                name: "Listing authority".to_string(),
                description: "Only the NFT owner can create or cancel a listing.".to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::AuthorityChain,
            },
            ProtocolInvariant {
                name: "Bid escrow integrity".to_string(),
                description:
                    "Bid funds must be locked and only released on acceptance or cancellation."
                        .to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::ValueConservation,
            },
        ],
    }
}

fn options_pattern() -> ProtocolPattern {
    ProtocolPattern {
        name: "Options Protocol".to_string(),
        category: ProtocolCategory::Options,
        description:
            "Financial options with strike price, expiry, premium collection, and settlement."
                .to_string(),
        validators: vec![
            ValidatorRole {
                role: "option_contract".to_string(),
                handler_types: vec!["spend".to_string()],
                expected_signals: vec![
                    "checks_outputs".to_string(),
                    "checks_validity_range".to_string(),
                    "checks_value".to_string(),
                ],
            },
            ValidatorRole {
                role: "option_mint".to_string(),
                handler_types: vec!["mint".to_string()],
                expected_signals: vec!["checks_inputs".to_string()],
            },
        ],
        invariants: vec![
            ProtocolInvariant {
                name: "Expiry enforcement".to_string(),
                description: "Options must only be exercisable before the expiry deadline."
                    .to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::TemporalCoordination,
            },
            ProtocolInvariant {
                name: "Collateral locked until expiry".to_string(),
                description:
                    "Collateral backing the option must remain locked until exercise or expiry."
                        .to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::ValueConservation,
            },
            ProtocolInvariant {
                name: "Option token lifecycle".to_string(),
                description: "Option tokens must be burned on exercise or expiry.".to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::TokenLifecycle,
            },
        ],
    }
}

fn escrow_pattern() -> ProtocolPattern {
    ProtocolPattern {
        name: "Escrow Contract".to_string(),
        category: ProtocolCategory::Escrow,
        description: "Two-party escrow with dispute resolution and timeout.".to_string(),
        validators: vec![ValidatorRole {
            role: "escrow".to_string(),
            handler_types: vec!["spend".to_string()],
            expected_signals: vec![
                "checks_outputs".to_string(),
                "checks_signatories".to_string(),
                "checks_validity_range".to_string(),
            ],
        }],
        invariants: vec![
            ProtocolInvariant {
                name: "Escrow release authority".to_string(),
                description: "Funds must only be released with appropriate signatures.".to_string(),
                severity: Severity::Critical,
                check_type: InvariantCheckType::AuthorityChain,
            },
            ProtocolInvariant {
                name: "Timeout reclaim".to_string(),
                description: "Depositor must be able to reclaim funds after timeout.".to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::TemporalCoordination,
            },
            ProtocolInvariant {
                name: "Value preservation".to_string(),
                description: "Full escrowed value must be disbursed; no value leak.".to_string(),
                severity: Severity::High,
                check_type: InvariantCheckType::ValueConservation,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Protocol detection
// ---------------------------------------------------------------------------

/// Keyword sets used for heuristic protocol detection.
struct CategoryKeywords {
    category: ProtocolCategory,
    /// Keywords in validator/module names.
    name_keywords: Vec<&'static str>,
    /// Keywords in data type names, field labels, redeemer variant names, function names,
    /// and variable references.
    semantic_keywords: Vec<&'static str>,
}

fn category_keyword_sets() -> Vec<CategoryKeywords> {
    vec![
        CategoryKeywords {
            category: ProtocolCategory::Dex,
            name_keywords: vec!["pool", "swap", "dex", "amm", "router", "lp"],
            semantic_keywords: vec![
                "reserve",
                "liquidity",
                "swap",
                "lp_token",
                "lp_mint",
                "constant_product",
                "fee_numerator",
                "sqrt",
                "pool_datum",
                "batching",
            ],
        },
        CategoryKeywords {
            category: ProtocolCategory::Lending,
            name_keywords: vec!["lend", "loan", "borrow", "collateral", "liquidat"],
            semantic_keywords: vec![
                "collateral",
                "loan",
                "liquidation",
                "liquidate",
                "interest",
                "borrow",
                "health_factor",
                "debt",
                "supply",
                "utilization",
            ],
        },
        CategoryKeywords {
            category: ProtocolCategory::Staking,
            name_keywords: vec!["stake", "staking", "farm", "reward"],
            semantic_keywords: vec![
                "stake",
                "reward",
                "delegation",
                "epoch",
                "unstake",
                "claim_reward",
                "staked_amount",
                "reward_rate",
                "accumulator",
            ],
        },
        CategoryKeywords {
            category: ProtocolCategory::Dao,
            name_keywords: vec!["dao", "governance", "proposal", "vote", "treasury"],
            semantic_keywords: vec![
                "proposal",
                "vote",
                "quorum",
                "treasury",
                "ballot",
                "tally",
                "execution_delay",
                "governance_token",
            ],
        },
        CategoryKeywords {
            category: ProtocolCategory::NftMarketplace,
            name_keywords: vec!["marketplace", "listing", "auction", "bid"],
            semantic_keywords: vec![
                "listing",
                "bid",
                "royalty",
                "escrow",
                "seller",
                "buyer",
                "floor_price",
                "accept_bid",
                "cancel_listing",
            ],
        },
        CategoryKeywords {
            category: ProtocolCategory::Options,
            name_keywords: vec!["option", "call", "put", "strike"],
            semantic_keywords: vec![
                "strike",
                "expiry",
                "premium",
                "settlement",
                "exercise",
                "option_type",
                "underlying",
                "maturity",
                "binary",
            ],
        },
        CategoryKeywords {
            category: ProtocolCategory::Escrow,
            name_keywords: vec!["escrow"],
            semantic_keywords: vec![
                "escrow",
                "release",
                "dispute",
                "mediator",
                "timeout",
                "refund",
                "beneficiary",
            ],
        },
    ]
}

/// Collect all searchable text from modules for keyword matching.
fn collect_module_text(modules: &[ModuleInfo]) -> ModuleTextCorpus {
    let mut corpus = ModuleTextCorpus::default();

    for module in modules {
        // Module name
        corpus.names.push(module.name.to_lowercase());

        // Validator and handler names
        for validator in &module.validators {
            corpus.names.push(validator.name.to_lowercase());
            for handler in &validator.handlers {
                corpus.names.push(handler.name.to_lowercase());
                // Handler body signals: function calls, var references, record labels
                for call in &handler.body_signals.function_calls {
                    corpus.semantics.push(call.to_lowercase());
                }
                for var in &handler.body_signals.var_references {
                    corpus.semantics.push(var.to_lowercase());
                }
                for label in &handler.body_signals.all_record_labels {
                    corpus.semantics.push(label.to_lowercase());
                }
                // Handler param type names
                for param in &handler.params {
                    corpus.semantics.push(param.type_name.to_lowercase());
                    corpus.semantics.push(param.name.to_lowercase());
                }
            }
            // Validator params
            for param in &validator.params {
                corpus.semantics.push(param.type_name.to_lowercase());
                corpus.semantics.push(param.name.to_lowercase());
            }
        }

        // Data type names, constructor names, field labels
        for dt in &module.data_types {
            corpus.semantics.push(dt.name.to_lowercase());
            for ctor in &dt.constructors {
                corpus.semantics.push(ctor.name.to_lowercase());
                for field in &ctor.fields {
                    if let Some(ref label) = field.label {
                        corpus.semantics.push(label.to_lowercase());
                    }
                }
            }
        }

        // Function names
        for func in &module.functions {
            corpus.names.push(func.name.to_lowercase());
            for param in &func.params {
                corpus.semantics.push(param.name.to_lowercase());
            }
        }
    }

    corpus
}

#[derive(Default)]
struct ModuleTextCorpus {
    /// Validator/module/function names (matched against name_keywords).
    names: Vec<String>,
    /// Semantic tokens: data type fields, var references, function calls, etc.
    semantics: Vec<String>,
}

/// Score how well the corpus matches a set of keywords. Returns 0.0..1.0.
fn score_keywords(corpus: &ModuleTextCorpus, keywords: &CategoryKeywords) -> f64 {
    let mut score = 0.0_f64;
    let max_possible = (keywords.name_keywords.len() + keywords.semantic_keywords.len()) as f64;
    if max_possible == 0.0 {
        return 0.0;
    }

    // Name keyword matches carry double weight.
    for kw in &keywords.name_keywords {
        if corpus.names.iter().any(|n| n.contains(kw)) {
            score += 2.0;
        }
    }

    for kw in &keywords.semantic_keywords {
        if corpus.semantics.iter().any(|s| s.contains(kw)) {
            score += 1.0;
        }
    }

    // Normalize: name keywords count as 2 each, semantic as 1 each.
    let max_score =
        (keywords.name_keywords.len() as f64) * 2.0 + (keywords.semantic_keywords.len() as f64);
    if max_score == 0.0 {
        return 0.0;
    }
    (score / max_score).min(1.0)
}

/// Heuristic scoring: how well do the modules match each protocol category?
///
/// Returns a list of (category, score) pairs sorted by descending score.
pub fn score_protocol_patterns(modules: &[ModuleInfo]) -> Vec<(ProtocolCategory, f64)> {
    let corpus = collect_module_text(modules);
    let keyword_sets = category_keyword_sets();

    let mut scores: Vec<(ProtocolCategory, f64)> = keyword_sets
        .iter()
        .map(|kws| {
            let s = score_keywords(&corpus, kws);
            (kws.category.clone(), s)
        })
        .collect();

    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scores
}

/// Minimum score threshold to consider a pattern detected.
const DETECTION_THRESHOLD: f64 = 0.15;

/// Analyze modules and detect which protocol pattern they best match.
///
/// Returns `None` if no pattern scores above the detection threshold.
pub fn detect_protocol_pattern(modules: &[ModuleInfo]) -> Option<ProtocolPattern> {
    let scores = score_protocol_patterns(modules);
    let best = scores.first()?;
    if best.1 < DETECTION_THRESHOLD {
        return None;
    }

    let library = builtin_protocol_patterns();
    library.into_iter().find(|p| p.category == best.0)
}

// ---------------------------------------------------------------------------
// Token flow analysis
// ---------------------------------------------------------------------------

/// Analyze token flows between validators.
///
/// Detects mint->spend coordination, token reference patterns, and burn flows
/// by inspecting handler signals and validator graph relationships.
pub fn analyze_token_flows(modules: &[ModuleInfo]) -> Vec<TokenFlow> {
    let mut flows = Vec::new();

    // Pass 1: Categorize all validators by their handler types and signals.
    let mut mint_validators: Vec<String> = Vec::new();
    let mut spend_validators: Vec<String> = Vec::new();
    let mut burn_validators: Vec<String> = Vec::new();
    let mut spend_with_mint_access: Vec<String> = Vec::new();

    for module in modules {
        for validator in &module.validators {
            let vname = format!("{}/{}", module.name, validator.name);
            for handler in &validator.handlers {
                let signals = &handler.body_signals;

                if handler.name == "mint" {
                    mint_validators.push(vname.clone());
                }

                if handler.name == "spend" {
                    spend_validators.push(vname.clone());

                    if signals.tx_field_accesses.contains("mint") {
                        spend_with_mint_access.push(vname.clone());
                    }
                }

                // Burn evidence: mint handler with negate/burn calls
                let has_burn_evidence = signals.tx_field_accesses.contains("mint")
                    && signals.function_calls.iter().any(|c| {
                        c.contains("negate")
                            || c.contains("burn")
                            || c.contains("from_minted_value")
                    });
                if has_burn_evidence {
                    burn_validators.push(vname.clone());
                }
            }
        }
    }

    // Pass 2: Build flows from categorized validators.

    // Mint coordination: spend handlers that access `mint` field coordinate with mint validators.
    for spender in &spend_with_mint_access {
        for minter in &mint_validators {
            if spender != minter {
                flows.push(TokenFlow {
                    source_validator: spender.clone(),
                    dest_validator: minter.clone(),
                    token_type: TokenFlowType::Mint,
                    description: format!(
                        "Spend handler in {} coordinates with mint in {}",
                        spender, minter
                    ),
                });
            }
        }
    }

    // Token reference flows: spend validators that reference tokens (via param ByteArray)
    for module in modules {
        for validator in &module.validators {
            let vname = format!("{}/{}", module.name, validator.name);
            let has_token_param = validator
                .params
                .iter()
                .any(|p| p.type_name.contains("ByteArray") || p.type_name.contains("PolicyId"));
            if has_token_param {
                for minter in &mint_validators {
                    if minter != &vname {
                        flows.push(TokenFlow {
                            source_validator: minter.clone(),
                            dest_validator: vname.clone(),
                            token_type: TokenFlowType::Reference,
                            description: format!(
                                "{} references a token from {} via parameter",
                                vname, minter
                            ),
                        });
                    }
                }
            }
        }
    }

    // Transfer flows: spend validators that check outputs and value
    for module in modules {
        for validator in &module.validators {
            let vname = format!("{}/{}", module.name, validator.name);
            for handler in &validator.handlers {
                if handler.name == "spend" {
                    let signals = &handler.body_signals;
                    let checks_outputs = signals.tx_field_accesses.contains("outputs");
                    let checks_value = signals.all_record_labels.contains("value");

                    if checks_outputs && checks_value {
                        // This spend handler transfers value to outputs — find other spend
                        // validators that might receive it.
                        for other_spend in &spend_validators {
                            if other_spend != &vname {
                                flows.push(TokenFlow {
                                    source_validator: vname.clone(),
                                    dest_validator: other_spend.clone(),
                                    token_type: TokenFlowType::Transfer,
                                    description: format!(
                                        "Value transfer from {} to {} via outputs",
                                        vname, other_spend
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Burn flows: from spend validators to burn validators
    for burner in &burn_validators {
        for spender in &spend_validators {
            if spender != burner {
                flows.push(TokenFlow {
                    source_validator: spender.clone(),
                    dest_validator: burner.clone(),
                    token_type: TokenFlowType::Burn,
                    description: format!("Token from {} can be burned via {}", spender, burner),
                });
            }
        }
    }

    flows
}

// ---------------------------------------------------------------------------
// Authority flow analysis
// ---------------------------------------------------------------------------

/// Analyze how authorization requirements flow through the protocol.
///
/// Detects authority sources (signature checks, admin parameters) and identifies
/// validators that should propagate the same authority but may be missing checks.
pub fn analyze_authority_flows(modules: &[ModuleInfo]) -> Vec<AuthorityFlow> {
    let mut flows = Vec::new();

    // 1. Identify admin/authority parameters (ByteArray params with names suggesting PKH).
    let mut authority_sources: HashMap<String, Vec<String>> = HashMap::new();

    for module in modules {
        for validator in &module.validators {
            let vname = format!("{}/{}", module.name, validator.name);
            for param in &validator.params {
                let name_lower = param.name.to_lowercase();
                let is_authority = (name_lower.contains("admin")
                    || name_lower.contains("owner")
                    || name_lower.contains("authority")
                    || name_lower.contains("operator")
                    || name_lower.contains("pkh")
                    || name_lower.contains("key_hash"))
                    && (param.type_name.contains("ByteArray")
                        || param.type_name.contains("Credential")
                        || param.type_name.contains("Hash"));

                if is_authority {
                    let source = format!("{} (param: {})", vname, param.name);
                    authority_sources
                        .entry(param.name.clone())
                        .or_default()
                        .push(source);
                }
            }
        }
    }

    // 2. For each authority param, check which validators verify it via extra_signatories.
    for (param_name, sources) in &authority_sources {
        let mut checking_validators = Vec::new();
        let mut missing_validators = Vec::new();

        for module in modules {
            for validator in &module.validators {
                let vname = format!("{}/{}", module.name, validator.name);
                // Does this validator have the same authority param?
                let has_param = validator.params.iter().any(|p| p.name == *param_name);
                if !has_param {
                    continue;
                }

                // Does any handler in this validator check extra_signatories?
                let checks_sigs = validator.handlers.iter().any(|h| {
                    h.body_signals
                        .tx_field_accesses
                        .contains("extra_signatories")
                        || h.body_signals.requires_signature
                });

                if checks_sigs {
                    checking_validators.push(vname);
                } else {
                    missing_validators.push(vname);
                }
            }
        }

        if !sources.is_empty() {
            flows.push(AuthorityFlow {
                source: format!(
                    "Authority parameter '{}' in: {}",
                    param_name,
                    sources.join(", ")
                ),
                validators: checking_validators,
                missing_checks: missing_validators,
            });
        }
    }

    // 3. Detect shared datum authority: if a datum has an admin/owner field, validators
    //    using that datum type should check it.
    let mut admin_datum_types: HashMap<String, String> = HashMap::new();
    for module in modules {
        for dt in &module.data_types {
            for ctor in &dt.constructors {
                for field in &ctor.fields {
                    if let Some(ref label) = field.label {
                        let label_lower = label.to_lowercase();
                        if label_lower.contains("admin")
                            || label_lower.contains("owner")
                            || label_lower.contains("authority")
                        {
                            admin_datum_types.insert(dt.name.clone(), label.clone());
                        }
                    }
                }
            }
        }
    }

    for (type_name, field_name) in &admin_datum_types {
        let mut checking = Vec::new();
        let mut missing = Vec::new();

        for module in modules {
            for validator in &module.validators {
                let vname = format!("{}/{}", module.name, validator.name);
                // Does any handler use this datum type?
                let uses_type = validator
                    .handlers
                    .iter()
                    .any(|h| h.params.iter().any(|p| p.type_name == *type_name));
                if !uses_type {
                    continue;
                }

                let checks_field = validator.handlers.iter().any(|h| {
                    h.body_signals.datum_field_accesses.contains(field_name)
                        || h.body_signals.var_references.contains(field_name)
                        || h.body_signals
                            .tx_field_accesses
                            .contains("extra_signatories")
                });

                if checks_field {
                    checking.push(vname);
                } else {
                    missing.push(vname);
                }
            }
        }

        if !checking.is_empty() || !missing.is_empty() {
            flows.push(AuthorityFlow {
                source: format!("Datum field '{}' in type '{}'", field_name, type_name),
                validators: checking,
                missing_checks: missing,
            });
        }
    }

    flows
}

// ---------------------------------------------------------------------------
// Protocol report
// ---------------------------------------------------------------------------

/// Generate a human-readable protocol-level analysis report.
pub fn format_protocol_report(
    pattern: &Option<ProtocolPattern>,
    token_flows: &[TokenFlow],
    authority_flows: &[AuthorityFlow],
) -> String {
    let mut lines = Vec::new();

    lines.push("=== Protocol Analysis Report ===".to_string());
    lines.push(String::new());

    // Pattern detection
    match pattern {
        Some(p) => {
            lines.push(format!("Detected Pattern: {} ({})", p.name, p.category));
            lines.push(format!("Description: {}", p.description));
            lines.push(String::new());

            lines.push("Expected Validator Roles:".to_string());
            for role in &p.validators {
                lines.push(format!(
                    "  - {} [{}]: expects {}",
                    role.role,
                    role.handler_types.join(", "),
                    role.expected_signals.join(", ")
                ));
            }
            lines.push(String::new());

            lines.push("Protocol Invariants:".to_string());
            for inv in &p.invariants {
                lines.push(format!(
                    "  [{:?}] {} ({}): {}",
                    inv.severity, inv.name, inv.check_type, inv.description
                ));
            }
        }
        None => {
            lines.push("Detected Pattern: None (no recognized protocol pattern)".to_string());
        }
    }
    lines.push(String::new());

    // Token flows
    lines.push(format!("Token Flows ({}):", token_flows.len()));
    if token_flows.is_empty() {
        lines.push("  (none detected)".to_string());
    } else {
        for flow in token_flows {
            lines.push(format!(
                "  {} -> {} [{}]: {}",
                flow.source_validator, flow.dest_validator, flow.token_type, flow.description
            ));
        }
    }
    lines.push(String::new());

    // Authority flows
    lines.push(format!("Authority Flows ({}):", authority_flows.len()));
    if authority_flows.is_empty() {
        lines.push("  (none detected)".to_string());
    } else {
        for flow in authority_flows {
            lines.push(format!("  Source: {}", flow.source));
            if !flow.validators.is_empty() {
                lines.push(format!("    Checked by: {}", flow.validators.join(", ")));
            }
            if !flow.missing_checks.is_empty() {
                lines.push(format!(
                    "    MISSING checks in: {}",
                    flow.missing_checks.join(", ")
                ));
            }
        }
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;
    use std::collections::HashSet;

    // ---- Test helpers ----

    fn make_module(name: &str, validators: Vec<ValidatorInfo>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Validator,
            validators,
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    fn make_lib_module(name: &str, data_types: Vec<DataTypeInfo>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types,
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    fn make_validator(
        name: &str,
        params: Vec<ParamInfo>,
        handlers: Vec<HandlerInfo>,
    ) -> ValidatorInfo {
        ValidatorInfo {
            name: name.to_string(),
            params,
            handlers,
            summary: None,
        }
    }

    fn make_handler(name: &str, params: Vec<ParamInfo>, signals: BodySignals) -> HandlerInfo {
        HandlerInfo {
            name: name.to_string(),
            params,
            return_type: "Bool".to_string(),
            location: None,
            body_signals: signals,
        }
    }

    fn make_param(name: &str, type_name: &str) -> ParamInfo {
        ParamInfo {
            name: name.to_string(),
            type_name: type_name.to_string(),
        }
    }

    fn signals_with_tx_accesses(accesses: &[&str]) -> BodySignals {
        BodySignals {
            tx_field_accesses: accesses.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn signals_with_calls_and_accesses(calls: &[&str], accesses: &[&str]) -> BodySignals {
        BodySignals {
            tx_field_accesses: accesses.iter().map(|s| s.to_string()).collect(),
            function_calls: calls.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn signals_with_vars(vars: &[&str], accesses: &[&str]) -> BodySignals {
        BodySignals {
            tx_field_accesses: accesses.iter().map(|s| s.to_string()).collect(),
            var_references: vars.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn make_data_type(name: &str, constructors: Vec<ConstructorInfo>) -> DataTypeInfo {
        DataTypeInfo {
            name: name.to_string(),
            public: true,
            constructors,
        }
    }

    fn make_constructor(name: &str, fields: Vec<(&str, &str)>) -> ConstructorInfo {
        ConstructorInfo {
            name: name.to_string(),
            fields: fields
                .into_iter()
                .map(|(label, type_name)| FieldInfo {
                    label: Some(label.to_string()),
                    type_name: type_name.to_string(),
                })
                .collect(),
        }
    }

    // ---- Protocol detection tests ----

    #[test]
    fn test_detect_dex_pattern() {
        let modules = vec![
            make_module(
                "dex/pool",
                vec![make_validator(
                    "pool",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_vars(
                            &["reserve_a", "reserve_b", "liquidity"],
                            &["outputs", "mint"],
                        ),
                    )],
                )],
            ),
            make_module(
                "dex/lp_token",
                vec![make_validator(
                    "lp_mint",
                    vec![],
                    vec![make_handler(
                        "mint",
                        vec![],
                        signals_with_tx_accesses(&["inputs", "mint"]),
                    )],
                )],
            ),
        ];

        let pattern = detect_protocol_pattern(&modules);
        assert!(pattern.is_some(), "should detect DEX pattern");
        let p = pattern.unwrap();
        assert_eq!(p.category, ProtocolCategory::Dex);
    }

    #[test]
    fn test_detect_lending_pattern() {
        let modules = vec![
            make_module(
                "lending/pool",
                vec![make_validator(
                    "lending_pool",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_vars(
                            &["collateral", "loan_amount", "interest_rate"],
                            &["outputs"],
                        ),
                    )],
                )],
            ),
            make_module(
                "lending/liquidation",
                vec![make_validator(
                    "liquidation",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_vars(&["health_factor", "debt"], &["outputs"]),
                    )],
                )],
            ),
        ];

        let pattern = detect_protocol_pattern(&modules);
        assert!(pattern.is_some(), "should detect Lending pattern");
        let p = pattern.unwrap();
        assert_eq!(p.category, ProtocolCategory::Lending);
    }

    #[test]
    fn test_detect_staking_pattern() {
        let modules = vec![make_module(
            "staking/pool",
            vec![make_validator(
                "staking_pool",
                vec![],
                vec![make_handler(
                    "spend",
                    vec![],
                    signals_with_vars(
                        &["staked_amount", "reward_rate", "epoch"],
                        &["outputs", "validity_range"],
                    ),
                )],
            )],
        )];

        let pattern = detect_protocol_pattern(&modules);
        assert!(pattern.is_some(), "should detect Staking pattern");
        assert_eq!(pattern.unwrap().category, ProtocolCategory::Staking);
    }

    #[test]
    fn test_detect_dao_pattern() {
        let modules = vec![
            make_module(
                "dao/treasury",
                vec![make_validator(
                    "treasury",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_vars(
                            &["proposal", "quorum"],
                            &["outputs", "extra_signatories"],
                        ),
                    )],
                )],
            ),
            make_module(
                "dao/governance",
                vec![make_validator(
                    "governance",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_vars(&["vote", "tally"], &["outputs"]),
                    )],
                )],
            ),
        ];

        let pattern = detect_protocol_pattern(&modules);
        assert!(pattern.is_some(), "should detect DAO pattern");
        assert_eq!(pattern.unwrap().category, ProtocolCategory::Dao);
    }

    #[test]
    fn test_detect_options_pattern() {
        let modules = vec![make_module(
            "options/contract",
            vec![make_validator(
                "option_contract",
                vec![],
                vec![make_handler(
                    "spend",
                    vec![],
                    signals_with_vars(
                        &["strike_price", "expiry", "premium", "settlement"],
                        &["outputs", "validity_range"],
                    ),
                )],
            )],
        )];

        let pattern = detect_protocol_pattern(&modules);
        assert!(pattern.is_some(), "should detect Options pattern");
        assert_eq!(pattern.unwrap().category, ProtocolCategory::Options);
    }

    #[test]
    fn test_detect_nft_marketplace_pattern() {
        let modules = vec![make_module(
            "marketplace/listing",
            vec![make_validator(
                "listing",
                vec![],
                vec![make_handler(
                    "spend",
                    vec![],
                    signals_with_vars(
                        &["seller", "buyer", "royalty", "floor_price"],
                        &["outputs", "extra_signatories"],
                    ),
                )],
            )],
        )];

        let pattern = detect_protocol_pattern(&modules);
        assert!(pattern.is_some(), "should detect NFT Marketplace pattern");
        assert_eq!(pattern.unwrap().category, ProtocolCategory::NftMarketplace);
    }

    #[test]
    fn test_detect_escrow_pattern() {
        let modules = vec![make_module(
            "escrow/escrow",
            vec![make_validator(
                "escrow",
                vec![],
                vec![make_handler(
                    "spend",
                    vec![],
                    signals_with_vars(
                        &["beneficiary", "mediator", "refund", "timeout"],
                        &["outputs", "extra_signatories", "validity_range"],
                    ),
                )],
            )],
        )];

        let pattern = detect_protocol_pattern(&modules);
        assert!(pattern.is_some(), "should detect Escrow pattern");
        assert_eq!(pattern.unwrap().category, ProtocolCategory::Escrow);
    }

    #[test]
    fn test_detect_no_pattern_for_empty_modules() {
        let modules: Vec<ModuleInfo> = vec![];
        let pattern = detect_protocol_pattern(&modules);
        assert!(
            pattern.is_none(),
            "empty modules should not match any pattern"
        );
    }

    #[test]
    fn test_detect_no_pattern_for_generic_modules() {
        let modules = vec![make_module(
            "test/foo",
            vec![make_validator(
                "foo",
                vec![],
                vec![make_handler(
                    "spend",
                    vec![],
                    signals_with_tx_accesses(&["outputs"]),
                )],
            )],
        )];

        let pattern = detect_protocol_pattern(&modules);
        // Generic module with no matching keywords should be None or Unknown
        // depending on threshold
        if let Some(p) = &pattern {
            assert_eq!(p.category, ProtocolCategory::Unknown);
        }
    }

    #[test]
    fn test_score_protocol_patterns_returns_sorted() {
        let modules = vec![make_module(
            "dex/pool",
            vec![make_validator(
                "pool",
                vec![],
                vec![make_handler(
                    "spend",
                    vec![],
                    signals_with_vars(&["reserve_a", "liquidity", "swap"], &["outputs", "mint"]),
                )],
            )],
        )];

        let scores = score_protocol_patterns(&modules);
        assert!(!scores.is_empty());
        // Verify descending order
        for i in 1..scores.len() {
            assert!(
                scores[i - 1].1 >= scores[i].1,
                "scores should be sorted descending"
            );
        }
        // DEX should be the top scorer
        assert_eq!(scores[0].0, ProtocolCategory::Dex);
    }

    // ---- Token flow tests ----

    #[test]
    fn test_analyze_token_flows_mint_coordination() {
        let modules = vec![
            make_module(
                "protocol/pool",
                vec![make_validator(
                    "pool",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs", "mint"]),
                    )],
                )],
            ),
            make_module(
                "protocol/token",
                vec![make_validator(
                    "token",
                    vec![],
                    vec![make_handler(
                        "mint",
                        vec![],
                        signals_with_tx_accesses(&["mint"]),
                    )],
                )],
            ),
        ];

        let flows = analyze_token_flows(&modules);
        assert!(
            flows.iter().any(|f| f.token_type == TokenFlowType::Mint),
            "should detect mint coordination flow"
        );
    }

    #[test]
    fn test_analyze_token_flows_burn() {
        let modules = vec![
            make_module(
                "protocol/pool",
                vec![make_validator(
                    "pool",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs", "inputs"]),
                    )],
                )],
            ),
            make_module(
                "protocol/token",
                vec![make_validator(
                    "token",
                    vec![],
                    vec![make_handler(
                        "mint",
                        vec![],
                        signals_with_calls_and_accesses(
                            &["value.negate", "value.from_minted_value"],
                            &["mint"],
                        ),
                    )],
                )],
            ),
        ];

        let flows = analyze_token_flows(&modules);
        assert!(
            flows.iter().any(|f| f.token_type == TokenFlowType::Burn),
            "should detect burn flow"
        );
    }

    #[test]
    fn test_analyze_token_flows_reference() {
        let modules = vec![
            make_module(
                "protocol/pool",
                vec![make_validator(
                    "pool",
                    vec![make_param("token_policy", "ByteArray")],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs"]),
                    )],
                )],
            ),
            make_module(
                "protocol/token",
                vec![make_validator(
                    "token",
                    vec![],
                    vec![make_handler(
                        "mint",
                        vec![],
                        signals_with_tx_accesses(&["mint"]),
                    )],
                )],
            ),
        ];

        let flows = analyze_token_flows(&modules);
        assert!(
            flows
                .iter()
                .any(|f| f.token_type == TokenFlowType::Reference),
            "should detect token reference flow"
        );
    }

    #[test]
    fn test_analyze_token_flows_transfer() {
        let modules = vec![
            make_module(
                "protocol/pool_a",
                vec![make_validator(
                    "pool_a",
                    vec![],
                    vec![make_handler("spend", vec![], {
                        let mut s = signals_with_tx_accesses(&["outputs"]);
                        s.all_record_labels.insert("value".to_string());
                        s
                    })],
                )],
            ),
            make_module(
                "protocol/pool_b",
                vec![make_validator(
                    "pool_b",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs"]),
                    )],
                )],
            ),
        ];

        let flows = analyze_token_flows(&modules);
        assert!(
            flows
                .iter()
                .any(|f| f.token_type == TokenFlowType::Transfer),
            "should detect value transfer flow"
        );
    }

    #[test]
    fn test_analyze_token_flows_empty() {
        let flows = analyze_token_flows(&[]);
        assert!(flows.is_empty());
    }

    // ---- Authority flow tests ----

    #[test]
    fn test_authority_flow_param_checked() {
        let modules = vec![
            make_module(
                "protocol/pool",
                vec![make_validator(
                    "pool",
                    vec![make_param("admin_pkh", "ByteArray")],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs", "extra_signatories"]),
                    )],
                )],
            ),
            make_module(
                "protocol/token",
                vec![make_validator(
                    "token",
                    vec![make_param("admin_pkh", "ByteArray")],
                    vec![make_handler(
                        "mint",
                        vec![],
                        signals_with_tx_accesses(&["mint"]),
                    )],
                )],
            ),
        ];

        let flows = analyze_authority_flows(&modules);
        assert!(!flows.is_empty(), "should detect authority flows");

        let admin_flow = flows
            .iter()
            .find(|f| f.source.contains("admin_pkh"))
            .expect("should have admin_pkh flow");
        assert!(
            !admin_flow.validators.is_empty(),
            "pool should be in checking validators"
        );
        assert!(
            !admin_flow.missing_checks.is_empty(),
            "token should be in missing checks"
        );
    }

    #[test]
    fn test_authority_flow_datum_field() {
        let modules = vec![
            make_lib_module(
                "protocol/types",
                vec![make_data_type(
                    "PoolDatum",
                    vec![make_constructor(
                        "PoolDatum",
                        vec![("admin_key", "ByteArray"), ("reserve", "Int")],
                    )],
                )],
            ),
            make_module(
                "protocol/pool",
                vec![make_validator(
                    "pool",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![make_param("datum", "PoolDatum")],
                        {
                            let mut s = signals_with_tx_accesses(&["outputs", "extra_signatories"]);
                            s.datum_field_accesses.insert("admin_key".to_string());
                            s
                        },
                    )],
                )],
            ),
            make_module(
                "protocol/token",
                vec![make_validator(
                    "token",
                    vec![],
                    vec![make_handler(
                        "mint",
                        vec![make_param("datum", "PoolDatum")],
                        signals_with_tx_accesses(&["mint"]),
                    )],
                )],
            ),
        ];

        let flows = analyze_authority_flows(&modules);
        let datum_flow = flows.iter().find(|f| f.source.contains("admin_key"));
        assert!(
            datum_flow.is_some(),
            "should detect datum field authority flow"
        );
    }

    #[test]
    fn test_authority_flow_all_checked() {
        let modules = vec![
            make_module(
                "protocol/pool",
                vec![make_validator(
                    "pool",
                    vec![make_param("admin_pkh", "ByteArray")],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs", "extra_signatories"]),
                    )],
                )],
            ),
            make_module(
                "protocol/token",
                vec![make_validator(
                    "token",
                    vec![make_param("admin_pkh", "ByteArray")],
                    vec![make_handler(
                        "mint",
                        vec![],
                        signals_with_tx_accesses(&["mint", "extra_signatories"]),
                    )],
                )],
            ),
        ];

        let flows = analyze_authority_flows(&modules);
        let admin_flow = flows
            .iter()
            .find(|f| f.source.contains("admin_pkh"))
            .expect("should have admin_pkh flow");
        assert!(
            admin_flow.missing_checks.is_empty(),
            "all validators check admin_pkh, no missing"
        );
        assert_eq!(admin_flow.validators.len(), 2);
    }

    #[test]
    fn test_authority_flow_empty_modules() {
        let flows = analyze_authority_flows(&[]);
        assert!(flows.is_empty());
    }

    // ---- Report formatting tests ----

    #[test]
    fn test_format_report_with_pattern() {
        let pattern = Some(dex_pattern());
        let flows = vec![TokenFlow {
            source_validator: "pool".to_string(),
            dest_validator: "lp_mint".to_string(),
            token_type: TokenFlowType::Mint,
            description: "Pool coordinates LP mint".to_string(),
        }];
        let auth = vec![AuthorityFlow {
            source: "admin_pkh param".to_string(),
            validators: vec!["pool".to_string()],
            missing_checks: vec!["factory".to_string()],
        }];

        let report = format_protocol_report(&pattern, &flows, &auth);
        assert!(report.contains("Decentralized Exchange"));
        assert!(report.contains("Token Flows (1)"));
        assert!(report.contains("pool -> lp_mint"));
        assert!(report.contains("Authority Flows (1)"));
        assert!(report.contains("MISSING checks in: factory"));
    }

    #[test]
    fn test_format_report_without_pattern() {
        let report = format_protocol_report(&None, &[], &[]);
        assert!(report.contains("no recognized protocol pattern"));
        assert!(report.contains("Token Flows (0)"));
        assert!(report.contains("Authority Flows (0)"));
    }

    #[test]
    fn test_format_report_multiple_flows() {
        let flows = vec![
            TokenFlow {
                source_validator: "a".to_string(),
                dest_validator: "b".to_string(),
                token_type: TokenFlowType::Mint,
                description: "mint flow".to_string(),
            },
            TokenFlow {
                source_validator: "b".to_string(),
                dest_validator: "c".to_string(),
                token_type: TokenFlowType::Transfer,
                description: "transfer flow".to_string(),
            },
        ];

        let report = format_protocol_report(&None, &flows, &[]);
        assert!(report.contains("Token Flows (2)"));
        assert!(report.contains("a -> b [Mint]"));
        assert!(report.contains("b -> c [Transfer]"));
    }

    // ---- Built-in pattern library tests ----

    #[test]
    fn test_builtin_patterns_cover_all_categories() {
        let patterns = builtin_protocol_patterns();
        let categories: HashSet<_> = patterns.iter().map(|p| &p.category).collect();

        assert!(categories.contains(&ProtocolCategory::Dex));
        assert!(categories.contains(&ProtocolCategory::Lending));
        assert!(categories.contains(&ProtocolCategory::Staking));
        assert!(categories.contains(&ProtocolCategory::Dao));
        assert!(categories.contains(&ProtocolCategory::NftMarketplace));
        assert!(categories.contains(&ProtocolCategory::Options));
        assert!(categories.contains(&ProtocolCategory::Escrow));
        assert_eq!(patterns.len(), 7);
    }

    #[test]
    fn test_all_patterns_have_invariants() {
        for pattern in builtin_protocol_patterns() {
            assert!(
                !pattern.invariants.is_empty(),
                "pattern {} should have at least one invariant",
                pattern.name
            );
        }
    }

    #[test]
    fn test_all_patterns_have_validators() {
        for pattern in builtin_protocol_patterns() {
            assert!(
                !pattern.validators.is_empty(),
                "pattern {} should have at least one validator role",
                pattern.name
            );
        }
    }

    #[test]
    fn test_invariant_check_types_coverage() {
        let patterns = builtin_protocol_patterns();
        let check_types: HashSet<_> = patterns
            .iter()
            .flat_map(|p| p.invariants.iter().map(|i| &i.check_type))
            .collect();

        assert!(check_types.contains(&InvariantCheckType::TokenLifecycle));
        assert!(check_types.contains(&InvariantCheckType::ValueConservation));
        assert!(check_types.contains(&InvariantCheckType::AuthorityChain));
        assert!(check_types.contains(&InvariantCheckType::DatumConsistency));
        assert!(check_types.contains(&InvariantCheckType::TemporalCoordination));
    }

    // ---- Display impl tests ----

    #[test]
    fn test_protocol_category_display() {
        assert_eq!(format!("{}", ProtocolCategory::Dex), "DEX");
        assert_eq!(format!("{}", ProtocolCategory::Lending), "Lending");
        assert_eq!(format!("{}", ProtocolCategory::Staking), "Staking");
        assert_eq!(format!("{}", ProtocolCategory::Dao), "DAO");
        assert_eq!(
            format!("{}", ProtocolCategory::NftMarketplace),
            "NFT Marketplace"
        );
        assert_eq!(format!("{}", ProtocolCategory::Options), "Options");
        assert_eq!(format!("{}", ProtocolCategory::Escrow), "Escrow");
        assert_eq!(format!("{}", ProtocolCategory::Unknown), "Unknown");
    }

    #[test]
    fn test_invariant_check_type_display() {
        assert_eq!(
            format!("{}", InvariantCheckType::TokenLifecycle),
            "Token Lifecycle"
        );
        assert_eq!(
            format!("{}", InvariantCheckType::ValueConservation),
            "Value Conservation"
        );
        assert_eq!(
            format!("{}", InvariantCheckType::AuthorityChain),
            "Authority Chain"
        );
        assert_eq!(
            format!("{}", InvariantCheckType::DatumConsistency),
            "Datum Consistency"
        );
        assert_eq!(
            format!("{}", InvariantCheckType::TemporalCoordination),
            "Temporal Coordination"
        );
    }

    #[test]
    fn test_token_flow_type_display() {
        assert_eq!(format!("{}", TokenFlowType::Mint), "Mint");
        assert_eq!(format!("{}", TokenFlowType::Transfer), "Transfer");
        assert_eq!(format!("{}", TokenFlowType::Burn), "Burn");
        assert_eq!(format!("{}", TokenFlowType::Reference), "Reference");
    }

    // ---- Edge case tests ----

    #[test]
    fn test_scoring_with_no_keywords() {
        let corpus = ModuleTextCorpus::default();
        let kws = CategoryKeywords {
            category: ProtocolCategory::Unknown,
            name_keywords: vec![],
            semantic_keywords: vec![],
        };
        assert_eq!(score_keywords(&corpus, &kws), 0.0);
    }

    #[test]
    fn test_lib_modules_ignored_for_validator_analysis() {
        let modules = vec![make_lib_module("types", vec![])];
        let flows = analyze_token_flows(&modules);
        assert!(flows.is_empty());
    }

    #[test]
    fn test_multiple_authority_sources() {
        let modules = vec![
            make_module(
                "protocol/a",
                vec![make_validator(
                    "a",
                    vec![
                        make_param("admin_pkh", "ByteArray"),
                        make_param("owner_key", "Hash<Blake2b_224, VerificationKey>"),
                    ],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs", "extra_signatories"]),
                    )],
                )],
            ),
            make_module(
                "protocol/b",
                vec![make_validator(
                    "b",
                    vec![make_param("admin_pkh", "ByteArray")],
                    vec![make_handler(
                        "mint",
                        vec![],
                        signals_with_tx_accesses(&["mint"]),
                    )],
                )],
            ),
        ];

        let flows = analyze_authority_flows(&modules);
        // Should find flows for both admin_pkh and owner_key
        assert!(!flows.is_empty());
        assert!(
            flows.iter().any(|f| f.source.contains("admin_pkh")),
            "should track admin_pkh authority"
        );
    }

    #[test]
    fn test_protocol_detection_data_types_influence_score() {
        // Data type fields should contribute to scoring
        let modules = vec![
            make_lib_module(
                "types",
                vec![make_data_type(
                    "PoolDatum",
                    vec![make_constructor(
                        "PoolDatum",
                        vec![
                            ("reserve_a", "Int"),
                            ("reserve_b", "Int"),
                            ("liquidity_shares", "Int"),
                        ],
                    )],
                )],
            ),
            make_module(
                "validators/swap",
                vec![make_validator(
                    "swap",
                    vec![],
                    vec![make_handler(
                        "spend",
                        vec![],
                        signals_with_tx_accesses(&["outputs"]),
                    )],
                )],
            ),
        ];

        let scores = score_protocol_patterns(&modules);
        let dex_score = scores
            .iter()
            .find(|(c, _)| *c == ProtocolCategory::Dex)
            .map(|(_, s)| *s)
            .unwrap_or(0.0);
        assert!(
            dex_score > 0.0,
            "data type fields 'reserve', 'liquidity' should boost DEX score"
        );
    }

    #[test]
    fn test_requires_signature_flag_counts_as_authority_check() {
        let modules = vec![make_module(
            "protocol/pool",
            vec![make_validator(
                "pool",
                vec![make_param("admin_pkh", "ByteArray")],
                vec![make_handler("spend", vec![], {
                    let mut s = BodySignals {
                        requires_signature: true,
                        ..Default::default()
                    };
                    s.tx_field_accesses.insert("outputs".to_string());
                    s
                })],
            )],
        )];

        let flows = analyze_authority_flows(&modules);
        let admin_flow = flows.iter().find(|f| f.source.contains("admin_pkh"));
        assert!(admin_flow.is_some());
        assert!(
            admin_flow
                .unwrap()
                .validators
                .contains(&"protocol/pool/pool".to_string()),
            "requires_signature should count as authority check"
        );
    }
}
