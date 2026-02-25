use serde::Serialize;

use crate::detector::trait_def::{Confidence, SourceLocation};

/// Evidence level indicating how thoroughly a finding has been verified.
/// Higher levels provide stronger proof of exploitability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum EvidenceLevel {
    /// Level 0: Current static analysis - pattern matched in AST
    PatternMatch,
    /// Level 1: CFG path verified - a concrete execution path exists
    PathVerified,
    /// Level 2: Z3 proved exploitability - SMT solver confirmed satisfiability
    SmtProven,
    /// Level 3: UPLC execution confirmed - actual on-chain bytecode simulation
    SimulationConfirmed,
    /// Level 4: Multiple analysis lanes agree on the finding
    Corroborated,
}

impl std::fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceLevel::PatternMatch => write!(f, "pattern-match"),
            EvidenceLevel::PathVerified => write!(f, "path-verified"),
            EvidenceLevel::SmtProven => write!(f, "smt-proven"),
            EvidenceLevel::SimulationConfirmed => write!(f, "simulation-confirmed"),
            EvidenceLevel::Corroborated => write!(f, "corroborated"),
        }
    }
}

/// Evidence attached to a finding, providing proof and traceability.
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    /// The verification level achieved for this finding.
    pub level: EvidenceLevel,
    /// Method used to produce this evidence (e.g., "static-pattern", "cfg-path", "z3-sat", "uplc-exec").
    pub method: String,
    /// Human-readable explanation of the evidence.
    pub details: Option<String>,
    /// Step-by-step path through the code showing how data flows to the vulnerability.
    pub code_flow: Vec<CodeFlowStep>,
    /// SMT witness values or simulation trace (serialized as JSON).
    pub witness: Option<serde_json::Value>,
    /// Confidence multiplier from this evidence (0.0 to 1.0).
    /// Higher values increase confidence; lower values decrease it.
    pub confidence_boost: f64,
}

/// A single step in a code flow trace.
#[derive(Debug, Clone, Serialize)]
pub struct CodeFlowStep {
    /// Source location of this step, if available.
    pub location: Option<SourceLocation>,
    /// Human-readable description of what happens at this step.
    pub message: String,
    /// The role of this step in the vulnerability flow.
    pub kind: CodeFlowKind,
}

/// The role of a code flow step in the vulnerability trace.
#[derive(Debug, Clone, Serialize)]
pub enum CodeFlowKind {
    /// Where tainted/untrusted data enters the system.
    Source,
    /// How the data propagates through the code.
    Propagation,
    /// Where the tainted data reaches a sensitive operation.
    Sink,
    /// A check/guard that should have caught the issue but didn't.
    Guard,
}

impl std::fmt::Display for CodeFlowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeFlowKind::Source => write!(f, "source"),
            CodeFlowKind::Propagation => write!(f, "propagation"),
            CodeFlowKind::Sink => write!(f, "sink"),
            CodeFlowKind::Guard => write!(f, "guard"),
        }
    }
}

/// Create Level 0 (PatternMatch) evidence with a description.
pub fn evidence_pattern_match(description: &str) -> Evidence {
    Evidence {
        level: EvidenceLevel::PatternMatch,
        method: "static-pattern".to_string(),
        details: Some(description.to_string()),
        code_flow: vec![],
        witness: None,
        confidence_boost: 0.0,
    }
}

/// Create Level 1 (PathVerified) evidence with a concrete code flow path.
pub fn evidence_path_verified(path: &[CodeFlowStep]) -> Evidence {
    Evidence {
        level: EvidenceLevel::PathVerified,
        method: "cfg-path".to_string(),
        details: Some("Concrete execution path verified through CFG analysis".to_string()),
        code_flow: path.to_vec(),
        witness: None,
        confidence_boost: 0.3,
    }
}

/// Compute effective confidence by boosting/reducing the base confidence
/// according to the evidence level and confidence_boost.
///
/// The evidence level provides a baseline multiplier:
/// - PatternMatch: no change (0.0)
/// - PathVerified: +0.3 boost
/// - SmtProven: +0.6 boost
/// - SimulationConfirmed: +0.8 boost
/// - Corroborated: +1.0 boost (always Definite)
///
/// The `confidence_boost` field on Evidence can override the level-based default.
pub fn compute_effective_confidence(base: &Confidence, evidence: &Evidence) -> Confidence {
    let boost = if evidence.confidence_boost > 0.0 {
        evidence.confidence_boost
    } else {
        match evidence.level {
            EvidenceLevel::PatternMatch => 0.0,
            EvidenceLevel::PathVerified => 0.3,
            EvidenceLevel::SmtProven => 0.6,
            EvidenceLevel::SimulationConfirmed => 0.8,
            EvidenceLevel::Corroborated => 1.0,
        }
    };

    if boost >= 0.8 {
        Confidence::Definite
    } else if boost >= 0.3 {
        match base {
            Confidence::Possible => Confidence::Likely,
            Confidence::Likely => Confidence::Definite,
            Confidence::Definite => Confidence::Definite,
        }
    } else {
        base.clone()
    }
}

/// Format evidence into a human-readable description.
pub fn format_evidence(evidence: &Evidence) -> String {
    let mut parts = Vec::new();

    parts.push(format!(
        "Evidence Level: {} ({})",
        evidence.level, evidence.method
    ));

    if let Some(ref details) = evidence.details {
        parts.push(format!("Details: {details}"));
    }

    if !evidence.code_flow.is_empty() {
        parts.push("Code Flow:".to_string());
        for (i, step) in evidence.code_flow.iter().enumerate() {
            let loc_str = step
                .location
                .as_ref()
                .map(|loc| {
                    let line = loc.line_start.map_or("?".to_string(), |l| l.to_string());
                    let col = loc.column_start.map_or("?".to_string(), |c| c.to_string());
                    format!("{}:{}:{}", loc.module_path, line, col)
                })
                .unwrap_or_else(|| "unknown".to_string());
            parts.push(format!(
                "  Step {}: [{}] {} (at {})",
                i + 1,
                step.kind,
                step.message,
                loc_str
            ));
        }
    }

    if let Some(ref witness) = evidence.witness {
        parts.push(format!("Witness: {witness}"));
    }

    if evidence.confidence_boost > 0.0 {
        parts.push(format!(
            "Confidence Boost: +{:.0}%",
            evidence.confidence_boost * 100.0
        ));
    }

    parts.join("\n")
}

/// Convert evidence to a SARIF codeFlows JSON value.
///
/// Produces a SARIF v2.1.0 codeFlows array with a single threadFlow
/// containing the evidence's code flow steps.
pub fn evidence_to_sarif_code_flow(evidence: &Evidence) -> serde_json::Value {
    if evidence.code_flow.is_empty() {
        return serde_json::json!([]);
    }

    let locations: Vec<serde_json::Value> = evidence
        .code_flow
        .iter()
        .map(|step| {
            let (uri, region) = step
                .location
                .as_ref()
                .map(|loc| {
                    let uri = loc.module_path.clone();
                    let region = if let Some(line) = loc.line_start {
                        let mut r = serde_json::json!({ "startLine": line });
                        if let Some(col) = loc.column_start {
                            r["startColumn"] = serde_json::json!(col);
                        }
                        if let Some(end_line) = loc.line_end {
                            r["endLine"] = serde_json::json!(end_line);
                        }
                        if let Some(end_col) = loc.column_end {
                            r["endColumn"] = serde_json::json!(end_col);
                        }
                        Some(r)
                    } else {
                        None
                    };
                    (uri, region)
                })
                .unwrap_or_else(|| ("unknown".to_string(), None));

            let mut physical_location = serde_json::json!({
                "artifactLocation": { "uri": uri }
            });
            if let Some(r) = region {
                physical_location["region"] = r;
            }

            let mut tfl = serde_json::json!({
                "location": {
                    "physicalLocation": physical_location
                }
            });

            // Add message with kind prefix
            let msg = format!("[{}] {}", step.kind, step.message);
            tfl["message"] = serde_json::json!({ "text": msg });

            tfl
        })
        .collect();

    serde_json::json!([{
        "threadFlows": [{
            "locations": locations
        }]
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::trait_def::SourceLocation;

    #[test]
    fn test_evidence_level_display() {
        assert_eq!(EvidenceLevel::PatternMatch.to_string(), "pattern-match");
        assert_eq!(EvidenceLevel::PathVerified.to_string(), "path-verified");
        assert_eq!(EvidenceLevel::SmtProven.to_string(), "smt-proven");
        assert_eq!(
            EvidenceLevel::SimulationConfirmed.to_string(),
            "simulation-confirmed"
        );
        assert_eq!(EvidenceLevel::Corroborated.to_string(), "corroborated");
    }

    #[test]
    fn test_evidence_level_equality() {
        assert_eq!(EvidenceLevel::PatternMatch, EvidenceLevel::PatternMatch);
        assert_ne!(EvidenceLevel::PatternMatch, EvidenceLevel::PathVerified);
    }

    #[test]
    fn test_code_flow_kind_display() {
        assert_eq!(CodeFlowKind::Source.to_string(), "source");
        assert_eq!(CodeFlowKind::Propagation.to_string(), "propagation");
        assert_eq!(CodeFlowKind::Sink.to_string(), "sink");
        assert_eq!(CodeFlowKind::Guard.to_string(), "guard");
    }

    #[test]
    fn test_evidence_pattern_match() {
        let evidence = evidence_pattern_match("Missing signature check in spend handler");
        assert_eq!(evidence.level, EvidenceLevel::PatternMatch);
        assert_eq!(evidence.method, "static-pattern");
        assert_eq!(
            evidence.details.as_deref(),
            Some("Missing signature check in spend handler")
        );
        assert!(evidence.code_flow.is_empty());
        assert!(evidence.witness.is_none());
        assert_eq!(evidence.confidence_boost, 0.0);
    }

    #[test]
    fn test_evidence_path_verified_empty() {
        let evidence = evidence_path_verified(&[]);
        assert_eq!(evidence.level, EvidenceLevel::PathVerified);
        assert_eq!(evidence.method, "cfg-path");
        assert!(evidence.code_flow.is_empty());
        assert_eq!(evidence.confidence_boost, 0.3);
    }

    #[test]
    fn test_evidence_path_verified_with_steps() {
        let steps = vec![
            CodeFlowStep {
                location: Some(SourceLocation::from_bytes("validators/test.ak", 0, 10)),
                message: "Redeemer data enters here".to_string(),
                kind: CodeFlowKind::Source,
            },
            CodeFlowStep {
                location: Some(SourceLocation::from_bytes("validators/test.ak", 50, 80)),
                message: "Passed to arithmetic operation".to_string(),
                kind: CodeFlowKind::Propagation,
            },
            CodeFlowStep {
                location: Some(SourceLocation::from_bytes("validators/test.ak", 100, 120)),
                message: "Used in value calculation without bounds check".to_string(),
                kind: CodeFlowKind::Sink,
            },
        ];
        let evidence = evidence_path_verified(&steps);
        assert_eq!(evidence.level, EvidenceLevel::PathVerified);
        assert_eq!(evidence.code_flow.len(), 3);
        assert_eq!(evidence.code_flow[0].message, "Redeemer data enters here");
        assert!(matches!(evidence.code_flow[0].kind, CodeFlowKind::Source));
        assert!(matches!(evidence.code_flow[2].kind, CodeFlowKind::Sink));
    }

    #[test]
    fn test_compute_effective_confidence_pattern_match_no_boost() {
        let evidence = evidence_pattern_match("test");
        assert_eq!(
            compute_effective_confidence(&Confidence::Possible, &evidence),
            Confidence::Possible
        );
        assert_eq!(
            compute_effective_confidence(&Confidence::Likely, &evidence),
            Confidence::Likely
        );
        assert_eq!(
            compute_effective_confidence(&Confidence::Definite, &evidence),
            Confidence::Definite
        );
    }

    #[test]
    fn test_compute_effective_confidence_path_verified_boosts() {
        let evidence = evidence_path_verified(&[]);
        // PathVerified has 0.3 boost (from the confidence_boost field)
        assert_eq!(
            compute_effective_confidence(&Confidence::Possible, &evidence),
            Confidence::Likely
        );
        assert_eq!(
            compute_effective_confidence(&Confidence::Likely, &evidence),
            Confidence::Definite
        );
        assert_eq!(
            compute_effective_confidence(&Confidence::Definite, &evidence),
            Confidence::Definite
        );
    }

    #[test]
    fn test_compute_effective_confidence_smt_proven() {
        let evidence = Evidence {
            level: EvidenceLevel::SmtProven,
            method: "z3-sat".to_string(),
            details: None,
            code_flow: vec![],
            witness: Some(serde_json::json!({"x": 0, "y": -1})),
            confidence_boost: 0.6,
        };
        // 0.6 boost -> Possible becomes Likely
        assert_eq!(
            compute_effective_confidence(&Confidence::Possible, &evidence),
            Confidence::Likely
        );
    }

    #[test]
    fn test_compute_effective_confidence_simulation_confirmed() {
        let evidence = Evidence {
            level: EvidenceLevel::SimulationConfirmed,
            method: "uplc-exec".to_string(),
            details: None,
            code_flow: vec![],
            witness: None,
            confidence_boost: 0.8,
        };
        // 0.8 boost -> always Definite
        assert_eq!(
            compute_effective_confidence(&Confidence::Possible, &evidence),
            Confidence::Definite
        );
    }

    #[test]
    fn test_compute_effective_confidence_corroborated() {
        let evidence = Evidence {
            level: EvidenceLevel::Corroborated,
            method: "multi-lane".to_string(),
            details: None,
            code_flow: vec![],
            witness: None,
            confidence_boost: 1.0,
        };
        assert_eq!(
            compute_effective_confidence(&Confidence::Possible, &evidence),
            Confidence::Definite
        );
    }

    #[test]
    fn test_compute_effective_confidence_custom_boost_overrides_level() {
        // PatternMatch level normally gives 0.0 boost, but custom boost overrides
        let evidence = Evidence {
            level: EvidenceLevel::PatternMatch,
            method: "static-pattern".to_string(),
            details: None,
            code_flow: vec![],
            witness: None,
            confidence_boost: 0.5, // custom override
        };
        assert_eq!(
            compute_effective_confidence(&Confidence::Possible, &evidence),
            Confidence::Likely
        );
    }

    #[test]
    fn test_format_evidence_basic() {
        let evidence = evidence_pattern_match("Missing check");
        let formatted = format_evidence(&evidence);
        assert!(formatted.contains("Evidence Level: pattern-match (static-pattern)"));
        assert!(formatted.contains("Details: Missing check"));
        // No code flow, witness, or boost for pattern match
        assert!(!formatted.contains("Code Flow:"));
        assert!(!formatted.contains("Witness:"));
        assert!(!formatted.contains("Confidence Boost:"));
    }

    #[test]
    fn test_format_evidence_with_code_flow() {
        let steps = vec![
            CodeFlowStep {
                location: Some(SourceLocation {
                    module_path: "validators/test.ak".to_string(),
                    byte_start: 0,
                    byte_end: 10,
                    line_start: Some(5),
                    column_start: Some(3),
                    line_end: Some(5),
                    column_end: Some(20),
                }),
                message: "Data enters here".to_string(),
                kind: CodeFlowKind::Source,
            },
            CodeFlowStep {
                location: None,
                message: "Flows through function call".to_string(),
                kind: CodeFlowKind::Propagation,
            },
        ];
        let evidence = evidence_path_verified(&steps);
        let formatted = format_evidence(&evidence);
        assert!(formatted.contains("Code Flow:"));
        assert!(formatted.contains("Step 1: [source] Data enters here (at validators/test.ak:5:3)"));
        assert!(
            formatted.contains("Step 2: [propagation] Flows through function call (at unknown)")
        );
        assert!(formatted.contains("Confidence Boost: +30%"));
    }

    #[test]
    fn test_format_evidence_with_witness() {
        let evidence = Evidence {
            level: EvidenceLevel::SmtProven,
            method: "z3-sat".to_string(),
            details: Some("Division by zero is satisfiable".to_string()),
            code_flow: vec![],
            witness: Some(serde_json::json!({"divisor": 0})),
            confidence_boost: 0.6,
        };
        let formatted = format_evidence(&evidence);
        assert!(formatted.contains("Evidence Level: smt-proven (z3-sat)"));
        assert!(formatted.contains("Witness:"));
        assert!(formatted.contains("\"divisor\":0") || formatted.contains("\"divisor\": 0"));
    }

    #[test]
    fn test_evidence_to_sarif_code_flow_empty() {
        let evidence = evidence_pattern_match("test");
        let sarif = evidence_to_sarif_code_flow(&evidence);
        assert_eq!(sarif, serde_json::json!([]));
    }

    #[test]
    fn test_evidence_to_sarif_code_flow_with_steps() {
        let steps = vec![
            CodeFlowStep {
                location: Some(SourceLocation {
                    module_path: "validators/test.ak".to_string(),
                    byte_start: 0,
                    byte_end: 10,
                    line_start: Some(5),
                    column_start: Some(3),
                    line_end: Some(5),
                    column_end: Some(20),
                }),
                message: "Redeemer data enters".to_string(),
                kind: CodeFlowKind::Source,
            },
            CodeFlowStep {
                location: Some(SourceLocation {
                    module_path: "validators/test.ak".to_string(),
                    byte_start: 100,
                    byte_end: 120,
                    line_start: Some(15),
                    column_start: Some(5),
                    line_end: Some(15),
                    column_end: Some(30),
                }),
                message: "Used in division".to_string(),
                kind: CodeFlowKind::Sink,
            },
        ];
        let evidence = evidence_path_verified(&steps);
        let sarif = evidence_to_sarif_code_flow(&evidence);

        // Should be an array with one code flow
        let flows = sarif.as_array().expect("should be an array");
        assert_eq!(flows.len(), 1);

        // Should have one thread flow
        let thread_flows = flows[0]["threadFlows"]
            .as_array()
            .expect("threadFlows array");
        assert_eq!(thread_flows.len(), 1);

        // Should have two locations
        let locations = thread_flows[0]["locations"]
            .as_array()
            .expect("locations array");
        assert_eq!(locations.len(), 2);

        // Check first location
        let first = &locations[0];
        assert_eq!(
            first["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "validators/test.ak"
        );
        assert_eq!(
            first["location"]["physicalLocation"]["region"]["startLine"],
            5
        );
        assert_eq!(
            first["location"]["physicalLocation"]["region"]["startColumn"],
            3
        );
        assert!(first["message"]["text"]
            .as_str()
            .unwrap()
            .contains("[source]"));
        assert!(first["message"]["text"]
            .as_str()
            .unwrap()
            .contains("Redeemer data enters"));

        // Check second location
        let second = &locations[1];
        assert_eq!(
            second["location"]["physicalLocation"]["region"]["startLine"],
            15
        );
        assert!(second["message"]["text"]
            .as_str()
            .unwrap()
            .contains("[sink]"));
    }

    #[test]
    fn test_evidence_to_sarif_code_flow_no_location() {
        let steps = vec![CodeFlowStep {
            location: None,
            message: "Unknown location step".to_string(),
            kind: CodeFlowKind::Propagation,
        }];
        let evidence = evidence_path_verified(&steps);
        let sarif = evidence_to_sarif_code_flow(&evidence);

        let flows = sarif.as_array().unwrap();
        assert_eq!(flows.len(), 1);
        let locations = flows[0]["threadFlows"][0]["locations"].as_array().unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(
            locations[0]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "unknown"
        );
        // No region when no line info
        assert!(locations[0]["location"]["physicalLocation"]
            .get("region")
            .is_none());
    }

    #[test]
    fn test_evidence_to_sarif_code_flow_partial_location() {
        // Location with line_start but no column info
        let steps = vec![CodeFlowStep {
            location: Some(SourceLocation {
                module_path: "lib/utils.ak".to_string(),
                byte_start: 0,
                byte_end: 10,
                line_start: Some(42),
                column_start: None,
                line_end: None,
                column_end: None,
            }),
            message: "Partial location".to_string(),
            kind: CodeFlowKind::Guard,
        }];
        let evidence = evidence_path_verified(&steps);
        let sarif = evidence_to_sarif_code_flow(&evidence);

        let loc = &sarif[0]["threadFlows"][0]["locations"][0];
        let region = &loc["location"]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 42);
        // column, endLine, endColumn should not be present
        assert!(region.get("startColumn").is_none());
        assert!(region.get("endLine").is_none());
        assert!(region.get("endColumn").is_none());
        assert!(loc["message"]["text"].as_str().unwrap().contains("[guard]"));
    }

    #[test]
    fn test_evidence_serialization() {
        let evidence = evidence_pattern_match("test serialization");
        let json = serde_json::to_string(&evidence).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");
        assert_eq!(parsed["level"], "PatternMatch");
        assert_eq!(parsed["method"], "static-pattern");
        assert_eq!(parsed["details"], "test serialization");
        assert!(parsed["code_flow"].as_array().unwrap().is_empty());
        assert!(parsed["witness"].is_null());
        assert_eq!(parsed["confidence_boost"], 0.0);
    }

    #[test]
    fn test_code_flow_step_serialization() {
        let step = CodeFlowStep {
            location: Some(SourceLocation::from_bytes("test.ak", 10, 20)),
            message: "test step".to_string(),
            kind: CodeFlowKind::Source,
        };
        let json = serde_json::to_string(&step).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");
        assert_eq!(parsed["message"], "test step");
        assert_eq!(parsed["kind"], "Source");
    }

    #[test]
    fn test_evidence_clone() {
        let evidence = evidence_pattern_match("clone test");
        let cloned = evidence.clone();
        assert_eq!(evidence.level, cloned.level);
        assert_eq!(evidence.method, cloned.method);
        assert_eq!(evidence.details, cloned.details);
    }

    #[test]
    fn test_full_evidence_pipeline() {
        // Simulate the full pipeline: create evidence, compute confidence, format, and convert to SARIF
        let steps = vec![
            CodeFlowStep {
                location: Some(SourceLocation {
                    module_path: "validators/swap.ak".to_string(),
                    byte_start: 100,
                    byte_end: 150,
                    line_start: Some(10),
                    column_start: Some(5),
                    line_end: Some(10),
                    column_end: Some(40),
                }),
                message: "User-controlled redeemer amount".to_string(),
                kind: CodeFlowKind::Source,
            },
            CodeFlowStep {
                location: Some(SourceLocation {
                    module_path: "validators/swap.ak".to_string(),
                    byte_start: 200,
                    byte_end: 250,
                    line_start: Some(15),
                    column_start: Some(5),
                    line_end: Some(15),
                    column_end: Some(30),
                }),
                message: "Passed to division without zero check".to_string(),
                kind: CodeFlowKind::Sink,
            },
        ];

        let evidence = evidence_path_verified(&steps);

        // Confidence should be boosted
        let confidence = compute_effective_confidence(&Confidence::Possible, &evidence);
        assert_eq!(confidence, Confidence::Likely);

        // Format should be readable
        let formatted = format_evidence(&evidence);
        assert!(formatted.contains("path-verified"));
        assert!(formatted.contains("User-controlled redeemer amount"));

        // SARIF should be valid
        let sarif = evidence_to_sarif_code_flow(&evidence);
        let flows = sarif.as_array().unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(
            flows[0]["threadFlows"][0]["locations"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
