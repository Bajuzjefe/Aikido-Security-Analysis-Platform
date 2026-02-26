/** Severity levels matching the Rust Severity enum */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Confidence levels matching the Rust Confidence enum */
export type Confidence = "definite" | "likely" | "possible";

/** Detector reliability tiers */
export type ReliabilityTier = "stable" | "beta" | "experimental";

/** Evidence verification levels */
export type EvidenceLevel =
  | "PatternMatch"
  | "PathVerified"
  | "SmtProven"
  | "SimulationConfirmed"
  | "Corroborated";

/** Code flow step kinds */
export type CodeFlowKind = "Source" | "Propagation" | "Sink" | "Guard";

/** Source location in an Aiken file */
export interface SourceLocation {
  path: string;
  byte_start: number;
  byte_end: number;
  line_start: number | null;
  column_start: number | null;
  line_end: number | null;
  column_end: number | null;
}

/** Code flow step within evidence */
export interface CodeFlowStep {
  location: SourceLocation | null;
  message: string;
  kind: CodeFlowKind;
}

/** Evidence supporting a finding */
export interface Evidence {
  level: EvidenceLevel;
  method: string;
  details: string | null;
  code_flow: CodeFlowStep[];
  witness: unknown;
  confidence_boost: number;
}

/** CWC reference attached to a finding */
export interface CwcRef {
  id: string;
  name: string;
  severity: string;
}

/** A single security finding */
export interface Finding {
  detector: string;
  reliability_tier: ReliabilityTier;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  module: string;
  cwc: CwcRef | null;
  location: SourceLocation | null;
  suggestion: string | null;
  related_findings: string[];
  semantic_group: string | null;
  evidence: Evidence | null;
}

/** Top-level JSON output from `aikido --format json` */
export interface AnalysisOutput {
  schema_version: string;
  project: string;
  version: string;
  analysis_lanes: Record<string, unknown>;
  findings: Finding[];
  total: number;
}

/** CWC registry entry (static data) */
export interface CwcEntry {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  detectors: string[];
  remediation: string;
  references: string[];
}

/** Parsed detector info from --list-rules output */
export interface DetectorInfo {
  name: string;
  severity: Severity;
  category: string;
  tier: ReliabilityTier;
  cwe: string | null;
  description: string;
  doc_url: string;
}

/** Parsed detector explanation from --explain output */
export interface DetectorExplanation {
  name: string;
  severity: string;
  category: string;
  cwe: string | null;
  doc_url: string;
  long_description: string;
}

/** Severity ordering for filtering */
export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
