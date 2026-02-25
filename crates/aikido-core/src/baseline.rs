use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::detector::Finding;

/// A baseline entry representing an accepted finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineEntry {
    pub detector: String,
    pub module: String,
    /// Fingerprint: detector + module + first 80 chars of description
    pub fingerprint: String,
}

/// A baseline file containing accepted findings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    pub version: String,
    pub entries: Vec<BaselineEntry>,
}

impl Baseline {
    /// Load a baseline from `.aikido-baseline.json`.
    pub fn load(project_root: &Path) -> Self {
        let path = project_root.join(".aikido-baseline.json");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        serde_json::from_str(&content).unwrap_or_default()
    }

    /// Save the baseline to `.aikido-baseline.json`.
    pub fn save(&self, project_root: &Path) -> Result<(), String> {
        let path = project_root.join(".aikido-baseline.json");
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("JSON error: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("Write error: {e}"))
    }

    /// Create a baseline from current findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let entries = findings.iter().map(finding_to_entry).collect();
        Self {
            version: "1".to_string(),
            entries,
        }
    }

    /// Filter out findings that are already in the baseline.
    pub fn filter_baselined(&self, findings: Vec<Finding>) -> Vec<Finding> {
        if self.entries.is_empty() {
            return findings;
        }

        let baseline_fingerprints: HashSet<&str> = self
            .entries
            .iter()
            .map(|e| e.fingerprint.as_str())
            .collect();

        findings
            .into_iter()
            .filter(|f| {
                let entry = finding_to_entry(f);
                !baseline_fingerprints.contains(entry.fingerprint.as_str())
            })
            .collect()
    }
}

fn finding_to_entry(f: &Finding) -> BaselineEntry {
    // Use byte_start for deterministic fingerprints — descriptions can vary
    // when detectors iterate over HashSet fields in non-deterministic order.
    let byte_start = f.location.as_ref().map_or(0, |l| l.byte_start);
    let fingerprint = format!("{}:{}:{}", f.detector_name, f.module, byte_start);
    BaselineEntry {
        detector: f.detector_name.clone(),
        module: f.module.clone(),
        fingerprint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Severity};

    fn make_finding(detector: &str, module: &str, desc: &str) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: desc.to_string(),
            module: module.to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        }
    }

    #[test]
    fn test_baseline_from_findings() {
        let findings = vec![
            make_finding("detector-a", "mod1", "description one"),
            make_finding("detector-b", "mod2", "description two"),
        ];
        let baseline = Baseline::from_findings(&findings);
        assert_eq!(baseline.entries.len(), 2);
        assert_eq!(baseline.version, "1");
    }

    #[test]
    fn test_filter_baselined() {
        let findings = vec![
            make_finding("detector-a", "mod1", "description one"),
            make_finding("detector-b", "mod2", "description two"),
        ];
        let baseline = Baseline::from_findings(&findings);

        // Same findings should be fully filtered
        let same = vec![
            make_finding("detector-a", "mod1", "description one"),
            make_finding("detector-b", "mod2", "description two"),
        ];
        let filtered = baseline.filter_baselined(same);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_new_findings_pass_through() {
        let baseline = Baseline::from_findings(&[make_finding("old", "mod1", "old issue")]);

        let new_findings = vec![make_finding("new-detector", "mod1", "new issue")];
        let filtered = baseline.filter_baselined(new_findings);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_empty_baseline_passes_all() {
        let baseline = Baseline::default();
        let findings = vec![make_finding("a", "m", "d")];
        let filtered = baseline.filter_baselined(findings);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let baseline = Baseline::load(Path::new("/nonexistent/path"));
        assert!(baseline.entries.is_empty());
    }
}
