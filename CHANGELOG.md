# Changelog

## v0.3.0 — Multi-Lane Architecture

### New Analysis Modules (11 modules, 18,779 lines, 507+ tests)
- **Evidence framework** (`evidence.rs`) — 5-level evidence hierarchy (PatternMatch → PathVerified → SmtProven → SimulationConfirmed → Corroborated), SARIF codeFlow enrichment
- **CWC Registry** (`cwc.rs`) — 30 Cardano Weakness Classification entries mapping all 75 detectors
- **Scorecard** (`scorecard.rs`) — Detector promotion/demotion system (Experimental → Beta → Stable) with quality gates
- **SSA IR** (`ssa.rs`) — Full SSA form with phi nodes, dominators, use-def chains, taint propagation
- **Compliance analysis** (`compliance.rs`) — Securify2-style dual-pattern compliance + violation, 10 SecurityProperty variants
- **SMT verification** (`smt.rs`) — Solver-independent interface with Cardano domain axioms, constraint solving
- **Path-sensitive analysis** (`path_analysis.rs`) — CFG path enumeration, feasibility checking, guard detection
- **Invariant spec** (`invariant_spec.rs`) — `.aikido-invariants.toml` DSL for value conservation, access control, state transition, temporal invariants
- **Protocol patterns** (`protocol_patterns.rs`) — Automatic DeFi protocol detection (DEX/Lending/Staking/DAO/NFT/Options/Escrow), token flow + authority analysis
- **Transaction simulation** (`tx_simulation.rs`) — ScriptContext builder, exploit scenario generation for 6 detector types
- **Fuzz lane** (`fuzz_lane.rs`) — Grammar-aware Cardano tx generation, Echidna-style stateful protocol fuzzing

### New Detectors (17 new, 58 → 75 total)
- `tautological-comparison` (Critical), `value-comparison-semantics`, `output-count-validation`
- Delegation-aware suppression on 6 detectors (missing-signature-check, missing-utxo-authentication, output-address-not-validated, missing-redeemer-validation, state-transition-integrity, missing-datum-field-validation)
- Enhanced burn verification, datum continuity tracking

### Core Engine Improvements
- Delegation analysis (`delegation.rs`) — withdraw-zero pattern detection, `build_delegation_set()` for O(1) suppression
- Transitive function merging — 2-phase fixed-point (max 5 rounds for fn→fn chains)
- Datum continuity tracking — `has_datum_continuity_assertion` and `datum_equality_checks` in BodySignals
- PKH output detection — positive evidence (VerificationKeyCredential), not absence of ScriptCredential
- FP reduction: oracle time verification, guarded vars in fee-calculation-unchecked, var_references fallback

### Strike Finance Audit Comparison
- 85% coverage on TxPipe professional audit findings (12 full match, 5 partial, 3 false negatives on 20 unfixed findings)
- 26 unique findings not in the professional audit
- Full comparison report: `AUDIT_COMPARISON.md`

### Stats
- 1186+ tests (up from 526+)
- 75 detectors (up from 58)
- 11 new analysis modules
- 30 CWC classifications

---

## v0.2.0 — Ecosystem Validated

### New Detectors (23 new, 35 → 58 total)

**Critical**: output-address-not-validated
**High**: unsafe-match-comparison, integer-underflow-risk, quantity-of-double-counting, state-transition-integrity, withdraw-zero-trick, other-token-minting, unsafe-redeemer-arithmetic, value-preservation-gap, uncoordinated-multi-validator, missing-burn-verification, oracle-manipulation-risk
**Medium**: missing-datum-field-validation, reference-script-injection, missing-token-burn, missing-state-update, rounding-error-risk, missing-input-credential-check, duplicate-asset-name-risk, fee-calculation-unchecked, datum-tampering-risk, missing-protocol-token, unbounded-protocol-operations
**Low/Info**: (severity adjustments only)

### Cross-Module Interprocedural Analysis
- Resolves qualified function calls across module boundaries (e.g., `utils.get_upper_bound`)
- Transitive signal propagation through call chains
- Eliminated 22+ false positives on Strike Finance validation

### False Positive Reduction
- **reference-script-injection**: Downgraded Medium → Low, restricted to spend handlers only, added output construction guard (previously fired on any handler accessing outputs)
- **missing-min-ada-check**: Downgraded Low → Info, added output construction guard, expanded keyword patterns (value_geq, merge, from_asset)
- **utxo-contention-risk**: Added singleton-pattern datum skip (Settings, Config, Protocol, Pool, etc.), single-handler validator skip, expanded user-identifying field patterns (+15 terms)
- **Overall FP rate**: Estimated 31% → 19% (from 173 findings pre-tuning to 176 findings post-tuning with better signal)

### Stdlib v1.x Support
- Projects using stdlib v1.x now get a warning instead of a hard error
- Non-semver version strings (e.g., "main" branch refs) handled gracefully
- New `--strict-stdlib` CLI flag to enforce v2.0+ requirement
- Note: compilation of v1.x projects still fails (aiken compiler v1.1.21 incompatibility) but with clear messaging

### Ecosystem Validation
- Validated against 10 real-world projects with 0 crashes
- 176 total findings, 81% estimated true positive rate
- Projects: SundaeSwap, Anastasia Labs (2), Seedelf, Strike Finance (4), Acca
- Full results in `reports/ecosystem-validation-v0.2.md`

### CLI
- New `--strict-stdlib` flag
- New `--fix` command for auto-inserting suppression comments
- New `--generate-config` for creating `.aikido.toml` from findings
- New `--interactive` terminal navigator
- New `--lsp` for editor integration

### Other
- 526+ tests (up from 375+)
- Updated README with 58 detectors, installation methods, ecosystem validation results
- Homebrew, npm, Docker distribution updated to v0.2.0

---

## v0.1.0 — Initial Release

First public release of Aikido, a static security analyzer for Aiken smart contracts on Cardano.

### Analysis Engine
- Typed AST traversal via aiken-project v1.1.21
- Interprocedural analysis (1-level function call tracking)
- Cross-handler analysis (correlating signals across validator handlers)
- Taint tracking from untrusted redeemer fields to critical operations
- Call graph construction for function dependency mapping
- Symbolic execution with constraint propagation
- Confidence scoring (definite / likely / possible)
- Finding deduplication
- UPLC bytecode analysis (size, budget estimation, trend tracking)

### Detectors (35)
- **Critical**: double-satisfaction, missing-minting-policy-check, missing-utxo-authentication, unrestricted-minting
- **High**: missing-signature-check, missing-redeemer-validation, unsafe-datum-deconstruction, arbitrary-datum-in-output, missing-datum-in-script-output, division-by-zero-risk, token-name-not-validated, value-not-preserved
- **Medium**: missing-validity-range, insufficient-staking-control, unbounded-list-iteration, unbounded-datum-size, unbounded-value-size, oracle-freshness-not-checked, non-exhaustive-redeemer, unsafe-list-head, hardcoded-addresses, unsafe-partial-pattern, unconstrained-recursion, empty-handler-body, utxo-contention-risk, cheap-spam-vulnerability
- **Low/Info**: unused-validator-parameter, fail-only-redeemer-branch, missing-min-ada-check, dead-code-path, redundant-check, shadowed-variable, magic-numbers, excessive-validator-params, unused-import

### Output Formats (9)
text, json, sarif, markdown, html, pdf, csv, gitlab-sast, rdjson

### Configuration
- `.aikido.toml` with inheritance (`extends`), presets (strict/lenient), per-file overrides
- Inline suppression: `// aikido:ignore[detector-name]`
- Baseline file support (`.aikido-baseline.json`)

### CLI
- `--fail-on <severity>` for CI gating
- `--min-severity <severity>` for output filtering
- `--verbose` for UPLC metrics
- `--list-rules` and `--explain <rule>` for detector documentation
- `--diff <branch>` for diff-only analysis
- `--watch` for file watching
- `--format` for all 9 output formats
- `--quiet` mode

### CI/CD
- GitHub Actions composite action (`action.yml`)
- Reusable workflow (`aikido.yml`)
- SARIF upload to GitHub Security tab
- Cross-platform builds (Linux, macOS, Windows; x64, arm64)

### Distribution
- Pre-compiled binaries via GitHub Releases
- npm package (`aikido-aiken`)
- Homebrew formula
- Docker multi-stage image
- VS Code extension
