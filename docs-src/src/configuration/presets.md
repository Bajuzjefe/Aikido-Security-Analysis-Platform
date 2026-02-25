# Presets

Aikido ships with two built-in configuration presets that provide sensible defaults for common use cases. Presets can be activated in two ways: through config inheritance (`extends`) or through the `severity_profile` field.

## Using Presets

### Via `extends` (config inheritance)

```toml
extends = "aikido-strict"
```

This loads the preset as a base and merges your config on top. You can override any setting from the preset.

### Via `severity_profile` (inline)

```toml
[detectors]
severity_profile = "strict"
```

This applies the preset's disable rules inline without the full inheritance mechanism. Note that `severity_profile` only controls which detectors are disabled by profile -- it does not apply the severity overrides that the `extends` approach includes.

## The `strict` Preset

**Use when:** Running pre-audit checks, reviewing production-ready code, or enforcing maximum coverage in CI pipelines.

The strict preset enables all 58 detectors with no exceptions, and escalates severity for several detectors that are commonly underweighted:

| Detector | Default Severity | Strict Severity |
|----------|-----------------|-----------------|
| `missing-validity-range` | Medium | **High** |
| `unused-validator-parameter` | Low | **High** |
| `fail-only-redeemer-branch` | Low | **Medium** |
| `hardcoded-addresses` | Medium | **High** |
| `magic-numbers` | Low | **Medium** |
| `missing-min-ada-check` | Low | **Medium** |

All other detectors remain at their default severity levels.

### Example: Strict with overrides

```toml
extends = "aikido-strict"

[detectors]
# Even in strict mode, we trust our address constants
disable = ["hardcoded-addresses"]

# Escalate further for our security-critical validators
[detectors.severity_override]
double-satisfaction = "critical"
```

### When to use strict

- **Pre-audit preparation.** Before sending code to an external auditor, run with strict to catch everything the auditor might flag. Fewer surprises in the audit report means lower remediation costs.
- **CI gate for production deployments.** Pair `extends = "aikido-strict"` with `--fail-on medium` to block merges that introduce medium-or-higher findings.
- **New projects.** Starting strict from day one prevents technical debt from accumulating. It is easier to relax rules later than to tighten them on an existing codebase.

## The `lenient` Preset

**Use when:** Onboarding Aikido to an existing project, running exploratory analysis, or working on early-stage prototypes where informational noise is counterproductive.

The lenient preset disables five detectors that tend to produce high volumes of low-value findings:

| Disabled Detector | Default Severity | Reason |
|-------------------|-----------------|--------|
| `hardcoded-addresses` | Medium | Flags address literals that are often intentional (e.g., protocol addresses, well-known script hashes) |
| `unused-validator-parameter` | Low | Common during development when parameters are planned but not yet wired |
| `fail-only-redeemer-branch` | Low | Pattern-match branches that only call `fail` are sometimes intentional placeholders |
| `magic-numbers` | Low | Numeric literals are frequent in financial calculations and protocol constants |
| `empty-handler-body` | Medium | Stub handlers are common during incremental development |

All other detectors remain enabled at their default severity levels. The lenient preset does **not** reduce any severity levels -- it only disables detectors.

### Example: Lenient with selective re-enables

```toml
extends = "aikido-lenient"

[detectors]
# We still want to catch magic numbers in validators
# (this overrides the lenient preset's disable for this detector)
# Note: you cannot "un-disable" from extends, but you can use
# severity_profile instead for finer control
```

> **Note:** Because `extends` merges disable lists with union semantics, you cannot re-enable a detector that the base preset disables. If you need the lenient preset but want to keep `hardcoded-addresses` enabled, use `severity_profile = "lenient"` and manage the disable list manually.

### When to use lenient

- **Existing projects adopting Aikido.** Start with lenient to focus on critical and high-severity findings first. Tighten the config as the team addresses findings incrementally.
- **Prototyping and experimentation.** During early development, informational findings about magic numbers and unused parameters create noise that slows iteration.
- **Large codebases with many modules.** Lenient reduces the total finding count to a manageable level, letting teams focus on actionable security issues.

## The `default` Profile

The `default` profile enables all detectors at their built-in severity levels with no modifications. This is what you get when no config file exists. You can set it explicitly:

```toml
[detectors]
severity_profile = "default"
```

This is primarily useful when inheriting from another config file and wanting to reset the profile:

```toml
extends = "team-base-config.toml"

[detectors]
# Override the team's lenient profile back to default
severity_profile = "default"
```

## Comparison Table

| Aspect | `strict` | `default` | `lenient` |
|--------|----------|-----------|-----------|
| Detectors enabled | 58/58 | 58/58 | 53/58 |
| Severity escalations | 6 detectors raised | None | None |
| Best for | Audits, CI gates | General use | Onboarding, prototypes |
| Noise level | Highest | Moderate | Lowest |
| `--fail-on high` triggers | More findings at high | Default distribution | Fewer findings overall |

## Combining Presets with Overrides

Presets are starting points, not final configurations. The recommended workflow:

1. **Start with a preset** that matches your project phase.
2. **Add `disable` entries** for detectors that produce known false positives in your codebase.
3. **Add `severity_override` entries** to adjust specific detectors up or down based on your risk model.
4. **Add `[[files]]` blocks** to relax rules for test files and utility modules. See [Per-File Overrides](per-file.md).

```toml
extends = "aikido-strict"

[detectors]
disable = ["unused-import"]

[detectors.severity_override]
utxo-contention-risk = "high"

[[files]]
pattern = "lib/tests/**/*.ak"
disable = ["hardcoded-addresses", "magic-numbers"]
```
