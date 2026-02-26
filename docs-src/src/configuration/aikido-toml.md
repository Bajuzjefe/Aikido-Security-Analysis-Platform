# .aikido.toml Reference

Aikido is configured through a `.aikido.toml` file placed at the root of your Aiken project (next to `aiken.toml`). If no configuration file is found, Aikido runs with all 58 detectors enabled at their default severity levels.

## Generating a Config File

The fastest way to create a config file is with the `--init` flag:

```bash
aikido --init
```

This creates a `.aikido.toml` with all detectors listed as comments, ready for you to customize.

Alternatively, `--generate-config` analyzes your project first and pre-populates the disable list with detectors that produced findings:

```bash
aikido --generate-config
```

This is useful when onboarding an existing project -- you can suppress current findings and address them incrementally.

## Config File Structure

A `.aikido.toml` file has three main sections:

1. **Top-level** -- config inheritance via `extends`
2. **`[detectors]`** -- global detector settings
3. **`[[files]]`** -- per-file overrides (repeatable)

## Complete Example

```toml
# Inherit from a built-in preset
extends = "aikido-strict"

[detectors]
# Disable specific detectors entirely
disable = [
  "magic-numbers",
  "unused-import",
]

# Override default severity levels
[detectors.severity_override]
missing-validity-range = "critical"
hardcoded-addresses = "low"
utxo-contention-risk = "info"

# Severity profile (alternative to manual overrides)
# severity_profile = "strict"    # strict | default | lenient

# Custom field name patterns for domain-specific analysis
authority_patterns = ["admin", "governor", "operator"]
time_patterns = ["expiry", "lock_until", "valid_until"]

# Per-file overrides: relax rules for test files
[[files]]
pattern = "lib/tests/*.ak"
disable = ["hardcoded-addresses", "magic-numbers"]

# Per-file overrides: stricter rules for validators
[[files]]
pattern = "validators/*.ak"
[files.severity_override]
missing-validity-range = "critical"
missing-signature-check = "critical"
```

## Top-Level Settings

### `extends`

Inherit from a base configuration. The overlay (your config) takes precedence over the base for any overlapping settings.

```toml
extends = "aikido-strict"
```

Accepted values:

| Value | Description |
|-------|-------------|
| `"aikido-strict"` | Built-in strict preset -- all detectors enabled, severity escalated for key detectors |
| `"aikido-lenient"` | Built-in lenient preset -- disables noisy/informational detectors |
| `"path/to/base.toml"` | Path to another `.aikido.toml` file (relative to project root) |

When using `extends`, your config is merged on top of the base:

- **`disable` lists** are unioned (both base and overlay disables apply).
- **`severity_override` maps** are merged, with your overrides taking precedence.
- **`authority_patterns` and `time_patterns`** are unioned.
- **`severity_profile`** from your config wins if set.
- **`[[files]]` sections** are concatenated (both base and overlay file overrides apply).

## `[detectors]` Section

### `disable`

A list of detector names to turn off globally. Disabled detectors are never executed, so they produce zero findings and consume zero analysis time.

```toml
[detectors]
disable = [
  "hardcoded-addresses",
  "unused-validator-parameter",
  "fail-only-redeemer-branch",
]
```

Use `aikido --list-rules` to see all available detector names.

### `[detectors.severity_override]`

Override the default severity level for specific detectors. The value must be one of: `info`, `low`, `medium`, `high`, `critical` (case-insensitive).

```toml
[detectors.severity_override]
missing-validity-range = "high"
missing-min-ada-check = "medium"
hardcoded-addresses = "info"
```

This affects reporting, filtering (via `--min-severity`), and exit code behavior (via `--fail-on`). It does not change what the detector looks for -- only how the finding is classified.

### `severity_profile`

A shorthand that applies a predefined set of severity adjustments and disables. See the [Presets](presets.md) page for details.

```toml
[detectors]
severity_profile = "lenient"
```

Accepted values: `"strict"`, `"default"`, `"lenient"`.

When `severity_profile` is set alongside explicit `disable` and `severity_override` entries, the explicit entries take precedence.

### `authority_patterns`

Custom field name patterns that indicate authority/ownership fields in your datum types. These help detectors like `missing-signature-check` and `missing-input-credential-check` recognize domain-specific naming conventions.

```toml
[detectors]
authority_patterns = ["admin", "governor", "operator"]
```

The matching is word-boundary-aware on `_`-delimited segments. For example, `"admin"` matches `admin`, `admin_key`, `pool_admin`, and `my_admin_key`, but does not match `administrator`.

### `time_patterns`

Custom field name patterns that indicate time/deadline fields in your datum types. These help detectors like `missing-validity-range` and `oracle-freshness-not-checked` recognize domain-specific naming.

```toml
[detectors]
time_patterns = ["expiry", "lock_until", "valid_until"]
```

## `[[files]]` Section

Per-file overrides allow you to customize detector behavior for specific source files using glob patterns. See the [Per-File Overrides](per-file.md) page for detailed examples.

```toml
[[files]]
pattern = "validators/*.ak"
disable = ["magic-numbers"]

[files.severity_override]
missing-validity-range = "critical"
```

The `[[files]]` syntax uses TOML's array of tables -- each `[[files]]` block defines a separate override rule. You can have as many as needed.

## Config Validation

Aikido validates your config at startup and prints warnings for:

- Unknown detector names in `disable` or `severity_override`
- Invalid severity values (must be `info`, `low`, `medium`, `high`, or `critical`)
- Unknown `severity_profile` values

```
warning: unknown detector 'nonexistent-detector' in disable list
warning: invalid severity 'super-critical' for detector 'double-satisfaction' in severity_override (use: info, low, medium, high, critical)
```

These are warnings, not errors -- Aikido continues running with the valid parts of your config.

## Custom Config Path

By default, Aikido looks for `.aikido.toml` in the project root. You can specify an alternative path with `--config`:

```bash
aikido --config path/to/custom-config.toml ./my-project
```

## Precedence Order

When multiple configuration sources overlap, the precedence is (highest first):

1. **Inline suppression comments** (`// aikido:ignore[...]`) -- always wins
2. **`[[files]]` per-file overrides** -- file-specific severity overrides take precedence over global
3. **`[detectors]` global overrides** -- explicit disable and severity_override entries
4. **`severity_profile`** -- profile-based disables (e.g., lenient)
5. **`extends` base config** -- inherited settings
6. **Built-in defaults** -- all detectors enabled at their default severity

## All 58 Detector Names

For reference, here is the complete list of detector names you can use in `disable` and `severity_override`:

**Critical:** `double-satisfaction`, `missing-minting-policy-check`, `missing-utxo-authentication`, `unrestricted-minting`, `output-address-not-validated`

**High:** `missing-redeemer-validation`, `missing-signature-check`, `unsafe-datum-deconstruction`, `missing-datum-in-script-output`, `arbitrary-datum-in-output`, `division-by-zero-risk`, `token-name-not-validated`, `value-not-preserved`, `unsafe-match-comparison`, `integer-underflow-risk`, `quantity-of-double-counting`, `state-transition-integrity`, `withdraw-zero-trick`, `other-token-minting`, `unsafe-redeemer-arithmetic`, `value-preservation-gap`, `uncoordinated-multi-validator`, `missing-burn-verification`, `oracle-manipulation-risk`

**Medium:** `missing-validity-range`, `insufficient-staking-control`, `unbounded-list-iteration`, `unbounded-datum-size`, `unbounded-value-size`, `oracle-freshness-not-checked`, `non-exhaustive-redeemer`, `unsafe-list-head`, `hardcoded-addresses`, `unsafe-partial-pattern`, `unconstrained-recursion`, `empty-handler-body`, `utxo-contention-risk`, `cheap-spam-vulnerability`, `missing-datum-field-validation`, `missing-token-burn`, `missing-state-update`, `rounding-error-risk`, `missing-input-credential-check`, `duplicate-asset-name-risk`, `fee-calculation-unchecked`, `datum-tampering-risk`, `missing-protocol-token`, `unbounded-protocol-operations`

**Low/Info:** `reference-script-injection`, `unused-validator-parameter`, `fail-only-redeemer-branch`, `missing-min-ada-check`, `dead-code-path`, `redundant-check`, `shadowed-variable`, `magic-numbers`, `excessive-validator-params`, `unused-import`
