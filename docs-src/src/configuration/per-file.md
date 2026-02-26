# Per-File Overrides

Per-file overrides let you customize detector behavior for specific source files using glob patterns. This is useful when different parts of your codebase have different risk profiles -- validators need strict checking, while test helpers and utility libraries can tolerate patterns that would be concerning in production code.

## Syntax

Per-file overrides use TOML's array of tables syntax (`[[files]]`). Each block defines a rule with a `pattern` and optional `disable` list and `severity_override` map:

```toml
[[files]]
pattern = "validators/*.ak"
disable = ["magic-numbers"]

[files.severity_override]
missing-validity-range = "critical"
```

You can define as many `[[files]]` blocks as needed. They are evaluated in order, and the **first matching block** that has a relevant override wins for each detector/file combination.

## Pattern Syntax

The `pattern` field uses glob-style matching against module paths (relative to the project root):

| Pattern | Matches |
|---------|---------|
| `*.ak` | All `.ak` files in the project root |
| `validators/*.ak` | All `.ak` files directly in `validators/` |
| `validators/**/*.ak` | All `.ak` files anywhere under `validators/` |
| `lib/utils.ak` | Exactly `lib/utils.ak` |
| `lib/tests/*.ak` | All `.ak` files directly in `lib/tests/` |
| `**/*_test.ak` | Any file ending in `_test.ak` at any depth |

The `*` wildcard matches any characters except `/`. The `**` wildcard matches any path segments (including none), crossing directory boundaries.

## Disabling Detectors for Specific Files

The most common use case is disabling noisy detectors for test files and utility modules.

### Example: Relaxed rules for test files

Test files routinely use hardcoded addresses, magic numbers, and stub validator parameters. Disabling these detectors for test modules eliminates noise without weakening analysis of production code:

```toml
[[files]]
pattern = "lib/tests/**/*.ak"
disable = [
  "hardcoded-addresses",
  "magic-numbers",
  "unused-validator-parameter",
  "empty-handler-body",
]
```

### Example: Ignoring addresses in config modules

If your project has a module that defines well-known addresses as constants, you can suppress the `hardcoded-addresses` detector just for that file:

```toml
[[files]]
pattern = "lib/config.ak"
disable = ["hardcoded-addresses"]
```

### Example: Relaxed checks for example code

```toml
[[files]]
pattern = "examples/**/*.ak"
disable = [
  "hardcoded-addresses",
  "magic-numbers",
  "missing-validity-range",
  "missing-signature-check",
]
```

## Overriding Severity for Specific Files

You can raise or lower severity levels for specific files. This is particularly useful for escalating findings in security-critical validators while keeping default severity elsewhere.

### Example: Stricter severity for validators

```toml
[[files]]
pattern = "validators/*.ak"

[files.severity_override]
missing-validity-range = "critical"
missing-signature-check = "critical"
double-satisfaction = "critical"
missing-redeemer-validation = "critical"
```

### Example: Reduced severity for library code

Library modules that are not validators have a different threat model. Some findings are less severe when the code is not directly exposed to transaction validation:

```toml
[[files]]
pattern = "lib/**/*.ak"

[files.severity_override]
missing-validity-range = "low"
missing-signature-check = "low"
```

## Combining Disable and Severity Override

A single `[[files]]` block can both disable detectors and override severities:

```toml
[[files]]
pattern = "validators/pool.ak"
disable = ["magic-numbers"]

[files.severity_override]
missing-validity-range = "critical"
oracle-freshness-not-checked = "high"
```

## Multiple Overrides

When multiple `[[files]]` blocks match the same file, the behavior depends on the setting:

- **`disable`**: A detector is disabled if *any* matching block disables it (union semantics).
- **`severity_override`**: The *first* matching block with an override for that detector wins.

```toml
# Block 1: applies to all lib files
[[files]]
pattern = "lib/**/*.ak"
disable = ["magic-numbers"]

[files.severity_override]
missing-validity-range = "low"

# Block 2: applies specifically to test files in lib
[[files]]
pattern = "lib/tests/**/*.ak"
disable = ["hardcoded-addresses"]
```

For a file at `lib/tests/helpers.ak`:
- `magic-numbers` is disabled (from Block 1)
- `hardcoded-addresses` is disabled (from Block 2)
- `missing-validity-range` severity is `low` (from Block 1, which matches first)

## Interaction with Global Config

Per-file overrides layer on top of the global `[detectors]` section:

1. If a detector is globally disabled, it is disabled everywhere regardless of per-file settings. Per-file overrides cannot re-enable a globally disabled detector.
2. Per-file severity overrides take precedence over global severity overrides for matching files.
3. Per-file settings do not affect files that do not match the pattern.

```toml
[detectors]
disable = ["unused-import"]  # Globally disabled -- no per-file override can re-enable it

[detectors.severity_override]
missing-validity-range = "high"  # Global: high

[[files]]
pattern = "validators/*.ak"
[files.severity_override]
missing-validity-range = "critical"  # Validators: critical (overrides global)
```

For `validators/pool.ak`, `missing-validity-range` findings report as `critical`.
For `lib/utils.ak`, `missing-validity-range` findings report as `high` (global default).

## Real-World Configuration

Here is a complete configuration for a multi-validator DeFi project:

```toml
extends = "aikido-strict"

[detectors]
disable = ["unused-import"]

[detectors.severity_override]
utxo-contention-risk = "high"

# Validators get maximum scrutiny
[[files]]
pattern = "validators/**/*.ak"
[files.severity_override]
missing-validity-range = "critical"
missing-signature-check = "critical"
double-satisfaction = "critical"
value-not-preserved = "critical"

# Library helpers have a lower threat surface
[[files]]
pattern = "lib/**/*.ak"
disable = ["empty-handler-body"]
[files.severity_override]
missing-validity-range = "low"

# Test fixtures are noise-free
[[files]]
pattern = "lib/tests/**/*.ak"
disable = [
  "hardcoded-addresses",
  "magic-numbers",
  "unused-validator-parameter",
  "fail-only-redeemer-branch",
  "empty-handler-body",
]
```
