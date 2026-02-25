# Inline Suppression

When a finding is a known false positive or an accepted risk, you can suppress it directly in your source code using `// aikido:ignore` comments. This is the most precise suppression mechanism -- it targets a specific finding at a specific location, and the suppression rationale lives right next to the code it applies to.

## Syntax

### Suppress all detectors on the next line

```aiken
// aikido:ignore
let admin_address = #"abcdef1234..."
```

This suppresses every Aikido finding reported on the line immediately following the comment.

### Suppress a specific detector (space syntax)

```aiken
// aikido:ignore hardcoded-addresses
let admin_address = #"abcdef1234..."
```

Only the `hardcoded-addresses` detector is suppressed. Other detectors that flag the same line still report normally.

### Suppress a specific detector (bracket syntax)

```aiken
// aikido:ignore[hardcoded-addresses]
let admin_address = #"abcdef1234..."
```

Functionally identical to the space syntax. The bracket syntax is the preferred form because it is unambiguous and easier to parse visually in code review.

### Suppress with a reason

```aiken
// aikido:ignore[hardcoded-addresses] reason: protocol treasury address, verified on-chain
let treasury_address = #"abcdef1234..."
```

The `reason:` tag documents why the suppression is acceptable. Aikido tracks the reason internally and includes it in suppression reports. Adding a reason is strongly recommended -- it helps future maintainers understand why the suppression exists and whether it is still valid.

The space syntax also supports reasons:

```aiken
// aikido:ignore hardcoded-addresses reason: well-known Minswap router
let router_address = #"1234abcdef..."
```

### Suppress all with bracket syntax

```aiken
// aikido:ignore[]
let x = some_dangerous_pattern()
```

Empty brackets suppress all detectors, equivalent to `// aikido:ignore` without any detector name.

## Placement

Suppression comments can be placed in two positions:

### On the line before the finding

```aiken
// aikido:ignore[magic-numbers]
let fee_basis_points = 250
```

This is the standard placement. The comment must be on the line immediately before the line where the finding is reported.

### On the same line as the finding (inline)

```aiken
let fee_basis_points = 250  // aikido:ignore[magic-numbers]
```

The `// aikido:ignore` marker can appear anywhere on the same line as the finding.

## Stacking Multiple Suppressions

When a single line triggers multiple detectors, you can stack suppression comments on consecutive lines above it:

```aiken
// aikido:ignore[hardcoded-addresses] reason: known protocol address
// aikido:ignore[magic-numbers] reason: ADA amount in lovelace
let min_deposit = 2_000_000
```

Both suppressions are effective because Aikido walks upward through consecutive comment lines from the finding's location. The scan stops at the first non-comment line, so all stacked `// aikido:ignore` comments above a finding are considered.

Important: if a non-comment line breaks the chain, earlier suppression comments do not apply:

```aiken
// aikido:ignore[double-satisfaction]
let y = 1
// aikido:ignore[missing-signature-check]
let x = do_something()
```

Here, `double-satisfaction` is **not** suppressed for line 4 (`let x = ...`) because line 2 (`let y = 1`) is not a comment, breaking the consecutive chain.

## Automatic Suppression with `--fix`

The `--fix` flag automatically inserts suppression comments for all current findings:

```bash
# Suppress all findings
aikido --fix

# Suppress only a specific detector
aikido --fix=hardcoded-addresses
```

The inserted comments use the bracket syntax with proper indentation matching the target line:

```aiken
fn validate(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) -> Bool {
  // aikido:ignore[hardcoded-addresses]
  let admin = #"abcdef1234..."
  // aikido:ignore[magic-numbers]
  let threshold = 1000
  True
}
```

This is useful for onboarding existing projects. Run `--fix` to suppress all current findings, then address them incrementally by removing suppression comments and fixing the underlying issues.

When `--fix` targets a line that already has multiple findings, it inserts one suppression comment per finding, stacked above the line. The comments are inserted bottom-up (highest line numbers first) so that line number offsets remain correct.

## Examples

### Suppressing a known false positive

```aiken
// aikido:ignore[double-satisfaction] reason: own_ref is validated in check_ownership helper
fn process_withdrawal(datum: Datum, ctx: ScriptContext) -> Bool {
  // ...
}
```

### Suppressing hardcoded addresses in a config module

```aiken
// Protocol-level constants -- these addresses are governance-controlled
// and verified in the protocol documentation.

// aikido:ignore[hardcoded-addresses] reason: Minswap v2 pool validator hash
const minswap_pool_hash = #"e4214b7cce62ac6fbba385d164df48e157eae5863521b4b67ca71d86"

// aikido:ignore[hardcoded-addresses] reason: SundaeSwap escrow validator hash
const sundae_escrow_hash = #"4020e7fc2de75a0729c3cc3af715b34d98381e0cdbcfa99c950bc3ac"
```

### Suppressing magic numbers in fee calculations

```aiken
fn calculate_fee(amount: Int) -> Int {
  // aikido:ignore[magic-numbers] reason: 0.3% fee = 3 basis points per 1000
  amount * 3 / 1000
}
```

### Suppressing findings in test helpers

```aiken
// aikido:ignore[missing-signature-check] reason: test-only validator, not deployed
fn mock_validator(_datum: Datum, _redeemer: Redeemer, _ctx: ScriptContext) -> Bool {
  True
}
```

## Best Practices

1. **Prefer specific detector names over blanket suppression.** Use `// aikido:ignore[detector-name]` rather than `// aikido:ignore`. Blanket suppression hides all findings on that line, including new ones added by future detector updates.

2. **Always include a reason.** The `reason:` tag costs nothing and provides critical context for code reviewers and future maintainers. A suppression without a reason is a liability -- nobody knows if it is still valid.

3. **Review suppressions periodically.** Search for `aikido:ignore` in your codebase and verify that each suppression is still justified. Code changes can make a suppression obsolete or invalid.

4. **Use `[[files]]` for broad patterns.** If you are suppressing the same detector across many lines in a file, it is cleaner to use a [per-file override](per-file.md) in `.aikido.toml` instead of littering the source with inline comments.

5. **Use `--fix` for onboarding, not as a permanent solution.** The `--fix` flag is a convenient starting point, but every auto-inserted suppression should eventually be reviewed and either given a proper reason or resolved by fixing the underlying code.

## How It Works

Suppression filtering runs after detectors have produced findings and after line numbers have been resolved. For each finding with a source location, Aikido:

1. Checks the same line for an inline `// aikido:ignore` comment.
2. Walks upward through consecutive comment lines immediately above the finding line.
3. If any `// aikido:ignore` comment matches (either all-detectors or the specific detector name), the finding is suppressed.
4. The walk stops at the first non-comment line.

Suppressed findings are removed from all output formats. They do not count toward `--fail-on` exit code thresholds and are not included in finding totals.
