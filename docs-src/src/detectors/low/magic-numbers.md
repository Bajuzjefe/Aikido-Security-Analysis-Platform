# magic-numbers

**Severity:** Info | **CWE:** CWE-547 (Use of Hard-coded, Security-relevant Constants)

## What it detects

Numeric literals in validator handler bodies that are not commonly recognized safe values (0, 1, 2, -1, 1000000). These "magic numbers" are used directly in comparisons, arithmetic, or conditions without being assigned to named constants.

## Why it matters

Magic numbers in smart contracts are a readability and maintainability concern with security implications:

- **Unclear intent**: A literal like `86400` in a validity range check is a number of seconds (one day), but this is not obvious at a glance. A named constant like `one_day_seconds` immediately communicates the intent.
- **Inconsistent updates**: If the same value appears in multiple places and one occurrence is updated but another is not, the validator behaves inconsistently. Named constants ensure a single source of truth.
- **Audit difficulty**: Auditors must manually verify what each magic number represents. Named constants with descriptive names reduce audit time and the risk of overlooked issues.
- **Configuration rigidity**: Hard-coded values cannot be changed without redeploying the contract. Values that may need adjustment (fee percentages, time windows, thresholds) should be validator parameters instead.

The safe-list exempts values that are ubiquitous in Cardano development: `0` (empty/zero), `1` and `2` (common increment/comparison), `-1` (decrement), and `1000000` (one ADA in lovelace).

## Example: Flagged Code

```aiken
validator staking_pool {
  spend(datum: Option<PoolDatum>, _redeemer: PoolRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum

    // Magic numbers: what do 86400000, 500, and 10000 mean?
    let lock_period = 86400000
    let reward_numerator = 500
    let reward_denominator = 10000

    let time_elapsed =
      when self.validity_range.upper_bound.bound_type is {
        Finite(upper) -> upper - d.deposit_time
        _ -> 0
      }

    time_elapsed >= lock_period && compute_reward(d, reward_numerator, reward_denominator)
  }
}
```

## Example: Improved Code

```aiken
// Option A: Named constants in the module
const one_day_ms: Int = 86_400_000
const reward_bps: Int = 500       // 5% in basis points
const bps_base: Int = 10_000      // basis points denominator

validator staking_pool {
  spend(datum: Option<PoolDatum>, _redeemer: PoolRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum

    let time_elapsed =
      when self.validity_range.upper_bound.bound_type is {
        Finite(upper) -> upper - d.deposit_time
        _ -> 0
      }

    time_elapsed >= one_day_ms && compute_reward(d, reward_bps, bps_base)
  }
}
```

```aiken
// Option B: Validator parameters for configurable values
validator staking_pool(lock_period_ms: Int, reward_bps: Int) {
  spend(datum: Option<PoolDatum>, _redeemer: PoolRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum

    let time_elapsed =
      when self.validity_range.upper_bound.bound_type is {
        Finite(upper) -> upper - d.deposit_time
        _ -> 0
      }

    time_elapsed >= lock_period_ms && compute_reward(d, reward_bps, 10_000)
  }
}
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines validator handler bodies in validator modules.
2. **Variable reference scan**: Numeric literals captured during AST walking appear in the handler's variable reference set. The detector filters these for values that look like numeric literals.
3. **Safe-list filter**: Values in the safe list (`0`, `1`, `2`, `-1`, `True`, `False`, `1000000`) are excluded.
4. **Numeric validation**: The value must parse as a pure integer (optionally negative). Non-numeric strings are ignored.
5. **Significance threshold**: Only values with absolute magnitude greater than 2 are flagged. Small values (0, 1, 2) are too common to be meaningful magic numbers.
6. **1 ADA exemption**: The value `1000000` (one ADA in lovelace) is excluded as it is a universally understood Cardano constant.
7. **Confidence**: Rated as `possible` because the detector cannot distinguish between a genuinely magic number and a well-understood domain constant.

## False Positives

This detector may produce false positives when:

- The numeric literal is a well-known domain constant that does not need a name (e.g., `1000` for converting units, `100` for percentage calculations).
- The number appears in a test-related context or assertion, not in production logic.
- The value is assigned to a descriptively named variable on the same line (e.g., `let fee_percentage = 250`). The detector sees the literal before the assignment.
- Protocol-specific constants that are standardized across the ecosystem (e.g., Cardano epoch length, slot duration) are used directly.

Suppress with:

```aiken
// aikido:ignore[magic-numbers] -- 86400000 is standard one-day-in-ms
```

Or disable globally in `.aikido.toml` if your project uses many well-understood literals:

```toml
[detectors]
disable = ["magic-numbers"]
```

## Related Detectors

- [hardcoded-addresses](../medium/hardcoded-addresses.md) -- Hard-coded ByteArray addresses in validators
- [excessive-validator-params](excessive-validator-params.md) -- Too many parameters (related: extracting magic numbers to parameters)
- [unused-validator-parameter](unused-validator-parameter.md) -- Parameter defined but not used
