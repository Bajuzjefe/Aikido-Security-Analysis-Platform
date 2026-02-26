# unsafe-partial-pattern

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-252](https://cwe.mitre.org/data/definitions/252.html)

## What it detects

Identifies `expect` patterns used on non-Option, redeemer-derived values. If a redeemer-tainted variable is destructured with `expect` and the pattern does not match, the transaction fails at runtime.

## Why it matters

The `expect` keyword in Aiken performs an irrefutable pattern match -- if the pattern does not match the actual value, the program crashes. When the value being destructured comes from the redeemer (attacker-controlled), the attacker can cause the crash intentionally:

- **Transaction griefing**: Force specific redeemer values to crash the validator
- **Denial of service**: Prevent legitimate operations by triggering crashes
- **Logic bypass**: If a crash in one branch prevents proper cleanup in another

The datum `expect Some(x) = datum` case is handled by the separate `unsafe-datum-deconstruction` detector.

## Example: Vulnerable Code

```aiken
type SwapParams {
  Buy { amount: Int }
  Sell { amount: Int }
}

validator dex {
  spend(datum: PoolDatum, redeemer: SwapParams, _ref: OutputReference, self: Transaction) {
    // If redeemer is Sell, this crashes!
    expect Buy { amount } = redeemer
    validate_buy(datum, amount, self)
  }
}
```

## Example: Safe Code

```aiken
validator dex {
  spend(datum: PoolDatum, redeemer: SwapParams, _ref: OutputReference, self: Transaction) {
    when redeemer is {
      Buy { amount } -> validate_buy(datum, amount, self)
      Sell { amount } -> validate_sell(datum, amount, self)
    }
  }
}
```

## Detection Logic

1. Tracks variables used in `expect Some(...)` patterns via `expect_some_vars` in body signals.
2. Cross-references with `redeemer_tainted_vars` to identify which variables are derived from the redeemer.
3. Skips the datum parameter (first handler parameter) since that case is covered by `unsafe-datum-deconstruction`.
4. Flags any remaining `expect` patterns on redeemer-tainted values.

## False Positives

- **Intentional assertion**: If the `expect` is used to deliberately reject invalid redeemer data (e.g., `expect amount > 0`), the crash is intentional and serves as validation.
- **Single-constructor types**: If the redeemer type has exactly one constructor, `expect` always matches.
- **Taint propagation artifacts**: If a variable is marked as redeemer-tainted through indirect flow but is actually safe.

Suppress with:
```aiken
// aikido:ignore[unsafe-partial-pattern] -- single-constructor redeemer type
```

## Related Detectors

- [unsafe-datum-deconstruction](../high/unsafe-datum-deconstruction.md) -- Option datum not safely deconstructed
- [non-exhaustive-redeemer](non-exhaustive-redeemer.md) -- Redeemer match missing constructors
