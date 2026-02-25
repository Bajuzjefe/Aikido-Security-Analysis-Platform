# precise-taint-to-sink

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

## What it detects

Unsanitized attacker-controlled data (from the redeemer) that flows directly to sensitive operations like division, output address construction, or arithmetic without passing through proper validation guards.

## Why it matters

The redeemer is fully attacker-controlled. Unlike pattern-based detectors that check whether validation exists somewhere in the handler, this detector uses taint analysis to verify that validation actually occurs on the data flow path between the redeemer source and the sensitive sink.

**Real-world impact:** A DEX handler reads `redeemer.slippage_tolerance` and uses it directly in the swap calculation `output_amount = pool_reserve * input / (pool_reserve + input) * (10000 - redeemer.slippage_tolerance) / 10000`. An attacker sets `slippage_tolerance = 9999`, receiving almost nothing, which imbalances the pool for a follow-up arbitrage.

## Example: Vulnerable Code

```aiken
validator dex {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, _own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: redeemer.amount flows directly to division
    let output_tokens = datum.reserve_b * redeemer.amount / (datum.reserve_a + redeemer.amount)

    list.any(self.outputs, fn(o) {
      value.quantity_of(o.value, datum.token_b_policy, datum.token_b_name) >= output_tokens
    })
  }
}
```

## Example: Safe Code

```aiken
validator dex {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, _own_ref: OutputReference, self: Transaction) {
    // SAFE: validate redeemer input before using in arithmetic
    expect redeemer.amount > 0
    expect redeemer.amount <= datum.reserve_a / 3  // max 33% of pool per swap

    let output_tokens = datum.reserve_b * redeemer.amount / (datum.reserve_a + redeemer.amount)

    expect output_tokens >= redeemer.min_output  // slippage protection

    list.any(self.outputs, fn(o) {
      value.quantity_of(o.value, datum.token_b_policy, datum.token_b_name) >= output_tokens
    })
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A variable is tainted** - originates from the redeemer parameter.
2. **The tainted variable reaches a sensitive sink** - division denominator, output address, value arithmetic.
3. **No validation guard exists on the path** between source and sink - no bounds check, no comparison, no `expect`.

## False Positives

- **Implicit bounds from types:** If the redeemer field is a bounded type (e.g., a small enum), the range is inherently safe. Suppress with `// aikido:ignore[precise-taint-to-sink]`.
- **Validation in called functions:** Deep call chains may prevent Aikido from tracing the guard.

## Related Detectors

- [path-sensitive-guard-check](path-sensitive-guard-check.md) - Detects guards present on some paths but not others.
- [unsafe-redeemer-arithmetic](unsafe-redeemer-arithmetic.md) - Pattern-based version focused on arithmetic.
- [division-by-zero-risk](division-by-zero-risk.md) - Specific sink: division by zero.
