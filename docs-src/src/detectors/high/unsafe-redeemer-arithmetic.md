# unsafe-redeemer-arithmetic

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-682](https://cwe.mitre.org/data/definitions/682.html) -- Incorrect Calculation

## What it detects

Finds handlers that perform division or multiplication using redeemer-derived values without prior validation. The redeemer is entirely attacker-controlled, so using it directly in arithmetic operations enables division-by-zero, integer overflow, and precision manipulation attacks.

## Why it matters

On Cardano, the redeemer is submitted by the transaction builder and is completely untrusted. Unlike the datum (which was placed on-chain by a previous transaction and may have been validated at that time), the redeemer can contain any value the attacker chooses. When redeemer fields flow directly into arithmetic:

- **Division by zero**: The attacker sets a redeemer field to `0` and uses it as a divisor. In Aiken, division by zero causes a script error (`fail`), which can be exploited for denial-of-service or to force a specific code path.
- **Precision manipulation**: The attacker uses extremely small or large multipliers to skew financial calculations. For example, setting `num_shares` to `1` in a division-based payout calculation to claim the entire pool.
- **Integer overflow**: Large multiplier values can cause intermediate products to exceed the expected range, corrupting downstream comparisons.
- **Rounding exploitation**: Integer division truncates. By choosing specific redeemer values, an attacker can systematically exploit rounding in their favor across many transactions.

This is especially dangerous in DeFi validators that compute payouts, fees, exchange rates, or liquidation thresholds using redeemer-supplied parameters.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference}
use cardano/value

type VaultDatum {
  total_deposited: Int,
  admin: ByteArray,
}

type VaultAction {
  Withdraw { num_shares: Int, share_price: Int }
}

validator payout_vault {
  spend(
    datum: Option<VaultDatum>,
    redeemer: VaultAction,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    when redeemer is {
      Withdraw { num_shares, share_price } -> {
        // BUG: Both num_shares and share_price come from the redeemer.
        // Division by zero if num_shares == 0.
        // Precision manipulation if share_price is attacker-chosen.
        let payout = d.total_deposited * share_price / num_shares

        let output = list.head(self.outputs)
        value.lovelace_of(output.value) >= d.total_deposited - payout
      }
    }
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction, OutputReference}
use cardano/value

type VaultDatum {
  total_deposited: Int,
  total_shares: Int,
  admin: ByteArray,
}

type VaultAction {
  Withdraw { num_shares: Int }
}

validator payout_vault {
  spend(
    datum: Option<VaultDatum>,
    redeemer: VaultAction,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    when redeemer is {
      Withdraw { num_shares } -> {
        // SAFE: Validate redeemer value before arithmetic
        expect num_shares > 0
        expect num_shares <= d.total_shares

        // Use datum-sourced total_shares as divisor (not attacker-controlled)
        // and validate the redeemer input is within expected bounds
        let payout = d.total_deposited * num_shares / d.total_shares

        let output = list.head(self.outputs)
        value.lovelace_of(output.value) >= d.total_deposited - payout
      }
    }
  }
}
```

Key principles:

```aiken
// 1. Always validate redeemer values before arithmetic
expect redeemer.amount > 0
expect redeemer.amount <= datum.max_allowed

// 2. Prefer datum-sourced values as divisors (they were validated on-chain)
let result = datum.total * redeemer.share_count / datum.total_shares

// 3. For multiplication, bound the result
let product = redeemer.quantity * datum.unit_price
expect product <= datum.max_payout
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator.
2. The handler has **redeemer-tainted variables** -- variables whose values flow from the redeemer parameter (tracked via taint analysis).
3. The handler performs **division or multiplication** (detected via `has_division` or `has_multiplication` body signals).

The detector uses taint tracking to identify variables derived from the redeemer. When tainted variables coexist with risky arithmetic operations, the finding is reported with the names of the tainted variables.

## False Positives

Suppress this finding when:

- **Redeemer values are validated before use**: The handler contains explicit bounds checks (`expect redeemer.value > 0`, `expect redeemer.value <= max`) before any arithmetic, but the validation and arithmetic are in different branches that the taint tracker does not connect.
- **Redeemer used only in comparison**: The redeemer value is used as a multiplier/divisor only in a comparison (e.g., `datum.x * redeemer.y >= threshold`), not to compute an actual output amount. The attacker cannot benefit from manipulating the comparison.
- **Datum-sourced divisor**: The division uses a datum field as the divisor and the redeemer only as the dividend. Since the divisor is not attacker-controlled, division-by-zero is impossible (assuming the datum was validated when created).

```aiken
// aikido:ignore[unsafe-redeemer-arithmetic] -- redeemer.amount validated on line 42
```

## Related Detectors

- [division-by-zero-risk](division-by-zero-risk.md) -- Division with any attacker-controlled denominator (broader than redeemer-specific).
- [integer-underflow-risk](integer-underflow-risk.md) -- Subtraction with redeemer-controlled values causing underflow.
- [rounding-error-risk](../medium/rounding-error-risk.md) -- Integer division on financial values that may lose precision.
