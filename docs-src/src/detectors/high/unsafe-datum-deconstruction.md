# unsafe-datum-deconstruction

**Severity:** High | **Confidence:** definite | **CWE:** [CWE-252](https://cwe.mitre.org/data/definitions/252.html)

## What it detects

Spend handlers where the datum parameter is typed as `Option<T>` (as required by Plutus V3) but the handler never safely deconstructs it with `expect Some(datum) = datum_opt`. Accessing fields on an `Option` value without first extracting the inner value leads to runtime errors or, worse, silently incorrect behavior.

## Why it matters

In Plutus V3 (Aiken v1.1+), spend handler datum parameters are `Option<T>` because a UTXO at a script address may or may not have an inline datum. If the UTXO has no datum (e.g., someone accidentally sends ADA to the script without a datum), the datum parameter will be `None`. If the handler attempts to use this value without checking for `Some`, the validator will crash with an unhelpful error, potentially creating a denial-of-service vector or permanently locking funds.

**Real-world impact:** A lending protocol's spend handler expects a `PositionDatum` but does not safely deconstruct the `Option`. An attacker sends a minimum-ADA UTXO to the script address without a datum. When anyone tries to interact with the protocol (even with their own legitimate UTXOs), the transaction fails because the attacker's datum-less UTXO causes the validator to error when processing the global UTXO set. In the worst case, datum-less UTXOs sent by mistake can become permanently unspendable, locking funds forever.

## Example: Vulnerable Code

```aiken
type LoanDatum {
  borrower: ByteArray,
  principal: Int,
  interest_rate: Int,
}

validator lending_pool {
  spend(datum_opt: Option<LoanDatum>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: datum_opt is Option<LoanDatum> but never safely deconstructed
    // If datum_opt is None, any field access will cause a runtime error
    when redeemer is {
      Repay -> {
        // This will crash if datum_opt is None
        let amount = datum_opt.principal + datum_opt.interest_rate
        validate_repayment(amount, self.transaction)
      }
      Liquidate -> {
        validate_liquidation(datum_opt, self.transaction)
      }
    }
  }
}
```

## Example: Safe Code

```aiken
type LoanDatum {
  borrower: ByteArray,
  principal: Int,
  interest_rate: Int,
}

validator lending_pool {
  spend(datum_opt: Option<LoanDatum>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    // SAFE: safely deconstruct the Option before any use
    expect Some(datum) = datum_opt

    when redeemer is {
      Repay -> {
        let amount = datum.principal + datum.interest_rate
        validate_repayment(datum.borrower, amount, self.transaction)
      }
      Liquidate -> {
        validate_liquidation(datum, self.transaction)
      }
    }
  }
}
```

## Detection Logic

Aikido checks the following conditions:

1. **Handler type is `spend`** -- only spend handlers receive `Option<T>` datum in Plutus V3.
2. **First parameter type starts with `Option<`** -- indicating the datum is wrapped in `Option`.
3. **Parameter name does not start with `_`** -- if the datum is explicitly discarded (e.g., `_datum`), the handler intentionally ignores it.
4. **The `expect_some_vars` body signal does not contain the datum parameter name** -- the handler never uses `expect Some(..) = datum_param` to safely deconstruct it.

The confidence is **likely** because in some cases the datum might be deconstructed through a different pattern (e.g., `when datum_opt is { Some(d) -> ..., None -> ... }`) that Aikido's current analysis does not track as an `expect Some` signal.

## False Positives

- **When-based deconstruction:** If the handler uses `when datum_opt is { Some(d) -> ..., None -> fail }` instead of `expect Some(d) = datum_opt`, the handler is safe but Aikido may not recognize this pattern. Suppress with `// aikido:ignore[unsafe-datum-deconstruction]`.
- **Helper function deconstruction:** If the `Option` is passed to a helper function that performs the `expect Some` internally, the detector may not trace this across modules.
- **Intentionally discarded datum:** If the handler explicitly names the datum (not with `_` prefix) but never uses it, this is flagged. If the datum is truly unused, rename the parameter with a `_` prefix to indicate this.

## Related Detectors

- [unsafe-partial-pattern](../medium/unsafe-partial-pattern.md) -- A broader detector for `expect` patterns on types that may fail, not limited to `Option` datum.
- [missing-datum-in-script-output](missing-datum-in-script-output.md) -- Related concern: outputs created without datum lead to the `None` case that this detector guards against.
- [missing-datum-field-validation](../medium/missing-datum-field-validation.md) -- Even after safe deconstruction, individual datum fields should be validated.
