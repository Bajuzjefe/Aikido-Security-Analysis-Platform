# path-sensitive-guard-check

**Severity:** High | **Confidence:** possible | **CWE:** [CWE-807](https://cwe.mitre.org/data/definitions/807.html)

## What it detects

Variables derived from attacker-controlled inputs (redeemer) that are validated in some execution paths but used without validation in others. An attacker can craft a redeemer that takes the unguarded path.

## Why it matters

When a `when` expression branches on a redeemer variant, each branch may handle validation differently. If one branch validates a critical variable (e.g., bounds-checks an amount) but another branch uses the same variable without validation, the attacker simply chooses the unguarded branch.

**Real-world impact:** A lending protocol's liquidation handler validates `redeemer.repay_amount >= minimum_repayment` in the partial-liquidation branch but uses `redeemer.repay_amount` without any check in the full-liquidation branch. An attacker sends a full-liquidation with `repay_amount = 0`, seizing collateral without repaying.

## Example: Vulnerable Code

```aiken
validator lending {
  spend(datum: LoanDatum, redeemer: LoanRedeemer, _own_ref: OutputReference, self: Transaction) {
    when redeemer.action is {
      PartialRepay -> {
        // This path validates the amount
        expect redeemer.amount > 0
        expect redeemer.amount <= datum.outstanding
        process_partial_repay(datum, redeemer.amount, self)
      }
      FullRepay -> {
        // VULNERABLE: uses redeemer.amount without validation
        process_full_repay(datum, redeemer.amount, self)
      }
    }
  }
}
```

## Example: Safe Code

```aiken
validator lending {
  spend(datum: LoanDatum, redeemer: LoanRedeemer, _own_ref: OutputReference, self: Transaction) {
    // SAFE: validate amount before branching
    expect redeemer.amount > 0
    expect redeemer.amount <= datum.outstanding

    when redeemer.action is {
      PartialRepay -> process_partial_repay(datum, redeemer.amount, self)
      FullRepay -> process_full_repay(datum, redeemer.amount, self)
    }
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A variable is tainted** - derived from the redeemer (attacker-controlled).
2. **The variable is guarded in at least one branch** of a `when` expression.
3. **The same variable is used without a guard in another branch** of the same `when`.

## False Positives

- **Branch-specific semantics:** Some branches may not need the validation (e.g., a Cancel branch that ignores the amount entirely). Suppress with `// aikido:ignore[path-sensitive-guard-check]`.
- **Guard in helper functions:** If validation happens inside a called function, Aikido may miss it if cross-module analysis cannot trace the call.

## Related Detectors

- [precise-taint-to-sink](precise-taint-to-sink.md) - More precise taint tracking from redeemer to sensitive sinks.
- [missing-redeemer-validation](missing-redeemer-validation.md) - Broader: detects redeemers not validated at all.
- [non-exhaustive-redeemer](../medium/non-exhaustive-redeemer.md) - Missing branches can also leave gaps.
