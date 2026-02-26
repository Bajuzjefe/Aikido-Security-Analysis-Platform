# missing-redeemer-validation

**Severity:** High | **Confidence:** definite | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

## What it detects

Redeemer pattern matching branches that trivially return `True` without performing any validation logic. This includes catch-all patterns (`_ -> True`) that accept any redeemer variant, and named branches that return `True` without checking any conditions.

## Why it matters

The redeemer in a Cardano transaction represents the *action* being performed. Each redeemer variant should have corresponding validation logic. A catch-all pattern that returns `True` means any redeemer (even unexpected ones) will succeed, effectively disabling access control for the validator.

**Real-world impact:** A DEX validator has three intended actions: `Swap`, `AddLiquidity`, and `RemoveLiquidity`. During development, a catch-all branch `_ -> True` was added as a placeholder. An attacker discovers this and submits a transaction with a garbage redeemer value. The catch-all matches, the validator returns `True`, and the attacker drains the liquidity pool without performing any legitimate action.

Even named branches that trivially return `True` are dangerous. If a `Close` action returns `True` without verifying the signer, anyone can close (and claim) the contract's funds.

## Example: Vulnerable Code

```aiken
type Action {
  Swap
  AddLiquidity
  RemoveLiquidity
}

validator dex_pool {
  spend(datum: PoolDatum, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    when redeemer is {
      Swap -> {
        // ... swap validation logic ...
        validate_swap(datum, self.transaction)
      }
      AddLiquidity -> {
        // ... liquidity validation ...
        validate_add_liquidity(datum, self.transaction)
      }
      // VULNERABLE: catch-all bypasses all validation
      _ -> True
    }
  }
}
```

## Example: Safe Code

```aiken
type Action {
  Swap
  AddLiquidity
  RemoveLiquidity
}

validator dex_pool {
  spend(datum: PoolDatum, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    when redeemer is {
      Swap -> validate_swap(datum, own_ref, self.transaction)
      AddLiquidity -> validate_add_liquidity(datum, own_ref, self.transaction)
      RemoveLiquidity -> validate_remove_liquidity(datum, own_ref, self.transaction)
      // SAFE: every variant has explicit validation
      // No catch-all needed -- Aiken enforces exhaustive matching
    }
  }
}
```

## Detection Logic

Aikido inspects `when` expression branches in validator handler bodies:

1. **Catch-all with literal `True`:** If a branch has `is_catchall == true` and `body_is_literal_true == true`, a **High/definite** finding is emitted. This is the most dangerous pattern: any redeemer value passes.
2. **Named branch with literal `True`:** If a branch has `is_catchall == false` but `body_is_literal_true == true`, a **Medium/likely** finding is emitted. The specific variant is handled but with no validation.

The detector examines the `when_branches` body signal, which records each pattern match branch's text, whether it is a catch-all, and whether its body is a literal `True`.

## False Positives

- **Intentional pass-through branches:** Some protocols have redeemer variants that are intentionally unrestricted (e.g., a `Heartbeat` action used only for transaction ordering, not security). Suppress with `// aikido:ignore[missing-redeemer-validation] -- Heartbeat requires no auth`.
- **Authorization delegated to other validators:** In multi-validator designs, one validator's redeemer branch may return `True` because authorization is enforced by a companion validator in the same transaction. This is a valid pattern but risky -- the dependency should be documented.
- **Test validators:** Validators used in test suites may intentionally have permissive redeemers.

## Related Detectors

- [non-exhaustive-redeemer](../medium/non-exhaustive-redeemer.md) -- Catches redeemer `when` expressions that do not cover all constructors, a complementary issue.
- [missing-signature-check](missing-signature-check.md) -- Even when redeemer branches have logic, they may lack signature verification for privileged actions.
- [empty-handler-body](../medium/empty-handler-body.md) -- Catches handlers with no meaningful logic at all, a related but broader issue.
