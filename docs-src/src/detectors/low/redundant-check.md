# redundant-check

**Severity:** Low | **CWE:** CWE-570 (Expression is Always False) / CWE-571 (Expression is Always True)

## What it detects

Named redeemer `when`/`match` branches whose body is a literal `True` with no validation logic. These branches unconditionally succeed regardless of the transaction context, effectively allowing anyone to use that redeemer action without constraints.

## Why it matters

A redeemer branch that returns `True` without performing any checks is a significant security concern disguised as a code quality issue:

- **Unrestricted action**: Anyone can submit a transaction using this redeemer action and it will succeed. If the action was intended to have authorization or state-transition checks, they are entirely missing.
- **Wasted execution budget**: The branch still consumes execution units for pattern matching, even though the result is predetermined. In validators with many branches, this adds unnecessary cost.
- **Placeholder risk**: Developers sometimes use `True` as a placeholder during development. If this reaches production, it creates an open door in the validator.
- **Audit red flag**: Any branch that unconditionally succeeds warrants careful review. It is the on-chain equivalent of `return true` in an authorization check.

Note: Catch-all branches (`_ -> True`) are excluded from this detector because they may represent legitimate "allow by default" patterns in certain validator designs, and are separately handled by [missing-redeemer-validation](../high/missing-redeemer-validation.md).

## Example: Flagged Code

```aiken
type VaultAction {
  Deposit
  Withdraw
  UpdateOracle
}

validator vault {
  spend(datum: Option<VaultDatum>, redeemer: VaultAction, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      Deposit -> verify_deposit(d, self)
      Withdraw -> verify_withdrawal(d, self)
      UpdateOracle -> True  // No checks! Anyone can "update" the oracle.
    }
  }
}
```

## Example: Improved Code

```aiken
validator vault {
  spend(datum: Option<VaultDatum>, redeemer: VaultAction, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      Deposit -> verify_deposit(d, self)
      Withdraw -> verify_withdrawal(d, self)
      UpdateOracle -> {
        // Require admin signature for oracle updates
        let signed_by_admin =
          list.has(self.extra_signatories, d.admin_pkh)
        signed_by_admin && verify_oracle_update(d, self)
      }
    }
  }
}
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines `when`/`match` branches in validator handler bodies.
2. **Catch-all exclusion**: Branches marked as catch-all (`_`, `..`) are skipped.
3. **Literal True check**: During AST walking, Aikido records whether each branch body is a literal `True` expression (not a variable named `True`, not a function call that returns `True`, but the actual boolean literal).
4. **Finding generation**: Each named branch with `body_is_literal_true` set to `true` generates a finding.
5. **Confidence**: Rated as `likely` because the AST analysis unambiguously identifies literal `True` expressions.

## False Positives

This detector may produce false positives when:

- The branch is intentionally permissionless by design (e.g., a `Deposit` action in a lending protocol where anyone should be able to deposit). In this case, the lack of checks is correct behavior.
- The `when` expression matches on something other than the redeemer where returning `True` for a specific variant is logically correct (e.g., `when is_valid is { True -> True; False -> ... }`).
- The real validation happens in a wrapper function that calls the validator, and the branch is `True` as a signal to the wrapper.

Suppress with:

```aiken
// aikido:ignore[redundant-check] -- Deposit is intentionally permissionless
```

## Related Detectors

- [missing-redeemer-validation](../high/missing-redeemer-validation.md) -- Catch-all redeemer pattern trivially returns True
- [fail-only-redeemer-branch](fail-only-redeemer-branch.md) -- Branch that always fails (opposite problem)
- [dead-code-path](dead-code-path.md) -- All named branches are dead code
- [empty-handler-body](../medium/empty-handler-body.md) -- Handler with no meaningful logic
