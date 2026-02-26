# dead-code-path

**Severity:** Low | **CWE:** CWE-561 (Dead Code)

## What it detects

Validator handlers where all named `when`/`match` branches unconditionally fail, leaving only the catch-all branch as the sole executable path. This means the named redeemer variants are dead code and the validator effectively ignores its redeemer type.

## Why it matters

When every named branch in a redeemer match fails, the validator's behavior depends entirely on the catch-all branch. This pattern has several implications:

- **Type system bypass**: The redeemer type definition declares specific actions (e.g., `Deposit`, `Withdraw`, `Close`), but none of them work. The actual behavior is determined solely by the catch-all, making the type definition misleading.
- **Incomplete implementation**: This pattern commonly arises during development when a developer stubs out branches with `fail` and forgets to implement them. The catch-all may have been intended as a temporary workaround.
- **Maintenance burden**: Future developers will spend time trying to understand why named branches exist if they all fail. The dead code obscures the validator's true logic.
- **Possible logic error**: The developer may have accidentally inverted which branches should fail and which should succeed.

## Example: Flagged Code

```aiken
type Action {
  Deposit
  Withdraw
  Close
}

validator pool {
  spend(datum: Option<PoolDatum>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      Deposit -> fail @"Deposits disabled"
      Withdraw -> fail @"Withdrawals disabled"
      Close -> fail @"Closing disabled"
      _ -> verify_admin_action(d, self)  // Only reachable path
    }
  }
}
```

## Example: Improved Code

```aiken
// Option A: Implement the branches
validator pool {
  spend(datum: Option<PoolDatum>, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      Deposit -> verify_deposit(d, self)
      Withdraw -> verify_withdrawal(d, self)
      Close -> verify_close(d, self)
      _ -> fail @"Unknown action"
    }
  }
}

// Option B: Remove dead branches and simplify the type
type Action {
  AdminAction
}

validator pool {
  spend(datum: Option<PoolDatum>, _redeemer: Action, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    verify_admin_action(d, self)
  }
}
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines validator handler bodies in validator modules.
2. **Branch threshold**: Requires at least 2 branches in the `when`/`match` expression. A single-branch match is not flagged since it may be a legitimate pattern.
3. **Named vs. catch-all separation**: Splits branches into named branches (specific constructors) and catch-all branches (`_`, `..`).
4. **All-fail check**: If all named branches have `body_is_error` set to `true` AND at least one catch-all branch exists, the detector fires.
5. **Confidence**: Rated as `possible` because there are legitimate scenarios where all named branches are intentionally disabled.

## False Positives

This detector may produce false positives when:

- The validator is in a transitional state where specific actions are deliberately disabled (e.g., a migration period where only admin actions are allowed via the catch-all).
- The `when` expression matches on something other than the redeemer (e.g., a datum field or credential type) where having all named branches fail is a valid "filter" pattern.
- The named branches call `fail` with informative error messages as part of a feature-flagging system controlled by off-chain configuration.

Suppress with:

```aiken
// aikido:ignore[dead-code-path] -- branches disabled during migration phase
```

## Related Detectors

- [fail-only-redeemer-branch](fail-only-redeemer-branch.md) -- Individual redeemer branch that always fails
- [redundant-check](redundant-check.md) -- Branches that always return True without validation
- [empty-handler-body](../medium/empty-handler-body.md) -- Handler with no meaningful logic at all
- [non-exhaustive-redeemer](../medium/non-exhaustive-redeemer.md) -- Redeemer match missing constructors
