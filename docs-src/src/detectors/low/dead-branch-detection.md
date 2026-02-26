# dead-branch-detection

**Severity:** Info | **Confidence:** possible | **CWE:** [CWE-561](https://cwe.mitre.org/data/definitions/561.html)

## What it detects

Branches in `when` expressions that always fail or error, indicating unreachable code or intentionally disabled functionality.

## Why it matters

While always-failing branches can be intentional (defense in depth), they can also indicate logic errors or incomplete implementation. A branch that always calls `fail` means any transaction matching that redeemer variant will be rejected unconditionally, which may not be the intended behavior.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, redeemer: PoolAction, _own_ref: OutputReference, self: Transaction) {
    when redeemer is {
      Deposit -> validate_deposit(datum, self)
      Withdraw -> validate_withdraw(datum, self)
      // Dead branch: always fails, effectively disabling migration
      Migrate -> fail @"not implemented yet"
    }
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(datum: PoolDatum, redeemer: PoolAction, _own_ref: OutputReference, self: Transaction) {
    when redeemer is {
      Deposit -> validate_deposit(datum, self)
      Withdraw -> validate_withdraw(datum, self)
      Migrate -> validate_migration(datum, self)
    }
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A branch in a `when` expression** has a body that always evaluates to `fail` or `error`.
2. **The branch is not a catchall** (`_` wildcard) used for exhaustiveness.

## False Positives

- **Intentional defense in depth:** Some protocols deliberately disable certain actions by making their branches always fail. This is a valid security pattern. Suppress with `// aikido:ignore[dead-branch-detection]`.
- **Staged rollout:** Branches may be disabled temporarily during phased deployment.

## Related Detectors

- [dead-code-path](dead-code-path.md) - Unreachable code within functions (broader).
- [fail-only-redeemer-branch](fail-only-redeemer-branch.md) - Specifically targets redeemer branches that only fail.
- [state-machine-violation](../high/state-machine-violation.md) - Unhandled or always-succeeding state transitions.
