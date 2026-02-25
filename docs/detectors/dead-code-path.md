# dead-code-path

**Severity:** Low
**Confidence:** Possible

## Description

A handler with a `when`/`match` where every named branch either fails or returns `True` without meaningful logic may contain unreachable code. This includes handlers where all non-catchall branches unconditionally fail, leaving only the fallback to execute. This pattern often indicates incomplete implementation or leftover scaffolding.

## Vulnerable Example

```aiken
type Action {
  Withdraw
  Update
  Close
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Withdraw -> fail @"not implemented"
      Update -> fail @"not implemented"
      Close -> fail @"not implemented"
      // Only the catch-all ever executes
      _ -> True
    }
  }
}
```

All named redeemer branches fail unconditionally. The catch-all branch `_ -> True` is the only code that ever executes, bypassing any intended validation.

## Safe Example

```aiken
type Action {
  Withdraw
  Update
  Close
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Withdraw -> check_withdrawal(datum, self)
      Update -> check_update(datum, self)
      Close -> check_close(datum, self)
    }
  }
}
```

## Remediation

1. Review all branches in the `when`/`match` expression and implement real validation logic.
2. Remove dead branches that unconditionally fail if they are no longer needed.
3. If branches are intentionally disabled, use `fail` in the catch-all instead of `True` to prevent accidental acceptance.

## References

- [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html)
