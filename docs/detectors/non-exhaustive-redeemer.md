# non-exhaustive-redeemer

**Severity:** Medium
**Confidence:** Likely

## Description

When a handler uses `when` on the redeemer, all constructors of the redeemer type should be explicitly handled. A catch-all `_` branch that returns `True` or performs no meaningful validation may indicate missing redeemer logic. This detector flags handlers where the redeemer has a named type with constructors but the `when` branches don't cover them all and fall through to a catch-all.

## Vulnerable Example

```aiken
type Action {
  Withdraw
  Update
  Close
  AdminOverride
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Withdraw -> check_withdrawal(datum, self)
      // Update, Close, AdminOverride all fall through to catch-all!
      _ -> True
    }
  }
}
```

The `Update`, `Close`, and `AdminOverride` actions are not explicitly handled. The catch-all accepts them without any validation, allowing an attacker to use any unhandled redeemer variant to bypass validation.

## Safe Example

```aiken
type Action {
  Withdraw
  Update
  Close
  AdminOverride
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Withdraw -> check_withdrawal(datum, self)
      Update -> check_update(datum, self)
      Close -> check_close(datum, self)
      AdminOverride -> check_admin(datum, self)
    }
  }
}
```

## Remediation

1. Handle all redeemer constructors explicitly instead of relying on a catch-all branch.
2. If a catch-all is intentional, make it `_ -> fail @"unsupported action"` to reject unknown variants rather than accepting them.
3. Review the redeemer type definition to identify all constructors and ensure each has appropriate validation logic.

## References

- [CWE-478: Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
