# shadowed-variable

**Severity:** Info
**Confidence:** Possible

## Description

When a `when`/match pattern binding uses the same name as a handler parameter, the parameter is shadowed within that branch. This can lead to confusion and bugs where the developer intends to reference the outer parameter but accidentally uses the pattern-bound value.

## Vulnerable Example

```aiken
type Action {
  Close { datum: Int }
  Update { datum: Int }
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Close { datum } -> {
        // BUG: `datum` here is the redeemer field, not the spend datum!
        // The handler parameter `datum` is shadowed.
        datum > 0
      }
      Update { datum } -> {
        datum > 0
      }
    }
  }
}
```

The developer likely intended to validate the spend datum, but the pattern binding `datum` shadows the handler parameter. The check operates on the redeemer field instead, which an attacker controls.

## Safe Example

```aiken
type Action {
  Close { close_value: Int }
  Update { update_value: Int }
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Close { close_value } -> {
        // Unambiguous: `datum` is the handler param, `close_value` is the pattern binding
        datum > 0 && close_value > 0
      }
      Update { update_value } -> {
        datum > 0 && update_value > 0
      }
    }
  }
}
```

## Remediation

1. Use distinct names for pattern bindings that do not collide with handler parameter names
2. Prefix pattern bindings descriptively (e.g., `redeemer_datum`, `close_value`) to avoid ambiguity
3. If shadowing is intentional, prefix the handler parameter with `_` to signal it is unused in that branch

## References

- [CWE-1078: Inappropriate Source Code Style or Formatting](https://cwe.mitre.org/data/definitions/1078.html)
