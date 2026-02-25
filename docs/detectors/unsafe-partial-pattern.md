# unsafe-partial-pattern

**Severity:** Medium
**Confidence:** Possible

## Description

Using `expect` to destructure values can crash at runtime if the pattern doesn't match. While `expect Some(x) = option_val` is a common and necessary pattern for `Option` types, using `expect` on redeemer-derived values is risky because the redeemer is entirely attacker-controlled. If the redeemer value doesn't match the expected pattern, the transaction fails at runtime.

This detector specifically flags `expect` patterns applied to variables that are derived from the redeemer parameter. Datum `expect` patterns are handled by the separate `unsafe-datum-deconstruction` detector.

## Vulnerable Example

```aiken
type Action {
  Transfer { details: Data }
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Transfer { details } -> {
        // Dangerous: `details` comes from the redeemer (attacker-controlled)
        // If the structure doesn't match, expect crashes
        expect transfer_info: TransferInfo = details
        transfer_info.amount > 0
      }
    }
  }
}
```

An attacker submits a redeemer where `details` does not decode as `TransferInfo`, causing a runtime crash instead of a clean `False`.

## Safe Example

```aiken
type Action {
  Transfer { amount: Int, recipient: VerificationKeyHash }
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Transfer { amount, recipient } -> {
        // Use typed redeemer fields directly — no partial pattern needed
        amount > 0 && list.has(self.extra_signatories, recipient)
      }
    }
  }
}
```

## Remediation

1. Use fully typed redeemer constructors instead of `Data` fields that require runtime casting
2. If runtime casting is unavoidable, use `when` pattern matching instead of `expect` to handle the failure case explicitly
3. Validate redeemer structure with `when`/`if` guards before destructuring
4. Keep redeemer types simple and flat to avoid nested `expect` chains

## References

- [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
