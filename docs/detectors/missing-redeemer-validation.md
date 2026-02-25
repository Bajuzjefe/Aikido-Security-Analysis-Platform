# missing-redeemer-validation

**Severity:** High (catch-all) / Medium (named branch)
**Confidence:** Definite (catch-all) / Likely (named)

## Description

Detects redeemer branches that unconditionally return `True`. A catch-all (`_ -> True`) means ANY redeemer value is accepted without validation. A named branch returning `True` means that specific action bypasses all checks.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    when redeemer is {
      Close -> verify_close(datum, self)
      _ -> True  // Any other redeemer passes!
    }
  }
}
```

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    when redeemer is {
      Close -> verify_close(datum, self)
      Update -> verify_update(datum, redeemer, self)
    }
    // No catch-all — unknown redeemers fail automatically
  }
}
```

## Remediation

1. Remove catch-all branches that return `True`
2. Explicitly handle each redeemer variant with proper validation
3. Let Aiken's exhaustiveness checking catch unhandled variants

## References

- [MLabs Plutus Audit Checklist](https://library.mlabs.city/common-plutus-security-vulnerabilities)
