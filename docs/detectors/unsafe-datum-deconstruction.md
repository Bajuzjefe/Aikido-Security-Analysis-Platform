# unsafe-datum-deconstruction

**Severity:** High
**Confidence:** Likely

## Description

Detects spend handlers with `Option<T>` datum parameter that never safely deconstruct it with `expect Some(x) = datum`. In Plutus V3/Aiken, spend datums can be `None` if the UTXO was created without a datum. Failing to handle this case causes a runtime crash.

## Vulnerable Example

```aiken
validator {
  spend(datum_opt: Option<Datum>, _redeemer, _own_ref, self) {
    // Accesses datum_opt directly without checking if it's Some
    datum_opt.amount > 0  // Runtime crash if None!
  }
}
```

## Safe Example

```aiken
validator {
  spend(datum_opt: Option<Datum>, _redeemer, _own_ref, self) {
    expect Some(datum) = datum_opt
    datum.amount > 0
  }
}
```

## Remediation

1. Always use `expect Some(datum) = datum_opt` to safely unwrap the Option
2. This ensures a clear error if the UTXO has no datum, rather than a confusing runtime crash

## References

- [Aiken V3 Datum Handling](https://aiken-lang.org/language-tour/validators)
