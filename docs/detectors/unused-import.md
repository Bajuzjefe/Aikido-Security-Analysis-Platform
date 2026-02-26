# unused-import

**Severity:** Info
**Confidence:** Possible

## Description

Validator handlers that don't call any library functions may have unused imports. While not a security issue, unused imports add clutter and may indicate incomplete implementations where expected checks were never added.

This detector flags handlers that reference variables but make no function calls at all. Most real validators call stdlib functions (`list.has`, `value.lovelace_of`, interval checks, etc.), so the absence of function calls is suspicious.

## Vulnerable Example

```aiken
use aiken/list
use cardano/value
use cardano/interval

validator {
  spend(datum, redeemer, own_ref, self) {
    // Imports list, value, and interval — but never calls any of them!
    // This may indicate missing validation logic
    datum.flag == True
  }
}
```

The imports suggest the developer intended to add list checks, value verification, and interval validation, but none of those checks are actually present.

## Safe Example

```aiken
use aiken/list
use cardano/value

validator {
  spend(datum, redeemer, own_ref, self) {
    // Imports are actually used
    let has_signer = list.has(self.extra_signatories, datum.owner)
    let output_value = value.lovelace_of(find_output(self.outputs).value)
    has_signer && output_value >= datum.min_amount
  }
}
```

## Remediation

1. Review the validator logic and add the missing validation that the imports were intended to support
2. Remove any imports that are genuinely not needed
3. If the validator intentionally avoids function calls (e.g., pure field comparisons), remove the unused imports to clarify intent

## References

- Aiken style guide recommends removing unused imports for clarity
