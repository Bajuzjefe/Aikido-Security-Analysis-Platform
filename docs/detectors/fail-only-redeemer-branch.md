# fail-only-redeemer-branch

**Severity:** Low
**Confidence:** Likely

## Description

Detects redeemer when/match branches that always fail (return `False`, call `fail`, or `error`). Named branches that always fail are dead code — the redeemer variant exists but can never be used successfully. This may indicate incomplete implementation or a placeholder that was never replaced.

Note: Catch-all branches (`_ -> fail`) are NOT flagged, as they represent a valid "deny by default" pattern.

## Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    when redeemer is {
      Close -> verify_close(datum, self)
      Update -> fail  // Dead branch — always fails
    }
  }
}
```

## Remediation

1. Implement the branch with proper validation logic
2. Or remove the unused redeemer variant from the type definition

## References

- [Aiken Pattern Matching](https://aiken-lang.org/language-tour/control-flow)
