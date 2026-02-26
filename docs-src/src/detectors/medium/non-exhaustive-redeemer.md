# non-exhaustive-redeemer

**Severity:** Medium | **Confidence:** likely | **CWE:** [CWE-478](https://cwe.mitre.org/data/definitions/478.html)

## What it detects

Identifies handlers where a `when` match on the redeemer type does not explicitly handle all constructors, with remaining cases falling through to a catch-all (`_`) branch.

## Why it matters

If a redeemer type has constructors `Withdraw`, `Update`, and `Close`, but the handler only matches `Withdraw` with a catch-all for the rest, the `Update` and `Close` actions silently take whatever path the catch-all defines. This can lead to:

- **Unintended authorization**: If the catch-all returns `True`, any unhandled redeemer action succeeds without validation.
- **Silent failures**: If the catch-all calls `fail`, legitimate actions that were supposed to be implemented are blocked.
- **Logic errors**: New constructors added to the redeemer type are automatically handled by the catch-all, bypassing intended validation.

## Example: Vulnerable Code

```aiken
type Action {
  Withdraw
  Update { new_amount: Int }
  Close
}

validator escrow {
  spend(datum: EscrowDatum, redeemer: Action, _ref: OutputReference, self: Transaction) {
    when redeemer is {
      Withdraw -> check_withdrawal(datum, self)
      _ -> True  // Update and Close are silently accepted!
    }
  }
}
```

## Example: Safe Code

```aiken
validator escrow {
  spend(datum: EscrowDatum, redeemer: Action, _ref: OutputReference, self: Transaction) {
    when redeemer is {
      Withdraw -> check_withdrawal(datum, self)
      Update { new_amount } -> check_update(datum, new_amount, self)
      Close -> check_close(datum, self)
    }
  }
}
```

## Detection Logic

1. Examines `when` branches in handler bodies for patterns that include both named constructors and a catch-all (`_`).
2. Identifies the redeemer parameter by name (`redeemer`, `action`, `rdmr`).
3. Looks up the redeemer type definition to count its constructors.
4. Flags handlers where the number of explicitly named branches is less than the total constructor count.
5. Reports the coverage ratio (e.g., "1/3 constructors covered").

## False Positives

- **Intentional catch-all with `fail`**: If the catch-all branch calls `fail` (rejecting unknown actions), this is a safe defensive pattern. However, Aikido flags it because explicitly listing all constructors is more maintainable.
- **Single-constructor redeemers**: If the redeemer type has only one constructor, a catch-all is unnecessary but not dangerous.
- **Redeemer type in external dependency**: If the redeemer type is defined in an external package, Aikido may not find its definition.

Suppress with:
```aiken
// aikido:ignore[non-exhaustive-redeemer] -- catch-all intentionally calls fail
```

## Related Detectors

- [missing-redeemer-validation](../high/missing-redeemer-validation.md) -- Catch-all redeemer pattern that trivially returns True
- [empty-handler-body](empty-handler-body.md) -- Handler with no meaningful logic
