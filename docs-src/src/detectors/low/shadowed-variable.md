# shadowed-variable

**Severity:** Info | **CWE:** CWE-1078 (Inappropriate Source Code Style or Formatting)

## What it detects

Handler parameters that are shadowed by identically named bindings in `when`/`match` pattern destructuring. Within the shadowed branch, references to the name resolve to the pattern-bound value rather than the original handler parameter.

## Why it matters

Variable shadowing is a common source of subtle bugs in any language, but it is particularly dangerous in smart contract validators where a single incorrect variable reference can lead to funds being locked or stolen:

- **Wrong value used**: A developer may intend to reference the handler's `datum` parameter but accidentally use a pattern-bound `datum` from a destructured type. The two may have completely different types or values.
- **Silent type change**: Aiken's type system may not catch the error if both the parameter and the pattern binding happen to have compatible types. The code compiles and runs, but uses the wrong data.
- **Review difficulty**: During code review, it is easy to overlook shadowing because the name looks correct. The bug only becomes apparent when tracing the exact scoping rules.
- **Refactoring hazard**: Renaming a field in a type definition can inadvertently introduce or remove shadowing, changing validator behavior.

## Example: Flagged Code

```aiken
type MyRedeemer {
  Update { datum: Data }
  Close
}

validator escrow {
  spend(datum: Option<EscrowDatum>, redeemer: MyRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      // "datum" in the pattern shadows the handler's "datum" parameter!
      Update { datum } -> {
        // This references the redeemer's datum field, NOT the UTXO datum
        verify_update(datum, self)
        // Developer likely intended: verify_update(d, self)
      }
      Close -> verify_close(d, self)
    }
  }
}
```

## Example: Improved Code

```aiken
type MyRedeemer {
  Update { datum: Data }
  Close
}

validator escrow {
  spend(datum: Option<EscrowDatum>, redeemer: MyRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      // Use a distinct name to avoid confusion
      Update { datum: new_datum } -> {
        verify_update(d, new_datum, self)
      }
      Close -> verify_close(d, self)
    }
  }
}
```

Alternatively, use the field access pattern to make the source explicit:

```aiken
when redeemer is {
  Update(update_data) -> {
    let new_datum = update_data.datum
    verify_update(d, new_datum, self)
  }
  Close -> verify_close(d, self)
}
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines validator handlers in validator modules.
2. **Parameter collection**: Collects all handler parameter names, excluding those prefixed with `_` (intentionally discarded).
3. **Pattern scan**: For each `when`/`match` branch, checks whether any handler parameter name appears within the branch's pattern text (e.g., `Update { datum }` contains `datum`).
4. **Self-match exclusion**: Skips cases where the pattern text is exactly the parameter name (this would be a direct match, not destructuring).
5. **Catch-all exclusion**: Catch-all branches are skipped since they do not introduce new bindings.
6. **Confidence**: Rated as `possible` because the detector uses string containment on pattern text, which may match substrings (e.g., parameter `a` matching inside `datum`).

## False Positives

This detector may produce false positives when:

- A handler parameter name is a substring of an unrelated identifier in the pattern text. For example, parameter `id` would match in `Update { validator_id }` even though `validator_id` is a different binding.
- The pattern text contains the parameter name as part of a type annotation or comment, not as an actual binding.
- The shadowing is intentional and the developer wants to use the pattern-bound value rather than the parameter within that branch.

Suppress with:

```aiken
// aikido:ignore[shadowed-variable] -- intentional: using redeemer's datum field
```

## Related Detectors

- [unused-validator-parameter](unused-validator-parameter.md) -- Validator parameter never referenced at all
- [dead-code-path](dead-code-path.md) -- Unreachable code paths that may result from shadowing confusion
- [unsafe-datum-deconstruction](../high/unsafe-datum-deconstruction.md) -- Unsafe Option datum handling
