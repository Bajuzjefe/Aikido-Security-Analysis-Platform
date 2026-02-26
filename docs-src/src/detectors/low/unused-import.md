# unused-import

**Severity:** Info | **CWE:** -

## What it detects

Validator handlers that reference variables but make zero function calls. Since most real validators use standard library functions (e.g., `list.has`, `value.lovelace_of`, `interval.is_entirely_before`), a handler with no function calls likely has unused imports and may be missing expected validation logic.

## Why it matters

While unused imports are primarily a code cleanliness issue, in smart contracts they can signal a deeper problem:

- **Missing validation**: The most common reason a validator handler has no function calls is that expected checks were never implemented. For example, a handler might reference `datum` and `redeemer` variables but never call any functions to validate them.
- **Dead imports**: Aiken's `use` statements import modules, but if no functions from those modules are called, the imports serve no purpose. This clutters the module and can confuse readers about which dependencies are actually needed.
- **Incomplete refactoring**: During a refactoring session, function calls may be removed but the imports left behind. The handler logic may have been simplified to the point where it no longer performs meaningful validation.
- **Compile-time noise**: While Aiken itself may warn about unused imports, this detector catches the semantic pattern where a handler "looks active" (references variables) but "does nothing" (calls no functions).

## Example: Flagged Code

```aiken
use aiken/collection/list
use cardano/transaction/value

validator simple_lock {
  spend(datum: Option<LockDatum>, redeemer: LockRedeemer, own_ref: OutputReference, self: Transaction) {
    // References variables but calls no functions from imported modules!
    expect Some(d) = datum
    when redeemer is {
      Unlock -> d.owner == redeemer.signer
      // Missing: list.has(self.extra_signatories, d.owner)
      // Missing: value.lovelace_of(...)
      _ -> False
    }
  }
}
```

## Example: Improved Code

```aiken
use aiken/collection/list
use cardano/transaction/value

validator simple_lock {
  spend(datum: Option<LockDatum>, _redeemer: LockRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum

    // Actually use the imported modules for proper validation
    let signed_by_owner =
      list.has(self.extra_signatories, d.owner)

    let own_input = utils.find_input(self.inputs, own_ref)
    let preserves_value =
      value.lovelace_of(own_input.output.value) <= value.lovelace_of(
        list.find(self.outputs, fn(o) { o.address == d.recipient }).value,
      )

    signed_by_owner && preserves_value
  }
}
```

If the imports are genuinely unnecessary, remove them:

```aiken
// No imports needed for a simple validator
validator simple_lock {
  spend(datum: Option<LockDatum>, _redeemer: LockRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    list.has(self.extra_signatories, d.owner)
  }
}
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines validator handler bodies in validator modules.
2. **Function call check**: Examines the handler's `function_calls` set. If it is empty, the handler calls no functions at all.
3. **Activity check**: Verifies the handler has a non-empty `var_references` set, confirming the handler does reference variables (and is not simply an empty body, which is caught by [empty-handler-body](../medium/empty-handler-body.md)).
4. **Combined signal**: Only fires when function calls are empty AND variable references are non-empty. This distinguishes "active but function-less" handlers from truly empty handlers.
5. **Confidence**: Rated as `possible` because some validators legitimately perform all logic through pattern matching and comparisons without calling library functions.

## False Positives

This detector may produce false positives when:

- The validator performs all its logic through pattern matching, direct field comparisons, and boolean operators without calling any named functions. Simple validators like `datum.owner == signer` are valid but uncommon in production.
- Function calls happen in `expect` patterns (e.g., `expect Some(d) = datum`) which may not be captured in the function call set depending on the AST walking depth.
- The handler delegates all logic to inline lambdas or closures that are not tracked as named function calls.
- The validator is intentionally minimal (e.g., a "burn only" minting policy that just returns `False`).

Suppress with:

```aiken
// aikido:ignore[unused-import] -- validation done via pattern matching only
```

Or disable globally if your project style avoids library function calls:

```toml
[detectors]
disable = ["unused-import"]
```

## Related Detectors

- [empty-handler-body](../medium/empty-handler-body.md) -- Handler with no logic at all (no variables, no calls)
- [dead-code-path](dead-code-path.md) -- Unreachable code paths in handlers
- [unused-validator-parameter](unused-validator-parameter.md) -- Parameter declared but never referenced
- [redundant-check](redundant-check.md) -- Branches with trivially true conditions
