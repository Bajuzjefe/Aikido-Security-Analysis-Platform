# unused-library-module

**Severity:** Info | **Confidence:** possible | **CWE:** [CWE-561](https://cwe.mitre.org/data/definitions/561.html)

## What it detects

Library modules whose functions are not transitively reachable from any validator module. Type-only modules (those with no functions) are excluded since Aiken imports types implicitly.

## Why it matters

Unused library modules increase codebase size without contributing to the on-chain validators. They add maintenance burden, can confuse auditors, and may contain outdated logic that developers mistakenly reference.

## Example: Vulnerable Code

```
lib/
  myproject/
    utils.ak       <- used by validators
    deprecated.ak   <- NOT used by any validator (flagged)
validators/
  pool.ak           <- imports utils.ak
```

## Example: Safe Code

```
lib/
  myproject/
    utils.ak       <- used by validators
validators/
  pool.ak           <- imports utils.ak
```

Remove `deprecated.ak` or add a validator dependency.

## Detection Logic

Aikido flags this pattern when:

1. **A module exists in `lib/`** and contains at least one function definition.
2. **No validator module imports the module** either directly or transitively through other library modules.

## False Positives

- **Test-only modules:** Modules used only in tests are not reachable from validators but serve a purpose. Suppress with `// aikido:ignore[unused-library-module]`.
- **Modules imported for types only:** If a module exports only types and no functions, it is excluded from detection.

## Related Detectors

- [unused-import](unused-import.md) - Unused imports within a single module.
- [dead-code-path](dead-code-path.md) - Unreachable code within a function.
