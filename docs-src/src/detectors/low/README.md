# Low / Info Detectors

Low and Info severity detectors identify code quality issues, potential design concerns, and best practice violations. These findings rarely represent direct security risks but can indicate areas for improvement.

| Detector | Severity | Description |
|----------|----------|-------------|
| [reference-script-injection](reference-script-injection.md) | Low | Outputs don't constrain reference_script field |
| [unused-validator-parameter](unused-validator-parameter.md) | Low | Validator parameter never referenced |
| [fail-only-redeemer-branch](fail-only-redeemer-branch.md) | Low | Redeemer branch that always fails |
| [missing-min-ada-check](missing-min-ada-check.md) | Info | Script output without minimum ADA check |
| [dead-code-path](dead-code-path.md) | Low | Unreachable code paths |
| [redundant-check](redundant-check.md) | Low | Trivially true conditions |
| [shadowed-variable](shadowed-variable.md) | Info | Handler parameter shadowed by pattern binding |
| [magic-numbers](magic-numbers.md) | Info | Unexplained numeric literals |
| [excessive-validator-params](excessive-validator-params.md) | Info | Too many validator parameters |
| [unused-import](unused-import.md) | Info | Imported module with no function calls |
