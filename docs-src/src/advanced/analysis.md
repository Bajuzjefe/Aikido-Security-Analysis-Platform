# Analysis Techniques

Aikido goes beyond simple pattern matching. It uses several analysis techniques to reduce false positives and catch vulnerabilities that span multiple functions, modules, and handlers.

## Cross-module interprocedural analysis

Aiken projects commonly split logic across modules -- a `utils.ak` module with helper functions, a `types.ak` module with data type definitions, and validator modules that import from both. A vulnerability that depends on what a helper function does (or fails to do) cannot be detected by analyzing each module in isolation.

Aikido resolves qualified function calls across module boundaries. When a validator calls `utils.check_signature(ctx)`, Aikido follows the call into the `utils` module, analyzes what `check_signature` actually checks, and carries that information back to the calling validator. This works transitively -- if `check_signature` calls another helper, that call is followed too.

The call resolution handles:

- **Qualified imports** -- `use my_project/utils` followed by `utils.check_signature(ctx)`.
- **Unqualified imports** -- `use my_project/utils.{check_signature}` followed by `check_signature(ctx)`.
- **Transitive calls** -- chains of function calls across multiple modules.
- **Opaque types** -- type definitions whose internals are not exported are tracked by name so detectors can reason about data flow even when constructors are hidden.

This analysis is what allows Aikido to avoid a class of false positive where a validator delegates a check to a helper function. Without cross-module resolution, the analyzer would see the validator body as missing the check and emit a false finding.

## Cross-handler analysis

Aiken validators often handle multiple purposes (spend, mint, withdraw) in a single module using a `when` expression on the redeemer. Aikido correlates signals across all handlers within a validator:

- A check that appears in one handler branch but not another is flagged only for the branch that lacks it.
- Shared state mutations (datum updates, token movements) are tracked across handler boundaries.
- Multi-validator coordination -- when a spend validator references a minting policy or vice versa -- is detected and analyzed for consistency.

## Taint tracking

Taint tracking traces data from untrusted sources to security-critical operations. In the context of Aiken validators, the primary untrusted sources are:

- **Redeemer fields** -- attacker-controlled data submitted with the transaction.
- **Transaction outputs** -- the outputs of the spending transaction, which the attacker constructs.
- **Datum fields** -- while datums are set by previous transactions, validators must still verify their contents.

Aikido marks these sources as tainted and follows the data through variable bindings, function arguments, pattern matches, and list operations. When tainted data reaches a critical sink without validation, a finding is emitted. Critical sinks include:

- Arithmetic operations (division by zero, integer underflow).
- Value comparisons used for authorization decisions.
- Output construction (address, value, datum fields).
- Minting policy token name and quantity.

## Symbolic execution

Aikido performs lightweight symbolic execution with constraint propagation to reason about value ranges and reachability:

- **Constraint propagation** -- when a branch condition like `amount > 0` is true, Aikido narrows the possible range of `amount` within that branch. This reduces false positives for checks like division-by-zero where a guard clause has already excluded zero.
- **Path feasibility** -- unreachable code paths (guarded by contradictory conditions) are identified and excluded from analysis, preventing findings in dead code that could never execute.
- **Arithmetic tracking** -- operations on constrained values propagate constraints forward. If `x > 10` and `y = x - 5`, then `y > 5` is inferred.

This is not full symbolic execution in the formal verification sense. It does not explore all possible execution paths exhaustively. It is a best-effort analysis that significantly improves precision for common patterns.

## Call graph construction

Aikido builds a complete call graph for every module in the project. The call graph maps which functions call which other functions, including cross-module calls. This serves several purposes:

- **Reachability analysis** -- determines whether a function is reachable from a validator entry point. Findings in unreachable code are downgraded or suppressed.
- **Recursive call detection** -- identifies recursive and mutually recursive functions for the unconstrained-recursion detector.
- **Interprocedural data flow** -- enables taint tracking and signal propagation across function call boundaries.
- **Dead code detection** -- functions that are defined but never called from any validator entry point are flagged by the dead-code-path detector.

## UPLC budget estimation

Beyond the typed AST analysis, Aikido inspects the compiled UPLC (Untyped Plutus Lambda Calculus) code from the project blueprint:

- **Compiled size** -- reports the byte size of each compiled validator.
- **Execution budget** -- estimates CPU and memory costs from the UPLC term structure.
- **Budget warnings** -- flags validators that exceed configurable thresholds (default: 50% of the on-chain execution budget limit).

Use the `--verbose` flag to see UPLC metrics in the terminal output. Budget warnings are always shown regardless of verbosity.

## Confidence scoring

Every finding includes a confidence level that indicates how certain Aikido is that the finding represents a real vulnerability:

| Confidence | Meaning |
|------------|---------|
| `definite` | The analyzer has high certainty this is a real issue. The vulnerable pattern is present with no mitigating factors found in the reachable code. |
| `likely` | The pattern is present and likely vulnerable, but there may be mitigating factors that the analyzer cannot fully resolve (e.g., an external oracle check, off-chain validation). |
| `possible` | The pattern matches a known vulnerability class, but the context suggests it may be intentional or mitigated in ways the analyzer cannot verify. Review recommended. |

Confidence is determined by combining multiple signals:

- Whether the check is missing entirely vs. present but incomplete.
- Whether cross-module analysis found a mitigating function call.
- Whether the finding is in a reachable code path.
- Whether similar patterns elsewhere in the codebase suggest intentional design.

You can use `--min-severity` to filter output by severity, but confidence is always shown alongside each finding to help you prioritize review. Definite findings should be investigated first; possible findings can often be deferred.
