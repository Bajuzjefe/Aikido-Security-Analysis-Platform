# unconstrained-recursion

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-674](https://cwe.mitre.org/data/definitions/674.html)

## What it detects

Identifies functions that call themselves (direct recursion) without clear base case indicators such as `when`/`match` branches that return a literal or call `fail`. Also flags handler functions that appear to call themselves recursively.

## Why it matters

On Cardano, every script execution has a strict CPU and memory budget. Unbounded recursion will consume the entire budget, causing the transaction to fail and the user to lose their fee:

- **Budget exhaustion**: A recursive function without a proper termination condition runs until it hits the Plutus execution limit.
- **Logic errors**: Missing base cases often indicate incomplete implementations.
- **Attacker-controlled depth**: If the recursion depth depends on attacker-controlled data (e.g., list length from redeemer), the attacker can force arbitrarily deep recursion.

## Example: Vulnerable Code

```aiken
fn sum_values(items: List<Int>, acc: Int) -> Int {
  // Missing base case for empty list!
  let head = list.head(items)
  let tail = list.tail(items)
  sum_values(tail, acc + head)
}
```

## Example: Safe Code

```aiken
fn sum_values(items: List<Int>, acc: Int) -> Int {
  when items is {
    [] -> acc                                    // Base case: empty list
    [head, ..tail] -> sum_values(tail, acc + head)  // Recursive case
  }
}
```

Or use built-in list functions:

```aiken
fn sum_values(items: List<Int>) -> Int {
  list.foldl(items, 0, fn(item, acc) { acc + item })
}
```

## Detection Logic

1. For library functions: checks if the function calls itself (by name or fully-qualified name) and looks for base case indicators -- `when` branches with `body_is_literal_true` or `body_is_error`.
2. For validator handlers: flags any handler that appears to call itself, since recursive handlers are unusual and likely indicate logic errors.
3. Skips standard library modules (`aiken/`, `cardano/`) whose recursive functions are well-tested.

## False Positives

- **Correct recursion with base cases**: If the base case uses a mechanism Aikido does not recognize (e.g., a conditional `if` instead of `when`), the function may be flagged incorrectly.
- **Mutual recursion**: This detector only finds direct self-recursion. Indirect recursion (A calls B calls A) is not detected.
- **Tail-recursive functions**: Aiken optimizes tail recursion, so the budget concern is reduced. The function is still flagged for review.

Suppress with:
```aiken
// aikido:ignore[unconstrained-recursion] -- base case handled by if-else
```

## Related Detectors

- [unbounded-list-iteration](unbounded-list-iteration.md) -- Iteration over unbounded transaction lists
- [unbounded-protocol-operations](unbounded-protocol-operations.md) -- O(n*m) dual iteration
