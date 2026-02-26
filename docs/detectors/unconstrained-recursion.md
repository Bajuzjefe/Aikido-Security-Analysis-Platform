# unconstrained-recursion

**Severity:** Medium
**Confidence:** Possible

## Description

A handler or function that calls itself (directly recursive) without clear base case indicators may loop indefinitely, consuming all available execution budget. On Cardano, this results in a failed transaction and lost fees.

This detector flags both library functions with self-recursive calls that lack obvious base cases (no `when`/match branches with `True` or `fail` returns), and validator handlers that appear to call themselves recursively.

## Vulnerable Example

```aiken
fn process_items(items: List<Item>, acc: Int) -> Int {
  // No when/match with a base case — if the list is infinite
  // or the termination condition is never met, this loops forever
  let item = list.head(items)
  let rest = list.tail(items)
  process_items(rest, acc + item.value)
}

validator {
  spend(datum, redeemer, own_ref, self) {
    process_items(datum.items, 0) > 100
  }
}
```

If the list manipulation does not converge, the function consumes the entire execution budget and the transaction fails.

## Safe Example

```aiken
fn process_items(items: List<Item>, acc: Int) -> Int {
  when items is {
    [] -> acc  // Clear base case: empty list returns accumulator
    [item, ..rest] -> process_items(rest, acc + item.value)
  }
}

validator {
  spend(datum, redeemer, own_ref, self) {
    process_items(datum.items, 0) > 100
  }
}
```

## Remediation

1. Ensure every recursive function has an explicit base case using `when`/match pattern matching
2. Prefer `list.foldl`, `list.map`, or other higher-order functions from the stdlib instead of manual recursion
3. If recursion depth depends on user-controlled data, enforce a maximum depth
4. Review recursive handler calls carefully -- validators calling themselves recursively is unusual and may indicate a logic error

## References

- [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)
