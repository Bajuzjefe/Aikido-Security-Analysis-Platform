# redundant-check

**Severity:** Low
**Confidence:** Likely

## Description

A redeemer branch that unconditionally returns `True` without any validation is likely missing checks. This pattern makes the branch a no-op from a security perspective, allowing anyone to use that redeemer action without constraints.

## Vulnerable Example

```aiken
type Action {
  Deposit
  Withdraw
  Admin
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Deposit -> True  // No validation at all!
      Withdraw -> check_withdrawal(datum, self)
      Admin -> check_admin(datum, self)
    }
  }
}
```

Anyone can submit a `Deposit` redeemer and the validator will accept it unconditionally, regardless of what the transaction does.

## Safe Example

```aiken
type Action {
  Deposit
  Withdraw
  Admin
}

validator {
  spend(datum, redeemer: Action, own_ref, self) {
    when redeemer is {
      Deposit -> {
        let continuing_output = find_continuing_output(self.outputs, own_ref)
        value.lovelace_of(continuing_output.value) > value.lovelace_of(own_input.value)
      }
      Withdraw -> check_withdrawal(datum, self)
      Admin -> check_admin(datum, self)
    }
  }
}
```

## Remediation

1. Add appropriate validation logic to every redeemer branch
2. If a branch truly should accept all transactions, document the reasoning with a comment
3. If a branch should never be used, replace `True` with `fail @"Not implemented"` or remove it entirely

## References

- [CWE-570: Expression is Always True](https://cwe.mitre.org/data/definitions/570.html)
