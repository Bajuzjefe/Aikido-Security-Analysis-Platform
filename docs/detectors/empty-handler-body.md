# empty-handler-body

**Severity:** Medium
**Confidence:** Likely

## Description

A handler that has no function calls, no variable references, no `when` branches, and no transaction field accesses is essentially empty -- it either trivially succeeds or fails without performing any validation. This is a strong indicator of a missing implementation or a placeholder that was accidentally left in production code.

## Vulnerable Example

```aiken
validator {
  spend(_datum, _redeemer, _own_ref, _self) {
    // No validation at all -- anyone can spend!
    True
  }

  mint(_redeemer, _policy_id, _self) {
    // No validation -- anyone can mint!
    True
  }
}
```

An empty spend handler allows anyone to spend UTXOs locked at the script address without any checks. An empty mint handler allows unrestricted token minting.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let must_be_signed = list.has(self.extra_signatories, datum.owner)
    let input = transaction.find_input(self.inputs, own_ref)
    let preserves_value = check_continuing_output(self.outputs, input)
    must_be_signed && preserves_value
  }

  mint(redeemer, policy_id, self) {
    let authorized = list.has(self.extra_signatories, redeemer.admin_key)
    authorized
  }
}
```

## Remediation

1. Add appropriate validation logic to the handler: signature checks, value preservation, datum validation, etc.
2. If the handler is a placeholder for future work, use `fail @"not implemented"` instead of `True` to prevent accidental acceptance.
3. Remove the handler entirely if it is not needed.

## References

- [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html)
