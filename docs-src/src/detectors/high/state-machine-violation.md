# state-machine-violation

**Severity:** High | **Confidence:** varies | **CWE:** [CWE-754](https://cwe.mitre.org/data/definitions/754.html)

## What it detects

State machine issues in redeemer handling, including: unhandled redeemer actions, actions that always succeed without validation, terminal actions without token burns, non-terminal actions without continuing outputs, and catchall branches that accept unknown actions.

## Why it matters

Validators often implement state machines through redeemer variants. Each variant represents an action that transitions the protocol state. If any action is unhandled, always succeeds, or lacks proper cleanup, an attacker can exploit the gap to bypass protocol logic.

**Real-world impact:** A lending protocol has redeemer variants `Deposit`, `Borrow`, `Repay`, and `Liquidate`. The developer adds a catchall `_ -> True` branch for "future compatibility." An attacker sends any unknown redeemer action, which passes validation unconditionally, allowing them to spend the UTXO however they want.

## Example: Vulnerable Code

```aiken
validator lending {
  spend(datum: LoanDatum, redeemer: LoanAction, _own_ref: OutputReference, self: Transaction) {
    when redeemer is {
      Deposit -> validate_deposit(datum, self)
      Borrow -> validate_borrow(datum, self)
      // VULNERABLE: catchall accepts any unknown action
      _ -> True
    }
  }
}
```

## Example: Safe Code

```aiken
validator lending {
  spend(datum: LoanDatum, redeemer: LoanAction, _own_ref: OutputReference, self: Transaction) {
    when redeemer is {
      Deposit -> validate_deposit(datum, self)
      Borrow -> validate_borrow(datum, self)
      Repay -> validate_repay(datum, self)
      Liquidate -> {
        // Terminal action: burns the loan token
        let burns_token =
          value.quantity_of(value.from_minted_value(self.mint), datum.loan_policy, datum.loan_name) == -1
        burns_token && validate_liquidation(datum, self)
      }
    }
  }
}
```

## Detection Logic

Aikido flags multiple sub-patterns:

1. **UnhandledAction** (High/Likely) - A redeemer type has variants that are not matched in the `when` expression.
2. **AlwaysSucceeds** (High/Definite) - A branch body evaluates to `True` unconditionally.
3. **CatchallAcceptsUnknown** (High/Likely) - A `_` wildcard branch succeeds without validation.
4. **TerminalWithoutBurn** (Medium/Possible) - A destructive action does not check `self.mint` for burns.
5. **NonTerminalWithoutOutput** (Medium/Possible) - A non-terminal action does not produce a continuing output.

## False Positives

- **Intentional catchall for admin override:** Some protocols use a catchall for emergency admin actions. Suppress with `// aikido:ignore[state-machine-violation]`.
- **Terminal actions with external burn:** If the burn is handled by a separate minting policy validator, the detector may not trace the connection.

## Related Detectors

- [non-exhaustive-redeemer](../medium/non-exhaustive-redeemer.md) - Simpler check for unmatched redeemer variants.
- [incomplete-burn-flow](incomplete-burn-flow.md) - Terminal actions missing burns across validators.
- [empty-handler-body](../medium/empty-handler-body.md) - Handlers that do nothing (always succeed).
