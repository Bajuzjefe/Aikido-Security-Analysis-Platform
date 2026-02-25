# incomplete-burn-flow

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-404](https://cwe.mitre.org/data/definitions/404.html)

## What it detects

Destructive operations (close, cancel, liquidate) that consume tokens from inputs but no validator in the project checks the mint field for burning. The tokens remain in circulation as "ghost tokens."

## Why it matters

When a protocol issues tokens (identity tokens, state tokens, receipt tokens) and later performs a terminal action that logically ends the lifecycle, those tokens must be burned. If they are not, ghost tokens persist on-chain and can be used to forge identities or bypass authentication checks in other parts of the protocol.

**Real-world impact:** A staking protocol mints a "stake_receipt" token when users deposit. The unstake handler returns funds but never burns the receipt token. An attacker collects spent receipt tokens and uses them to claim rewards from other pools that check for receipt token presence.

## Example: Vulnerable Code

```aiken
validator staking {
  spend(datum: StakeDatum, redeemer: Unstake, own_ref: OutputReference, self: Transaction) {
    let is_signed = list.has(self.extra_signatories, datum.staker)
    let rewards = calculate_rewards(datum)

    // VULNERABLE: returns funds but never burns the stake receipt token
    let pays_staker =
      list.any(self.outputs, fn(o) {
        o.address == datum.staker_address
          && value.lovelace_of(o.value) >= datum.staked_amount + rewards
      })

    is_signed && pays_staker
  }
}
```

## Example: Safe Code

```aiken
validator staking {
  spend(datum: StakeDatum, redeemer: Unstake, own_ref: OutputReference, self: Transaction) {
    let is_signed = list.has(self.extra_signatories, datum.staker)

    // SAFE: burn the receipt token on unstake
    let burns_receipt =
      value.quantity_of(
        value.from_minted_value(self.mint),
        datum.receipt_policy,
        datum.receipt_name,
      ) == -1

    let pays_staker =
      list.any(self.outputs, fn(o) {
        o.address == datum.staker_address
          && value.lovelace_of(o.value) >= datum.staked_amount + calculate_rewards(datum)
      })

    is_signed && burns_receipt && pays_staker
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A spend handler performs a terminal action** - detected by redeemer variant names (Close, Cancel, Liquidate, Remove, Unstake) or by not producing a continuing output.
2. **Tokens are present in the consumed input** - the input UTXO contains native assets beyond ADA.
3. **No validator in the project checks `self.mint` for negative quantities** on the relevant policy.

## False Positives

- **Tokens managed externally:** If a separate minting policy handles burns in its own validator, Aikido may not trace the connection. Suppress with `// aikido:ignore[incomplete-burn-flow]`.
- **Non-identity tokens:** If the tokens are fungible rewards rather than identity tokens, burning may not be required.

## Related Detectors

- [missing-burn-verification](missing-burn-verification.md) - Detects minting without checking for burns in general.
- [missing-token-burn](../medium/missing-token-burn.md) - Complementary: focuses on specific token lifecycle.
- [state-transition-integrity](state-transition-integrity.md) - Terminal states should enforce cleanup including burns.
