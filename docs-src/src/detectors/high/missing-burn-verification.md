# missing-burn-verification

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html) -- Missing Authorization

## What it detects

Finds spend handlers in multi-handler validators that perform value reduction (subtraction) and produce continuing outputs but do not check the transaction's `mint` field. When a validator has a mint handler, protocol tokens exist -- and withdrawals or value reductions should verify that corresponding tokens are burned in the same transaction.

## Why it matters

In Cardano DeFi, receipt tokens, LP tokens, and debt tokens represent claims on locked value. When a user withdraws value from a protocol, the corresponding tokens must be burned to prevent double-spending. If the spend handler processes a withdrawal without verifying that the mint field contains the expected burns:

- **LP token double-spend**: A DEX pool allows a withdrawal that reduces the pool's reserve. The attacker does not burn their LP tokens, keeping them for a second withdrawal. The pool is drained over multiple transactions.
- **Receipt token fraud**: A lending protocol processes a collateral withdrawal without burning receipt tokens. The attacker still holds receipts that can be redeemed again, extracting value beyond their deposit.
- **Phantom debt**: A loan repayment reduces the lender's tracked value but does not burn the borrower's debt tokens. The debt still "exists" and can be traded or used as collateral elsewhere.
- **Staking reward theft**: A staking contract processes an unstake operation (value subtraction) without burning the staking receipt NFT. The attacker unstakes, keeps the receipt, and claims rewards again.

The root cause is a missing coordination check: the spend handler manages value but is blind to token supply changes, creating a gap between economic state and token state.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference, InlineDatum}
use cardano/value

type PoolDatum {
  total_reserve: Int,
  lp_supply: Int,
}

type PoolAction {
  Deposit { amount: Int }
  Withdraw { lp_tokens: Int }
}

type MintAction {
  MintLP
  BurnLP
}

validator lending_pool {
  spend(
    datum: Option<PoolDatum>,
    redeemer: PoolAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum
    expect Some(output) =
      list.find(self.outputs, fn(o) { o.address == own_ref.output_reference })
    expect InlineDatum(raw) = output.datum
    expect new_datum: PoolDatum = raw

    when redeemer is {
      Deposit { amount } -> {
        new_datum.total_reserve == d.total_reserve + amount
      }
      Withdraw { lp_tokens } -> {
        let payout = lp_tokens * d.total_reserve / d.lp_supply

        // BUG: Subtracts from reserve and produces continuing output,
        // but NEVER checks self.mint to verify LP tokens are burned!
        // Attacker keeps their LP tokens after withdrawing.
        new_datum.total_reserve == d.total_reserve - payout &&
        value.lovelace_of(output.value) >= d.total_reserve - payout
      }
    }
  }

  mint(redeemer: MintAction, self: Transaction) {
    when redeemer is {
      MintLP -> {
        let minted = value.from_minted_value(self.mint)
        value.quantity_of(minted, self.id, "LP") > 0
      }
      BurnLP -> {
        let minted = value.from_minted_value(self.mint)
        value.quantity_of(minted, self.id, "LP") < 0
      }
    }
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction, OutputReference, InlineDatum}
use cardano/value

type PoolDatum {
  total_reserve: Int,
  lp_supply: Int,
}

type PoolAction {
  Deposit { amount: Int }
  Withdraw { lp_tokens: Int }
}

type MintAction {
  MintLP
  BurnLP
}

validator lending_pool {
  spend(
    datum: Option<PoolDatum>,
    redeemer: PoolAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum
    expect Some(output) =
      list.find(self.outputs, fn(o) { o.address == own_ref.output_reference })
    expect InlineDatum(raw) = output.datum
    expect new_datum: PoolDatum = raw

    // SAFE: Check the mint field in every code path
    let minted = value.from_minted_value(self.mint)
    let lp_burned = value.quantity_of(minted, self.id, "LP")

    when redeemer is {
      Deposit { amount } -> {
        let expected_lp = amount * d.lp_supply / d.total_reserve
        // Verify LP tokens are minted during deposit
        lp_burned == expected_lp &&
        new_datum.total_reserve == d.total_reserve + amount &&
        new_datum.lp_supply == d.lp_supply + expected_lp
      }
      Withdraw { lp_tokens } -> {
        let payout = lp_tokens * d.total_reserve / d.lp_supply

        // SAFE: Verify LP tokens are burned (negative quantity)
        lp_burned == -lp_tokens &&
        new_datum.total_reserve == d.total_reserve - payout &&
        new_datum.lp_supply == d.lp_supply - lp_tokens &&
        value.lovelace_of(output.value) >= d.total_reserve - payout
      }
    }
  }

  mint(redeemer: MintAction, self: Transaction) {
    when redeemer is {
      MintLP -> {
        let minted = value.from_minted_value(self.mint)
        value.quantity_of(minted, self.id, "LP") > 0
      }
      BurnLP -> {
        let minted = value.from_minted_value(self.mint)
        value.quantity_of(minted, self.id, "LP") < 0
      }
    }
  }
}
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator and the handler is a `spend` handler.
2. The handler accesses `outputs` from the transaction context (indicating continuing UTXO production).
3. The handler performs **subtraction** (`has_subtraction` signal), indicating value reduction.
4. The handler does **not** access the `mint` field from the transaction context.
5. The validator also has a **`mint` handler**, indicating that protocol tokens exist and can be minted/burned.

The combination of value reduction (step 3) without burn verification (step 4) in a validator that has minting capabilities (step 5) strongly suggests that token burns are not coordinated with value withdrawals.

Note: The confidence is set to `possible` rather than `likely` because the subtraction may be used for fee calculations or other non-withdrawal purposes.

## False Positives

Suppress this finding when:

- **Subtraction is not a withdrawal**: The subtraction computes a fee, a ratio, or an intermediate value, not an actual value reduction from the UTXO. The output value may still be greater than or equal to the input value.
- **No protocol tokens to burn**: The mint handler mints a one-time authentication NFT during initialization, not ongoing receipt tokens. There is nothing to burn during regular spend operations.
- **Burn enforced by separate validator**: A separate spend validator in the same transaction verifies the burn. The detected handler delegates burn checking to another validator via composition.
- **Token burning is optional**: The protocol allows partial withdrawals without burning (e.g., accrued rewards that do not require token exchange).

```aiken
// aikido:ignore[missing-burn-verification] -- subtraction is fee calculation, not withdrawal
```

## Related Detectors

- [uncoordinated-multi-validator](uncoordinated-multi-validator.md) -- Broader check: spend handler in a multi-validator does not check the mint field at all.
- [missing-token-burn](../medium/missing-token-burn.md) -- Minting policy that has no burn handling.
- [value-not-preserved](value-not-preserved.md) -- Output value not verified against input value.
