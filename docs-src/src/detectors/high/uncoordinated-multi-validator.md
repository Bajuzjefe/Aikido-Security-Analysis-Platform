# uncoordinated-multi-validator

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-362](https://cwe.mitre.org/data/definitions/362.html) -- Concurrent Execution Using Shared Resource with Improper Synchronization

## What it detects

Finds multi-handler validators (validators with both `spend` and `mint` handlers) where the spend handler manages protocol state by producing continuing outputs but does not check the transaction's `mint` field. This means minting and burning operations are uncoordinated with state transitions, allowing an attacker to manipulate token supply independently of protocol state.

## Why it matters

In Cardano DeFi protocols, multi-handler validators are a standard pattern. The spend handler manages UTXO state (pool reserves, user balances, configuration), while the mint handler controls token supply (LP tokens, receipt tokens, debt tokens). These two handlers must be coordinated -- the spend handler should verify that any minting in the transaction is consistent with the state change being performed.

When the spend handler ignores the `mint` field:

- **DEX LP token inflation**: An attacker submits a deposit transaction to a liquidity pool. The spend handler verifies the deposit value and updates the pool datum. But because the spend handler does not check `mint`, the attacker also mints 10x the expected LP tokens via the mint handler in the same transaction, creating unbacked LP tokens.
- **Lending protocol receipt fraud**: A lending protocol mints receipt tokens when users deposit collateral. The spend handler processes a small deposit but does not verify the corresponding mint amount. The attacker mints excess receipt tokens, then redeems them later for more than they deposited.
- **Governance token dilution**: A DAO treasury allows minting governance tokens proportional to contributions. The spend handler records contributions but does not check how many tokens are actually minted. The attacker inflates their governance power.
- **Burn without withdrawal**: An attacker burns LP tokens (triggering the mint handler to validate the burn) without triggering a corresponding state update in the spend handler, keeping pool reserves intact while receiving the token's backing value through a separate transaction.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference, InlineDatum}
use cardano/value

type PoolDatum {
  reserve: Int,
  lp_supply: Int,
}

type PoolAction {
  Deposit { amount: Int }
  Withdraw { lp_amount: Int }
}

type MintAction {
  MintLP
  BurnLP
}

validator dex_pool {
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
        // BUG: Validates the deposit and updates state,
        // but does NOT check self.mint.
        // An attacker can mint arbitrary LP tokens in the same tx!
        new_datum.reserve == d.reserve + amount &&
        value.lovelace_of(output.value) >= d.reserve + amount
      }
      Withdraw { lp_amount } -> {
        lp_amount > 0 &&
        new_datum.reserve == d.reserve - lp_amount
      }
    }
  }

  mint(redeemer: MintAction, self: Transaction) {
    // Mint handler validates LP token operations
    // but spend handler doesn't coordinate with it!
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
  reserve: Int,
  lp_supply: Int,
}

type PoolAction {
  Deposit { amount: Int }
  Withdraw { lp_amount: Int }
}

type MintAction {
  MintLP
  BurnLP
}

validator dex_pool {
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

    // SAFE: Check the mint field in the spend handler to coordinate
    let minted = value.from_minted_value(self.mint)
    let lp_minted = value.quantity_of(minted, self.id, "LP")

    when redeemer is {
      Deposit { amount } -> {
        // Verify LP tokens minted match the deposit proportionally
        let expected_lp = amount * d.lp_supply / d.reserve
        lp_minted == expected_lp &&
        new_datum.reserve == d.reserve + amount &&
        new_datum.lp_supply == d.lp_supply + expected_lp &&
        value.lovelace_of(output.value) >= d.reserve + amount
      }
      Withdraw { lp_amount } -> {
        // Verify LP tokens are burned during withdrawal
        lp_minted == -lp_amount &&
        new_datum.reserve == d.reserve - lp_amount * d.reserve / d.lp_supply &&
        new_datum.lp_supply == d.lp_supply - lp_amount
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

1. The module is a validator.
2. The validator has **both** a `spend` handler and a `mint` handler (multi-handler pattern).
3. The `spend` handler accesses `outputs` from the transaction context (indicating state management with continuing UTXOs).
4. The `spend` handler does **not** access the `mint` field from the transaction context.

The combination of a multi-handler validator with state-managing spend logic (step 3) that ignores minting activity (step 4) indicates that token supply changes are uncoordinated with state transitions.

## False Positives

Suppress this finding when:

- **Independent handlers by design**: The mint and spend handlers are intentionally independent. For example, the mint handler controls a utility token unrelated to the spend handler's state (e.g., a governance token that can be minted/burned independently of pool operations).
- **Coordination via staking handler**: The protocol uses a staking (withdraw) handler as the coordination point instead of the spend handler. Both spend and mint delegate to the staking validator.
- **One-shot minting**: The mint handler is used only once during protocol initialization and is permanently locked afterward (e.g., minting a one-time auth NFT). Ongoing spend operations do not need to check minting.

```aiken
// aikido:ignore[uncoordinated-multi-validator] -- mint handler is for unrelated utility token
```

## Related Detectors

- [missing-burn-verification](missing-burn-verification.md) -- Value reduction without checking that tokens are burned.
- [other-token-minting](other-token-minting.md) -- Minting policy that does not restrict other policies.
- [missing-minting-policy-check](../critical/missing-minting-policy-check.md) -- Mint handler that does not validate token names.
