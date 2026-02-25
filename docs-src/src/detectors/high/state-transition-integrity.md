# state-transition-integrity

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html) -- Insufficient Verification of Data Authenticity

## What it detects

Finds spend handlers that implement multiple redeemer actions (state machine transitions) but never verify the output datum. When a validator processes actions like Deposit, Withdraw, or Update without checking that the continuing output carries the correctly updated datum, an attacker can submit a valid action while attaching a manipulated datum to the output.

## Why it matters

Cardano smart contracts commonly implement state machines where the datum represents protocol state and the redeemer selects which transition to apply. Each transition must enforce two things: (1) the action's preconditions are met, and (2) the output datum correctly reflects the new state.

If only the preconditions are checked but the output datum is not verified:

- **Lending protocol**: An attacker performs a Deposit action with the correct collateral amount but attaches a datum that inflates their recorded balance, enabling them to borrow more than they deposited.
- **DEX pool**: A swap action verifies the constant-product invariant on values but does not verify the output datum's recorded reserves. The attacker corrupts the price oracle embedded in the datum.
- **Escrow contract**: A Release action checks the signer but does not verify the output datum's status field. The attacker keeps the escrow in an "active" state while extracting funds, allowing a second release.
- **DAO treasury**: A Vote action checks quorum but not the output datum, allowing an attacker to reset the vote count while keeping the proposal active.

This vulnerability is particularly dangerous because the transaction appears valid -- the action's value-level checks pass -- while the protocol's logical state is silently corrupted.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference, InlineDatum}
use cardano/value

type PoolDatum {
  reserve_a: Int,
  reserve_b: Int,
  lp_supply: Int,
}

type PoolAction {
  Deposit { amount_a: Int, amount_b: Int }
  Withdraw { lp_amount: Int }
  Swap { amount_in: Int }
}

validator liquidity_pool {
  spend(
    datum: Option<PoolDatum>,
    redeemer: PoolAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum
    let output =
      list.find(self.outputs, fn(o) {
        o.address == own_ref.output_reference
      })

    when redeemer is {
      // BUG: Checks value but NEVER verifies output datum.
      // Attacker can attach any datum to the continuing output.
      Deposit { amount_a, amount_b } -> {
        value.lovelace_of(output.value) >= value.lovelace_of(own_ref.value) + amount_a
      }
      Withdraw { lp_amount } -> {
        lp_amount > 0
      }
      Swap { amount_in } -> {
        amount_in > 0 && value.lovelace_of(output.value) > 0
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
  reserve_a: Int,
  reserve_b: Int,
  lp_supply: Int,
}

type PoolAction {
  Deposit { amount_a: Int, amount_b: Int }
  Withdraw { lp_amount: Int }
  Swap { amount_in: Int }
}

validator liquidity_pool {
  spend(
    datum: Option<PoolDatum>,
    redeemer: PoolAction,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum
    let output =
      list.find(self.outputs, fn(o) {
        o.address == own_ref.output_reference
      })

    // SAFE: Extract and verify the output datum for every action
    expect InlineDatum(raw_datum) = output.datum
    expect new_datum: PoolDatum = raw_datum

    when redeemer is {
      Deposit { amount_a, amount_b } -> {
        // Verify the output datum reflects the deposit
        new_datum.reserve_a == d.reserve_a + amount_a &&
        new_datum.reserve_b == d.reserve_b + amount_b &&
        new_datum.lp_supply == d.lp_supply &&
        value.lovelace_of(output.value) >= value.lovelace_of(own_ref.value) + amount_a
      }
      Withdraw { lp_amount } -> {
        let share = lp_amount * d.reserve_a / d.lp_supply
        new_datum.reserve_a == d.reserve_a - share &&
        new_datum.lp_supply == d.lp_supply - lp_amount
      }
      Swap { amount_in } -> {
        // Constant product invariant on BOTH value and datum
        let new_product = new_datum.reserve_a * new_datum.reserve_b
        let old_product = d.reserve_a * d.reserve_b
        new_product >= old_product
      }
    }
  }
}
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator and the handler is a `spend` handler.
2. The handler has **two or more** non-catchall, non-error `when` branches (indicating multiple redeemer actions).
3. The handler accesses `outputs` from the transaction context (indicating it produces continuing UTXOs).
4. The handler does **not** reference `datum` in record label accesses, does not call `InlineDatum`, `inline_datum`, `DatumHash`, or `datum_hash`, and does not reference `InlineDatum`, `DatumHash`, or `NoDatum` as variable names.

The absence of any datum inspection on outputs, combined with multi-action state management, strongly indicates that output state is not validated.

## False Positives

Suppress this finding when:

- **Terminal actions only**: All redeemer branches consume the UTXO entirely (no continuing output). In this case, there is no output datum to verify.
- **Datum verification in a helper module**: A cross-module helper function handles datum validation. Aikido's cross-module analysis may not trace into all helper patterns.
- **Single-output validator**: The validator sends funds to a different script that is responsible for datum validation.

```aiken
// aikido:ignore[state-transition-integrity] -- datum verified in helpers/validate.ak
```

## Related Detectors

- [arbitrary-datum-in-output](arbitrary-datum-in-output.md) -- Outputs produced without validating datum correctness (broader check).
- [missing-datum-in-script-output](missing-datum-in-script-output.md) -- Script outputs that have no datum attached at all.
- [missing-state-update](../medium/missing-state-update.md) -- State machine without any datum update logic.
