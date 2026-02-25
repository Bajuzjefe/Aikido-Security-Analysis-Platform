// Lending pool validator inspired by Lenfi (Aada Finance).
// Deliberately includes vulnerability patterns for aikido to detect.

use aiken/collection/list
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}
use lenfi/lending/types.{
  Borrow, LoanDatum, Liquidate, PoolAction, PoolDatum, Repay, Supply,
  UpdateConfig, Withdraw,
}

validator lending_pool(oracle_pkh: ByteArray) {
  spend(
    datum: Option<PoolDatum>,
    redeemer: PoolAction,
    _own_ref: OutputReference,
    tx: Transaction,
  ) {
    // VULN: uses _own_ref → double satisfaction risk
    expect Some(d) = datum

    when redeemer is {
      Supply -> {
        // Check that pool output exists with increased total
        // VULN: doesn't verify the output datum is correctly updated
        // VULN: doesn't verify value preservation
        let has_pool_output =
          list.any(tx.outputs, fn(o) { assets.lovelace_of(o.value) > 0 })
        has_pool_output
      }

      Withdraw -> {
        // VULN: no signature check — anyone can withdraw
        // VULN: no value preservation — doesn't check withdrawal amount
        list.length(tx.outputs) > 0
      }

      Borrow { amount } -> {
        // VULN: no signature check for borrower
        // VULN: doesn't check collateral ratio
        // VULN: magic number for minimum borrow
        // VULN: integer underflow if total_supplied < amount
        let valid_amount = amount > 2000000 && amount < d.total_supplied
        valid_amount
      }

      Repay -> {
        // VULN: doesn't verify interest payment
        // VULN: doesn't check that loan is actually being repaid
        // VULN: no signature check
        True
      }

      Liquidate { loan_id } -> {
        // VULN: doesn't check oracle price for undercollateralization
        // VULN: no validity range check (oracle freshness)
        // VULN: doesn't verify liquidation penalty distribution
        let _uses_oracle = d.oracle_pkh
        let _has_loan = loan_id
        let has_output =
          list.any(tx.outputs, fn(o) { assets.lovelace_of(o.value) > 0 })
        has_output
      }

      UpdateConfig -> {
        // Only admin can update config
        list.has(tx.extra_signatories, d.admin)
      }
    }
  }

  else(_) {
    fail
  }
}

/// Loan position validator — holds individual collateral UTXOs.
validator loan_position {
  spend(
    datum: Option<LoanDatum>,
    _redeemer: Data,
    _own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum

    // VULN: no signature check — borrower field not validated
    // VULN: doesn't use own_ref (double satisfaction risk)
    // VULN: doesn't verify collateral amount is preserved
    // VULN: unbounded iteration over all outputs
    let _borrower = d.borrower
    let _collateral = d.collateral_amount

    list.any(tx.outputs, fn(o) { assets.lovelace_of(o.value) > 0 })
  }

  else(_) {
    fail
  }
}
