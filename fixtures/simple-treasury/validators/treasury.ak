// Simple treasury validator inspired by SundaeSwap treasury contracts.
// Deliberately includes some vulnerability patterns for aikido to detect.

use aiken/collection/list
use cardano/address.{Script}
use cardano/transaction.{OutputReference, Transaction}

/// Treasury datum tracks locked funds.
pub type TreasuryDatum {
  admin: ByteArray,
  deadline: Int,
  total_deposited: Int,
}

/// Treasury redeemer actions.
pub type TreasuryRedeemer {
  Withdraw
  Reorganize
  Deposit
}

validator treasury {
  spend(
    datum: Option<TreasuryDatum>,
    redeemer: TreasuryRedeemer,
    _own_ref: OutputReference,
    tx: Transaction,
  ) {
    // VULN: unsafe datum deconstruction - no expect Some pattern
    // VULN: doesn't use own_ref (double satisfaction risk)
    when redeemer is {
      Withdraw -> {
        // Check outputs exist but doesn't verify value preservation
        // VULN: no value preservation check
        // VULN: no min ADA check
        let has_output =
          list.any(
            tx.outputs,
            fn(o) {
              when o.address.payment_credential is {
                Script(_hash) -> True
                _ -> False
              }
            },
          )
        has_output
      }
      Reorganize -> {
        // VULN: no signature check for admin
        // Just checks outputs exist
        list.length(tx.outputs) > 0
      }
      Deposit -> True
    }
  }

  else(_) {
    fail
  }
}
