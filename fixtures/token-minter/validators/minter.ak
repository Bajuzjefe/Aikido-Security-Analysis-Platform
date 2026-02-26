// Token minting validator inspired by Anastasia-Labs tx-level-minter.
// Deliberately includes vulnerability patterns for aikido to detect.

use aiken/collection/list
use cardano/address.{Script}
use cardano/transaction.{OutputReference, Transaction}

/// Minting policy redeemer.
pub type MintAction {
  MintTokens
  BurnTokens
}

validator token_policy {
  // VULN: mint handler doesn't check token names (#5 missing-minting-policy-check)
  // VULN: no authorization check at all (#9 unrestricted-minting)
  mint(_redeemer: MintAction, _policy_id: ByteArray, _tx: Transaction) {
    True
  }

  else(_) {
    fail
  }
}

/// A spend validator that holds tokens.
/// Has a hardcoded address and no signature check.
pub type HolderDatum {
  owner: ByteArray,
  token_count: Int,
}

validator token_holder {
  spend(
    datum: Option<HolderDatum>,
    _redeemer: Data,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum

    // Uses own_ref (good for double satisfaction)
    expect Some(_own_input) =
      list.find(tx.inputs, fn(i) { i.output_reference == own_ref })

    // VULN: checks outputs but doesn't check value
    let has_continuing_output =
      list.any(
        tx.outputs,
        fn(o) {
          when o.address.payment_credential is {
            Script(_) -> True
            _ -> False
          }
        },
      )

    // VULN: no signature check for owner field
    has_continuing_output
  }

  else(_) {
    fail
  }
}
