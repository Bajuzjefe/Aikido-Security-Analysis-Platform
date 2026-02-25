// Escrow contract inspired by Fusion maker contract.
// Time-locked escrow with multiple phases.

use aiken/collection/list
use aiken/crypto.{blake2b_256}
use aiken/interval
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

/// Escrow datum with time windows.
pub type EscrowDatum {
  seller: ByteArray,
  buyer: ByteArray,
  price: Int,
  deadline: Int,
  secret_hash: ByteArray,
}

/// Escrow actions.
pub type EscrowAction {
  Complete { secret: ByteArray }
  Cancel
  Refund
}

validator escrow {
  spend(
    datum: Option<EscrowDatum>,
    redeemer: EscrowAction,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum

    // Good: uses own_ref for double satisfaction prevention
    expect Some(own_input) =
      list.find(tx.inputs, fn(i) { i.output_reference == own_ref })

    let own_value = assets.lovelace_of(own_input.output.value)

    when redeemer is {
      Complete { secret } -> {
        // Verify secret matches hash
        let hash_matches = blake2b_256(secret) == d.secret_hash

        // Check validity range (time-locked)
        let in_time =
          interval.is_entirely_before(tx.validity_range, d.deadline)

        // Check buyer gets the goods — verify signatories
        let buyer_signed =
          list.has(tx.extra_signatories, d.buyer)

        hash_matches && in_time && buyer_signed
      }
      Cancel -> {
        // Only seller can cancel
        let seller_signed =
          list.has(tx.extra_signatories, d.seller)

        // Must be after deadline
        let after_deadline =
          interval.is_entirely_after(tx.validity_range, d.deadline)

        // VULN: value not preserved - doesn't check refund amount
        seller_signed && after_deadline
      }
      Refund -> {
        // VULN: fail-only branch - always fails
        fail @"Refund not implemented"
      }
    }
  }

  else(_) {
    fail
  }
}
