// Order book validator for batched DEX swaps.
// Deliberately includes vulnerability patterns for aikido to detect.

use aiken/collection/list
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}
use amm/dex/types.{Cancel, Execute, OrderDatum, OrderRedeemer}

validator swap_order {
  spend(
    datum: Option<OrderDatum>,
    redeemer: OrderRedeemer,
    _own_ref: OutputReference,
    tx: Transaction,
  ) {
    // VULN: doesn't use own_ref (double satisfaction risk)
    expect Some(d) = datum

    when redeemer is {
      Execute -> {
        // VULN: no signature check for executor (batcher)
        // VULN: doesn't verify min_amount_out is actually received by owner
        // VULN: no validity range / deadline check
        // VULN: doesn't validate output address matches owner
        let has_output =
          list.any(
            tx.outputs,
            fn(o) { assets.lovelace_of(o.value) >= d.min_amount_out },
          )
        has_output
      }

      Cancel -> {
        // Owner can cancel — checks signature
        list.has(tx.extra_signatories, d.owner)
      }
    }
  }

  else(_) {
    fail
  }
}
