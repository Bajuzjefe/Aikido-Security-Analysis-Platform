// AMM DEX pool validator inspired by Minswap/SundaeSwap.
// Deliberately includes vulnerability patterns for aikido to detect.

use aiken/collection/list
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}
use amm/dex/types.{
  AddLiquidity, CollectFees, PoolDatum, PoolRedeemer, RemoveLiquidity, Swap,
}
use amm/dex/math

validator amm_pool {
  spend(
    datum: Option<PoolDatum>,
    redeemer: PoolRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum

    // Good: uses own_ref for double satisfaction prevention
    expect Some(own_input) =
      list.find(tx.inputs, fn(i) { i.output_reference == own_ref })
    let own_value = assets.lovelace_of(own_input.output.value)

    when redeemer is {
      Swap { min_received } -> {
        // VULN: no validity range check (deadline not enforced)
        // VULN: doesn't verify pool NFT in output (output address not validated)
        // VULN: fee calculation done off-chain, not verified on-chain
        let has_output =
          list.any(
            tx.outputs,
            fn(o) { assets.lovelace_of(o.value) >= min_received },
          )
        // VULN: doesn't verify constant product invariant (k = x * y)
        // VULN: doesn't check that pool output has correct updated reserves
        has_output && min_received > 0
      }

      AddLiquidity -> {
        // VULN: no signature check
        // VULN: doesn't verify LP tokens minted match ratio
        // VULN: doesn't verify pool datum updated correctly
        // VULN: value not fully preserved — no check on reserve changes
        let pool_output_exists =
          list.any(
            tx.outputs,
            fn(o) { assets.lovelace_of(o.value) > own_value },
          )
        pool_output_exists
      }

      RemoveLiquidity { lp_amount } -> {
        // VULN: no signature check for LP token holder
        // VULN: doesn't verify LP tokens are burned
        // VULN: doesn't check proportional withdrawal
        // VULN: magic number minimum
        lp_amount > 1000 && list.length(tx.outputs) > 0
      }

      CollectFees -> {
        // VULN: hardcoded fee collector check is too permissive
        // VULN: no verification of fee amount
        // VULN: no signature check for admin
        list.length(tx.outputs) > 0
      }
    }
  }

  else(_) {
    fail
  }
}
