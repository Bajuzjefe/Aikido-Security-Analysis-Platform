/// Core types for the DEX AMM protocol.

/// Datum for AMM liquidity pool.
pub type PoolDatum {
  reserve_a: Int,
  reserve_b: Int,
  total_lp_tokens: Int,
  fee_numerator: Int,
  fee_denominator: Int,
  pool_nft_policy: ByteArray,
  lp_token_policy: ByteArray,
}

/// Pool redeemer actions.
pub type PoolRedeemer {
  Swap { min_received: Int }
  AddLiquidity
  RemoveLiquidity { lp_amount: Int }
  CollectFees
}

/// LP token minting actions.
pub type LPAction {
  MintLP
  BurnLP
}

/// Order datum for batched swaps.
pub type OrderDatum {
  owner: ByteArray,
  token_in_policy: ByteArray,
  token_in_name: ByteArray,
  amount_in: Int,
  min_amount_out: Int,
  deadline: Int,
}

/// Order redeemer.
pub type OrderRedeemer {
  Execute
  Cancel
}
