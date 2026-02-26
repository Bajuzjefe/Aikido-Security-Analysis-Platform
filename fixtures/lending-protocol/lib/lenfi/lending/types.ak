/// Core types for the lending protocol.

/// Datum for the lending pool UTXO.
pub type PoolDatum {
  admin: ByteArray,
  oracle_pkh: ByteArray,
  total_supplied: Int,
  total_borrowed: Int,
  interest_rate_bps: Int,
  min_collateral_ratio: Int,
}

/// Datum for individual loan positions.
pub type LoanDatum {
  borrower: ByteArray,
  collateral_amount: Int,
  borrowed_amount: Int,
  interest_accrued: Int,
  start_time: Int,
}

/// Oracle price datum.
pub type OraclePrice {
  price: Int,
  timestamp: Int,
  signer: ByteArray,
}

/// Pool redeemer actions.
pub type PoolAction {
  Supply
  Withdraw
  Borrow { amount: Int }
  Repay
  Liquidate { loan_id: ByteArray }
  UpdateConfig
}

/// Loan redeemer actions.
pub type LoanAction {
  AddCollateral
  RepayLoan
  LiquidateLoan
}
