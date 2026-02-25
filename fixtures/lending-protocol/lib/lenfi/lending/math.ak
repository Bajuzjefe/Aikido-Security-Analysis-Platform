/// Math utilities for interest and collateral calculations.

/// Calculate simple interest on a loan.
/// VULN: magic numbers (10000, 31536000000), potential division issues
pub fn calculate_interest(
  principal: Int,
  rate_bps: Int,
  elapsed_ms: Int,
) -> Int {
  // annual milliseconds = 365 * 24 * 60 * 60 * 1000
  principal * rate_bps * elapsed_ms / 31536000000 / 10000
}

/// Check if collateral ratio is below minimum threshold.
/// VULN: division by zero if borrowed_value is 0
pub fn is_undercollateralized(
  collateral_value: Int,
  borrowed_value: Int,
  min_ratio_bps: Int,
) -> Bool {
  collateral_value * 10000 / borrowed_value < min_ratio_bps
}

/// Calculate liquidation penalty (5% of collateral).
/// VULN: magic number, rounding error for small values
pub fn liquidation_penalty(collateral_value: Int) -> Int {
  collateral_value * 5 / 100
}

/// Calculate utilization rate of the pool in basis points.
/// VULN: division by zero if total_supplied is 0
pub fn utilization_rate(total_borrowed: Int, total_supplied: Int) -> Int {
  total_borrowed * 10000 / total_supplied
}

/// Unused helper — dead code for detector testing.
pub fn unused_fee_calculation(amount: Int) -> Int {
  amount * 3 / 1000
}
