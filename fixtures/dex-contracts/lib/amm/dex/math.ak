/// AMM constant-product math utilities.

/// Calculate swap output using constant product formula (x * y = k).
/// VULN: rounding error — integer division truncates towards zero.
/// VULN: no overflow protection for large reserves.
pub fn calculate_swap_output(
  amount_in: Int,
  reserve_in: Int,
  reserve_out: Int,
  fee_num: Int,
  fee_den: Int,
) -> Int {
  let amount_with_fee = amount_in * fee_num
  let numerator = amount_with_fee * reserve_out
  let denominator = reserve_in * fee_den + amount_with_fee
  // VULN: division by zero if reserve_in is 0 and fee_den is 0
  numerator / denominator
}

/// Calculate LP tokens to mint for adding liquidity.
/// VULN: division by zero if reserve_a is 0 (initial liquidity edge case).
/// VULN: magic number for initial LP calculation.
pub fn calculate_lp_tokens(
  amount_a: Int,
  amount_b: Int,
  reserve_a: Int,
  reserve_b: Int,
  total_lp: Int,
) -> Int {
  if total_lp == 0 {
    // Initial liquidity — VULN: magic number sqrt approximation
    // sqrt(amount_a * amount_b) approximated
    amount_a * amount_b / 1000
  } else {
    let lp_a = amount_a * total_lp / reserve_a
    let lp_b = amount_b * total_lp / reserve_b
    // Take minimum to prevent manipulation
    if lp_a < lp_b {
      lp_a
    } else {
      lp_b
    }
  }
}

/// Calculate price impact of a swap in basis points.
/// VULN: division by zero if amount_in + reserve_in is 0.
pub fn price_impact_bps(amount_in: Int, reserve_in: Int) -> Int {
  amount_in * 10000 / (amount_in + reserve_in)
}

/// Dead code — unused helper function.
pub fn unused_slippage_check(expected: Int, actual: Int, tolerance: Int) -> Bool {
  let diff = expected - actual
  diff * 10000 / expected < tolerance
}
