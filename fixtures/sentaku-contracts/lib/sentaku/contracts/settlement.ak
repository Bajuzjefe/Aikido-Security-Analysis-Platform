use sentaku/contracts/types.{
  Direction, Above, Below, Lovelace, PositionResult, Price, Win, Lose, Push,
}

/// Determine position result from direction and prices.
/// Matches off-chain `resolveResult()` in shared/trading.ts:52-62
pub fn resolve_result(
  direction: Direction,
  entry_price: Price,
  settlement_price: Price,
) -> PositionResult {
  if entry_price == settlement_price {
    Push
  } else {
    when direction is {
      Above ->
        if settlement_price > entry_price {
          Win
        } else {
          Lose
        }
      Below ->
        if settlement_price < entry_price {
          Win
        } else {
          Lose
        }
    }
  }
}

/// Compute the expected payout in lovelace for a given result.
/// Matches off-chain `settlePosition()` in shared/trading.ts:64-99
///
/// WIN:  payout = stake * 2 - (stake * 2 * fee_bps / 10_000)
/// PUSH: payout = stake
/// LOSE: payout = 0
///
/// Integer math note: we compute fee as (gross * fee_bps) / 10_000.
/// This matches the off-chain `roundAda` because lovelace is already
/// the smallest unit — no sub-lovelace fractions exist.
pub fn compute_payout(
  stake_lovelace: Lovelace,
  platform_fee_bps: Int,
  result: PositionResult,
) -> Lovelace {
  when result is {
    Win -> {
      let gross = stake_lovelace * 2
      let fee = gross * platform_fee_bps / 10_000
      gross - fee
    }
    Push -> stake_lovelace
    Lose -> 0
  }
}
