/// Price scaled to micro-USD (1 USD = 1_000_000)
pub type Price =
  Int

/// ADA amount in lovelace (1 ADA = 1_000_000)
pub type Lovelace =
  Int

/// Cardano slot number
pub type Slot =
  Int

/// Asset symbol identifier — matches off-chain SUPPORTED_SYMBOLS
pub type Symbol {
  BTC
  ETH
  SOL
  ADA
  SNEK
}

/// Binary option direction
pub type Direction {
  Above
  Below
}

/// Duration identifier
pub type Duration {
  H1
  H4
  H12
  H24
}

/// Position outcome
pub type PositionResult {
  Win
  Lose
  Push
}
