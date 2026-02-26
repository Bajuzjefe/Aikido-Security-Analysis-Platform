use sentaku/contracts/types.{Direction, Duration, Lovelace, Price, Symbol}

/// Inline datum locked at each position UTXO.
/// Contains all parameters needed to validate settlement on-chain.
pub type PositionDatum {
  /// Unique position identifier (deterministic hash of creation params)
  position_id: ByteArray,
  /// Owner's payment public key hash (28 bytes, Blake2b-224 of Ed25519 pubkey)
  owner: ByteArray,
  /// Traded asset symbol
  symbol: Symbol,
  /// Prediction direction
  direction: Direction,
  /// Option duration
  duration: Duration,
  /// Stake amount in lovelace
  stake_lovelace: Lovelace,
  /// Entry price at position open (micro-USD, PRICE_SCALE = 1_000_000)
  entry_price: Price,
  /// POSIX time (ms) at which position was opened
  opened_at: Int,
  /// POSIX time (ms) at which position expires
  expires_at: Int,
  /// Platform fee in basis points at time of opening (e.g. 100 = 1%)
  platform_fee_bps: Int,
}
