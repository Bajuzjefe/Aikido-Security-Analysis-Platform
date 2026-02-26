use sentaku/contracts/types.{Lovelace, Price, PositionResult}

/// Oracle-signed price attestation.
///
/// Message format (deterministic, 17 bytes):
///   symbol_index (1 byte) ++ price (8 bytes big-endian) ++ observed_at (8 bytes big-endian)
///
/// Validator verifies Ed25519 signature over this message and checks that
/// blake2b_224(oracle_pubkey) matches the parameterized oracle pubkey hash.
pub type OracleAttestation {
  /// The attested settlement price (micro-USD, PRICE_SCALE = 1_000_000)
  price: Price,
  /// POSIX time (ms) at which the price was observed
  observed_at: Int,
  /// Ed25519 signature (64 bytes) over the deterministic message
  signature: ByteArray,
  /// Oracle's Ed25519 public key (32 bytes) — verified against parameterized hash
  oracle_pubkey: ByteArray,
}

/// Redeemer for spending a position UTXO.
pub type PositionRedeemer {
  /// Normal settlement with oracle attestation after expiry.
  /// Validator checks: oracle sig, freshness, payout math, result correctness, outputs.
  Settle {
    attestation: OracleAttestation,
    result: PositionResult,
    payout_lovelace: Lovelace,
  }
  /// Emergency reclaim by operator after extended timeout (24h past expiry).
  /// All funds go to operator. Safety net if oracle is unavailable.
  EmergencyReclaim
}
