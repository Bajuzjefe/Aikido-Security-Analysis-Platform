use aiken/crypto.{blake2b_224, verify_ed25519_signature}
use aiken/primitive/bytearray
use sentaku/contracts/redeemer.{OracleAttestation}
use sentaku/contracts/types.{Symbol, BTC, ETH, SOL, ADA, SNEK}

/// Maximum allowed age of an oracle attestation relative to the TX validity
/// lower bound. 2 minutes = 120,000 milliseconds.
/// Cardano blocks every ~20s, TX inclusion typically <60s.
/// 2-minute window gives ~3x safety margin while limiting operator timing flexibility.
pub const max_oracle_age_ms: Int = 120_000

/// Encode a Symbol as a single byte for the oracle message.
pub fn symbol_to_byte(s: Symbol) -> ByteArray {
  when s is {
    BTC -> #"00"
    ETH -> #"01"
    SOL -> #"02"
    ADA -> #"03"
    SNEK -> #"04"
  }
}

/// Build the deterministic oracle message (17 bytes):
///   symbol_byte (1) ++ price_big_endian (8) ++ observed_at_big_endian (8)
pub fn build_oracle_message(
  symbol: Symbol,
  price: Int,
  observed_at: Int,
) -> ByteArray {
  let sym = symbol_to_byte(symbol)
  let price_bytes = bytearray.from_int_big_endian(price, 8)
  let time_bytes = bytearray.from_int_big_endian(observed_at, 8)
  bytearray.concat(sym, bytearray.concat(price_bytes, time_bytes))
}

/// Verify an oracle attestation:
///   1. blake2b_224(oracle_pubkey) == expected oracle pubkey hash
///   2. Ed25519 signature over the deterministic message is valid
///   3. Attestation is fresh (within max_oracle_age_ms of tx_lower_bound)
pub fn verify_attestation(
  attestation: OracleAttestation,
  expected_oracle_pkh: ByteArray,
  symbol: Symbol,
  tx_lower_bound: Int,
) -> Bool {
  // 1. Oracle identity: pubkey hash must match parameterized value
  let pubkey_hash = blake2b_224(attestation.oracle_pubkey)
  expect pubkey_hash == expected_oracle_pkh

  // 2. Freshness: attestation must be recent relative to TX validity
  let age = tx_lower_bound - attestation.observed_at
  expect age >= 0
  expect age <= max_oracle_age_ms

  // 3. Signature: verify Ed25519 over deterministic message
  let message =
    build_oracle_message(symbol, attestation.price, attestation.observed_at)
  verify_ed25519_signature(attestation.oracle_pubkey, message, attestation.signature)
}
