use aiken/collection/list
use cardano/address.{Credential, VerificationKey}
use cardano/assets
use cardano/transaction.{Transaction}
use aiken/interval.{Finite}
use sentaku/contracts/datum.{PositionDatum}
use sentaku/contracts/oracle
use sentaku/contracts/redeemer.{EmergencyReclaim, PositionRedeemer, Settle}
use sentaku/contracts/settlement
use sentaku/contracts/types.{Lose, Push, Win}

/// Emergency reclaim grace period: 24 hours in milliseconds.
const emergency_reclaim_delay_ms: Int = 86_400_000

/// Position validator — guards individual position UTXOs.
///
/// Option 2 architecture (v0):
///   - No pool validator. Settlement TX spends position UTXO + operator wallet UTXO.
///   - WIN: operator provides matching funds; user receives 2x stake - fee.
///   - LOSE: all position value goes to operator.
///   - PUSH: user gets stake back from position UTXO.
///
/// Parameters (applied at deploy time via `anvil_apply_blueprint_params`):
///   - oracle_pkh: trusted oracle's public key hash (28 bytes, Blake2b-224)
///   - operator_pkh: platform operator's payment key hash (28 bytes)
validator position(oracle_pkh: ByteArray, operator_pkh: ByteArray) {
  spend(
    datum_opt: Option<PositionDatum>,
    redeemer: PositionRedeemer,
    _own_ref: Data,
    self: Transaction,
  ) {
    // Datum must be present (inline datum)
    expect Some(datum) = datum_opt

    when redeemer is {
      Settle { attestation, result, payout_lovelace } -> {
        // 1. TX validity: lower bound must be at or after position expiry
        let tx_lower_bound = get_tx_lower_bound(self)
        expect tx_lower_bound >= datum.expires_at

        // 2. Oracle attestation: verify identity, freshness, and signature
        expect
          oracle.verify_attestation(
            attestation,
            oracle_pkh,
            datum.symbol,
            tx_lower_bound,
          )

        // 3. Result correctness: claimed result must match direction + prices
        let expected_result =
          settlement.resolve_result(
            datum.direction,
            datum.entry_price,
            attestation.price,
          )
        expect result == expected_result

        // 4. Payout math: claimed payout must match the formula
        let expected_payout =
          settlement.compute_payout(
            datum.stake_lovelace,
            datum.platform_fee_bps,
            result,
          )
        expect payout_lovelace == expected_payout

        // 5. Output validation: if payout > 0, user must receive it
        when result is {
          Win ->
            has_output_to_pkh(self.outputs, datum.owner, payout_lovelace)
          Push ->
            has_output_to_pkh(self.outputs, datum.owner, payout_lovelace)
          Lose ->
            // No payout to user. Operator takes everything.
            // We only require the operator signed the TX (they provide the
            // treasury input in Option 2, so they must sign anyway).
            list.has(self.extra_signatories, operator_pkh)
        }
      }

      EmergencyReclaim -> {
        // Operator can reclaim after 24h past expiry (safety net)
        let tx_lower_bound = get_tx_lower_bound(self)
        let reclaim_after = datum.expires_at + emergency_reclaim_delay_ms
        expect tx_lower_bound >= reclaim_after
        list.has(self.extra_signatories, operator_pkh)
      }
    }
  }

  else(_) {
    fail
  }
}

/// Extract the lower bound of the TX validity interval as a finite POSIX time.
/// Fails if the lower bound is not finite (NegativeInfinity / PositiveInfinity).
fn get_tx_lower_bound(tx: Transaction) -> Int {
  when tx.validity_range.lower_bound.bound_type is {
    Finite(t) -> t
    _ -> fail @"TX must have a finite validity lower bound"
  }
}

/// Check that at least one TX output pays at least `min_lovelace` to a
/// public key hash address.
fn has_output_to_pkh(
  outputs: List<transaction.Output>,
  pkh: ByteArray,
  min_lovelace: Int,
) -> Bool {
  list.any(
    outputs,
    fn(output) {
      when output.address.payment_credential is {
        VerificationKey(key_hash) ->
          key_hash == pkh && assets.lovelace_of(output.value) >= min_lovelace
        _ -> False
      }
    },
  )
}
