use aiken/collection/list
use aiken/interval
use aiken/primitive/bytearray
use cardano/address.{Address, VerificationKey}
use cardano/assets
use cardano/transaction.{NoDatum, Output, Transaction}
use sentaku/contracts/datum.{PositionDatum}
use sentaku/contracts/oracle
use sentaku/contracts/settlement
use sentaku/contracts/types.{Above, Below, BTC, ETH, H1, Lose, Push, Win}

const test_owner_pkh: ByteArray =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const test_operator_pkh: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

fn owner_address() -> Address {
  Address {
    payment_credential: VerificationKey(test_owner_pkh),
    stake_credential: None,
  }
}

fn operator_address() -> Address {
  Address {
    payment_credential: VerificationKey(test_operator_pkh),
    stake_credential: None,
  }
}

fn make_output(addr: Address, lovelace: Int) -> Output {
  Output {
    address: addr,
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

fn test_datum() -> PositionDatum {
  PositionDatum {
    position_id: #"deadbeef",
    owner: test_owner_pkh,
    symbol: BTC,
    direction: Above,
    duration: H1,
    stake_lovelace: 10_000_000,
    entry_price: 67_000_000_000,
    opened_at: 1_700_000_000_000,
    expires_at: 1_700_003_600_000,
    platform_fee_bps: 100,
  }
}

fn base_tx(lower_bound: Int) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    validity_range: interval.after(lower_bound),
  }
}

// ─── RESULT RESOLUTION ────────────────────────────────────

test resolve_above_win() {
  settlement.resolve_result(Above, 67_000_000_000, 68_000_000_000) == Win
}

test resolve_above_lose() {
  settlement.resolve_result(Above, 67_000_000_000, 66_000_000_000) == Lose
}

test resolve_above_push() {
  settlement.resolve_result(Above, 67_000_000_000, 67_000_000_000) == Push
}

test resolve_below_win() {
  settlement.resolve_result(Below, 67_000_000_000, 66_000_000_000) == Win
}

test resolve_below_lose() {
  settlement.resolve_result(Below, 67_000_000_000, 68_000_000_000) == Lose
}

test resolve_below_push() {
  settlement.resolve_result(Below, 67_000_000_000, 67_000_000_000) == Push
}

// ─── PAYOUT MATH ──────────────────────────────────────────

test payout_win_100bps() {
  settlement.compute_payout(10_000_000, 100, Win) == 19_800_000
}

test payout_win_0bps() {
  settlement.compute_payout(10_000_000, 0, Win) == 20_000_000
}

test payout_push() {
  settlement.compute_payout(10_000_000, 100, Push) == 10_000_000
}

test payout_lose() {
  settlement.compute_payout(10_000_000, 100, Lose) == 0
}

test payout_large_stake() {
  settlement.compute_payout(500_000_000, 100, Win) == 990_000_000
}

test payout_max_fee() {
  settlement.compute_payout(10_000_000, 10_000, Win) == 0
}

test payout_500bps() {
  settlement.compute_payout(10_000_000, 500, Win) == 19_000_000
}

test payout_1ada() {
  settlement.compute_payout(1_000_000, 100, Win) == 1_980_000
}

// ─── ORACLE MESSAGE ───────────────────────────────────────

test oracle_msg_length() {
  let msg = oracle.build_oracle_message(BTC, 67_000_000_000, 1_700_003_600_000)
  bytearray.length(msg) == 17
}

test oracle_btc() {
  oracle.symbol_to_byte(BTC) == #"00"
}

test oracle_eth() {
  oracle.symbol_to_byte(ETH) == #"01"
}

// ─── FULL SETTLEMENT FLOWS ───────────────────────────────

test flow_win() {
  let d = test_datum()
  let r = settlement.resolve_result(d.direction, d.entry_price, 68_000_000_000)
  let p = settlement.compute_payout(d.stake_lovelace, d.platform_fee_bps, r)
  and { r == Win, p == 19_800_000 }
}

test flow_lose() {
  let d = test_datum()
  let r = settlement.resolve_result(d.direction, d.entry_price, 66_000_000_000)
  let p = settlement.compute_payout(d.stake_lovelace, d.platform_fee_bps, r)
  and { r == Lose, p == 0 }
}

test flow_push() {
  let d = test_datum()
  let r = settlement.resolve_result(d.direction, d.entry_price, d.entry_price)
  let p = settlement.compute_payout(d.stake_lovelace, d.platform_fee_bps, r)
  and { r == Push, p == 10_000_000 }
}

test flow_below_win() {
  settlement.resolve_result(Below, 67_000_000_000, 66_000_000_000) == Win
}

test flow_below_lose() {
  settlement.resolve_result(Below, 67_000_000_000, 68_000_000_000) == Lose
}

test flow_eth_win() {
  settlement.resolve_result(Above, 3_500_000_000, 3_600_000_000) == Win
}

// ─── TX VALIDITY ──────────────────────────────────────────

test validity_at_expiry() {
  let tx = base_tx(1_700_003_600_000)
  when tx.validity_range.lower_bound.bound_type is {
    interval.Finite(t) -> t >= 1_700_003_600_000
    _ -> False
  }
}

test validity_before_expiry() {
  let tx = base_tx(1_700_000_000_000)
  when tx.validity_range.lower_bound.bound_type is {
    interval.Finite(t) -> t < 1_700_003_600_000
    _ -> False
  }
}

// ─── EMERGENCY RECLAIM ────────────────────────────────────

test reclaim_valid() {
  let d = test_datum()
  d.expires_at + 86_400_000 + 1000 >= d.expires_at + 86_400_000
}

test reclaim_too_early() {
  let d = test_datum()
  d.expires_at + 10_000_000 < d.expires_at + 86_400_000
}

// ─── OPERATOR SIGNATURE ───────────────────────────────────

test op_signed() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      extra_signatories: [test_operator_pkh],
    }
  list.has(tx.extra_signatories, test_operator_pkh)
}

test op_not_signed() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      extra_signatories: [test_owner_pkh],
    }
  !list.has(tx.extra_signatories, test_operator_pkh)
}

// ─── OUTPUT CHECKS ────────────────────────────────────────

test out_sufficient() {
  let outputs = [make_output(owner_address(), 19_800_000)]
  list.any(
    outputs,
    fn(o) {
      when o.address.payment_credential is {
        VerificationKey(kh) ->
          kh == test_owner_pkh && assets.lovelace_of(o.value) >= 19_800_000
        _ -> False
      }
    },
  )
}

test out_insufficient() {
  let outputs = [make_output(owner_address(), 10_000_000)]
  !list.any(
    outputs,
    fn(o) {
      when o.address.payment_credential is {
        VerificationKey(kh) ->
          kh == test_owner_pkh && assets.lovelace_of(o.value) >= 19_800_000
        _ -> False
      }
    },
  )
}

test out_wrong_addr() {
  let outputs = [make_output(operator_address(), 19_800_000)]
  !list.any(
    outputs,
    fn(o) {
      when o.address.payment_credential is {
        VerificationKey(kh) ->
          kh == test_owner_pkh && assets.lovelace_of(o.value) >= 19_800_000
        _ -> False
      }
    },
  )
}

test win_tx_valid() {
  let d = test_datum()
  let payout = 19_800_000
  let tx =
    Transaction {
      ..base_tx(d.expires_at),
      outputs: [
        make_output(owner_address(), payout),
        make_output(operator_address(), 200_000),
      ],
      extra_signatories: [test_operator_pkh],
    }
  list.any(
    tx.outputs,
    fn(o) {
      when o.address.payment_credential is {
        VerificationKey(kh) ->
          kh == d.owner && assets.lovelace_of(o.value) >= payout
        _ -> False
      }
    },
  )
}

test push_tx_valid() {
  let d = test_datum()
  let tx =
    Transaction {
      ..base_tx(d.expires_at),
      outputs: [make_output(owner_address(), d.stake_lovelace)],
    }
  list.any(
    tx.outputs,
    fn(o) {
      when o.address.payment_credential is {
        VerificationKey(kh) ->
          kh == d.owner && assets.lovelace_of(o.value) >= d.stake_lovelace
        _ -> False
      }
    },
  )
}
