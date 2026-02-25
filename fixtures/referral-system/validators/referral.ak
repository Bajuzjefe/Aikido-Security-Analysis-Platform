// Referral system validators for aikido FP regression testing.
// Tests: fold-counting, correlated guards, admin signatures, full address comparison.

use aiken/collection/dict
use aiken/collection/list
use aiken/crypto
use aiken/primitive/bytearray
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}

pub type MintRedeemer {
  MintReferral { referrer: ByteArray, referred: ByteArray }
  BurnReferral
}

pub type ConfigDatum {
  admin: ByteArray,
  version: Int,
}

pub type ConfigRedeemer {
  UpdateConfig
  DestroyConfig
}

pub type TreasuryDatum {
  total_deposited: Int,
  total_withdrawn: Int,
}

pub type TreasuryRedeemer {
  Deposit { amount: Int }
  Withdraw { amount: Int, recipient: ByteArray }
}

// --- Mint validator ---
// Has: dict.foldl counting, quantity_of, admin signature
// Expected: suppress duplicate-asset-name-risk (foldl pattern)
// Expected: other-token-minting may fire (quantity_of without flatten)

validator referral_mint(admin_pkh: ByteArray) {
  mint(redeemer: MintRedeemer, policy_id: ByteArray, tx: Transaction) {
    expect list.has(tx.extra_signatories, admin_pkh)

    when redeemer is {
      MintReferral { referrer, referred } -> {
        expect referrer != referred
        let token_name =
          crypto.blake2b_256(bytearray.concat(referrer, referred))

        // Fold-counting pattern: counts minted tokens via dict.foldl
        let token_dict = assets.tokens(tx.mint, policy_id)
        let mint_count =
          dict.foldl(token_dict, 0, fn(_name, qty, acc) { acc + qty })
        expect mint_count == 1

        expect assets.quantity_of(tx.mint, policy_id, token_name) == 1
        True
      }
      BurnReferral -> {
        let token_dict = assets.tokens(tx.mint, policy_id)
        dict.foldl(token_dict, True, fn(_name, qty, acc) { acc && qty < 0 })
      }
    }
  }

  else(_) {
    fail
  }
}

// --- Config spend validator (admin-only) ---
// Has: admin signature (requires_signature = true), lovelace_of check
// Expected: suppress unbounded-value-size (admin-signed)

validator referral_config(admin_pkh: ByteArray) {
  spend(
    datum: Option<ConfigDatum>,
    redeemer: ConfigRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(_config) = datum
    expect Some(own_input) =
      list.find(tx.inputs, fn(i) { i.output_reference == own_ref })
    expect list.has(tx.extra_signatories, admin_pkh)

    when redeemer is {
      UpdateConfig -> {
        let own_address = own_input.output.address
        expect
          list.any(
            tx.outputs,
            fn(o) {
              o.address == own_address && assets.lovelace_of(o.value) >= 2_000_000
            },
          )
        True
      }
      DestroyConfig -> True
    }
  }

  else(_) {
    fail
  }
}

// --- Treasury spend validator ---
// Has: correlated guard before subtraction, lovelace_of check
// Expected: suppress integer-underflow-risk (correlated guard)
// Expected: value checks present (suppress value-not-preserved)

validator referral_treasury(admin_pkh: ByteArray) {
  spend(
    datum: Option<TreasuryDatum>,
    redeemer: TreasuryRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(treasury) = datum
    expect Some(own_input) =
      list.find(tx.inputs, fn(i) { i.output_reference == own_ref })
    let own_address = own_input.output.address

    when redeemer is {
      Deposit { amount } -> {
        expect amount > 0
        let expected_lovelace =
          assets.lovelace_of(own_input.output.value) + amount
        expect
          list.any(
            tx.outputs,
            fn(o) {
              o.address == own_address && assets.lovelace_of(o.value) >= expected_lovelace
            },
          )
        True
      }
      Withdraw { amount, recipient } -> {
        // Admin must sign withdrawals
        expect list.has(tx.extra_signatories, admin_pkh)

        // Correlated guard: total_deposited >= total_withdrawn + amount
        expect treasury.total_deposited >= treasury.total_withdrawn + amount

        // Safe subtraction (guarded above)
        let _remaining =
          treasury.total_deposited - treasury.total_withdrawn - amount

        let current_lovelace = assets.lovelace_of(own_input.output.value)
        expect current_lovelace >= amount + 2_000_000

        expect
          list.any(
            tx.outputs,
            fn(o) {
              o.address == own_address && assets.lovelace_of(o.value) >= current_lovelace - amount
            },
          )

        expect recipient != #""
        True
      }
    }
  }

  else(_) {
    fail
  }
}

test test_basic() {
  True
}
