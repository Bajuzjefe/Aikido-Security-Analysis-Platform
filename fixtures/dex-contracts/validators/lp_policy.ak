// LP token minting policy for the DEX.
// Deliberately includes vulnerability patterns for aikido to detect.

use cardano/transaction.{Transaction}
use amm/dex/types.{BurnLP, LPAction, MintLP}

validator lp_token {
  mint(redeemer: LPAction, _policy_id: ByteArray, _tx: Transaction) {
    // VULN: unrestricted minting — no authorization check
    // VULN: missing minting policy check — doesn't verify token names
    // VULN: doesn't verify pool interaction (anyone can mint LP tokens)
    when redeemer is {
      MintLP -> True
      BurnLP -> True
    }
  }

  else(_) {
    fail
  }
}
