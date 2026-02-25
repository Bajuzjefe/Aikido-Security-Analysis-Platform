# excessive-validator-params

**Severity:** Info
**Confidence:** Possible

## Description

Validators with many parameters increase deployment complexity and are more error-prone. Each parameter must be provided at deployment time and increases the script size. More than 4 validator parameters is a signal that related parameters should be grouped into a configuration datum or that a reference script should be used.

## Vulnerable Example

```aiken
validator(
  admin_key: ByteArray,
  oracle_key: ByteArray,
  treasury_address: ByteArray,
  fee_numerator: Int,
  fee_denominator: Int,
  min_deposit: Int,
  max_withdrawal: Int,
) {
  spend(datum, redeemer, own_ref, self) {
    // 7 parameters -- hard to manage at deployment time
    let authorized = list.has(self.extra_signatories, admin_key)
    let fee = amount * fee_numerator / fee_denominator
    authorized && amount >= min_deposit && amount <= max_withdrawal
  }
}
```

## Safe Example

```aiken
type Config {
  admin_key: ByteArray,
  oracle_key: ByteArray,
  treasury_address: ByteArray,
  fee_numerator: Int,
  fee_denominator: Int,
  min_deposit: Int,
  max_withdrawal: Int,
}

validator(config: Config) {
  spend(datum, redeemer, own_ref, self) {
    let authorized = list.has(self.extra_signatories, config.admin_key)
    let fee = amount * config.fee_numerator / config.fee_denominator
    authorized && amount >= config.min_deposit && amount <= config.max_withdrawal
  }
}
```

## Remediation

1. Group related parameters into a configuration record type and pass it as a single validator parameter.
2. Consider storing configuration in a reference UTXO's datum and reading it via reference inputs, reducing the number of deployment-time parameters.
3. Keep only truly immutable deployment parameters (e.g., a single admin key hash) as validator parameters.
