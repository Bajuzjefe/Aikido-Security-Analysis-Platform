# Critical Detectors

Critical detectors identify vulnerabilities that are **directly exploitable** and lead to **immediate fund loss**. These findings should always be addressed before deployment.

| Detector | CWE | Description |
|----------|-----|-------------|
| [double-satisfaction](double-satisfaction.md) | CWE-362 | Spend handler iterates outputs without referencing own input |
| [missing-minting-policy-check](missing-minting-policy-check.md) | CWE-862 | Mint handler doesn't validate which token names are minted |
| [missing-utxo-authentication](missing-utxo-authentication.md) | CWE-345 | Reference inputs used without authentication |
| [unrestricted-minting](unrestricted-minting.md) | CWE-862 | Minting policy with no authorization check at all |
| [output-address-not-validated](output-address-not-validated.md) | CWE-284 | Outputs sent to unchecked addresses |
