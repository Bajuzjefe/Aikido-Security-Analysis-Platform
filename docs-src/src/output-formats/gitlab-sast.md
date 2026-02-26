# GitLab SAST

GitLab SAST (Static Application Security Testing) JSON format for integration with the GitLab Security Dashboard. Findings appear as vulnerabilities in merge request widgets and the project's Vulnerability Report.

```bash
aikido /path/to/project --format gitlab-sast
aikido /path/to/project --format gitlab-sast > gl-sast-report.json
```

## GitLab CI integration

Add Aikido to your `.gitlab-ci.yml` as a SAST job. The key requirement is declaring the output file as a `reports:sast` artifact:

```yaml
aikido-sast:
  stage: test
  image: rust:latest
  before_script:
    - cargo install --git https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform aikido-cli
  script:
    - aikido . --format gitlab-sast --quiet > gl-sast-report.json 2>/dev/null || true
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

### With Docker

If you prefer using the Aikido Docker image:

```yaml
aikido-sast:
  stage: test
  image:
    name: ghcr.io/bajuzjefe/aikido:latest
    entrypoint: [""]
  script:
    - aikido . --format gitlab-sast --quiet > gl-sast-report.json 2>/dev/null || true
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

### Fail on threshold

Combine with `--fail-on` to block merge requests that introduce high-severity findings:

```yaml
aikido-sast:
  stage: test
  image: rust:latest
  before_script:
    - cargo install --git https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform aikido-cli
  script:
    - aikido . --format gitlab-sast --quiet > gl-sast-report.json
    - aikido . --fail-on high --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
  allow_failure:
    exit_codes:
      - 2
```

Note that `--format gitlab-sast` and `--fail-on` are used in separate invocations: the first generates the report file (ignoring exit code), the second checks the threshold.

## JSON structure

Aikido generates GitLab SAST format version 15.0.7:

```json
{
  "version": "15.0.7",
  "vulnerabilities": [
    {
      "id": "a1b2c3d4e5f67890",
      "category": "sast",
      "name": "Validator vulnerable to double satisfaction",
      "message": "Multiple UTXOs can be spent without unique identification.",
      "description": "Multiple UTXOs can be spent without unique identification.",
      "severity": "Critical",
      "confidence": "DEFINITE",
      "scanner": {
        "id": "aikido",
        "name": "Aikido"
      },
      "identifiers": [
        {
          "type": "aikido_rule",
          "name": "double-satisfaction",
          "value": "double-satisfaction",
          "url": "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/blob/main/docs/detectors/double-satisfaction.md"
        }
      ],
      "location": {
        "file": "validators/pool.ak",
        "start_line": 42,
        "end_line": 55
      },
      "solution": "Reference the validator's own input via the output reference parameter to ensure each UTXO is uniquely identified."
    }
  ],
  "scan": {
    "scanner": {
      "id": "aikido",
      "name": "Aikido",
      "url": "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform",
      "vendor": {
        "name": "aikido"
      },
      "version": "0.1.0"
    },
    "type": "sast",
    "status": "success"
  }
}
```

## Field mapping

### Severity

Aikido severities map directly to GitLab severity strings:

| Aikido | GitLab |
|--------|--------|
| Critical | `Critical` |
| High | `High` |
| Medium | `Medium` |
| Low | `Low` |
| Info | `Info` |

### Confidence

Aikido confidence levels are mapped to uppercase strings matching GitLab's expected values: `DEFINITE`, `LIKELY`, `POSSIBLE`.

### Vulnerability ID

Each vulnerability receives a stable hex ID computed from the detector name, module, and byte offset. This enables GitLab to track findings across pipeline runs and identify new vs. existing vulnerabilities.

### Identifiers

Each vulnerability includes an `aikido_rule` identifier linking to the detector's documentation page. GitLab uses identifiers to correlate findings across scanners and deduplicate results.

### Solution

When a finding includes a remediation suggestion, it is mapped to the `solution` field. GitLab displays this as the recommended fix in the vulnerability detail view.

## Notes

- The `--quiet` flag is recommended in CI to suppress progress messages on stderr.
- The `|| true` after the command ensures the pipeline step does not fail when findings are present (findings trigger exit code 2). Use a separate `--fail-on` step to control pipeline failure behavior.
- The `when: always` on the artifact ensures the report is uploaded even if the script step fails.
