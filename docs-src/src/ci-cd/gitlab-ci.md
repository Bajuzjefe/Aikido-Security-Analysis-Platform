# GitLab CI

Aikido integrates with GitLab CI/CD pipelines and produces output in the GitLab SAST format, which feeds directly into the GitLab Security Dashboard.

## Basic pipeline

Add the following to your `.gitlab-ci.yml`:

```yaml
stages:
  - test

aikido-sast:
  stage: test
  image: ghcr.io/bajuzjefe/aikido:0.3.0
  script:
    - aikido . --format gitlab-sast > gl-sast-report.json || true
    - aikido . --fail-on high --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

This does two things:

1. **Generates the SAST report** -- `--format gitlab-sast` produces a JSON file conforming to the [GitLab SAST report schema](https://docs.gitlab.com/ee/development/integrations/secure.html#sast). The `artifacts.reports.sast` key tells GitLab to pick it up for the Security Dashboard.
2. **Gates the pipeline** -- the second command runs with `--fail-on high --quiet` to fail the job if any high or critical findings are present.

## GitLab Security Dashboard

Once the pipeline runs, findings appear in:

- **Merge request widget** -- a summary of new, fixed, and existing vulnerabilities shows directly on the MR page.
- **Security Dashboard** -- navigate to Security & Compliance > Vulnerability Report to see all findings across branches.
- **Pipeline security tab** -- each pipeline run shows its SAST results.

GitLab tracks findings across runs, so you can see which vulnerabilities are new in a merge request and which were already present on the target branch.

## Building from source

If you prefer to compile Aikido from source instead of using the Docker image:

```yaml
aikido-sast:
  stage: test
  image: rust:1.86-slim
  before_script:
    - apt-get update && apt-get install -y git pkg-config
    - cargo install aikido-cli
  script:
    - aikido . --format gitlab-sast > gl-sast-report.json || true
    - aikido . --fail-on high --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
  cache:
    key: aikido-cargo
    paths:
      - $CARGO_HOME/registry
      - $CARGO_HOME/git
```

## Filtering severity

Control which findings appear in the report and which trigger failure independently:

```yaml
script:
  # Report medium and above in the dashboard
  - aikido . --format gitlab-sast --min-severity medium > gl-sast-report.json || true
  # Only fail on critical
  - aikido . --fail-on critical --quiet
```

## Diff-only mode for merge requests

Restrict analysis to files changed in the current merge request:

```yaml
aikido-sast:
  stage: test
  image: ghcr.io/bajuzjefe/aikido:0.3.0
  script:
    - aikido . --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --format gitlab-sast > gl-sast-report.json || true
    - aikido . --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --fail-on high --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
  rules:
    - if: $CI_MERGE_REQUEST_IID
```

## Output format details

The `gitlab-sast` format produces a JSON object with this structure:

```json
{
  "version": "15.0.0",
  "scan": {
    "scanner": {
      "id": "aikido",
      "name": "Aikido",
      "vendor": { "name": "Aikido" }
    },
    "type": "sast",
    "status": "success"
  },
  "vulnerabilities": [
    {
      "id": "...",
      "name": "double-satisfaction",
      "description": "...",
      "severity": "Critical",
      "location": {
        "file": "validators/market.ak",
        "start_line": 42,
        "end_line": 42
      },
      "identifiers": [
        {
          "type": "cwe",
          "name": "CWE-863",
          "value": "863"
        }
      ]
    }
  ]
}
```

Each finding maps to a GitLab vulnerability entry with severity, CWE classification, and precise source location.
