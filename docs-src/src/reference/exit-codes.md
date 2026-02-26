# Exit Codes

Aikido uses exit codes to communicate the analysis result to CI pipelines, shell scripts, and other automation tools.

## Codes

| Code | Meaning |
|------|---------|
| `0` | Success. No findings at or above the `--fail-on` severity threshold. |
| `1` | Findings present. One or more findings met or exceeded the `--fail-on` severity threshold. |
| `2` | Compilation error. The Aiken project failed to compile (missing `aiken.toml`, syntax errors, type errors, stdlib download failure). |
| `3` | Configuration error. Invalid CLI flags, unrecognized severity value, or malformed `.aikido.toml`. |

## The `--fail-on` threshold

The exit code depends on the `--fail-on` flag, which defaults to `high`. Only findings at or above the specified severity trigger a non-zero exit:

```bash
# Exit 1 only if critical findings exist
aikido . --fail-on critical

# Exit 1 if high or critical findings exist (default)
aikido . --fail-on high

# Exit 1 if medium, high, or critical findings exist
aikido . --fail-on medium

# Exit 1 if any finding exists at any severity
aikido . --fail-on info
```

Findings below the threshold are still printed in the output but do not affect the exit code.

## Interaction with baselines

Baselined findings (those in `.aikido-baseline.json`) are excluded before the exit code is evaluated. If all findings above the threshold are baselined, the exit code is `0`.

## Interaction with diff mode

In diff mode (`--diff <ref>`), only findings in changed files are considered. If all above-threshold findings are in unchanged files, the exit code is `0`.

## Interaction with watch mode

In watch mode (`--watch`), the `--fail-on` exit code is suppressed. The watch loop continues running regardless of findings. Use watch mode for development feedback, not for CI gating.

## CI usage

### GitHub Actions

```yaml
- name: Gate merge
  run: aikido . --fail-on high --quiet
```

A non-zero exit code fails the workflow step, which blocks the pull request if branch protection requires the check to pass.

### GitLab CI

```yaml
script:
  - aikido . --format gitlab-sast > gl-sast-report.json || true
  - aikido . --fail-on high --quiet
```

The first command always succeeds (due to `|| true`) so the SAST report is uploaded. The second command gates the job.

### Shell scripts

```bash
aikido /path/to/project --fail-on medium --quiet
status=$?

case $status in
  0) echo "No issues above threshold" ;;
  1) echo "Security findings detected" ;;
  2) echo "Project failed to compile" ;;
  3) echo "Configuration error" ;;
esac
```

## Commands that exit early

Some flags cause Aikido to exit before running the full analysis:

| Flag | Exit code |
|------|-----------|
| `--list-rules` | Always `0` |
| `--explain <rule>` | `0` if the rule exists, `1` if not found |
| `--init` | `0` on success, `1` if `.aikido.toml` already exists |
| `--accept-baseline` | `0` on success |
| `--generate-config` | `0` on success |
| `--fix` | `0` on success |
| `--version` | Always `0` |
| `--help` | Always `0` |
