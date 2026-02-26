# Baselines

Baselines let you accept existing findings so that subsequent runs only report new issues. This is useful when adopting Aikido on an existing project where you want to focus on preventing new vulnerabilities without being overwhelmed by pre-existing findings.

## Creating a baseline

Run Aikido with the `--accept-baseline` flag:

```bash
aikido . --accept-baseline
```

This does three things:

1. Compiles the project and runs all detectors.
2. Saves every current finding to `.aikido-baseline.json` in the project root.
3. Prints the count of baselined findings and exits.

The baseline file is a JSON array of finding fingerprints. Commit it to version control so that CI runs use the same baseline.

## How baselines work

On every subsequent run, Aikido automatically loads `.aikido-baseline.json` if it exists in the project directory. Findings that match a baselined fingerprint are silently excluded from the output and from the `--fail-on` exit code check.

### Fingerprinting

Each finding is fingerprinted using three components:

```
detector_name:module_name:byte_start
```

- **`detector_name`** -- the detector that produced the finding (e.g., `missing-signature-check`).
- **`module_name`** -- the Aiken module where the finding was located (e.g., `my_project/validators/market`).
- **`byte_start`** -- the byte offset of the finding in the source file.

This fingerprint is stable across runs as long as the code at that location does not change. If you modify the code around a baselined finding (changing its byte offset), the finding will no longer match the baseline and will be reported as new.

## Updating the baseline

When you fix some baselined findings or want to accept new ones, re-run:

```bash
aikido . --accept-baseline
```

This regenerates the entire baseline from the current state. The previous `.aikido-baseline.json` is overwritten.

To accept only specific new findings while keeping existing baselines, you would need to edit the JSON file manually. Each entry has this structure:

```json
{
  "fingerprint": "missing-validity-range:my_project/validators/market:1234",
  "detector": "missing-validity-range",
  "module": "my_project/validators/market",
  "title": "..."
}
```

## Baseline in CI

The baseline works seamlessly with CI pipelines. The typical workflow is:

1. **Locally**: Run `aikido . --accept-baseline` to establish the baseline.
2. **Commit**: Add `.aikido-baseline.json` to version control.
3. **CI**: The pipeline runs `aikido . --fail-on high` as usual. Baselined findings are automatically excluded, so the pipeline only fails on genuinely new issues.

```yaml
# .github/workflows/aikido.yml
- name: Gate on new findings
  run: aikido . --fail-on high --quiet
  # Baselined findings in .aikido-baseline.json are automatically excluded
```

## Removing the baseline

Delete `.aikido-baseline.json` to go back to reporting all findings:

```bash
rm .aikido-baseline.json
```

The next run will report every finding as new.

## Interaction with other filters

Baselines are applied after suppression comments (`// aikido:ignore`) and before severity filtering (`--min-severity`). The processing order is:

1. Run all detectors.
2. Remove findings suppressed by inline `// aikido:ignore` comments.
3. Remove findings that match the baseline.
4. Apply `--min-severity` filter.
5. Apply `--diff` filter (if used).
6. Output remaining findings.
7. Check `--fail-on` threshold against remaining findings.

This means a finding that is both baselined and suppressed by a comment will never appear in output regardless of which mechanism caught it first.
