# Diff Mode

Diff mode restricts analysis to files that have changed since a specified git reference. This is useful for pull request reviews where you only want to see findings in the code that was actually modified.

## Usage

```bash
aikido . --diff main
```

The argument to `--diff` is any valid git ref -- a branch name, a tag, or a commit hash:

```bash
# Diff against a branch
aikido . --diff main

# Diff against a specific commit
aikido . --diff abc1234

# Diff against a tag
aikido . --diff v1.0.0
```

## How it works

Aikido still compiles and analyzes the entire project (cross-module analysis requires the full context). After running all detectors, it executes:

```
git diff --name-only <ref>
```

from the project directory to get the list of changed files. Findings in files that do not appear in the diff output are filtered out before results are displayed and before the `--fail-on` exit code is evaluated.

This means diff mode is a post-analysis filter, not a way to skip analysis. The benefit is that cross-module findings are still accurate -- if a change in `utils.ak` introduces a vulnerability that manifests in `market.ak`, and both files are in the diff, the finding will be reported.

## CI integration

### GitHub Actions

In a pull request workflow, diff against the base branch:

```yaml
- name: Analyze changed files
  if: github.event_name == 'pull_request'
  run: |
    aikido . --diff origin/${{ github.base_ref }} \
      --format sarif > aikido-results.sarif || true
```

### GitLab CI

In a merge request pipeline, diff against the target branch:

```yaml
aikido-diff:
  stage: test
  image: ghcr.io/bajuzjefe/aikido:0.3.0
  script:
    - aikido . --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME \
        --format gitlab-sast > gl-sast-report.json || true
    - aikido . --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME \
        --fail-on high --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
  rules:
    - if: $CI_MERGE_REQUEST_IID
```

## Combining with other modes

Diff mode works alongside other filters:

```bash
# Diff + severity filter
aikido . --diff main --min-severity medium

# Diff + baseline
aikido . --diff main
# Baselined findings are excluded before the diff filter is applied

# Diff + SARIF output
aikido . --diff main --format sarif > results.sarif
```

## Limitations

- Diff mode requires git to be installed and the project directory to be a git repository.
- If the specified ref does not exist or git is not available, Aikido prints a warning and falls back to reporting all findings.
- Findings without source locations (rare, typically structural findings) are excluded in diff mode because they cannot be mapped to a specific file.
- If a change in a non-diff file causes a new vulnerability in a diff file, it will be reported. If a change in a diff file causes a vulnerability in a non-diff file, it will not be reported. For full coverage, run without `--diff` on the main branch.
