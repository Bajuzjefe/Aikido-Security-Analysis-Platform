# reviewdog (rdjson)

[reviewdog](https://github.com/reviewdog/reviewdog) Diagnostic Format (rdjson) v0.2 output for posting inline PR annotations on GitHub, GitLab, and Bitbucket.

```bash
aikido /path/to/project --format rdjson
aikido /path/to/project --format rdjson > rdjson.json
```

## What is reviewdog

reviewdog is a code review tool that posts linter/analyzer results as inline comments on pull requests. It supports multiple CI platforms (GitHub Actions, GitLab CI, Bitbucket Pipelines) and multiple input formats. Aikido's `rdjson` output is the native reviewdog diagnostic format, giving you the richest integration with zero conversion needed.

## GitHub Actions integration

```yaml
name: Security Review
on: [pull_request]

jobs:
  aikido:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Install Aikido
        run: cargo install --git https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform aikido-cli

      - name: Install reviewdog
        uses: reviewdog/action-setup@v1

      - name: Run Aikido with reviewdog
        env:
          REVIEWDOG_GITHUB_API_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          aikido . --format rdjson --quiet 2>/dev/null \
            | reviewdog -f rdjson -reporter github-pr-review -filter-mode nofilter
```

This posts each Aikido finding as an inline review comment on the exact file and line in the pull request.

### Reporter options

reviewdog supports multiple reporter modes:

| Reporter | Behavior |
|----------|----------|
| `github-pr-review` | Posts as a pull request review with inline comments |
| `github-pr-check` | Posts as a GitHub Check Run with annotations |
| `github-check` | Posts as a Check Run (non-PR context) |
| `gitlab-mr-discussion` | Posts as merge request discussion comments |
| `gitlab-mr-commit` | Posts as commit comments on GitLab |

### Filter modes

| Mode | Behavior |
|------|----------|
| `added` | Only findings on added/changed lines (default) |
| `diff_context` | Findings on lines in the diff context |
| `file` | Findings in any changed file |
| `nofilter` | All findings regardless of diff |

For security analysis, `nofilter` is recommended to ensure existing vulnerabilities are not ignored.

## JSON structure

The rdjson output follows the [reviewdog Diagnostic Format](https://github.com/reviewdog/reviewdog/tree/master/proto/rdf) v0.2:

```json
{
  "source": {
    "name": "aikido",
    "url": "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform"
  },
  "diagnostics": [
    {
      "message": "Validator vulnerable to double satisfaction: Multiple UTXOs can be spent without unique identification.",
      "severity": "ERROR",
      "code": {
        "value": "double-satisfaction",
        "url": "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/blob/main/docs/detectors/double-satisfaction.md"
      },
      "location": {
        "path": "validators/pool.ak",
        "range": {
          "start": {
            "line": 42,
            "column": 5
          },
          "end": {
            "line": 55,
            "column": 6
          }
        }
      }
    }
  ]
}
```

## Field mapping

### Severity

Aikido severities are mapped to reviewdog severity levels:

| Aikido | rdjson |
|--------|--------|
| Critical | `ERROR` |
| High | `ERROR` |
| Medium | `WARNING` |
| Low | `INFO` |
| Info | `INFO` |

### Message

The `message` field combines the finding title and description separated by a colon. This gives reviewdog a single string to display in the PR comment.

### Code

Each diagnostic includes a `code` object with:

- **value** -- The detector rule ID (e.g., `"double-satisfaction"`)
- **url** -- Link to the detector's documentation page

reviewdog renders the code value as a clickable link to the documentation.

### Location

File paths are made relative to the project root. The `range` object includes start and end positions with line and column numbers (1-based). The `end` field is omitted when only a start position is available.

## Notes

- Use `--quiet` to suppress progress messages that would otherwise corrupt the JSON output on stderr vs stdout.
- The `2>/dev/null` redirect discards stderr (progress messages) to ensure only clean JSON reaches reviewdog via the pipe.
- reviewdog must be installed separately. The `reviewdog/action-setup@v1` action handles this in GitHub Actions.
