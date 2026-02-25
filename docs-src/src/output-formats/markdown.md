# Markdown

Human-readable Markdown report suitable for GitHub PR comments, wikis, and documentation.

```bash
aikido /path/to/project --format markdown
aikido /path/to/project --format markdown > report.md
```

## Use cases

- **PR comments** -- Post the report as a comment on pull requests so reviewers see findings inline
- **Wiki pages** -- Save to a project wiki for historical tracking
- **README badges** -- Extract summary counts for status badges
- **Documentation** -- Include in project security documentation

## Example output

The Markdown output renders as follows when viewed on GitHub:

---

# Aikido Security Report

**Project:** my-dex v1.0.0

## Summary

**Total issues:** 3

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |

## Findings

### 1. **CRITICAL** `double-satisfaction`

**Validator vulnerable to double satisfaction**

Multiple UTXOs at this script address can be spent in a single transaction without the validator distinguishing which UTXO is being authorized.

**Location:** `validators/pool.ak:42`

```aiken
   40 | validator pool {
   41 |   spend(datum: PoolDatum, redeemer: PoolRedeemer, _self: OutputReference, tx: Transaction) {
>> 42 |     when redeemer is {
   43 |       Swap -> handle_swap(datum, tx)
   44 |       AddLiquidity -> handle_add(datum, tx)
```

> **Suggestion:** Reference the validator's own input via the output reference parameter to ensure each UTXO is uniquely identified.

---

## Structure

The report includes:

1. **Header** -- Project name and version
2. **Summary table** -- Finding counts broken down by severity
3. **Findings** -- Each finding as a numbered section with severity badge, detector name, title, description, file location, code snippet (when source is available), and remediation suggestion

Findings are sorted by severity (Critical first, Info last).

## Posting as a GitHub PR comment

You can automate posting the Markdown report as a PR comment using GitHub Actions:

```yaml
- name: Run Aikido
  id: aikido
  run: |
    aikido . --format markdown --quiet > aikido-report.md 2>/dev/null || true

- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: marocchino/sticky-pull-request-comment@v2
  with:
    path: aikido-report.md
    header: aikido-report
```

This uses a sticky comment that updates on each push rather than creating duplicate comments.

## Code snippets

When source code is available from the compiled modules, the Markdown output includes fenced code blocks with the `aiken` language tag for syntax highlighting. The snippet shows 2 lines of context above and below the finding, with the offending line marked by `>>`.

## Severity badges

Each finding's severity is rendered with a colored circle emoji for quick visual scanning:

| Severity | Badge |
|----------|-------|
| Critical | Red circle + **CRITICAL** |
| High | Orange circle + **HIGH** |
| Medium | Yellow circle + **MEDIUM** |
| Low | Blue circle + **LOW** |
| Info | White circle + **INFO** |
