# Remote Repos

The `--git` flag lets you analyze a remote Aiken project without cloning it manually. Aikido clones the repository to a temporary directory, runs analysis, and cleans up when done.

## Usage

```bash
aikido --git https://github.com/example/my-aiken-project.git
```

This performs a shallow clone (`--depth 1`) of the repository, then runs the full analysis pipeline against the cloned project.

## How it works

1. Aikido computes a deterministic temporary directory path from the URL.
2. Any previous clone at that path is removed.
3. `git clone --depth 1 <url> <temp_path>` is executed.
4. The analysis proceeds as if you had run `aikido <temp_path>`.
5. When Aikido exits (normally or on error), the temporary directory is deleted.

The shallow clone keeps the download fast -- only the latest commit is fetched, not the full history.

## Examples

```bash
# Analyze a public GitHub repository
aikido --git https://github.com/aiken-lang/aiken-starter-kit.git

# Combine with output format
aikido --git https://github.com/example/my-project.git --format json

# Combine with severity filter
aikido --git https://github.com/example/my-project.git --min-severity medium

# Gate on findings
aikido --git https://github.com/example/my-project.git --fail-on high --quiet
```

## SSH URLs

SSH URLs work if you have SSH keys configured:

```bash
aikido --git git@github.com:example/my-project.git
```

## CI use case

The `--git` flag is useful for analyzing third-party dependencies or auditing projects you do not have checked out locally:

```yaml
- name: Audit dependency
  run: |
    aikido --git https://github.com/example/aiken-library.git \
      --format sarif > dependency-audit.sarif || true
```

## Limitations

- The `--diff` flag is not available in remote mode because the shallow clone has no branch history.
- The `--watch` flag is not available in remote mode because there is no local development directory to monitor.
- The `--accept-baseline` and `--generate-config` flags write files to the cloned directory, which is deleted on exit. These flags are not useful in remote mode.
- Private repositories require appropriate authentication (SSH keys, or `https://token@github.com/...` URLs).
- The repository must contain a valid `aiken.toml` at its root.

## Alternative: analyze after manual clone

If you need features that are not available in remote mode (diff, watch, baseline), clone the repository yourself:

```bash
git clone https://github.com/example/my-project.git
aikido my-project --diff main --accept-baseline
```
