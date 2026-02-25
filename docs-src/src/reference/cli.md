# CLI Reference

Complete reference for all Aikido command-line flags and options.

## Synopsis

```
aikido [OPTIONS] [PROJECT_PATH]
```

`PROJECT_PATH` defaults to `.` (the current directory). It must point to a directory containing a valid `aiken.toml` file.

## General options

### `aikido <path>`

Analyze the Aiken project at the given path. Compiles the project, walks the typed AST, runs all enabled detectors, and outputs findings.

```bash
aikido .
aikido /path/to/my-project
```

### `--format <fmt>`

Set the output format. Default: `text`.

| Format | Description |
|--------|-------------|
| `text` | Colored terminal output with source snippets |
| `json` | Structured JSON with all finding details |
| `sarif` | SARIF v2.1.0 for GitHub Code Scanning |
| `markdown` | Markdown report suitable for documentation |
| `html` | Standalone HTML report with embedded CSS |
| `pdf` | PDF audit report |
| `csv` | Comma-separated values for spreadsheets |
| `gitlab-sast` | GitLab SAST schema for Security Dashboard |
| `rdjson` | reviewdog diagnostic format for PR annotations |

```bash
aikido . --format json
aikido . --format sarif > results.sarif
aikido . --format pdf > audit.pdf
```

### `--fail-on <severity>`

Exit with code `1` if any finding is at or above the specified severity. Default: `high`.

Valid values: `info`, `low`, `medium`, `high`, `critical`.

```bash
aikido . --fail-on critical    # Only fail on critical
aikido . --fail-on high        # Fail on high or critical (default)
aikido . --fail-on medium      # Fail on medium, high, or critical
aikido . --fail-on info        # Fail on any finding
```

In watch mode, the exit code behavior is suppressed and the loop continues running.

### `--min-severity <severity>`

Filter output to only include findings at or above the specified severity. Default: `info` (show everything).

```bash
aikido . --min-severity medium    # Hide low and info findings
aikido . --min-severity high      # Only show high and critical
```

### `--verbose`

Show additional detail including function signatures, constants, and UPLC metrics (compiled size, execution budget).

```bash
aikido . --verbose
```

### `-q`, `--quiet`

Suppress progress messages. Only output findings (or the formatted report). Useful in CI where you only care about the exit code.

```bash
aikido . --fail-on high --quiet
```

## Detector information

### `--list-rules`

Print all available detectors with their severity, category, CWE mapping, and description. Exits after printing.

```bash
aikido . --list-rules
```

Output format:
```
Available detectors (58):

  double-satisfaction                      [Critical] authorization      CWE-863    Validator can be satisfied...
  missing-minting-policy-check             [Critical] authorization      CWE-862    Minting policy does not...
  ...
```

### `--explain <rule>`

Print the detailed explanation for a specific detector, including severity, category, CWE classification, documentation URL, and a long description with vulnerable and safe code examples. Exits after printing.

```bash
aikido . --explain double-satisfaction
aikido . --explain missing-validity-range
```

## Analysis modes

### `--diff <branch>`

Only report findings in files that have changed since the specified git ref. The full project is still compiled and analyzed, but findings in unchanged files are filtered out.

```bash
aikido . --diff main
aikido . --diff v1.0.0
aikido . --diff abc1234
```

See [Diff Mode](../advanced/diff-mode.md) for details.

### `--watch`

Watch for `.ak` file changes and re-run analysis automatically. Polls every 2 seconds.

```bash
aikido . --watch
```

See [Watch Mode](../advanced/watch-mode.md) for details.

### `--git <url>`

Clone a remote git repository (shallow, depth 1) to a temporary directory and analyze it. The temp directory is cleaned up on exit.

```bash
aikido --git https://github.com/example/my-project.git
aikido --git git@github.com:example/my-project.git
```

See [Remote Repos](../advanced/remote-repos.md) for details.

## Configuration

### `--config <path>`

Specify the path to an `.aikido.toml` configuration file. By default, Aikido looks for `.aikido.toml` in the project directory.

```bash
aikido . --config /path/to/strict.aikido.toml
```

See [.aikido.toml Reference](../configuration/aikido-toml.md) for the config file format.

### `--generate-config`

Generate an `.aikido.toml` file pre-configured to suppress all current findings. The generated config has the triggered detector names in a commented-out `disable` list. Exits after writing the file.

```bash
aikido . --generate-config
```

### `--accept-baseline`

Run analysis and save all current findings as the baseline in `.aikido-baseline.json`. Subsequent runs automatically exclude baselined findings. Exits after saving.

```bash
aikido . --accept-baseline
```

See [Baselines](../advanced/baselines.md) for details.

### `--strict-stdlib`

Reject projects that use Aiken stdlib v1.x. By default, Aikido warns about v1.x but attempts compilation. With this flag, v1.x stdlib causes an immediate error exit.

```bash
aikido . --strict-stdlib
```

## Editor and tool integration

### `--lsp`

Output findings as LSP JSON-RPC `publishDiagnostics` notifications. Intended for editor extensions and language server integrations.

```bash
aikido . --lsp
```

### `--interactive`

Launch an interactive terminal navigator for browsing findings. Use `j`/`k` or arrow keys to navigate, Enter to expand details, `q` to quit. Requires a TTY.

```bash
aikido . --interactive
```

### `--fix`

Insert `// aikido:ignore[<detector>]` suppression comments above every finding with a source location. Optionally specify a detector name to only fix findings from that detector.

```bash
# Suppress all findings
aikido . --fix

# Suppress only a specific detector
aikido . --fix missing-validity-range
```

Comments are inserted with matching indentation. Files are modified in place.

## Miscellaneous

### `--no-detectors`

Skip vulnerability detection entirely. Only compile the project and show the module summary. Useful when you only want UPLC metrics.

```bash
aikido . --verbose --no-detectors
```

### `--init`

Generate a default `.aikido.toml` with all detectors listed as comments. Unlike `--generate-config`, this creates a clean template without reference to current findings. Errors if `.aikido.toml` already exists.

```bash
aikido . --init
```

### `--version`

Print the Aikido version and exit.

```bash
aikido --version
```

### `--help`

Print the help message with all available flags.

```bash
aikido --help
```
