# Watch Mode

Watch mode keeps Aikido running and automatically re-analyzes your project whenever source files change. This provides continuous feedback during development without manually re-running the command.

## Usage

```bash
aikido . --watch
```

Aikido runs a full analysis immediately, then watches for changes. When any `.ak` file in the project directory is modified, it re-compiles the project and re-runs all detectors.

## How it works

Watch mode uses a polling loop that checks file modification times every 2 seconds. When a change is detected:

1. The project is re-compiled from scratch (Aiken compilation is fast, typically under 2 seconds).
2. All enabled detectors are re-run against the fresh AST.
3. Suppression comments and baselines are re-evaluated.
4. New results are printed to the terminal.

The polling approach means watch mode works on all platforms without requiring filesystem notification libraries.

## Example output

```
Analyzing: /home/user/my-project
Project: my_project v0.1.0
[1/3] Compiling...
✔ 4 modules analyzed
[2/3] Running 58 detectors...
⚠ 3 issues found: 1 high, 2 medium

[... findings printed ...]

Watching for changes...
Watching for changes...

Changes detected, re-analyzing...
✔ 4 modules analyzed
⚠ 2 issues found: 2 medium

[... updated findings printed ...]

Watching for changes...
```

## Combining with other flags

Watch mode works with most other flags:

```bash
# Watch with severity filter
aikido . --watch --min-severity medium

# Watch with config file
aikido . --watch --config strict.aikido.toml

# Watch with quiet mode (minimal output)
aikido . --watch --quiet
```

Watch mode does not support output format flags other than text. In watch mode, findings are always printed in the colored terminal format for readability.

## Exiting

Press `Ctrl+C` to stop watch mode.

## Limitations

- Watch mode monitors `.ak` files only. Changes to `.aikido.toml`, `.aikido-baseline.json`, or `aiken.toml` require restarting the command.
- The `--fail-on` flag does not cause an exit in watch mode. The non-zero exit code behavior is suppressed so that the watch loop continues running even when findings are present.
- Watch mode is intended for local development. For CI pipelines, run Aikido without `--watch` to get a single analysis pass with a deterministic exit code.
