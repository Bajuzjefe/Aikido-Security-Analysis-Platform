#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="${1:-$ROOT_DIR/benchmarks/local-fixtures.toml}"
OUTPUT_PATH="${2:-$ROOT_DIR/benchmark-summary.json}"

cargo run -p aikido-cli -- \
  --benchmark-manifest "$MANIFEST_PATH" \
  --benchmark-enforce-gates \
  --format json > "$OUTPUT_PATH"

echo "benchmark summary written to $OUTPUT_PATH"
