#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pushd "$ROOT_DIR" >/dev/null
cargo test --all
"$ROOT_DIR/scripts/run_benchmark.sh"
popd >/dev/null

echo "release quality gates passed"
