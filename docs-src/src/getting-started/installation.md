# Installation

Aikido can be installed through several methods depending on your environment and preferences. Pick whichever fits your workflow.

## Homebrew (macOS and Linux)

The fastest way to install on macOS or Linux:

```bash
brew install Bajuzjefe/tap/aikido
```

This installs the `aikido` binary and keeps it updated through `brew upgrade`.

Verify the installation:

```bash
aikido --version
# aikido 0.3.0
```

## Cargo (from source via crates registry)

If you have a Rust toolchain installed (Rust >= 1.88.0):

```bash
cargo install --git https://github.com/Bajuzjefe/aikido aikido-cli
```

This compiles the binary from source and installs it to `~/.cargo/bin/aikido`. The compilation takes roughly 2-3 minutes on a modern machine.

Make sure `~/.cargo/bin` is on your PATH:

```bash
# Check if cargo bin is in your PATH
which aikido

# If not, add to your shell profile:
export PATH="$HOME/.cargo/bin:$PATH"
```

To update to the latest version, run the same `cargo install` command again.

## npm

Two options for Node.js environments:

**Run without installing** (downloads on first use):

```bash
npx aikido-aiken /path/to/your-aiken-project
```

**Install globally**:

```bash
npm install -g aikido-cli
aikido /path/to/your-aiken-project
```

The npm package is a thin wrapper that downloads the appropriate native binary for your platform on first run. Supported platforms: macOS (arm64, x86_64), Linux (x86_64, arm64).

## Docker

No installation required -- just mount your project directory:

```bash
docker run --rm -v $(pwd):/project ghcr.io/bajuzjefe/aikido:0.3.0 /project
```

This pulls a small multi-stage image with the Aikido binary pre-compiled. Useful for CI/CD pipelines and environments where you cannot install native binaries.

Pass additional flags after the project path:

```bash
# JSON output
docker run --rm -v $(pwd):/project ghcr.io/bajuzjefe/aikido:0.3.0 /project --format json

# Fail on high severity
docker run --rm -v $(pwd):/project ghcr.io/bajuzjefe/aikido:0.3.0 /project --fail-on high
```

## Pre-built binaries (GitHub Releases)

Download a pre-compiled binary for your platform from the [GitHub Releases page](https://github.com/Bajuzjefe/aikido/releases):

| Platform | Architecture | Filename |
|----------|-------------|----------|
| macOS | Apple Silicon (arm64) | `aikido-aarch64-apple-darwin.tar.gz` |
| macOS | Intel (x86_64) | `aikido-x86_64-apple-darwin.tar.gz` |
| Linux | x86_64 | `aikido-x86_64-unknown-linux-gnu.tar.gz` |
| Linux | arm64 | `aikido-aarch64-unknown-linux-gnu.tar.gz` |
| Windows | x86_64 | `aikido-x86_64-pc-windows-msvc.zip` |

Extract and move to a directory on your PATH:

```bash
# Example for macOS Apple Silicon
curl -L https://github.com/Bajuzjefe/aikido/releases/latest/download/aikido-aarch64-apple-darwin.tar.gz | tar xz
chmod +x aikido
sudo mv aikido /usr/local/bin/
```

## Building from source

Clone the repository and build with Cargo:

```bash
git clone https://github.com/Bajuzjefe/aikido.git
cd aikido
cargo build --release
```

The compiled binary is at `target/release/aikido`. Copy it to a directory on your PATH or run it directly:

```bash
./target/release/aikido /path/to/your-aiken-project
```

To run the full test suite (526+ tests):

```bash
cargo test
```

### Build requirements

- Rust >= 1.88.0 (install via [rustup](https://rustup.rs/))
- A C linker (usually already present on macOS and Linux)
- Network access on first run (Aiken downloads the stdlib when compiling a project for the first time)

## Verifying installation

After installing through any method, verify that Aikido is working:

```bash
# Check version
aikido --version

# List all 58 detectors
aikido --list-rules

# Get help
aikido --help
```

If you have an Aiken project available, try running a scan:

```bash
aikido /path/to/your-aiken-project
```

## Next steps

- [Quick Start](quick-start.md) -- Run your first scan in three steps
- [Your First Scan](your-first-scan.md) -- Learn to read the output
