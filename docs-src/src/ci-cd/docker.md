# Docker

Aikido provides a pre-built Docker image that includes everything needed to analyze Aiken projects without installing the Rust toolchain.

## Image

The official image is hosted on GitHub Container Registry:

```
ghcr.io/bajuzjefe/aikido:0.3.0
```

The image is based on `debian:bookworm-slim` and includes `git` (required for `--diff` and `--git` modes) and `ca-certificates` (required for fetching the Aiken stdlib on first compilation).

## Basic usage

Mount your Aiken project directory into the container and pass the path as the first argument:

```bash
docker run --rm -v $(pwd):/project ghcr.io/bajuzjefe/aikido:0.3.0 /project
```

The output is printed to stdout. All CLI flags work the same as the native binary:

```bash
# JSON output
docker run --rm -v $(pwd):/project \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project --format json

# SARIF output
docker run --rm -v $(pwd):/project \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project --format sarif > results.sarif

# Filter and gate
docker run --rm -v $(pwd):/project \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project --min-severity medium --fail-on high
```

## Volume mounting

The container expects the Aiken project to be mounted at the path you pass as the first argument. A few things to keep in mind:

**Project root** -- mount the directory that contains `aiken.toml`:

```bash
docker run --rm -v /path/to/my-project:/project \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project
```

**Config file** -- if you use a custom `.aikido.toml` location, mount it and pass `--config`:

```bash
docker run --rm \
  -v $(pwd):/project \
  -v /path/to/custom-config.toml:/config.toml:ro \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project --config /config.toml
```

**Output files** -- to write output to the host filesystem, redirect or mount an output directory:

```bash
# Redirect stdout
docker run --rm -v $(pwd):/project \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project --format sarif > results.sarif

# Mount output directory for PDF
docker run --rm \
  -v $(pwd):/project \
  -v $(pwd)/reports:/reports \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project --format pdf > /reports/audit.pdf
```

**Stdlib cache** -- Aiken downloads the standard library on first compilation. To avoid re-downloading on every run, mount a persistent cache volume:

```bash
docker run --rm \
  -v $(pwd):/project \
  -v aikido-cache:/root/.aiken \
  ghcr.io/bajuzjefe/aikido:0.3.0 /project
```

## CI usage

### GitHub Actions

```yaml
- name: Run Aikido
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/project \
      ghcr.io/bajuzjefe/aikido:0.3.0 \
      /project --format sarif > aikido-results.sarif || true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: aikido-results.sarif
    category: aikido
```

### GitLab CI

```yaml
aikido-sast:
  stage: test
  image: ghcr.io/bajuzjefe/aikido:0.3.0
  script:
    - aikido . --format gitlab-sast > gl-sast-report.json || true
    - aikido . --fail-on high --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

When using the image directly as the GitLab CI `image`, the project is already in the working directory and you can pass `.` as the path.

### Generic CI

For any CI system that supports Docker:

```bash
docker run --rm \
  -v "${WORKSPACE}:/project" \
  ghcr.io/bajuzjefe/aikido:0.3.0 \
  /project --fail-on high --quiet
```

Check the exit code to gate your pipeline:

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the threshold |
| `1` | Findings at or above the threshold |
| `2` | Compilation error |
| `3` | Configuration error |

## Building the image locally

To build from source:

```bash
git clone https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform.git
cd aikido
docker build -t aikido .
```

The Dockerfile uses a multi-stage build: the first stage compiles the Rust binary using `rust:1.86-slim`, and the second stage copies just the binary into a minimal `debian:bookworm-slim` image. The final image is approximately 80 MB.

```bash
# Run the locally built image
docker run --rm -v $(pwd):/project aikido /project
```
