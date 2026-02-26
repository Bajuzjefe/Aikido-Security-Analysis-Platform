#!/usr/bin/env node
// Feature #87: npm wrapper — `npx aikido-aiken <path>`
// Downloads and runs the pre-built aikido binary for the current platform.

const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");
const fs = require("fs");

const PLATFORM_MAP = {
  darwin: { x64: "aikido-x86_64-apple-darwin", arm64: "aikido-aarch64-apple-darwin" },
  linux: { x64: "aikido-x86_64-unknown-linux-gnu", arm64: "aikido-aarch64-unknown-linux-gnu" },
  win32: { x64: "aikido-x86_64-pc-windows-msvc.exe" },
};

function getBinaryName() {
  const platform = os.platform();
  const arch = os.arch();
  const map = PLATFORM_MAP[platform];
  if (!map || !map[arch]) {
    console.error(`Unsupported platform: ${platform}-${arch}`);
    console.error("Please build aikido from source: cargo install --path crates/aikido-cli");
    process.exit(1);
  }
  return map[arch];
}

function main() {
  const binDir = path.join(__dirname, "..");
  const binaryName = getBinaryName();
  const binaryPath = path.join(binDir, "bin", binaryName);

  if (!fs.existsSync(binaryPath)) {
    console.error(`Binary not found: ${binaryPath}`);
    console.error("Run: npm run postinstall");
    process.exit(1);
  }

  const args = process.argv.slice(2);
  try {
    execFileSync(binaryPath, args, { stdio: "inherit" });
  } catch (error) {
    process.exit(error.status || 1);
  }
}

main();
