#!/usr/bin/env node
// Postinstall script: downloads the correct aikido binary for the platform.

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");

const VERSION = "0.1.0";
const BASE_URL = `https://github.com/Bajuzjefe/aikido/releases/download/v${VERSION}`;

const PLATFORM_MAP = {
  darwin: { x64: "aikido-x86_64-apple-darwin", arm64: "aikido-aarch64-apple-darwin" },
  linux: { x64: "aikido-x86_64-unknown-linux-gnu", arm64: "aikido-aarch64-unknown-linux-gnu" },
  win32: { x64: "aikido-x86_64-pc-windows-msvc.exe" },
};

function download(url, destPath, redirects) {
  if (redirects === undefined) redirects = 5;
  if (redirects <= 0) {
    console.error("[aikido] Too many redirects");
    process.exit(1);
  }

  return new Promise((resolve, reject) => {
    const proto = url.startsWith("https") ? https : require("http");
    proto.get(url, { headers: { "User-Agent": "aikido-npm-installer" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // Follow redirect
        return download(res.headers.location, destPath, redirects - 1).then(resolve, reject);
      }

      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
        return;
      }

      const file = fs.createWriteStream(destPath);
      res.pipe(file);
      file.on("finish", () => {
        file.close();
        resolve();
      });
      file.on("error", reject);
    }).on("error", reject);
  });
}

function fetchText(url, redirects) {
  if (redirects === undefined) redirects = 5;
  if (redirects <= 0) return Promise.reject(new Error("Too many redirects"));

  return new Promise((resolve, reject) => {
    const proto = url.startsWith("https") ? https : require("http");
    proto.get(url, { headers: { "User-Agent": "aikido-npm-installer" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchText(res.headers.location, redirects - 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
}

function sha256File(filePath) {
  const crypto = require("crypto");
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
}

async function main() {
  const platform = os.platform();
  const arch = os.arch();
  const map = PLATFORM_MAP[platform];

  if (!map || !map[arch]) {
    console.warn(`[aikido] No pre-built binary for ${platform}-${arch}`);
    console.warn("[aikido] Build from source: cargo install --path crates/aikido-cli");
    return;
  }

  const binaryName = map[arch];
  const url = `${BASE_URL}/${binaryName}`;
  const destDir = path.join(__dirname, "..", "bin");
  const destPath = path.join(destDir, binaryName);

  if (fs.existsSync(destPath)) {
    console.log(`[aikido] Binary already exists: ${destPath}`);
    return;
  }

  fs.mkdirSync(destDir, { recursive: true });

  console.log(`[aikido] Downloading ${url}...`);
  try {
    await download(url, destPath);
    // Make executable on Unix
    if (platform !== "win32") {
      fs.chmodSync(destPath, 0o755);
    }
    // Verify SHA256 checksum if available
    try {
      const checksumUrl = `${BASE_URL}/checksums.sha256`;
      const checksumData = await fetchText(checksumUrl);
      const expectedHash = checksumData
        .split("\n")
        .map((l) => l.trim().split(/\s+/))
        .find(([, name]) => name === binaryName);

      if (expectedHash) {
        const actualHash = sha256File(destPath);
        if (actualHash !== expectedHash[0]) {
          console.error(`[aikido] Checksum mismatch! Expected ${expectedHash[0]}, got ${actualHash}`);
          fs.unlinkSync(destPath);
          process.exit(1);
        }
        console.log(`[aikido] Checksum verified (SHA256)`);
      }
    } catch (_) {
      // Checksums file not available yet — skip verification
    }

    console.log(`[aikido] Installed to ${destPath}`);
  } catch (err) {
    console.error(`[aikido] Download failed: ${err.message}`);
    console.error(`[aikido] Download manually from: ${url}`);
    console.error(`[aikido] Place in: ${destDir}/`);
    // Don't fail the npm install — the binary just won't be available
  }
}

main();
