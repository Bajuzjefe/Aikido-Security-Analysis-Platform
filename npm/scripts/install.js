#!/usr/bin/env node
// Postinstall script: downloads the correct aikido binary for the platform.

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

const VERSION = "0.3.1";
const BASE_URL = `https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v${VERSION}`;

const PLATFORM_MAP = {
  darwin: {
    x64: { tarball: "aikido-x86_64-apple-darwin.tar.gz", binary: "aikido" },
    arm64: { tarball: "aikido-aarch64-apple-darwin.tar.gz", binary: "aikido" },
  },
  linux: {
    x64: { tarball: "aikido-x86_64-unknown-linux-gnu.tar.gz", binary: "aikido" },
    arm64: { tarball: "aikido-aarch64-unknown-linux-gnu.tar.gz", binary: "aikido" },
  },
  win32: {
    x64: { tarball: "aikido-x86_64-pc-windows-msvc.tar.gz", binary: "aikido.exe" },
  },
};

// Binary name used by the wrapper (platform-specific identifier)
const BINARY_NAME_MAP = {
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
    proto
      .get(url, { headers: { "User-Agent": "aikido-npm-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
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
      })
      .on("error", reject);
  });
}

function fetchText(url, redirects) {
  if (redirects === undefined) redirects = 5;
  if (redirects <= 0) return Promise.reject(new Error("Too many redirects"));

  return new Promise((resolve, reject) => {
    const proto = url.startsWith("https") ? https : require("http");
    proto
      .get(url, { headers: { "User-Agent": "aikido-npm-installer" } }, (res) => {
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
      })
      .on("error", reject);
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
  const nameMap = BINARY_NAME_MAP[platform];

  if (!map || !map[arch]) {
    console.warn(`[aikido] No pre-built binary for ${platform}-${arch}`);
    console.warn("[aikido] Build from source: cargo install --path crates/aikido-cli");
    return;
  }

  const { tarball, binary } = map[arch];
  const destBinaryName = nameMap[arch];
  const destDir = path.join(__dirname, "..", "bin");
  const destPath = path.join(destDir, destBinaryName);

  if (fs.existsSync(destPath)) {
    console.log(`[aikido] Binary already exists: ${destPath}`);
    return;
  }

  fs.mkdirSync(destDir, { recursive: true });

  const tarballUrl = `${BASE_URL}/${tarball}`;
  const tarballPath = path.join(destDir, tarball);

  console.log(`[aikido] Downloading ${tarballUrl}...`);
  try {
    await download(tarballUrl, tarballPath);

    // Verify SHA256 checksum if available
    try {
      const checksumUrl = `${BASE_URL}/checksums.sha256`;
      const checksumData = await fetchText(checksumUrl);
      const expectedHash = checksumData
        .split("\n")
        .map((l) => l.trim().split(/\s+/))
        .find(([, name]) => name === tarball);

      if (expectedHash) {
        const actualHash = sha256File(tarballPath);
        if (actualHash !== expectedHash[0]) {
          console.error(`[aikido] Checksum mismatch! Expected ${expectedHash[0]}, got ${actualHash}`);
          fs.unlinkSync(tarballPath);
          process.exit(1);
        }
        console.log(`[aikido] Checksum verified (SHA256)`);
      }
    } catch (_) {
      // Checksums file not available yet - skip verification
    }

    // Extract binary from tarball
    console.log(`[aikido] Extracting ${binary} from ${tarball}...`);
    execSync(`tar xzf "${tarball}" "${binary}"`, { cwd: destDir });

    // Rename to platform-specific name for the wrapper
    const extractedPath = path.join(destDir, binary);
    if (extractedPath !== destPath) {
      fs.renameSync(extractedPath, destPath);
    }

    // Make executable on Unix
    if (platform !== "win32") {
      fs.chmodSync(destPath, 0o755);
    }

    // Clean up tarball
    fs.unlinkSync(tarballPath);

    console.log(`[aikido] Installed to ${destPath}`);
  } catch (err) {
    console.error(`[aikido] Download failed: ${err.message}`);
    console.error("[aikido] Install from source: cargo install --git https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform aikido-cli");
    // Clean up partial files
    try { fs.unlinkSync(tarballPath); } catch (_) {}
    // Don't fail npm install - the binary just won't be available
  }
}

main();
