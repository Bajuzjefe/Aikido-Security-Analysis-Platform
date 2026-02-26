import { execFile } from "node:child_process";
import { access, constants } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const PLATFORM_MAP: Record<string, Record<string, string>> = {
  darwin: {
    x64: "aikido-x86_64-apple-darwin",
    arm64: "aikido-aarch64-apple-darwin",
  },
  linux: {
    x64: "aikido-x86_64-unknown-linux-gnu",
    arm64: "aikido-aarch64-unknown-linux-gnu",
  },
  win32: {
    x64: "aikido-x86_64-pc-windows-msvc.exe",
  },
};

/** Result of running the aikido binary */
export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Discover the aikido binary path using priority chain */
async function discoverBinary(): Promise<string> {
  // 1. AIKIDO_BINARY env var
  const envPath = process.env.AIKIDO_BINARY;
  if (envPath) {
    await assertExecutable(envPath);
    return envPath;
  }

  // 2. npm sibling — aikido-aiken package bin directory
  const binaryName = PLATFORM_MAP[process.platform]?.[process.arch];
  if (binaryName) {
    // Look relative to this package for a sibling aikido-aiken installation
    // Typical layout: node_modules/.bin/ or node_modules/aikido-aiken/bin/
    const siblingPaths = [
      // npm/pnpm hoisted
      resolve(__dirname, "..", "node_modules", "aikido-aiken", "bin", binaryName),
      // yarn pnp or nested
      resolve(__dirname, "..", "..", "aikido-aiken", "bin", binaryName),
    ];
    for (const p of siblingPaths) {
      if (await isExecutable(p)) return p;
    }
  }

  // 3. aikido on PATH
  const pathBinary = await findOnPath("aikido");
  if (pathBinary) return pathBinary;

  // Also try aikido-aiken on PATH (the npm wrapper)
  const wrapperBinary = await findOnPath("aikido-aiken");
  if (wrapperBinary) return wrapperBinary;

  throw new Error(
    "Aikido binary not found. Install it via one of:\n" +
    "  npm install -g aikido-aiken\n" +
    "  cargo install aikido-aiken\n" +
    "  Set AIKIDO_BINARY env var to the binary path\n" +
    "  See: https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform"
  );
}

async function assertExecutable(path: string): Promise<void> {
  try {
    await access(path, constants.X_OK);
  } catch {
    throw new Error(`Aikido binary at ${path} is not executable`);
  }
}

async function isExecutable(path: string): Promise<boolean> {
  try {
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function findOnPath(name: string): Promise<string | null> {
  const pathDirs = (process.env.PATH ?? "").split(process.platform === "win32" ? ";" : ":");
  for (const dir of pathDirs) {
    const fullPath = join(dir, name);
    if (await isExecutable(fullPath)) return fullPath;
  }
  return null;
}

let cachedBinaryPath: string | null = null;

/** Get the aikido binary path (cached after first discovery) */
export async function getBinaryPath(): Promise<string> {
  if (!cachedBinaryPath) {
    cachedBinaryPath = await discoverBinary();
  }
  return cachedBinaryPath;
}

/** Run the aikido binary with the given arguments */
export function runAikido(
  args: string[],
  options: { timeout?: number; cwd?: string } = {}
): Promise<ExecResult> {
  const { timeout = 120_000, cwd } = options;

  return getBinaryPath().then(
    (binaryPath) =>
      new Promise((resolve) => {
        execFile(
          binaryPath,
          args,
          { timeout, cwd, maxBuffer: 50 * 1024 * 1024 },
          (error, stdout, stderr) => {
            const exitCode =
              error && "code" in error && typeof error.code === "number"
                ? error.code
                : error
                  ? 1
                  : 0;
            resolve({ stdout, stderr, exitCode });
          }
        );
      })
  );
}

/** Validate the binary works by checking --version */
export async function validateBinary(): Promise<string> {
  const result = await runAikido(["--version"], { timeout: 10_000 });
  if (result.exitCode !== 0) {
    throw new Error(`Aikido binary validation failed: ${result.stderr}`);
  }
  return result.stdout.trim();
}
