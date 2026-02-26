#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { validateBinary } from "./binary.js";
import { analyze } from "./tools/analyze.js";
import { listRules } from "./tools/list-rules.js";
import { explain } from "./tools/explain.js";
import { cwcLookup } from "./tools/cwc.js";
import type { Severity } from "./types.js";

const server = new McpServer({
  name: "aikido",
  version: "0.1.0",
});

// --- aikido_analyze ---
server.tool(
  "aikido_analyze",
  "Scan an Aiken smart contract project for security vulnerabilities. Returns findings with severity, location, CWC classification, and evidence. Exit code 2 (findings above threshold) is normal, not an error.",
  {
    project_path: z.string().describe("Path to the Aiken project directory (must contain aiken.toml)"),
    min_severity: z
      .enum(["info", "low", "medium", "high", "critical"])
      .default("info")
      .describe("Minimum severity threshold to report"),
    static_only: z
      .boolean()
      .default(false)
      .describe("Skip multi-lane orchestration (faster but less thorough)"),
    diff: z
      .string()
      .optional()
      .describe("Git ref for incremental analysis — only report findings in changed files"),
    config: z
      .string()
      .optional()
      .describe("Path to custom .aikido.toml config file"),
  },
  async ({ project_path, min_severity, static_only, diff, config }) => {
    try {
      const result = await analyze({
        project_path,
        min_severity: min_severity as Severity,
        static_only,
        diff,
        config,
      });
      return { content: [{ type: "text", text: result }] };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${(error as Error).message}` }],
        isError: true,
      };
    }
  }
);

// --- aikido_list_rules ---
server.tool(
  "aikido_list_rules",
  "List all 75 Aikido security detectors with severity, category, CWE mapping, and reliability tier.",
  {
    severity: z
      .enum(["info", "low", "medium", "high", "critical"])
      .optional()
      .describe("Filter by minimum severity level"),
    category: z
      .string()
      .optional()
      .describe("Filter by category (e.g., 'authorization', 'arithmetic', 'minting')"),
  },
  async ({ severity, category }) => {
    try {
      const result = await listRules({
        severity: severity as Severity | undefined,
        category,
      });
      return { content: [{ type: "text", text: result }] };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${(error as Error).message}` }],
        isError: true,
      };
    }
  }
);

// --- aikido_explain ---
server.tool(
  "aikido_explain",
  "Get a detailed explanation of a specific Aikido security detector, including what it checks, why it matters, and remediation guidance.",
  {
    detector: z.string().describe("Detector name (e.g., 'missing-signature-check', 'value-not-preserved')"),
  },
  async ({ detector }) => {
    try {
      const result = await explain(detector);
      return { content: [{ type: "text", text: result }] };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${(error as Error).message}` }],
        isError: true,
      };
    }
  }
);

// --- aikido_cwc_lookup ---
server.tool(
  "aikido_cwc_lookup",
  "Search the Cardano Weakness Classification (CWC) registry. Look up by CWC ID, severity, detector name, or keyword. Returns vulnerability descriptions, affected detectors, and remediation guidance.",
  {
    query: z.string().describe("CWC ID (e.g., 'CWC-001'), severity (e.g., 'critical'), detector name, or keyword"),
  },
  async ({ query }) => {
    try {
      const result = await cwcLookup(query);
      return { content: [{ type: "text", text: result }] };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${(error as Error).message}` }],
        isError: true,
      };
    }
  }
);

// --- Start server ---
async function main() {
  // Validate binary availability (non-fatal for cwc_lookup which doesn't need it)
  try {
    const version = await validateBinary();
    process.stderr.write(`aikido-mcp: binary found (${version})\n`);
  } catch {
    process.stderr.write(
      "aikido-mcp: WARNING — aikido binary not found. aikido_analyze, aikido_list_rules, and aikido_explain will fail.\n" +
      "Install: npm install -g aikido-aiken\n"
    );
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  process.stderr.write(`aikido-mcp: fatal error: ${error}\n`);
  process.exit(1);
});
