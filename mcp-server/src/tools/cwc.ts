import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { CwcEntry, Severity } from "../types.js";
import { SEVERITY_ORDER } from "../types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

let registry: CwcEntry[] | null = null;

async function loadRegistry(): Promise<CwcEntry[]> {
  if (!registry) {
    const dataPath = join(__dirname, "..", "..", "data", "cwc-registry.json");
    const raw = await readFile(dataPath, "utf-8");
    registry = JSON.parse(raw) as CwcEntry[];
  }
  return registry;
}

export async function cwcLookup(query: string): Promise<string> {
  const entries = await loadRegistry();
  const q = query.toLowerCase().trim();

  // Match by CWC ID (exact or prefix)
  const byId = entries.filter((e) =>
    e.id.toLowerCase() === q || e.id.toLowerCase().startsWith(q)
  );
  if (byId.length > 0) return formatEntries(byId);

  // Match by severity
  const severities: Severity[] = ["info", "low", "medium", "high", "critical"];
  if (severities.includes(q as Severity)) {
    const bySeverity = entries.filter((e) => e.severity === q);
    return formatEntries(bySeverity);
  }

  // Match by detector name
  const byDetector = entries.filter((e) =>
    e.detectors.some((d) => d.includes(q))
  );
  if (byDetector.length > 0) return formatEntries(byDetector);

  // Match by name or description (fuzzy)
  const byText = entries.filter(
    (e) =>
      e.name.toLowerCase().includes(q) ||
      e.description.toLowerCase().includes(q)
  );
  if (byText.length > 0) return formatEntries(byText);

  return `No CWC entries found matching "${query}". Try a CWC ID (e.g., "CWC-001"), severity (e.g., "critical"), or detector name (e.g., "missing-signature-check").`;
}

function formatEntries(entries: CwcEntry[]): string {
  // Sort by severity (critical first)
  const sorted = [...entries].sort(
    (a, b) =>
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
  );

  return sorted
    .map((e) => formatEntry(e))
    .join("\n\n---\n\n");
}

function formatEntry(e: CwcEntry): string {
  const lines = [
    `## ${e.id}: ${e.name}`,
    `**Severity:** ${e.severity.toUpperCase()}`,
    `**Detectors:** ${e.detectors.join(", ")}`,
    `**References:** ${e.references.join(", ")}`,
    "",
    e.description,
    "",
    `**Remediation:** ${e.remediation}`,
  ];
  return lines.join("\n");
}
