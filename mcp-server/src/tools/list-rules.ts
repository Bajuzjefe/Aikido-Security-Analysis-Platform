import { runAikido } from "../binary.js";
import type { DetectorInfo, Severity, ReliabilityTier } from "../types.js";
import { SEVERITY_ORDER } from "../types.js";

/** Parse the output of `aikido --list-rules` */
function parseListRules(stdout: string): DetectorInfo[] {
  const detectors: DetectorInfo[] = [];
  const lines = stdout.split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    // Detector lines have format:
    //   detector-name                        [Severity  ] Category           Tier         CWE        Description
    // Next line has the doc URL
    const match = line.match(
      /^\s{2}(\S+)\s+\[(\w+)\s*\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/
    );
    if (match) {
      const [, name, severity, category, tier, cwe, description] = match;
      // Next line should have the doc URL
      let docUrl = "";
      if (i + 1 < lines.length) {
        const urlMatch = lines[i + 1].match(/\s+(https?:\/\/\S+)/);
        if (urlMatch) {
          docUrl = urlMatch[1];
          i++; // Skip the URL line
        }
      }

      detectors.push({
        name,
        severity: severity.toLowerCase() as Severity,
        category,
        tier: tier as ReliabilityTier,
        cwe: cwe === "-" ? null : cwe,
        description: description.trim(),
        doc_url: docUrl,
      });
    }
    i++;
  }

  return detectors;
}

export interface ListRulesOptions {
  severity?: Severity;
  category?: string;
}

export async function listRules(options: ListRulesOptions = {}): Promise<string> {
  const result = await runAikido(["--list-rules"]);

  if (result.exitCode !== 0) {
    throw new Error(`Failed to list rules: ${result.stderr}`);
  }

  let detectors = parseListRules(result.stdout);

  // Filter by minimum severity
  if (options.severity) {
    const minOrder = SEVERITY_ORDER[options.severity];
    detectors = detectors.filter(
      (d) => (SEVERITY_ORDER[d.severity] ?? 0) >= minOrder
    );
  }

  // Filter by category
  if (options.category) {
    const cat = options.category.toLowerCase();
    detectors = detectors.filter(
      (d) => d.category.toLowerCase().includes(cat)
    );
  }

  if (detectors.length === 0) {
    return "No detectors match the specified filters.";
  }

  const header = `# Aikido Detectors (${detectors.length})\n`;
  const table = detectors
    .map(
      (d) =>
        `- **${d.name}** [${d.severity.toUpperCase()}] — ${d.description}\n  Category: ${d.category} | Tier: ${d.tier}${d.cwe ? ` | ${d.cwe}` : ""}`
    )
    .join("\n");

  return header + table;
}
