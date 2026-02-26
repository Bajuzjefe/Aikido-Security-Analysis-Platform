import { runAikido } from "../binary.js";
import type { DetectorExplanation } from "../types.js";

/** Parse the output of `aikido --explain <detector>` */
function parseExplain(stdout: string): DetectorExplanation {
  const lines = stdout.split("\n");

  const name = lines[0]?.trim() ?? "";
  let severity = "";
  let category = "";
  let cwe: string | null = null;
  let docUrl = "";
  let descStart = -1;

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("Severity: ")) {
      severity = line.slice("Severity: ".length).trim();
    } else if (line.startsWith("Category: ")) {
      category = line.slice("Category: ".length).trim();
    } else if (line.startsWith("CWE: ")) {
      cwe = line.slice("CWE: ".length).trim();
    } else if (line.startsWith("Docs: ")) {
      docUrl = line.slice("Docs: ".length).trim();
    } else if (line === "" && descStart === -1) {
      descStart = i + 1;
    }
  }

  const longDescription =
    descStart >= 0 ? lines.slice(descStart).join("\n").trim() : "";

  return { name, severity, category, cwe, doc_url: docUrl, long_description: longDescription };
}

export async function explain(detector: string): Promise<string> {
  const result = await runAikido(["--explain", detector]);

  if (result.exitCode !== 0) {
    if (result.stderr.includes("unknown rule")) {
      return `Unknown detector "${detector}". Use aikido_list_rules to see all available detectors.`;
    }
    throw new Error(`Failed to explain detector: ${result.stderr}`);
  }

  const info = parseExplain(result.stdout);

  const lines = [
    `# ${info.name}`,
    `**Severity:** ${info.severity}`,
    `**Category:** ${info.category}`,
    ...(info.cwe ? [`**CWE:** ${info.cwe}`] : []),
    `**Docs:** ${info.doc_url}`,
    "",
    info.long_description,
  ];

  return lines.join("\n");
}
