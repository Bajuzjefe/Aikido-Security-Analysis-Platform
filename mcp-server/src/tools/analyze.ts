import { runAikido } from "../binary.js";
import type { AnalysisOutput, Finding, Severity } from "../types.js";
import { SEVERITY_ORDER } from "../types.js";

export interface AnalyzeOptions {
  project_path: string;
  min_severity?: Severity;
  static_only?: boolean;
  diff?: string;
  config?: string;
}

export async function analyze(options: AnalyzeOptions): Promise<string> {
  const args = [
    options.project_path,
    "--format", "json",
    "--quiet",
  ];

  if (options.min_severity) {
    args.push("--min-severity", options.min_severity);
  }

  if (options.static_only) {
    args.push("--static-only");
  }

  if (options.diff) {
    args.push("--diff", options.diff);
  }

  if (options.config) {
    args.push("--config", options.config);
  }

  const result = await runAikido(args);

  // Exit code 0 = no findings above threshold, 2 = findings above threshold (both valid)
  // Exit code 1 = error (compilation failure, bad args)
  if (result.exitCode === 1) {
    const errorMsg = result.stderr.trim() || result.stdout.trim();
    throw new Error(`Analysis failed: ${errorMsg}`);
  }

  let output: AnalysisOutput;
  try {
    output = JSON.parse(result.stdout) as AnalysisOutput;
  } catch {
    throw new Error(
      `Failed to parse analysis output. stderr: ${result.stderr}`
    );
  }

  return formatAnalysis(output);
}

function formatAnalysis(output: AnalysisOutput): string {
  const { findings, project, version, total } = output;

  // Count by severity
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  const lines: string[] = [
    `# Security Analysis: ${project} v${version}`,
    "",
    `**Total findings:** ${total}`,
    `| Critical | High | Medium | Low | Info |`,
    `|----------|------|--------|-----|------|`,
    `| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |`,
    "",
  ];

  if (findings.length === 0) {
    lines.push("No security findings detected. The project passed all checks.");
    return lines.join("\n");
  }

  // Sort findings by severity (critical first)
  const sorted = [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
  );

  // Group by severity
  let currentSeverity: Severity | null = null;
  for (const f of sorted) {
    if (f.severity !== currentSeverity) {
      currentSeverity = f.severity;
      lines.push(`## ${currentSeverity.toUpperCase()} Findings\n`);
    }
    lines.push(formatFinding(f));
  }

  // Add raw JSON as a details block for programmatic use
  lines.push("");
  lines.push("<details><summary>Raw JSON</summary>\n");
  lines.push("```json");
  lines.push(JSON.stringify(output, null, 2));
  lines.push("```");
  lines.push("</details>");

  return lines.join("\n");
}

function formatFinding(f: Finding): string {
  const loc = f.location
    ? `${f.location.path}${f.location.line_start ? `:${f.location.line_start}` : ""}`
    : "unknown location";

  const parts = [
    `### ${f.title}`,
    `- **Detector:** ${f.detector} (${f.reliability_tier})`,
    `- **Severity:** ${f.severity.toUpperCase()} | **Confidence:** ${f.confidence}`,
    `- **Location:** \`${loc}\``,
    `- **Module:** ${f.module}`,
  ];

  if (f.cwc) {
    parts.push(`- **CWC:** ${f.cwc.id} — ${f.cwc.name}`);
  }

  parts.push("", f.description);

  if (f.suggestion) {
    parts.push("", `**Suggestion:** ${f.suggestion}`);
  }

  if (f.evidence) {
    parts.push(
      "",
      `**Evidence:** ${f.evidence.level} via ${f.evidence.method}${f.evidence.details ? ` — ${f.evidence.details}` : ""}`
    );
  }

  parts.push("");
  return parts.join("\n");
}
