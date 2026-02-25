// Feature #84: VS Code extension — show aikido findings inline
import * as vscode from "vscode";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const diagnosticCollection =
  vscode.languages.createDiagnosticCollection("aikido");

interface AikidoFinding {
  detector: string;
  severity: string;
  title: string;
  description: string;
  module: string;
  location?: {
    path: string;
    line_start?: number;
    column_start?: number;
    line_end?: number;
    column_end?: number;
  };
  suggestion?: string;
}

export function activate(context: vscode.ExtensionContext) {
  const analyzeCmd = vscode.commands.registerCommand("aikido.analyze", () =>
    runAnalysis()
  );
  const clearCmd = vscode.commands.registerCommand(
    "aikido.clearDiagnostics",
    () => diagnosticCollection.clear()
  );

  context.subscriptions.push(analyzeCmd, clearCmd, diagnosticCollection);

  // Auto-analyze on save if enabled
  const config = vscode.workspace.getConfiguration("aikido");
  if (config.get("autoAnalyze", true)) {
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.fileName.endsWith(".ak")) {
        runAnalysis();
      }
    });
  }
}

async function runAnalysis() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) return;

  const config = vscode.workspace.getConfiguration("aikido");
  const aikidoPath = config.get<string>("path", "aikido");
  const minSeverity = config.get<string>("minSeverity", "info");

  try {
    const { stdout } = await execFileAsync(aikidoPath, [
      workspaceFolder.uri.fsPath,
      "--format",
      "json",
      "--min-severity",
      minSeverity,
      "--quiet",
    ]);

    const result = JSON.parse(stdout);
    const findings: AikidoFinding[] = result.findings || [];

    diagnosticCollection.clear();
    const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
      if (!finding.location) continue;

      const filePath = vscode.Uri.joinPath(
        workspaceFolder.uri,
        finding.location.path
      ).fsPath;
      const range = new vscode.Range(
        (finding.location.line_start || 1) - 1,
        (finding.location.column_start || 1) - 1,
        (finding.location.line_end || finding.location.line_start || 1) - 1,
        (finding.location.column_end || 80) - 1
      );

      const severity = mapSeverity(finding.severity);
      const diagnostic = new vscode.Diagnostic(
        range,
        `[${finding.detector}] ${finding.description}`,
        severity
      );
      diagnostic.source = "aikido";
      diagnostic.code = finding.detector;

      const existing = diagnosticMap.get(filePath) || [];
      existing.push(diagnostic);
      diagnosticMap.set(filePath, existing);
    }

    for (const [filePath, diagnostics] of diagnosticMap) {
      diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);
    }

    vscode.window.showInformationMessage(
      `Aikido: Found ${findings.length} issue(s)`
    );
  } catch (error: any) {
    vscode.window.showErrorMessage(`Aikido analysis failed: ${error.message}`);
  }
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

export function deactivate() {
  diagnosticCollection.dispose();
}
