use std::path::PathBuf;

use aiken_lang::ast::Tracing;
use aiken_project::telemetry::{Event, EventListener};
use aiken_project::Project;

use crate::ast_walker::ModuleInfo;

#[derive(Debug, thiserror::Error)]
pub enum AikidoError {
    #[error("Project path does not exist: {0}")]
    PathNotFound(PathBuf),

    #[error("No aiken.toml found at: {0}")]
    NoAikenToml(PathBuf),

    #[error("Failed to load project: {0}")]
    LoadError(String),

    #[error("Compilation failed: {0}")]
    CompileError(String),

    #[error("Unsupported stdlib version: {0}")]
    UnsupportedStdlib(String),
}

struct SilentListener;

impl EventListener for SilentListener {
    fn handle_event(&self, _event: Event) {}
}

pub struct ProjectConfig {
    pub name: String,
    pub version: String,
}

#[derive(Debug)]
pub struct AikenProject {
    root: PathBuf,
}

impl AikenProject {
    pub fn new(root: PathBuf) -> Result<Self, AikidoError> {
        if !root.exists() {
            return Err(AikidoError::PathNotFound(root));
        }

        let toml_path = root.join("aiken.toml");
        if !toml_path.exists() {
            return Err(AikidoError::NoAikenToml(root));
        }

        Ok(Self { root })
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    /// Check if the project's stdlib version is compatible.
    /// Aikido pins aiken-project v1.1.21 which requires stdlib v2.0.0+.
    /// In strict mode, returns an error for v1.x. Otherwise, prints a warning
    /// and attempts compilation anyway.
    fn check_stdlib_version(&self, strict: bool) -> Result<(), AikidoError> {
        let toml_path = self.root.join("aiken.toml");
        let content = std::fs::read_to_string(&toml_path)
            .map_err(|e| AikidoError::LoadError(format!("Failed to read aiken.toml: {e}")))?;

        let table: toml::Table = content
            .parse()
            .map_err(|e| AikidoError::LoadError(format!("Failed to parse aiken.toml: {e}")))?;

        // Look for stdlib in [[dependencies]]
        if let Some(deps) = table.get("dependencies").and_then(|d| d.as_array()) {
            for dep in deps {
                let name = dep.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let source = dep.get("source").and_then(|s| s.as_str()).unwrap_or("");
                // Match stdlib by name or source URL
                if name == "stdlib"
                    || name == "aiken-lang/stdlib"
                    || source.contains("aiken-lang/stdlib")
                {
                    if let Some(version) = dep.get("version").and_then(|v| v.as_str()) {
                        // Handle non-semver version strings (e.g., "main", "develop")
                        let trimmed = version.trim_start_matches('v');
                        let major: Option<u32> =
                            trimmed.split('.').next().and_then(|s| s.parse().ok());

                        if major.is_none() {
                            // Non-semver version (e.g. "main" branch ref) — warn and try
                            eprintln!(
                                "\x1b[33mwarning\x1b[0m: stdlib version '{version}' is not semver. \
                                 Attempting compilation anyway."
                            );
                            return Ok(());
                        }

                        if major.unwrap_or(0) < 2 {
                            if strict {
                                return Err(AikidoError::UnsupportedStdlib(format!(
                                    "This project uses Aiken stdlib v{version}. \
                                     Aikido requires stdlib v2.0.0 or later (Aiken compiler v1.1.0+). \
                                     Please upgrade the project's stdlib dependency or use a compatible Aiken version."
                                )));
                            }
                            eprintln!(
                                "\x1b[33mwarning\x1b[0m: This project uses Aiken stdlib v{version}. \
                                 Aikido is built for stdlib v2.0.0+. Compilation may fail."
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn compile(&self) -> Result<Vec<ModuleInfo>, AikidoError> {
        self.compile_with_options(false)
    }

    pub fn compile_with_options(
        &self,
        strict_stdlib: bool,
    ) -> Result<Vec<ModuleInfo>, AikidoError> {
        // Check stdlib version compatibility before attempting compilation
        self.check_stdlib_version(strict_stdlib)?;

        let mut project = Project::new(self.root.clone(), SilentListener)
            .map_err(|e| AikidoError::LoadError(format!("{e}")))?;

        let blueprint_path = self.root.join("plutus.json");
        project
            .build(false, Tracing::silent(), blueprint_path, None)
            .map_err(|errs| {
                let msgs: Vec<String> = errs.into_iter().map(|e| format!("{e}")).collect();
                let raw = msgs.join("\n");

                // Provide helpful context for common failure modes
                let hint = if raw.contains("While parsing") || raw.contains("ParseError") {
                    "\n\nHint: This may indicate an incompatible Aiken stdlib version. \
                     Aikido requires stdlib v2.0.0+ (Aiken compiler v1.1.0+). \
                     Check the [[dependencies]] section in aiken.toml."
                } else if raw.contains("missing") && raw.contains("package") {
                    "\n\nHint: Missing dependency. Run `aiken packages` in the project directory first."
                } else if raw.contains("SyntaxError") || raw.contains("UnexpectedToken") {
                    "\n\nHint: Syntax error in source file. Run `aiken check` directly to see detailed error location."
                } else {
                    ""
                };

                AikidoError::CompileError(format!("{raw}{hint}"))
            })?;

        let modules = project.modules();
        let mut infos: Vec<ModuleInfo> = modules
            .iter()
            .map(crate::ast_walker::extract_module_info)
            .collect();

        // Cross-module interprocedural analysis: resolve qualified function calls
        // (e.g. `utils.get_upper_bound`) across module boundaries.
        crate::ast_walker::merge_cross_module_signals(&mut infos);

        // Sort modules by name for deterministic output regardless of HashMap iteration order
        infos.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(infos)
    }

    pub fn config(&self) -> Result<ProjectConfig, AikidoError> {
        let toml_path = self.root.join("aiken.toml");
        let content = std::fs::read_to_string(&toml_path)
            .map_err(|e| AikidoError::LoadError(format!("Failed to read aiken.toml: {e}")))?;

        let table: toml::Table = content
            .parse()
            .map_err(|e| AikidoError::LoadError(format!("Failed to parse aiken.toml: {e}")))?;

        let name = table
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let version = table
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0")
            .to_string();

        Ok(ProjectConfig { name, version })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_not_found() {
        let result = AikenProject::new(PathBuf::from("/nonexistent/path"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AikidoError::PathNotFound(_)));
    }

    #[test]
    fn test_no_aiken_toml() {
        let dir = tempfile::tempdir().unwrap();
        let result = AikenProject::new(dir.path().to_path_buf());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AikidoError::NoAikenToml(_)));
    }

    #[test]
    fn test_check_stdlib_v1_strict_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("aiken.toml"),
            r#"
name = "test/project"
version = "0.0.1"

[[dependencies]]
name = "aiken-lang/stdlib"
version = "1.5.0"
source = "github"
"#,
        )
        .unwrap();
        let project = AikenProject::new(dir.path().to_path_buf()).unwrap();
        // Strict mode: v1.x should error
        let result = project.check_stdlib_version(true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AikidoError::UnsupportedStdlib(_)));
        assert!(err.to_string().contains("v1.5.0"));
        assert!(err.to_string().contains("v2.0.0 or later"));
    }

    #[test]
    fn test_check_stdlib_v1_lenient_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("aiken.toml"),
            r#"
name = "test/project"
version = "0.0.1"

[[dependencies]]
name = "aiken-lang/stdlib"
version = "1.5.0"
source = "github"
"#,
        )
        .unwrap();
        let project = AikenProject::new(dir.path().to_path_buf()).unwrap();
        // Non-strict mode: v1.x should warn but succeed
        assert!(project.check_stdlib_version(false).is_ok());
    }

    #[test]
    fn test_check_stdlib_v2_accepted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("aiken.toml"),
            r#"
name = "test/project"
version = "0.0.1"

[[dependencies]]
name = "aiken-lang/stdlib"
version = "2.2.0"
source = "github"
"#,
        )
        .unwrap();
        let project = AikenProject::new(dir.path().to_path_buf()).unwrap();
        assert!(project.check_stdlib_version(false).is_ok());
    }

    #[test]
    fn test_check_stdlib_v3_accepted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("aiken.toml"),
            r#"
name = "test/project"
version = "0.0.1"

[[dependencies]]
name = "aiken-lang/stdlib"
version = "v3.0.0"
source = "github"
"#,
        )
        .unwrap();
        let project = AikenProject::new(dir.path().to_path_buf()).unwrap();
        assert!(project.check_stdlib_version(false).is_ok());
    }

    #[test]
    fn test_check_stdlib_no_deps_accepted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("aiken.toml"),
            r#"
name = "test/project"
version = "0.0.1"
"#,
        )
        .unwrap();
        let project = AikenProject::new(dir.path().to_path_buf()).unwrap();
        assert!(project.check_stdlib_version(false).is_ok());
    }

    #[test]
    fn test_check_stdlib_name_variants() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("aiken.toml"),
            r#"
name = "test/project"
version = "0.0.1"

[[dependencies]]
name = "stdlib"
version = "1.7.0"
source = "github"
"#,
        )
        .unwrap();
        let project = AikenProject::new(dir.path().to_path_buf()).unwrap();
        // Strict mode: should reject
        assert!(project.check_stdlib_version(true).is_err());
        // Lenient mode: should warn but accept
        assert!(project.check_stdlib_version(false).is_ok());
    }

    #[test]
    fn test_check_stdlib_non_semver_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("aiken.toml"),
            r#"
name = "test/project"
version = "0.0.1"

[[dependencies]]
name = "aiken-lang/stdlib"
version = "main"
source = "github"
"#,
        )
        .unwrap();
        let project = AikenProject::new(dir.path().to_path_buf()).unwrap();
        // Non-semver "main" branch ref should warn but not error
        assert!(project.check_stdlib_version(false).is_ok());
        assert!(project.check_stdlib_version(true).is_ok());
    }
}
