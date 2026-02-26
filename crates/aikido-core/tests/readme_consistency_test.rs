use std::fs;
use std::path::PathBuf;

use aikido_core::all_detectors;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("aikido-core should be nested under crates/")
        .to_path_buf()
}

#[test]
fn readme_detector_count_matches_registry() {
    let readme_path = repo_root().join("README.md");
    let readme = fs::read_to_string(&readme_path)
        .expect("README.md should be readable from repository root");

    let marker = "Current detector count:";
    let count_line = readme
        .lines()
        .find(|line| line.contains(marker))
        .expect("README.md must include `Current detector count: <N>`");

    let documented = count_line
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse::<usize>()
        .expect("detector count marker should contain a numeric value");

    let actual = all_detectors().len();
    assert_eq!(
        documented, actual,
        "README detector count is stale (documented {}, actual {})",
        documented, actual
    );
}
