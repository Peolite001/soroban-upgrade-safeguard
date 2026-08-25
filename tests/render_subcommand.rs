//! Integration tests for the `render` subcommand — the round trip that lets a
//! stored JSON report stand in for the original WASM files.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

/// Run a live comparison and return its stdout in the requested format.
fn live(format: &str) -> String {
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", format])
        .arg("--no-color")
        .arg("--no-timestamp")
        .output()
        .expect("failed to run binary");
    String::from_utf8(output.stdout).expect("stdout was not valid UTF-8")
}

/// Feed a saved report to `render` over stdin, returning (stdout, exit code).
fn render(report: &str, args: &[&str]) -> (String, i32) {
    let mut child = bin()
        .arg("render")
        .arg("-")
        .args(args)
        .arg("--no-color")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(report.as_bytes())
        .expect("failed to write report to stdin");

    let output = child.wait_with_output().expect("failed to wait for binary");
    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

/// The acceptance criterion: a saved report renders to what the live run would
/// have produced, without the original inputs.
#[test]
fn rendered_markdown_matches_a_live_run() {
    let report = live("json");
    let (rendered, code) = render(&report, &["--format", "markdown"]);

    assert_eq!(rendered, live("markdown"));
    assert_eq!(
        code, 1,
        "the stored verdict was a failure, so must the exit be"
    );
}

#[test]
fn rendered_text_matches_a_live_run() {
    let report = live("json");
    let (rendered, _) = render(&report, &["--format", "text"]);

    // The live text run prefixes decorative progress lines on stdout; the
    // report body itself is what must match.
    let live_text = live("text");
    let body_start = live_text
        .find("========================================")
        .expect("live text output should contain the report banner");

    assert!(
        rendered.contains(&live_text[body_start..]),
        "re-rendered text must reproduce the live report body"
    );
}

#[test]
fn text_is_the_default_format() {
    let report = live("json");
    let (explicit, _) = render(&report, &["--format", "text"]);
    let (default, _) = render(&report, &[]);
    assert_eq!(default, explicit);
}

#[test]
fn a_safe_report_round_trips_and_exits_zero() {
    // Comparing a build against itself yields a passing verdict, which the
    // re-render must preserve — verdict included.
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");
    assert_eq!(output.status.code(), Some(0));

    let report = String::from_utf8(output.stdout).unwrap();
    let (rendered, code) = render(&report, &["--format", "markdown"]);

    assert_eq!(code, 0, "a passing report must re-render with exit 0");
    assert!(rendered.contains("PASSED"));
}

#[test]
fn rendering_from_a_file_works() {
    let report = live("json");
    let dir = std::env::temp_dir().join("sus-render-test");
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    let path = dir.join("report.json");
    std::fs::write(&path, &report).expect("failed to write report");

    let output = bin()
        .arg("render")
        .arg(&path)
        .args(["--format", "markdown"])
        .arg("--no-color")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        live("markdown"),
        "reading from a file must match reading from stdin"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn the_report_carries_the_interface_hashes() {
    let report: serde_json::Value = serde_json::from_str(&live("json")).unwrap();

    let old = report["old_interface_hash"].as_str().expect("old hash");
    let new = report["new_interface_hash"].as_str().expect("new hash");
    assert_eq!(old.len(), 64);
    assert_ne!(old, new, "the fixtures have different interfaces");

    // And they surface in the rendered human output.
    let (markdown, _) = render(&live("json"), &["--format", "markdown"]);
    assert!(markdown.contains(old));
    assert!(markdown.contains(new));
}

// --- Error handling ----------------------------------------------------------

#[test]
fn a_malformed_report_fails_with_a_clear_error() {
    let (_, code) = render("{ this is not json", &[]);
    assert_ne!(code, 0);

    let mut child = bin()
        .arg("render")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{ this is not json")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a valid Soroban Upgrade Safeguard JSON report"),
        "error should explain what was expected, got: {stderr}"
    );
}

#[test]
fn an_incompatible_schema_version_fails_with_a_clear_error() {
    let mut report: serde_json::Value = serde_json::from_str(&live("json")).unwrap();
    report["report_schema_version"] = serde_json::json!(9999);
    report["tool_version"] = serde_json::json!("99.0.0");

    let mut child = bin()
        .arg("render")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(report.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("schema version 9999"),
        "error should name the unsupported version, got: {stderr}"
    );
    assert!(
        stderr.contains("99.0.0"),
        "error should name the writing tool version, got: {stderr}"
    );
}

#[test]
fn a_missing_report_file_fails_with_a_clear_error() {
    let output = bin()
        .arg("render")
        .arg("/nonexistent/report.json")
        .output()
        .expect("failed to run binary");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read report file"),
        "got: {stderr}"
    );
}
