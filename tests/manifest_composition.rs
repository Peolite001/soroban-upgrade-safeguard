//! Integration tests for composable batch manifests: `include`, `[defaults]`,
//! and per-pair overrides.
//!
//! These drive the compiled binary rather than the library, because the whole
//! point of the feature is what a CI invocation sees: the exit code, the
//! provenance in the batch JSON, and the quality of the error when a manifest is
//! wrong. Unit-level precedence coverage lives in `src/manifest.rs`.
//!
//! The checked-in fixtures give three verdicts to compose with:
//!
//! - `v1 -> v1` safe
//! - `v1 -> v2` breaking (3 criticals)
//! - `v1 -> v3` warning-only: passes normally, fails under `--strict`

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// A fresh directory for one test. Includes require real directory trees, so
/// each test gets its own root, isolated by process id.
fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

/// Write `contents` to `dir/name`, creating parent directories as needed.
fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent dir");
    }
    std::fs::write(&path, contents).expect("failed to write file");
    path
}

/// Copy the fixture WASMs into `dir` so manifests can reference them by bare
/// file name and exercise `base_dir` / relative-path anchoring.
fn stage_wasm(dir: &Path) {
    std::fs::create_dir_all(dir).expect("failed to create wasm dir");
    for name in ["v1.wasm", "v2.wasm", "v3.wasm"] {
        std::fs::copy(wasm(name), dir.join(name)).expect("failed to copy fixture wasm");
    }
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout was not valid JSON ({e}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

/// Run the binary with `args`, from `cwd` when given.
fn run_in(cwd: Option<&Path>, args: &[&str]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let output = command.output().expect("failed to run binary");
    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code().expect("process terminated by signal"),
    }
}

/// Run a manifest in JSON mode, deterministically.
fn run_manifest(manifest: &Path, extra: &[&str]) -> Run {
    let mut args = vec![
        "--manifest",
        manifest.to_str().unwrap(),
        "--format",
        "json",
        "--no-timestamp",
    ];
    args.extend_from_slice(extra);
    run_in(None, &args)
}

/// The `{value, origin}` pair for one setting of one named pair.
fn setting<'a>(json: &'a Value, pair_name: &str, path: &[&str]) -> &'a Value {
    let pair = json["manifest"]["pairs"]
        .as_array()
        .expect("manifest.pairs must be an array")
        .iter()
        .find(|p| p["name"] == pair_name)
        .unwrap_or_else(|| panic!("no pair named '{pair_name}' in manifest provenance"));
    let mut node = &pair["settings"];
    for key in path {
        node = &node[*key];
    }
    node
}

fn origin_of(json: &Value, pair_name: &str, path: &[&str]) -> String {
    setting(json, pair_name, path)["origin"]
        .as_str()
        .expect("origin must be a string")
        .to_string()
}

fn result<'a>(json: &'a Value, pair_name: &str) -> &'a Value {
    json["results"]
        .as_array()
        .expect("results must be an ordered array")
        .iter()
        .find(|entry| entry["name"] == pair_name)
        .and_then(|entry| entry.get("report"))
        .unwrap_or_else(|| panic!("no result named '{pair_name}'"))
}

// ── Composition ──────────────────────────────────────────────────────────────

#[test]
fn nested_includes_compose_depth_first() {
    let dir = temp_dir("mc-nested");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "b.toml",
        &format!(
            r#"
            [defaults]
            base_dir = {:?}

            [[pairs]]
            old  = "v1.wasm"
            new  = "v1.wasm"
            name = "b"
            "#,
            dir.join("wasm").to_str().unwrap()
        ),
    );
    write(
        &dir,
        "a.toml",
        &format!(
            r#"
            include = ["b.toml"]

            [defaults]
            base_dir = {:?}

            [[pairs]]
            old  = "v1.wasm"
            new  = "v1.wasm"
            name = "a"
            "#,
            dir.join("wasm").to_str().unwrap()
        ),
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["a.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "root"
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0, "all pairs are safe\nstderr:\n{}", run.stderr);

    let json = run.json();
    assert_eq!(json["total_pairs"], 3);

    // Composed order is depth-first: a file's includes before its own pairs.
    let names: Vec<&str> = json["manifest"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["b", "a", "root"]);

    // Every contributing file is listed, in first-visit order.
    let sources: Vec<String> = json["manifest"]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            Path::new(s.as_str().unwrap())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    assert_eq!(sources, vec!["b.toml", "a.toml", "root.toml"]);

    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["name"], "b");
    assert_eq!(results[1]["name"], "a");
    assert_eq!(results[2]["name"], "root");
}

#[test]
fn pair_beats_root_defaults_beats_included_defaults() {
    let dir = temp_dir("mc-override");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "common/policy.toml",
        r#"
        [defaults.policy]
        gate_event_indexer = true
        gate_source_level  = true
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["common/policy.toml"]

        [defaults]
        base_dir = "wasm"

        [defaults.policy]
        gate_source_level = false

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "inherits"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "overrides"

        [pairs.policy]
        gate_event_indexer = false
        "#,
    );

    let json = run_manifest(&root, &[]).json();

    // Included fragment wins where nothing later speaks.
    assert_eq!(
        setting(&json, "inherits", &["policy", "gate_event_indexer"])["value"],
        true
    );
    assert!(
        origin_of(&json, "inherits", &["policy", "gate_event_indexer"]).ends_with("policy.toml")
    );

    // Root [defaults] beats the included fragment.
    assert_eq!(
        setting(&json, "inherits", &["policy", "gate_source_level"])["value"],
        false
    );
    assert!(origin_of(&json, "inherits", &["policy", "gate_source_level"]).ends_with("root.toml"));

    // A pair field beats root [defaults].
    assert_eq!(
        setting(&json, "overrides", &["policy", "gate_event_indexer"])["value"],
        false
    );
    assert!(
        origin_of(&json, "overrides", &["policy", "gate_event_indexer"]).ends_with("root.toml")
    );

    // Untouched settings report the built-in default honestly.
    assert_eq!(
        origin_of(&json, "inherits", &["policy", "gate_storage_layout"]),
        "built-in"
    );
}

// ── Escalation vs valued ─────────────────────────────────────────────────────

#[test]
fn strict_escalates_per_pair_and_cli_strict_cannot_be_disabled() {
    let dir = temp_dir("mc-escalation");
    stage_wasm(&dir.join("wasm"));

    // `v1 -> v3` is warning-only: it passes normally and fails under --strict,
    // so `strict` is observable in the exit code rather than only in provenance.
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"
        strict   = false

        [[pairs]]
        old  = "v1.wasm"
        new  = "v3.wasm"
        name = "lenient"
        "#,
    );
    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0, "warning-only pair passes without strict");

    // A pair may escalate on its own.
    let strict_pair = write(
        &dir,
        "strict_pair.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v3.wasm"
        name   = "picky"
        strict = true
        "#,
    );
    let run = run_manifest(&strict_pair, &[]);
    assert_eq!(
        run.code, 1,
        "a pair-level strict must fail the warning-only pair"
    );
    assert!(origin_of(&run.json(), "picky", &["strict"]).ends_with("strict_pair.toml"));

    // --strict is an escalation: `strict = false` in the manifest cannot weaken it.
    let run = run_manifest(&root, &["--strict"]);
    assert_eq!(
        run.code, 1,
        "manifest strict=false must not be able to disable --strict"
    );
    assert_eq!(origin_of(&run.json(), "lenient", &["strict"]), "cli");
    assert_eq!(setting(&run.json(), "lenient", &["strict"])["value"], true);
}

#[test]
fn a_gate_can_be_turned_off_because_gates_are_valued_not_escalation() {
    let dir = temp_dir("mc-gate-off");
    stage_wasm(&dir.join("wasm"));

    // `v1 -> v2` breaks the call ABI. Ungating that axis is the whole point of
    // `[policy]`, so unlike `strict` it must be able to move in both directions.
    let gated = write(
        &dir,
        "gated.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"
        "#,
    );
    assert_eq!(
        run_manifest(&gated, &[]).code,
        1,
        "call-ABI break fails by default"
    );

    let ungated = write(
        &dir,
        "ungated.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"

        [pairs.policy]
        gate_call_abi       = false
        gate_storage_layout = false
        "#,
    );
    let run = run_manifest(&ungated, &[]);
    assert_eq!(run.code, 0, "ungating the failing axes must pass the run");

    let json = run.json();
    assert_eq!(
        setting(&json, "token", &["policy", "gate_call_abi"])["value"],
        false
    );
    // The findings are still reported — ungating changes the verdict, not visibility.
    assert_eq!(result(&json, "token")["counts"]["critical"], 3);
}

#[test]
fn per_pair_config_applies_only_to_its_own_pair() {
    let dir = temp_dir("mc-per-pair-config");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "token.safeguard.toml",
        r#"
        [[suppress]]
        category = "Event Enum Case Value Changed"
        target   = "StatusEvent.Paused"
        reason   = "Reviewed: indexers already updated."

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        reason   = "Planned re-init for the v2 migration."

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Reviewed."
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old    = "v1.wasm"
        new    = "v2.wasm"
        name   = "suppressed"
        config = "token.safeguard.toml"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "unsuppressed"
        "#,
    );

    let run = run_manifest(&root, &[]);
    let json = run.json();

    // The config applies to the pair that named it. Suppressed findings stay
    // counted and visible — suppression flips the verdict, not the tally.
    assert_eq!(result(&json, "suppressed")["counts"]["critical"], 3);
    assert_eq!(result(&json, "suppressed")["suppressed_count"], 3);
    assert_eq!(result(&json, "suppressed")["is_safe"], true);

    // ...and not to its sibling, which sees the same three findings unsuppressed.
    assert_eq!(result(&json, "unsuppressed")["counts"]["critical"], 3);
    assert_eq!(result(&json, "unsuppressed")["suppressed_count"], 0);
    assert_eq!(result(&json, "unsuppressed")["is_safe"], false);

    // One pair still failing keeps the batch verdict failing.
    assert_eq!(run.code, 1);
    assert_eq!(json["is_safe"], false);

    assert!(origin_of(&json, "suppressed", &["config"]).ends_with("root.toml"));
    assert_eq!(origin_of(&json, "unsuppressed", &["config"]), "built-in");
}

// ── Path resolution ──────────────────────────────────────────────────────────

#[test]
fn relative_paths_anchor_on_the_defining_file_not_the_cwd() {
    let dir = temp_dir("mc-paths");
    stage_wasm(&dir.join("wasm"));

    // The fragment sits one level down and reaches back up with `../wasm`.
    write(
        &dir,
        "fragments/pool.toml",
        r#"
        [defaults]
        base_dir = "../wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "pool"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["fragments/pool.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "root"
        "#,
    );

    // Run from a directory that is *not* the manifest's, so a CWD-relative
    // implementation would fail to find any fixture.
    let elsewhere = temp_dir("mc-paths-cwd");
    let run = run_in(
        Some(&elsewhere),
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--format",
            "json",
            "--no-timestamp",
        ],
    );
    assert_eq!(
        run.code, 0,
        "manifest must resolve relative to its own file\nstderr:\n{}",
        run.stderr
    );

    let json = run.json();
    let pairs = json["manifest"]["pairs"].as_array().unwrap();
    for pair in pairs {
        let old = pair["old"].as_str().unwrap();
        assert!(
            Path::new(old).is_absolute() && Path::new(old).exists(),
            "resolved path must exist: {old}"
        );
    }
}

#[test]
fn root_base_dir_does_not_reach_into_an_included_fragment() {
    let dir = temp_dir("mc-base-scope");
    stage_wasm(&dir.join("pool_artifacts"));
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "fragments/pool.toml",
        r#"
        [defaults]
        base_dir = "../pool_artifacts"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "pool"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["fragments/pool.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "root"
        "#,
    );

    let json = run_manifest(&root, &[]).json();
    let pairs = json["manifest"]["pairs"].as_array().unwrap();
    let pool = pairs.iter().find(|p| p["name"] == "pool").unwrap();
    let root_pair = pairs.iter().find(|p| p["name"] == "root").unwrap();

    // `base_dir` is file-scoped: the fragment keeps its own anchoring so it stays
    // relocatable, and the root's `base_dir` governs only the root's own pairs.
    assert!(
        pool["old"].as_str().unwrap().contains("pool_artifacts"),
        "fragment lost its own base_dir: {}",
        pool["old"]
    );
    assert!(
        root_pair["old"].as_str().unwrap().contains("wasm"),
        "root pair lost the root base_dir: {}",
        root_pair["old"]
    );
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[test]
fn duplicate_pair_names_fail_before_anything_runs() {
    let dir = temp_dir("mc-duplicate");
    stage_wasm(&dir.join("wasm"));
    let reports = dir.join("reports");

    write(
        &dir,
        "frag.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["frag.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"
        "#,
    );

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("Duplicate contract name 'token'"),
        "error must name the collision: {combined}"
    );
    // Both sides of the collision are named, so the fix is obvious.
    assert!(
        combined.contains("frag.toml"),
        "missing first file: {combined}"
    );
    assert!(
        combined.contains("root.toml"),
        "missing second file: {combined}"
    );

    // Detection runs ahead of execution, so no partial reports hit disk.
    let wrote_reports = reports
        .read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    assert!(
        !wrote_reports,
        "no reports may be written before the run aborts"
    );
}

#[test]
fn include_cycle_reports_the_chain_and_writes_nothing() {
    let dir = temp_dir("mc-cycle");
    let reports = dir.join("reports");

    write(&dir, "b.toml", r#"include = ["a.toml"]"#);
    write(&dir, "a.toml", r#"include = ["b.toml"]"#);
    let root = write(&dir, "root.toml", r#"include = ["a.toml"]"#);

    let run = run_in(
        None,
        &[
            "--manifest",
            root.to_str().unwrap(),
            "--per-contract-output-dir",
            reports.to_str().unwrap(),
        ],
    );
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("include cycle"),
        "must identify the cycle: {combined}"
    );
    assert!(combined.contains('→'), "must print the chain: {combined}");
    assert!(combined.contains("a.toml") && combined.contains("b.toml"));
    assert!(
        !reports.exists(),
        "no output may be written for an unresolvable manifest"
    );
}

#[test]
fn include_depth_cap_is_enforced_at_nine_and_allows_eight() {
    let dir = temp_dir("mc-depth");
    stage_wasm(&dir.join("wasm"));

    // `level0` is the root, so a chain ending at `level{n}` has depth n.
    let build_chain = |prefix: &str, deepest: usize| {
        for level in 0..=deepest {
            let contents = if level == deepest {
                format!(
                    r#"
                    [defaults]
                    base_dir = {:?}

                    [[pairs]]
                    old  = "v1.wasm"
                    new  = "v1.wasm"
                    name = "deep"
                    "#,
                    dir.join("wasm").to_str().unwrap()
                )
            } else {
                format!("include = [\"{prefix}{}.toml\"]", level + 1)
            };
            write(&dir, &format!("{prefix}{level}.toml"), &contents);
        }
        dir.join(format!("{prefix}0.toml"))
    };

    let ok_root = build_chain("ok", 8);
    let run = run_manifest(&ok_root, &[]);
    assert_eq!(
        run.code, 0,
        "a chain exactly at the cap must resolve\nstderr:\n{}",
        run.stderr
    );

    let deep_root = build_chain("deep", 9);
    let run = run_in(None, &["--manifest", deep_root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("maximum depth"),
        "must explain the cap: {combined}"
    );
}

#[test]
fn unknown_fields_are_rejected_wherever_they_appear() {
    let dir = temp_dir("mc-unknown");
    stage_wasm(&dir.join("wasm"));

    let cases = [
        // Top level.
        (
            "root_typo.toml",
            r#"
            includes = ["other.toml"]

            [[pairs]]
            old = "wasm/v1.wasm"
            new = "wasm/v1.wasm"
            "#,
            "includes",
        ),
        // Inside [defaults].
        (
            "defaults_typo.toml",
            r#"
            [defaults]
            strictt = true

            [[pairs]]
            old = "wasm/v1.wasm"
            new = "wasm/v1.wasm"
            "#,
            "strictt",
        ),
        // On a pair.
        (
            "pair_typo.toml",
            r#"
            [[pairs]]
            old     = "wasm/v1.wasm"
            new     = "wasm/v1.wasm"
            explainn = true
            "#,
            "explainn",
        ),
    ];

    for (file, contents, typo) in cases {
        let path = write(&dir, file, contents);
        let run = run_in(None, &["--manifest", path.to_str().unwrap()]);
        assert_eq!(run.code, 1, "{file} must fail");
        let combined = format!("{}{}", run.stdout, run.stderr);
        assert!(
            combined.contains(typo),
            "error for {file} must name '{typo}': {combined}"
        );
    }
}

#[test]
fn a_typo_in_an_included_fragment_is_rejected_and_names_the_fragment() {
    let dir = temp_dir("mc-unknown-fragment");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "fragments/bad.toml",
        r#"
        [defaults]
        base_dirr = "wasm"
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["fragments/bad.toml"]

        [[pairs]]
        old = "wasm/v1.wasm"
        new = "wasm/v1.wasm"
        "#,
    );

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("base_dirr"),
        "must name the typo: {combined}"
    );
    assert!(
        combined.contains("bad.toml"),
        "must name the fragment that holds it: {combined}"
    );
}

#[test]
fn malformed_manifest_reports_both_parser_errors_with_position() {
    let dir = temp_dir("mc-parse-error");
    let root = write(&dir, "root.toml", "[[pairs]\nold = \"a.wasm\"\n");

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);

    let combined = format!("{}{}", run.stdout, run.stderr);
    // The old message was just "as either TOML or JSON", with both errors
    // discarded — undebuggable once includes multiply the candidate files.
    assert!(
        combined.contains("TOML error:"),
        "missing TOML error: {combined}"
    );
    assert!(
        combined.contains("JSON error:"),
        "missing JSON error: {combined}"
    );
    assert!(
        combined.contains("line 1"),
        "the TOML error must carry a position: {combined}"
    );
}

#[test]
fn a_missing_include_names_the_referring_file() {
    let dir = temp_dir("mc-missing-include");
    let root = write(&dir, "root.toml", r#"include = ["nope.toml"]"#);

    let run = run_in(None, &["--manifest", root.to_str().unwrap()]);
    assert_eq!(run.code, 1);
    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("nope.toml"),
        "must name the target: {combined}"
    );
    assert!(
        combined.contains("root.toml"),
        "must name the referrer: {combined}"
    );
}

// ── Backward compatibility ───────────────────────────────────────────────────

#[test]
fn a_flat_toml_manifest_behaves_exactly_as_before() {
    let dir = temp_dir("mc-compat-toml");

    // No [defaults], no include, absolute paths — the pre-composition form.
    let root = write(
        &dir,
        "root.toml",
        &format!(
            r#"
            [[pairs]]
            old  = {:?}
            new  = {:?}
            name = "clean_contract"

            [[pairs]]
            old  = {:?}
            new  = {:?}
            name = "breaking_contract"
            "#,
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v2.wasm").to_str().unwrap(),
        ),
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 1);

    let json = run.json();
    assert_eq!(json["total_pairs"], 2);
    assert_eq!(json["is_safe"], false);
    assert_eq!(result(&json, "clean_contract")["is_safe"], true);
    assert_eq!(result(&json, "breaking_contract")["counts"]["critical"], 3);
}

#[test]
fn a_flat_json_manifest_behaves_exactly_as_before() {
    let dir = temp_dir("mc-compat-json");

    let root = write(
        &dir,
        "root.json",
        &serde_json::json!({
            "pairs": [
                { "old": wasm("v1.wasm"), "new": wasm("v1.wasm"), "name": "clean" },
                { "old": wasm("v1.wasm"), "new": wasm("v2.wasm"), "name": "breaking" },
            ]
        })
        .to_string(),
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 1);

    let json = run.json();
    assert_eq!(json["total_pairs"], 2);
    assert_eq!(result(&json, "clean")["is_safe"], true);
    assert_eq!(result(&json, "breaking")["counts"]["critical"], 3);
}

#[test]
fn a_manifest_declaring_dependencies_still_parses() {
    let dir = temp_dir("mc-compat-deps");
    stage_wasm(&dir.join("wasm"));

    // `[[dependencies]]` has been documented in `src/dependency.rs` since before
    // it was parseable. Adding deny_unknown_fields must not turn a manifest
    // written from those docs into a hard error, so the block is accepted and
    // reported — propagation stays unwired.
    let root = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "token"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "pool"

        [[dependencies]]
        caller    = "pool"
        callee    = "token"
        functions = ["transfer", "balance"]
        "#,
    );

    let run = run_manifest(&root, &[]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);

    let json = run.json();
    let deps = json["manifest"]["dependencies"].as_array().unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0]["caller"], "pool");
    assert_eq!(deps[0]["callee"], "token");
    assert!(deps[0]["defined_in"]
        .as_str()
        .unwrap()
        .ends_with("root.toml"));
}

#[test]
fn directory_scan_mode_is_unaffected_and_emits_no_manifest_block() {
    let dir = temp_dir("mc-dirscan");
    let old_dir = dir.join("old");
    let new_dir = dir.join("new");
    std::fs::create_dir_all(&old_dir).unwrap();
    std::fs::create_dir_all(&new_dir).unwrap();
    std::fs::copy(wasm("v1.wasm"), old_dir.join("token.wasm")).unwrap();
    std::fs::copy(wasm("v2.wasm"), new_dir.join("token.wasm")).unwrap();

    let run = run_in(
        None,
        &[
            "--old-dir",
            old_dir.to_str().unwrap(),
            "--new-dir",
            new_dir.to_str().unwrap(),
            "--format",
            "json",
            "--no-timestamp",
        ],
    );
    assert_eq!(run.code, 1);

    let json = run.json();
    assert_eq!(result(&json, "token")["counts"]["critical"], 3);
    // There is no composition to describe, so the key is absent rather than empty.
    assert!(
        json.get("manifest").is_none(),
        "directory scans must not emit a manifest block"
    );
}

// ── --explain-manifest ───────────────────────────────────────────────────────

#[test]
fn explain_manifest_resolves_without_comparing_anything() {
    let dir = temp_dir("mc-explain");
    // Deliberately do NOT stage the WASM files: resolution must not need them.
    write(
        &dir,
        "common/policy.toml",
        r#"
        [defaults.limits]
        max_xdr_depth = 32
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["common/policy.toml"]

        [defaults]
        base_dir = "wasm"
        strict   = true

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"
        "#,
    );

    let run = run_in(
        None,
        &["--manifest", root.to_str().unwrap(), "--explain-manifest"],
    );
    assert_eq!(
        run.code, 0,
        "resolution alone must exit 0\nstderr:\n{}",
        run.stderr
    );

    let out = run.stdout;
    assert!(out.contains("Manifest resolution"));
    assert!(
        out.contains("root.toml") && out.contains("policy.toml"),
        "sources missing: {out}"
    );
    assert!(out.contains("[1] token"), "pair missing: {out}");
    assert!(out.contains("strict"), "settings missing: {out}");
    assert!(out.contains("built-in"), "origins missing: {out}");
    assert!(out.contains("32"), "included limit missing: {out}");

    // Nothing was compared: no verdict, no findings.
    assert!(
        !out.contains("SOROBAN BATCH SAFETY REPORT"),
        "must not run: {out}"
    );
    assert!(!out.contains("Critical"), "must not report findings: {out}");
}

#[test]
fn explain_manifest_requires_a_manifest() {
    let run = run_in(None, &["--explain-manifest"]);
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("--manifest"),
        "must point at the missing flag: {}",
        run.stderr
    );
}

// ── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn the_same_manifest_yields_byte_identical_json() {
    let dir = temp_dir("mc-determinism");
    stage_wasm(&dir.join("wasm"));

    write(
        &dir,
        "frag.toml",
        r#"
        [defaults.policy]
        gate_event_indexer = true
        "#,
    );
    let root = write(
        &dir,
        "root.toml",
        r#"
        include = ["frag.toml"]

        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v1.wasm"
        name = "b"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v3.wasm"
        name = "a"
        "#,
    );

    let first = run_manifest(&root, &[]);
    let second = run_manifest(&root, &[]);
    assert_eq!(first.code, second.code);

    // Byte-identity is asserted on the `manifest` block specifically, not on the
    // whole document. The finding stream is ordered by iteration over the
    // `HashMap`s in `spec.rs`, so `findings_by_category` reorders between runs —
    // a pre-existing defect reproducible on a plain single-pair run with
    // `--no-timestamp` and unrelated to manifest composition. Asserting the whole
    // document here would make this test a flaky proxy for that bug; when it is
    // fixed, widen this to `first.stdout == second.stdout`.
    let manifest_of = |run: &Run| serde_json::to_string_pretty(&run.json()["manifest"]).unwrap();
    assert_eq!(
        manifest_of(&first),
        manifest_of(&second),
        "resolved manifest provenance must be byte-identical across runs"
    );
    assert_eq!(first.json()["is_safe"], second.json()["is_safe"]);
    assert_eq!(first.json()["total_pairs"], second.json()["total_pairs"]);

    // Report order follows manifest composition order.
    let json = first.json();
    let names: Vec<&str> = json["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["b", "a"]);

    // Provenance keeps composition order, which is the useful order there.
    let pair_names: Vec<&str> = json["manifest"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(pair_names, vec!["b", "a"]);
}
