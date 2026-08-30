//! Integration tests for the public library API.
//!
//! Unlike `json_output.rs`, these never spawn the CLI binary — they link the
//! library crate directly and call the top-level comparison helpers, proving
//! the core loading/parsing/diffing logic is reusable by external Rust tools.

use std::path::PathBuf;

use soroban_upgrade_safeguard::{
    compare_wasm_against_interface_lockfile, compare_wasm_bytes, compare_wasm_files,
};

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn library_detects_breaking_upgrade_from_files() {
    let report = compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed on valid fixtures");

    assert!(!report.is_safe(), "v1 -> v2 must be flagged as unsafe");
    assert!(!report.call_abi().old_client_to_new_contract.compatible);
    assert!(!report.call_abi().new_client_to_old_contract.compatible);
    assert!(
        report.critical_count() >= 1,
        "v1 -> v2 must report at least one critical finding"
    );
    assert_eq!(
        report.total_findings(),
        report.critical_count() + report.warning_count() + report.info_count(),
        "total findings must equal the sum of severity counts"
    );
}

#[test]
fn library_identical_upgrade_is_safe_from_files() {
    let report = compare_wasm_files(&wasm("v1.wasm"), &wasm("v1.wasm"))
        .expect("comparison should succeed on valid fixtures");

    assert!(report.is_safe(), "identical builds must be safe");
    assert_eq!(
        report.critical_count(),
        0,
        "identical builds have no criticals"
    );
}

#[test]
fn library_compares_in_memory_bytes() {
    let old = std::fs::read(wasm("v1.wasm")).expect("read v1 fixture");
    let new = std::fs::read(wasm("v2.wasm")).expect("read v2 fixture");

    let report =
        compare_wasm_bytes(&old, &new).expect("comparison should succeed on in-memory bytes");

    assert!(!report.is_safe());
    assert!(report.critical_count() >= 1);

    // The byte-slice and file-path entry points must agree.
    let from_files = compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm")).unwrap();
    assert_eq!(report.critical_count(), from_files.critical_count());
    assert_eq!(report.total_findings(), from_files.total_findings());
}

#[test]
fn library_compares_wasm_against_interface_lockfile() {
    let old = std::fs::read(wasm("v1.wasm")).expect("read v1 fixture");
    let new = std::fs::read(wasm("v2.wasm")).expect("read v2 fixture");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("extract")
        .arg(wasm("v1.wasm"))
        .output()
        .expect("extract v1");
    let extracted: soroban_upgrade_safeguard::spec_json::ExtractedSpec =
        serde_json::from_slice(&output.stdout).expect("parse extracted spec");
    let lockfile = soroban_upgrade_safeguard::InterfaceLockfile::from_extracted(&extracted);

    let matching = compare_wasm_against_interface_lockfile(
        &serde_json::to_string(&lockfile).unwrap(),
        &old,
        &Default::default(),
    )
    .expect("matching lockfile comparison should succeed");
    assert!(matching.is_safe());

    let drifting = compare_wasm_against_interface_lockfile(
        &serde_json::to_string(&lockfile).unwrap(),
        &new,
        &Default::default(),
    )
    .expect("drifting lockfile comparison should succeed");
    assert!(!drifting.is_safe());
    assert!(drifting.critical_count() >= 1);
}

#[test]
fn library_detects_parameter_reordering() {
    use soroban_upgrade_safeguard::diff::{compare, Severity};
    use soroban_upgrade_safeguard::spec::ContractSpec;
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, StringM, VecM,
    };

    let mut old_spec = ContractSpec::default();
    let old_inputs = vec![
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "a".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "b".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
    ];
    old_spec.functions.insert(
        "test_fn".to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "test_fn".try_into().unwrap(),
            inputs: VecM::try_from(old_inputs).unwrap(),
            outputs: VecM::default(),
        },
    );

    let mut new_spec = ContractSpec::default();
    let new_inputs = vec![
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "b".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "a".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
    ];
    new_spec.functions.insert(
        "test_fn".to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "test_fn".try_into().unwrap(),
            inputs: VecM::try_from(new_inputs).unwrap(),
            outputs: VecM::default(),
        },
    );

    let diff_report = compare(&old_spec, &new_spec);
    let reorder_finding = diff_report
        .findings
        .iter()
        .find(|f| f.category() == "Parameter Reordered");

    assert!(
        reorder_finding.is_some(),
        "Integration: Expected a Parameter Reordered finding"
    );
    let f = reorder_finding.unwrap();
    assert_eq!(*f.severity(), Severity::Critical);
}
