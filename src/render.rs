//! The report model, and the renderers that operate on it.
//!
//! The three output formats used to be produced only from a live
//! [`crate::report::SafetyReport`], which meant a pipeline that stored the JSON
//! could not later turn it into the Markdown a reviewer wanted without rerunning
//! the whole comparison against inputs that may have moved.
//!
//! [`RenderableReport`] breaks that coupling. It is the owned, round-trippable
//! model that `--format json` emits, and the text and Markdown renderers are
//! implemented *on it* rather than on the live report. A live run and a
//! re-render of that run's JSON therefore go through exactly the same code, so
//! they cannot drift apart.
//!
//! ```text
//!   SafetyReport ──to_renderable()──► RenderableReport ──► text / markdown / json
//!                                            ▲
//!                       saved report.json ───┘  (RenderableReport::from_json_str)
//! ```

use std::collections::{BTreeMap, BTreeSet};

use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::diff::{CompatibilityAxis, Severity};
use crate::report::{AxisStatus, ReportedFinding};

/// Version of the JSON report shape.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Provenance metadata embedded in every report for auditability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Provenance {
    /// Tool version from crate metadata (CARGO_PKG_VERSION).
    pub tool_version: String,
    /// Timestamp in ISO 8601 / RFC 3339 format.
    /// Empty string when `--no-timestamp` is active.
    #[serde(default)]
    pub timestamp: String,
    /// Input identifiers: paths, contract IDs, or content hashes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<String>,
}

/// Severity counts, serialized as a nested `counts` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
}

/// Errors from reading a saved JSON report.
#[derive(Debug)]
pub enum RenderError {
    /// The bytes were not valid JSON, or did not match the report shape.
    Malformed(serde_json::Error),
    /// The report declares a schema version this build cannot render.
    IncompatibleSchema {
        found: u32,
        supported: u32,
        tool_version: String,
    },
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenderError::Malformed(err) => write!(
                f,
                "not a valid Soroban Upgrade Safeguard JSON report: {err}. \
                 Expected a document produced by `--format json`."
            ),
            RenderError::IncompatibleSchema {
                found,
                supported,
                tool_version,
            } => write!(
                f,
                "report uses schema version {found}, but this build of \
                 soroban-upgrade-safeguard {} only understands version \
                 {supported}. The report was written by tool version {tool_version}. \
                 Re-run the comparison with this build, or use a build that \
                 supports schema version {found}.",
                env!("CARGO_PKG_VERSION"),
            ),
        }
    }
}

impl std::error::Error for RenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RenderError::Malformed(err) => Some(err),
            RenderError::IncompatibleSchema { .. } => None,
        }
    }
}

/// The machine-readable report, and the input to every renderer.
///
/// This is what `--format json` writes and what the `render` subcommand reads
/// back. It carries everything the text and Markdown renderers need, which is
/// what makes a stored report a complete artifact rather than a summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderableReport {
    /// Shape version of this document. See [`REPORT_SCHEMA_VERSION`].
    #[serde(default = "default_schema_version")]
    pub report_schema_version: u32,
    /// Provenance metadata (tool version, timestamp, inputs).
    #[serde(default)]
    pub provenance: Provenance,
    pub is_safe: bool,
    pub strict: bool,
    pub counts: SeverityCounts,
    /// Findings (of any severity) acknowledged by the suppression config.
    pub suppressed_count: usize,
    pub total_findings: usize,
    pub recommended_bump: String,
    /// Interface hash of the old build, when the pipeline supplied specs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_interface_hash: Option<String>,
    /// Interface hash of the new build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_interface_hash: Option<String>,
    /// Analysis scope and storage coverage for this report.
    #[serde(default)]
    pub scope: crate::report::AnalysisScope,
    #[serde(default)]
    pub storage_coverage: String,
    /// Categories in a [`BTreeMap`] so the JSON key order is stable and
    /// diffable across runs.
    pub findings_by_category: BTreeMap<String, Vec<ReportedFinding>>,
    /// Per-axis pass/warning/fail verdict.
    #[serde(default)]
    pub axis_verdicts: BTreeMap<CompatibilityAxis, AxisStatus>,
    /// Axes whose findings gate `is_safe` (per policy and `--strict`).
    #[serde(default)]
    pub gated_axes: BTreeSet<CompatibilityAxis>,
    /// Findings grouped by the compatibility axis they were classified under.
    #[serde(default)]
    pub findings_by_axis: BTreeMap<CompatibilityAxis, Vec<ReportedFinding>>,
    #[serde(default)]
    pub call_abi: crate::call_abi::CallAbiCompatibility,
    #[serde(default)]
    pub empirical: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub empirical_findings: Vec<crate::empirical::EmpiricalFinding>,
}

fn default_schema_version() -> u32 {
    REPORT_SCHEMA_VERSION
}

impl RenderableReport {
    /// Parse a previously emitted JSON report.
    pub fn from_json_str(json: &str) -> Result<Self, RenderError> {
        let probe: SchemaProbe = serde_json::from_str(json).map_err(RenderError::Malformed)?;
        if probe.report_schema_version > REPORT_SCHEMA_VERSION {
            return Err(RenderError::IncompatibleSchema {
                found: probe.report_schema_version,
                supported: REPORT_SCHEMA_VERSION,
                tool_version: probe.tool_version,
            });
        }

        serde_json::from_str(json).map_err(RenderError::Malformed)
    }

    /// True when both builds' interface hashes are known and equal.
    pub fn interface_unchanged(&self) -> Option<bool> {
        match (&self.old_interface_hash, &self.new_interface_hash) {
            (Some(old), Some(new)) => Some(old == new),
            _ => None,
        }
    }

    /// The interface-hash block shared by the text and Markdown headers.
    fn interface_hash_lines(&self) -> Vec<(&'static str, String)> {
        let mut lines = Vec::new();
        if let Some(old) = &self.old_interface_hash {
            lines.push(("Old Interface Hash", old.clone()));
        }
        if let Some(new) = &self.new_interface_hash {
            lines.push(("New Interface Hash", new.clone()));
        }
        if let Some(unchanged) = self.interface_unchanged() {
            lines.push((
                "Interface",
                if unchanged {
                    "unchanged (identical interface hash)".to_string()
                } else {
                    "changed (interface hash differs)".to_string()
                },
            ));
        }
        lines
    }

    /// Render provenance as a compact text block for human-readable outputs.
    fn provenance_block_text(&self) -> String {
        let mut block = String::new();
        block.push_str(
            &"────────────────────────────────────────\n"
                .dimmed()
                .to_string(),
        );
        block.push_str(&format!("Tool:     v{}\n", self.provenance.tool_version).dimmed());
        if !self.provenance.timestamp.is_empty() {
            block.push_str(&format!("Time:     {}\n", self.provenance.timestamp).dimmed());
        }
        for input in &self.provenance.inputs {
            block.push_str(&format!("Input:    {input}\n").dimmed());
        }
        block.push_str(
            &"────────────────────────────────────────\n"
                .dimmed()
                .to_string(),
        );
        block
    }

    /// Render provenance as a compact Markdown block.
    fn provenance_block_markdown(&self) -> String {
        let mut block = String::new();
        block.push_str("###### Provenance\n\n");
        block.push_str(&format!(
            "- **Tool**: {}\n",
            markdown_code_span(&format!(
                "soroban-upgrade-safeguard v{}",
                self.provenance.tool_version
            ))
        ));
        if !self.provenance.timestamp.is_empty() {
            block.push_str(&format!(
                "- **Timestamp**: {}\n",
                markdown_code_span(&self.provenance.timestamp)
            ));
        }
        for input in &self.provenance.inputs {
            block.push_str(&format!("- **Input**: {}\n", markdown_code_span(input)));
        }
        block.push('\n');
        block
    }

    /// Render the structured, human-readable text output for the CLI.
    pub fn to_text(&self, explain: bool) -> String {
        let mut output = String::new();
        output.push_str(
            &"\n========================================\n"
                .bold()
                .to_string(),
        );
        output.push_str(
            &"    SOROBAN UPGRADE SAFETY REPORT\n"
                .bold()
                .cyan()
                .to_string(),
        );
        if self.strict {
            output.push_str(&"    [STRICT MODE ACTIVE]\n".bold().yellow().to_string());
        }
        output.push_str(
            &"========================================\n"
                .bold()
                .to_string(),
        );

        let status = if self.is_safe {
            "✅ PASSED (No breaking changes detected)".green().bold()
        } else if self.strict && self.counts.critical == 0 {
            "❌ FAILED (Warnings detected in strict mode)".red().bold()
        } else {
            "❌ FAILED (Critical breaking changes detected)"
                .red()
                .bold()
        };
        output.push_str(&format!("Status: {}\n", status));
        output.push_str(&format!("Analysis scope: {}\n", self.scope.summary_line()));
        output.push_str(&format!("Storage coverage: {}\n", self.storage_coverage));

        output.push_str("\nCompatibility Verdicts:\n");
        let axes_in_order = vec![
            crate::diff::CompatibilityAxis::StorageLayout,
            crate::diff::CompatibilityAxis::CallAbi,
            crate::diff::CompatibilityAxis::EventIndexer,
            crate::diff::CompatibilityAxis::SourceLevel,
            crate::diff::CompatibilityAxis::RuntimeSurface,
        ];
        for axis in axes_in_order {
            let axis_status = self
                .axis_verdicts
                .get(&axis)
                .cloned()
                .unwrap_or(crate::report::AxisStatus::Passed);
            let status_str = match axis_status {
                crate::report::AxisStatus::Passed => "✅ PASSED".green().bold(),
                crate::report::AxisStatus::Warning => "⚠️ WARNING (Non-gated)".yellow().bold(),
                crate::report::AxisStatus::Failed => "❌ FAILED".red().bold(),
            };
            let label = match axis {
                crate::diff::CompatibilityAxis::StorageLayout => "Storage Layout",
                crate::diff::CompatibilityAxis::CallAbi => "Call ABI",
                crate::diff::CompatibilityAxis::EventIndexer => "Event & Indexer",
                crate::diff::CompatibilityAxis::SourceLevel => "Source Level",
                crate::diff::CompatibilityAxis::RuntimeSurface => "Runtime Surface",
            };
            output.push_str(&format!("  - {:<18} {}\n", label, status_str));
        }
        output.push_str(&self.directional_call_abi_text());
        output.push('\n');

        let crit_str = if self.counts.critical > 0 {
            self.counts.critical.to_string().red().bold()
        } else {
            self.counts.critical.to_string().green()
        };
        let warn_str = if self.counts.warning > 0 {
            self.counts.warning.to_string().yellow().bold()
        } else {
            self.counts.warning.to_string().normal()
        };
        let info_str = self.counts.info.to_string().blue();

        output.push_str(&format!("Critical: {}\n", crit_str));
        output.push_str(&format!("Warnings: {}\n", warn_str));
        output.push_str(&format!("Info:     {}\n", info_str));
        if self.suppressed_count > 0 {
            output.push_str(&format!(
                "Suppressed: {}\n",
                self.suppressed_count.to_string().magenta().bold()
            ));
        }
        let bump_str = match self.recommended_bump.as_str() {
            "major" => "major".red().bold(),
            "minor" => "minor".yellow().bold(),
            "patch" => "patch".green().bold(),
            other => other.normal(),
        };
        output.push_str(&format!("Recommended Bump: {}\n", bump_str));
        for (label, value) in self.interface_hash_lines() {
            output.push_str(&format!("{}: {}\n", label, value.dimmed()));
        }
        output.push_str(
            &"----------------------------------------\n\n"
                .dimmed()
                .to_string(),
        );

        output.push_str(&self.provenance_block_text());

        if self.total_findings == 0 {
            output.push_str(&"No relevant changes detected. The upgrade is identical in its exports and types.\n".green().to_string());
            return output;
        }

        for axis in &[
            crate::diff::CompatibilityAxis::StorageLayout,
            crate::diff::CompatibilityAxis::CallAbi,
            crate::diff::CompatibilityAxis::EventIndexer,
            crate::diff::CompatibilityAxis::SourceLevel,
            crate::diff::CompatibilityAxis::RuntimeSurface,
        ] {
            let group = match self.findings_by_axis.get(axis) {
                Some(g) if !g.is_empty() => g,
                _ => continue,
            };

            let label = match axis {
                crate::diff::CompatibilityAxis::StorageLayout => "STORAGE LAYOUT COMPATIBILITY",
                crate::diff::CompatibilityAxis::CallAbi => "CALL ABI COMPATIBILITY",
                crate::diff::CompatibilityAxis::EventIndexer => "EVENT & INDEXER COMPATIBILITY",
                crate::diff::CompatibilityAxis::SourceLevel => "SOURCE LEVEL COMPATIBILITY",
                crate::diff::CompatibilityAxis::RuntimeSurface => "RUNTIME SURFACE COMPATIBILITY",
            };

            output.push_str(
                &format!("--- [{}] ---\n", label)
                    .magenta()
                    .bold()
                    .to_string(),
            );

            for reported in group {
                let finding = &reported.finding;

                if reported.suppressed {
                    let label = format!("🔕 [SUPPRESSED] {}", finding.message)
                        .dimmed()
                        .to_string();
                    output.push_str(&format!("{}\n", label));
                    if let Some(reason) = &reported.suppression_reason {
                        output
                            .push_str(&format!("    ↳ reason: {}\n", reason).dimmed().to_string());
                    }
                    continue;
                }

                let formatted = match finding.severity {
                    Severity::Critical => format!("🔴 {}", finding.message).red(),
                    Severity::Warning => format!("🟡 {}", finding.message).yellow(),
                    Severity::Info => format!("🔵 {}", finding.message).cyan(),
                };
                output.push_str(&format!("{}\n", formatted));
                if self.empirical {
                    if let Some(ref udt_name) = finding.type_name {
                        let matching_emp: Vec<&crate::empirical::EmpiricalFinding> = self
                            .empirical_findings
                            .iter()
                            .filter(|ef| &ef.type_name == udt_name)
                            .collect();
                        if !matching_emp.is_empty() {
                            let has_failures = matching_emp.iter().any(|ef| !ef.is_success);
                            if has_failures {
                                for ef in matching_emp.iter().filter(|ef| !ef.is_success) {
                                    if let Some(ref err) = ef.error {
                                        output.push_str(&format!("    ↳ 🔴 [CONFIRMED] Stored data failed to decode: {}\n", err).red().bold().to_string());
                                    }
                                }
                            } else {
                                output.push_str(&"    ↳ 🟢 [CONTRADICTED] Sampled stored values all decoded successfully under the new spec.\n".green().to_string());
                            }
                        } else {
                            output.push_str(&"    ↳ ⚪ [UNCONFIRMED] No matching stored data found in the sample.\n".dimmed().to_string());
                        }
                    }
                }
                if explain {
                    if let Some(remediation) = &reported.remediation {
                        output.push_str(
                            &format!("    ↳ guidance: {}\n", remediation)
                                .green()
                                .to_string(),
                        );
                    }
                }
            }
            output.push('\n');
        }

        if !self.is_safe {
            if self.strict && self.counts.critical == 0 {
                output.push_str(
                    &"⚠️  ACTION REQUIRED: Strict mode is active and warnings were detected.\n"
                        .yellow()
                        .bold()
                        .to_string(),
                );
                output.push_str(
                    &"These warnings must be resolved or strict mode disabled to proceed.\n"
                        .yellow()
                        .to_string(),
                );
            } else {
                output.push_str(&"⚠️  ACTION REQUIRED: The new contract version modifies existing storage layouts or function interfaces.\n".red().bold().to_string());
                output.push_str(&"Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n".red().to_string());
            }
        }

        if self.empirical {
            output.push_str(
                &"\n========================================\n"
                    .bold()
                    .to_string(),
            );
            output.push_str(
                &"    EMPIRICAL STORAGE VALIDATION SUMMARY\n"
                    .bold()
                    .magenta()
                    .to_string(),
            );
            output.push_str(
                &"========================================\n"
                    .bold()
                    .to_string(),
            );
            let successes = self
                .empirical_findings
                .iter()
                .filter(|ef| ef.is_success)
                .count();
            let failures = self
                .empirical_findings
                .iter()
                .filter(|ef| !ef.is_success)
                .count();
            let total_sampled = self.empirical_findings.len();
            output.push_str(&format!("Total Sampled UDT Values: {}\n", total_sampled));
            output.push_str(&format!(
                "  - Decoded Successfully: {}\n",
                successes.to_string().green()
            ));
            output.push_str(&format!(
                "  - Failed to Decode:     {}\n",
                if failures > 0 {
                    failures.to_string().red().bold().to_string()
                } else {
                    failures.to_string()
                }
            ));
            output.push_str("Limits: Stellar RPC does not support wildcard ledger enumeration. Coverage is bounded to instance storage or offline files.\n");
        }

        output
    }

    pub fn to_markdown(&self) -> String {
        let mut output = String::new();
        output.push_str("# Soroban Upgrade Safety Report\n\n");

        let status = if self.is_safe {
            "✅ PASSED (No breaking changes detected)"
        } else {
            "❌ FAILED (Critical breaking changes detected)"
        };
        output.push_str(&format!("## Status: {}\n\n", status));
        output.push_str(&format!(
            "**Analysis scope**: {}  \n",
            markdown_code_span(&self.scope.summary_line())
        ));
        output.push_str(&format!(
            "**Storage coverage**: {}\n\n",
            markdown_code_span(&self.storage_coverage)
        ));

        output.push_str("### Compatibility Verdicts\n\n");
        output.push_str("| Compatibility Axis | Status | Gated |\n");
        output.push_str("| :--- | :--- | :--- |\n");

        let axes_in_order = vec![
            crate::diff::CompatibilityAxis::StorageLayout,
            crate::diff::CompatibilityAxis::CallAbi,
            crate::diff::CompatibilityAxis::EventIndexer,
            crate::diff::CompatibilityAxis::SourceLevel,
            crate::diff::CompatibilityAxis::RuntimeSurface,
        ];

        for axis in axes_in_order {
            let status = self
                .axis_verdicts
                .get(&axis)
                .cloned()
                .unwrap_or(crate::report::AxisStatus::Passed);
            let status_str = match status {
                crate::report::AxisStatus::Passed => "✅ PASSED",
                crate::report::AxisStatus::Warning => "⚠️ WARNING",
                crate::report::AxisStatus::Failed => "❌ FAILED",
            };
            let label = match axis {
                crate::diff::CompatibilityAxis::StorageLayout => "Storage Layout",
                crate::diff::CompatibilityAxis::CallAbi => "Call ABI",
                crate::diff::CompatibilityAxis::EventIndexer => "Event & Indexer",
                crate::diff::CompatibilityAxis::SourceLevel => "Source Level",
                crate::diff::CompatibilityAxis::RuntimeSurface => "Runtime Surface",
            };
            let gated = if self.gated_axes.contains(&axis) {
                "Yes"
            } else {
                "No"
            };
            output.push_str(&format!("| **{}** | {} | {} |\n", label, status_str, gated));
        }
        output.push('\n');

        output.push_str("### Summary Table\n\n");
        output.push_str("| Finding Severity | Count |\n");
        output.push_str("| :--- | :--- |\n");
        output.push_str(&format!("| **Critical** | {} |\n", self.counts.critical));
        output.push_str(&format!("| **Warning** | {} |\n", self.counts.warning));
        output.push_str(&format!("| **Info** | {} |\n", self.counts.info));
        if self.suppressed_count > 0 {
            output.push_str(&format!("| **Suppressed** | {} |\n", self.suppressed_count));
        }
        output.push_str(&format!(
            "\n**Recommended SemVer Bump**: {}\n\n",
            markdown_code_span(&self.recommended_bump)
        ));
        output.push_str(&self.directional_call_abi_markdown());
        for (label, value) in self.interface_hash_lines() {
            output.push_str(&format!(
                "**{}**: {}\n\n",
                markdown_escape_text(label),
                markdown_code_span(&value)
            ));
        }
        output.push_str("---\n\n");

        output.push_str(&self.provenance_block_markdown());
        output.push_str("---\n\n");

        if self.total_findings == 0 {
            output.push_str("No relevant changes detected. The upgrade is identical in its exports and types.\n");
            return output;
        }

        for axis in &[
            crate::diff::CompatibilityAxis::StorageLayout,
            crate::diff::CompatibilityAxis::CallAbi,
            crate::diff::CompatibilityAxis::EventIndexer,
            crate::diff::CompatibilityAxis::SourceLevel,
            crate::diff::CompatibilityAxis::RuntimeSurface,
        ] {
            let group = match self.findings_by_axis.get(axis) {
                Some(g) if !g.is_empty() => g,
                _ => continue,
            };

            let label = match axis {
                crate::diff::CompatibilityAxis::StorageLayout => "Storage Layout Compatibility",
                crate::diff::CompatibilityAxis::CallAbi => "Call ABI Compatibility",
                crate::diff::CompatibilityAxis::EventIndexer => "Event & Indexer Compatibility",
                crate::diff::CompatibilityAxis::SourceLevel => "Source Level Compatibility",
                crate::diff::CompatibilityAxis::RuntimeSurface => "Runtime Surface Compatibility",
            };

            output.push_str(&format!("### {}\n\n", markdown_escape_text(label)));
            let mut current_category: Option<&str> = None;
            for reported in group {
                let finding = &reported.finding;
                if current_category != Some(finding.category.as_str()) {
                    current_category = Some(&finding.category);
                    output.push_str(&format!(
                        "### {}\n\n",
                        markdown_escape_text(&finding.category)
                    ));
                }

                if reported.suppressed {
                    output.push_str(&format!(
                        "- 🔕 **[SUPPRESSED]** {}\n",
                        markdown_escape_text(&finding.message)
                    ));
                    if let Some(reason) = &reported.suppression_reason {
                        output
                            .push_str(&format!("  - ↳ reason: {}\n", markdown_escape_text(reason)));
                    }
                    continue;
                }

                let emoji = match finding.severity {
                    Severity::Critical => "🔴",
                    Severity::Warning => "🟡",
                    Severity::Info => "🔵",
                };
                output.push_str(&format!(
                    "- {} {}\n",
                    emoji,
                    markdown_escape_text(&finding.message)
                ));
                if self.empirical {
                    if let Some(ref udt_name) = finding.type_name {
                        let matching_emp: Vec<&crate::empirical::EmpiricalFinding> = self
                            .empirical_findings
                            .iter()
                            .filter(|ef| &ef.type_name == udt_name)
                            .collect();
                        if !matching_emp.is_empty() {
                            let has_failures = matching_emp.iter().any(|ef| !ef.is_success);
                            if has_failures {
                                for ef in matching_emp.iter().filter(|ef| !ef.is_success) {
                                    if let Some(ref err) = ef.error {
                                        output.push_str(&format!(
                                            "  - ↳ 🔴 **[CONFIRMED]** Stored data failed to decode: {}\n",
                                            markdown_code_span(err)
                                        ));
                                    }
                                }
                            } else {
                                output.push_str("  - ↳ 🟢 **[CONTRADICTED]** Sampled stored values all decoded successfully under the new spec.\n");
                            }
                        } else {
                            output.push_str("  - ↳ ⚪ **[UNCONFIRMED]** No matching stored data found in the sample.\n");
                        }
                    }
                }
            }
            output.push('\n');
        }

        if !self.is_safe {
            output.push_str("### ⚠️ Action Required\n\n");
            output.push_str("- The new contract version modifies existing storage layouts or function interfaces.\n");
            output.push_str("- Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n\n");
        }

        if self.empirical {
            output.push_str("### 📊 Empirical Storage Validation Summary\n\n");
            let successes = self
                .empirical_findings
                .iter()
                .filter(|ef| ef.is_success)
                .count();
            let failures = self
                .empirical_findings
                .iter()
                .filter(|ef| !ef.is_success)
                .count();
            let total_sampled = self.empirical_findings.len();
            output.push_str(&format!(
                "- **Total Sampled UDT Values**: {}\n",
                total_sampled
            ));
            output.push_str(&format!("- **Decoded Successfully**: {}\n", successes));
            output.push_str(&format!("- **Failed to Decode**: {}\n", failures));
            output.push_str("- **Limits**: Stellar RPC does not support wildcard ledger enumeration. Coverage is bounded to instance storage or offline files.\n\n");
        }

        output
    }

    fn directional_call_abi_text(&self) -> String {
        let mut out = String::from("\nDirectional Call ABI:\n");
        for verdict in [
            &self.call_abi.old_client_to_new_contract,
            &self.call_abi.new_client_to_old_contract,
        ] {
            let label = match verdict.direction {
                crate::call_abi::CallDirection::OldClientToNewContract => {
                    "old client -> new contract"
                }
                crate::call_abi::CallDirection::NewClientToOldContract => {
                    "new client -> old contract"
                }
            };
            out.push_str(&format!(
                "  - {:<28} {}\n",
                label,
                if verdict.compatible {
                    "PASSED"
                } else {
                    "FAILED"
                }
            ));
            for br in verdict.breaks.iter().take(8) {
                out.push_str(&format!("      {}: {}\n", br.path, br.reason));
            }
        }
        out
    }

    fn directional_call_abi_markdown(&self) -> String {
        let mut out = String::from("### Directional Call ABI\n\n");
        for verdict in [
            &self.call_abi.old_client_to_new_contract,
            &self.call_abi.new_client_to_old_contract,
        ] {
            let label = match verdict.direction {
                crate::call_abi::CallDirection::OldClientToNewContract => {
                    "Old client → new contract"
                }
                crate::call_abi::CallDirection::NewClientToOldContract => {
                    "New client → old contract"
                }
            };
            let compatibility = if verdict.compatible {
                "passed"
            } else {
                "failed"
            };
            out.push_str(&format!(
                "- **{}**: {}\n",
                label,
                markdown_code_span(compatibility)
            ));
            for br in verdict.breaks.iter().take(8) {
                out.push_str(&format!(
                    "  - {} — {}\n",
                    markdown_code_span(&br.path),
                    markdown_escape_text(&br.reason)
                ));
            }
        }
        out.push('\n');
        out
    }
}

/// Minimal view used to read the schema version before full deserialization.
#[derive(Deserialize)]
struct SchemaProbe {
    #[serde(default = "default_schema_version")]
    report_schema_version: u32,
    #[serde(default = "unknown_tool_version")]
    tool_version: String,
}

fn unknown_tool_version() -> String {
    "unknown".to_string()
}

fn markdown_escape_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.replace("\r\n", "\n").replace('\r', "\n").chars() {
        match ch {
            '\n' => escaped.push_str("\\n"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '!' | '|' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn markdown_code_span(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let normalized = normalized.replace('\n', "\\n");
    let mut longest_backtick_run = 0;
    let mut current_run = 0;
    for ch in normalized.chars() {
        if ch == '`' {
            current_run += 1;
            longest_backtick_run = longest_backtick_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    let fence = "`".repeat(longest_backtick_run + 1);
    format!("{fence}{normalized}{fence}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{DiffReport, Finding};
    use crate::report::SafetyReport;
    use crate::spec::ContractSpec;

    fn finding(severity: Severity, category: &str, message: &str) -> Finding {
        Finding {
            severity,
            axes: Vec::new(),
            category: category.to_string(),
            message: message.to_string(),
            type_name: None,
            target: Some("thing".to_string()),
            root_target: None,
        }
    }

    fn sample_report() -> SafetyReport {
        let diff = DiffReport {
            findings: vec![
                finding(
                    Severity::Critical,
                    "Function Removed",
                    "Function 'a' was removed.",
                ),
                finding(Severity::Warning, "Parameter Renamed", "Parameter renamed."),
                finding(Severity::Info, "Function Added", "New function 'b' added."),
            ],
        };
        let empty_spec = ContractSpec::default();
        SafetyReport::new_with_specs(&diff, &empty_spec, &empty_spec)
    }

    #[test]
    fn round_trip_text_matches_a_live_run() {
        let live = sample_report();
        let live_text = live.generate_summary_text(false);

        let json = serde_json::to_string_pretty(&live.to_renderable()).unwrap();
        let restored = RenderableReport::from_json_str(&json).unwrap();

        assert_eq!(restored.to_text(false), live_text);
    }

    #[test]
    fn round_trip_markdown_matches_a_live_run() {
        let live = sample_report();
        let live_markdown = live.generate_summary_markdown();

        let json = serde_json::to_string_pretty(&live.to_renderable()).unwrap();
        let restored = RenderableReport::from_json_str(&json).unwrap();

        assert_eq!(restored.to_markdown(), live_markdown);
    }

    #[test]
    fn round_trip_preserves_explain_guidance() {
        let diff = DiffReport {
            findings: vec![finding(
                Severity::Critical,
                "Function Removed",
                "Function 'a' was removed.",
            )],
        };
        let empty_spec = ContractSpec::default();
        let live = SafetyReport::with_suppressions_with_specs(
            &diff,
            &crate::suppression::SuppressionConfig::default(),
            true,
            false,
            &empty_spec,
            &empty_spec,
        );

        let json = serde_json::to_string(&live.to_renderable()).unwrap();
        let restored = RenderableReport::from_json_str(&json).unwrap();

        assert_eq!(
            restored.to_text(true),
            live.generate_summary_text(true),
            "remediation guidance must survive the round trip"
        );
        assert!(restored.to_text(true).contains("guidance:"));
    }

    #[test]
    fn round_trip_is_idempotent() {
        let json = serde_json::to_string(&sample_report().to_renderable()).unwrap();
        let once = RenderableReport::from_json_str(&json).unwrap();
        let twice_json = serde_json::to_string(&once).unwrap();
        let twice = RenderableReport::from_json_str(&twice_json).unwrap();

        assert_eq!(once.to_text(false), twice.to_text(false));
        assert_eq!(once.to_markdown(), twice.to_markdown());
        assert_eq!(json, twice_json);
    }

    #[test]
    fn a_newer_schema_version_is_rejected_clearly() {
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&sample_report().to_renderable()).unwrap())
                .unwrap();
        value["report_schema_version"] = serde_json::json!(REPORT_SCHEMA_VERSION + 1);
        value["tool_version"] = serde_json::json!("99.0.0");

        let err = RenderableReport::from_json_str(&value.to_string())
            .expect_err("a newer schema must be rejected");

        let message = err.to_string();
        assert!(matches!(err, RenderError::IncompatibleSchema { .. }));
        assert!(message.contains("schema version"), "got: {message}");
        assert!(
            message.contains("99.0.0"),
            "should name the writing tool version, got: {message}"
        );
    }

    #[test]
    fn malformed_json_is_rejected_clearly() {
        let err = RenderableReport::from_json_str("{ not json").unwrap_err();
        assert!(matches!(err, RenderError::Malformed(_)));
        assert!(err.to_string().contains("not a valid"), "got: {err}");
    }

    #[test]
    fn a_json_document_of_the_wrong_shape_is_rejected() {
        let err = RenderableReport::from_json_str(r#"{"hello": "world"}"#).unwrap_err();
        assert!(matches!(err, RenderError::Malformed(_)));
    }

    #[test]
    fn interface_unchanged_reflects_the_hashes() {
        let mut report = sample_report().to_renderable();
        assert_eq!(report.interface_unchanged(), None);

        report.old_interface_hash = Some("aa".to_string());
        assert_eq!(report.interface_unchanged(), None);

        report.new_interface_hash = Some("aa".to_string());
        assert_eq!(report.interface_unchanged(), Some(true));

        report.new_interface_hash = Some("bb".to_string());
        assert_eq!(report.interface_unchanged(), Some(false));
    }

    #[test]
    fn interface_hashes_appear_in_both_human_formats() {
        let mut report = sample_report().to_renderable();
        report.old_interface_hash = Some("a".repeat(64));
        report.new_interface_hash = Some("b".repeat(64));

        let text = report.to_text(false);
        assert!(text.contains("Old Interface Hash"));
        assert!(text.contains(&"b".repeat(64)));
        assert!(text.contains("changed (interface hash differs)"));

        let markdown = report.to_markdown();
        assert!(markdown.contains("**New Interface Hash**"));
        assert!(markdown.contains("unchanged") || markdown.contains("changed"));
    }

    #[test]
    fn provenance_appears_in_json_output() {
        let live = sample_report();
        let mut renderable = live.to_renderable();
        renderable.provenance = Provenance {
            tool_version: "0.1.0".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            inputs: vec!["v1.wasm".to_string(), "v2.wasm".to_string()],
        };

        let json = serde_json::to_string_pretty(&renderable).unwrap();
        assert!(json.contains("\"provenance\""));
        assert!(json.contains("0.1.0"));
        assert!(json.contains("2024-01-15T10:30:00Z"));
        assert!(json.contains("v1.wasm"));
        assert!(json.contains("v2.wasm"));
    }

    #[test]
    fn provenance_appears_in_text_output() {
        let live = sample_report();
        let mut renderable = live.to_renderable();
        renderable.provenance = Provenance {
            tool_version: "0.1.0".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            inputs: vec!["v1.wasm".to_string(), "v2.wasm".to_string()],
        };

        let text = renderable.to_text(false);
        assert!(text.contains("Tool:"));
        assert!(text.contains("v0.1.0"));
        assert!(text.contains("Time:"));
        assert!(text.contains("Input:"));
        assert!(text.contains("v1.wasm"));
    }

    #[test]
    fn provenance_appears_in_markdown_output() {
        let live = sample_report();
        let mut renderable = live.to_renderable();
        renderable.provenance = Provenance {
            tool_version: "0.1.0".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            inputs: vec!["v1.wasm".to_string(), "v2.wasm".to_string()],
        };

        let markdown = renderable.to_markdown();
        assert!(markdown.contains("###### Provenance"));
        assert!(markdown.contains("soroban-upgrade-safeguard v0.1.0"));
        assert!(markdown.contains("2024-01-15T10:30:00Z"));
    }

    #[test]
    fn markdown_escapes_sensitive_punctuation_in_findings() {
        let diff = DiffReport {
            findings: vec![Finding {
                severity: Severity::Critical,
                axes: Vec::new(),
                category: "Function [Removed]|Changed".to_string(),
                message: "target `name` has [brackets] | and a newline\nnext line".to_string(),
                type_name: Some("Type|Name`With`Punctuation".to_string()),
                target: Some("thing".to_string()),
                root_target: None,
            }],
        };
        let empty_spec = ContractSpec::default();
        let report = SafetyReport::new_with_specs(&diff, &empty_spec, &empty_spec);

        let markdown = report.generate_summary_markdown();

        assert!(markdown.contains("### Function \\[Removed\\]\\|Changed"));
        assert!(
            markdown.contains("target \\`name\\` has \\[brackets\\] \\| and a newline\\nnext line")
        );
        assert!(!markdown.contains("target `name` has [brackets] | and a newline\nnext line"));
    }

    #[test]
    fn markdown_code_spans_handle_backticks_without_breaking() {
        let rendered = markdown_code_span("value `with` backticks");

        assert!(rendered.starts_with("``"));
        assert!(rendered.ends_with("``"));
        assert!(rendered.contains("value `with` backticks"));
    }

    #[test]
    fn provenance_timestamp_suppressed_when_empty() {
        let live = sample_report();
        let mut renderable = live.to_renderable();
        renderable.provenance = Provenance {
            tool_version: "0.1.0".to_string(),
            timestamp: String::new(),
            inputs: vec![],
        };

        let text = renderable.to_text(false);
        assert!(text.contains("Tool:"));
        assert!(!text.contains("Time:"));

        let markdown = renderable.to_markdown();
        assert!(markdown.contains("###### Provenance"));
        assert!(!markdown.contains("Timestamp"));
    }

    #[test]
    fn provenance_round_trips_through_json() {
        let live = sample_report();
        let mut renderable = live.to_renderable();
        renderable.provenance = Provenance {
            tool_version: "0.2.0".to_string(),
            timestamp: "2024-06-01T00:00:00Z".to_string(),
            inputs: vec!["old.wasm".to_string(), "new.wasm".to_string()],
        };

        let json = serde_json::to_string(&renderable).unwrap();
        let restored = RenderableReport::from_json_str(&json).unwrap();

        assert_eq!(restored.provenance.tool_version, "0.2.0");
        assert_eq!(restored.provenance.timestamp, "2024-06-01T00:00:00Z");
        assert_eq!(restored.provenance.inputs.len(), 2);
        assert!(restored.provenance.inputs.contains(&"old.wasm".to_string()));
    }
}
