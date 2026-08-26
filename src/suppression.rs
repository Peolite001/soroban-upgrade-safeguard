//! Suppression configuration for known, intentional breaking changes.
//!
//! Some breaking changes are deliberate and already accounted for (for example
//! a planned storage migration). A suppression config lets a team whitelist
//! specific, reviewed findings so they no longer fail the run — while keeping
//! them visible in the report as explicitly acknowledged.
//!
//! ## File format (`.safeguard.toml`)
//!
//! ```toml
//! # Each [[suppress]] entry acknowledges exactly one reviewed finding.
//! [[suppress]]
//! category = "Struct Field Type Changed"
//! target   = "Data.amount"          # `Type.field` for fields
//! reason   = "Planned migration in v3 widens the balance to i128."
//!
//! [[suppress]]
//! category = "Function Removed"
//! target   = "legacy_init"          # bare name for functions
//! reason   = "Deprecated initializer dropped after the v2 cutover."
//! ```
//!
//! Matching is **exact**: a rule applies only when both its `category` and its
//! `target` equal the finding's own [`Finding::category`] and [`Finding::target`].
//! A rule that omits `target` matches only findings that themselves have no
//! target (e.g. environment-metadata changes). This deliberate strictness keeps
//! a suppression from over-applying to sibling fields, cases, or parameters.
//!
//! The `target` convention mirrors [`Finding::target`]:
//!
//! - functions: the function name (e.g. `transfer`)
//! - function parameters: `function.param` (e.g. `transfer.to`)
//! - types: the type name (e.g. `Data`)
//! - struct fields: `Type.field` (e.g. `Data.amount`)
//! - enum cases: `Enum.case` (e.g. `Status.Active`)

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::diff::Finding;
use crate::error::Error;

/// The default config file name looked up in the current working directory.
pub const DEFAULT_CONFIG_FILE: &str = ".safeguard.toml";

/// Gating policy configuration for compatibility axes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub gate_storage_layout: bool,
    #[serde(default = "default_true")]
    pub gate_call_abi: bool,
    #[serde(default = "default_false")]
    pub gate_event_indexer: bool,
    #[serde(default = "default_false")]
    pub gate_source_level: bool,
    #[serde(default = "default_true")]
    pub gate_runtime_surface: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            gate_storage_layout: true,
            gate_call_abi: true,
            gate_event_indexer: false,
            gate_source_level: false,
            gate_runtime_surface: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

/// A parsed suppression config: a flat list of reviewed acknowledgements.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SuppressionConfig {
    pub max_suppressions: Option<usize>,
    pub allow_targetless: Option<bool>,
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    #[cfg(feature = "unstable")]
    pub rules: Vec<SuppressionRule>,
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) rules: Vec<SuppressionRule>,

    /// Gating policy for compatibility axes.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub policy: PolicyConfig,
    /// Gating policy for compatibility axes.
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) policy: PolicyConfig,
}

impl SuppressionConfig {
    /// Get reference to raw slice of rules.
    pub fn rules(&self) -> &[SuppressionRule] {
        &self.rules
    }

    /// Get the gating policy configuration.
    pub fn policy(&self) -> &PolicyConfig {
        &self.policy
    }
}

/// A single whitelisted finding, keyed by category and (optionally) target.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuppressionRule {
    #[serde(default)]
    pub rule_id: Option<String>,
    /// The finding category to match exactly (e.g. `"Struct Field Type Changed"`).
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub category: String,
    /// The finding category to match exactly (e.g. `"Struct Field Type Changed"`).
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) category: String,

    /// The exact [`Finding::target`] to match. When omitted, the rule matches
    /// only findings whose target is `None`.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub target: Option<String>,
    /// The exact [`Finding::target`] to match. When omitted, the rule matches
    /// only findings whose target is `None`.
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) target: Option<String>,

    /// An optional human-readable justification, surfaced in the report.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub reason: Option<String>,
    /// An optional human-readable justification, surfaced in the report.
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) reason: Option<String>,

    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub author: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) author: Option<String>,
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub expiry: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) expiry: Option<String>,
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) fingerprint: Option<String>,
}

impl SuppressionRule {
    /// Create a new suppression rule.
    pub fn new(
        category: impl Into<String>,
        target: Option<impl Into<String>>,
        reason: Option<impl Into<String>>,
    ) -> Self {
        SuppressionRule {
            rule_id: None,
            category: category.into(),
            target: target.map(|s| s.into()),
            reason: reason.map(|s| s.into()),
            author: None,
            expiry: None,
            fingerprint: None,
        }
    }

    /// Get the category to match.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Get the target entity name if specified.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Get the human-readable reason/justification.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl SuppressionRule {
    /// Whether this rule matches `finding` exactly on both category and target.
    fn matches(&self, finding: &Finding) -> bool {
        let category_matches = self.category == finding.category
            || self
                .rule_id
                .as_deref()
                .map(|id| id == canonical_rule_id(&finding.category))
                .unwrap_or(false);
        if !category_matches || self.target.as_deref() != finding.target.as_deref() {
            return false;
        }
        match &self.fingerprint {
            Some(expected) => {
                let input = format!(
                    "category:{}\ntarget:{}\nmessage:{}",
                    finding.category,
                    finding.target.as_deref().unwrap_or(""),
                    finding
                        .message
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                let digest = Sha256::digest(input.as_bytes());
                expected.eq_ignore_ascii_case(&hex::encode(digest))
            }
            None => true,
        }
    }
}

fn canonical_rule_id(category: &str) -> String {
    category
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

impl SuppressionConfig {
    /// Parse a config from a TOML string.
    pub fn from_toml_str(contents: &str) -> Result<Self, Error> {
        toml::from_str(contents).map_err(|e| Error::SuppressionConfig {
            path: None,
            details: "Failed to parse suppression config as TOML".to_string(),
            source: Some(Box::new(e)),
        })
    }

    /// Load a config from an explicit path. Errors if the file is missing or
    /// malformed — callers that pass a path are asserting it should exist.
    pub fn load_from_path(path: &Path) -> Result<Self, Error> {
        let contents = fs::read_to_string(path).map_err(|e| Error::SuppressionConfig {
            path: Some(path.to_path_buf()),
            details: format!("Failed to read suppression config '{}'", path.display()),
            source: Some(Box::new(e)),
        })?;
        Self::from_toml_str(&contents).map_err(|e| Error::SuppressionConfig {
            path: Some(path.to_path_buf()),
            details: format!("Invalid suppression config '{}'", path.display()),
            source: Some(Box::new(e)),
        })
    }

    /// Load the default config file if it exists, returning `None` when it is
    /// absent. A present-but-malformed file is still an error, so typos are not
    /// silently ignored. This preserves today's behavior when no config is set.
    pub fn load_optional(path: &Path) -> Result<Option<Self>, Error> {
        if path.exists() {
            Ok(Some(Self::load_from_path(path)?))
        } else {
            Ok(None)
        }
    }

    /// Return the first rule that matches `finding`, if any.
    pub fn matching_rule(&self, finding: &Finding) -> Option<&SuppressionRule> {
        self.rules.iter().find(|rule| rule.matches(finding))
    }

    /// Whether any rule matches `finding`.
    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        self.matching_rule(finding).is_some()
    }

    /// Validate the config on its own, without running a comparison.
    ///
    /// Parsing problems already surface at load time (see
    /// [`Self::load_from_path`]); this second pass catches rules that parse but
    /// can never match anything — most usefully a rule naming a `category` the
    /// tool never emits, which would otherwise silently never fire. It needs no
    /// WASM inputs, so a team can check a `.safeguard.toml` in isolation.
    pub fn validate(&self) -> ConfigValidation {
        let unknown_categories = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                !is_known_category(&rule.category)
                    && !rule
                        .rule_id
                        .as_deref()
                        .map(is_known_rule_id)
                        .unwrap_or(false)
            })
            .map(|(i, rule)| (i + 1, rule.category.clone()))
            .collect();
        let mut errors = Vec::new();
        let max_allowed = self.max_suppressions.unwrap_or(10);
        if self.rules.len() > max_allowed {
            errors.push(format!(
                "configured suppressions ({}) exceed the maximum limit of {}",
                self.rules.len(),
                max_allowed
            ));
        }

        let targetless_count = self
            .rules
            .iter()
            .filter(|rule| rule.target.is_none())
            .count();
        if targetless_count > 0 && !self.allow_targetless.unwrap_or(false) {
            errors.push("targetless suppressions are disabled".to_string());
        }
        if targetless_count > 3 {
            errors.push(format!(
                "targetless suppressions ({targetless_count}) exceed the ceiling of 3"
            ));
        }

        for (index, rule) in self.rules.iter().enumerate() {
            if let Some(expiry) = &rule.expiry {
                match expiry_is_past(expiry) {
                    Ok(true) => errors.push(format!(
                        "rule #{} for '{}' expired on {}",
                        index + 1,
                        rule.category,
                        expiry
                    )),
                    Ok(false) => {}
                    Err(error) => errors.push(format!("rule #{}: {error}", index + 1)),
                }
            }
        }

        ConfigValidation {
            unknown_categories,
            errors,
        }
    }
}

/// Whether `category` is one the tool can actually emit as a finding category.
///
/// The valid set is shared with the report layer rather than duplicated: a
/// category is recognized exactly when the report has remediation guidance for
/// it, which by construction covers every category the diff stage emits. A rule
/// naming anything outside this set can never match a real finding.
pub fn is_known_category(category: &str) -> bool {
    crate::report::get_remediation_guidance(category).is_some()
}

fn is_known_rule_id(rule_id: &str) -> bool {
    crate::category::FindingCategory::all()
        .iter()
        .any(|category| canonical_rule_id(category.as_str()) == rule_id)
}

/// The outcome of [`SuppressionConfig::validate`].
///
/// A config is valid when this carries no problems. Today the only class of
/// problem detected is a rule naming an unknown category, but the type leaves
/// room to grow (e.g. rules that match nothing during a run).
#[derive(Debug, Default)]
pub struct ConfigValidation {
    /// `(1-based rule number, category)` for every rule whose `category` the
    /// tool never emits.
    pub unknown_categories: Vec<(usize, String)>,
    pub errors: Vec<String>,
}

impl ConfigValidation {
    /// Whether the config is free of detected problems.
    pub fn is_valid(&self) -> bool {
        self.unknown_categories.is_empty() && self.errors.is_empty()
    }
}

fn expiry_is_past(expiry: &str) -> Result<bool, String> {
    let mut parts = expiry.split('-');
    let year: i32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid expiry '{expiry}', expected YYYY-MM-DD"))?;
    let month: u32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid expiry '{expiry}', expected YYYY-MM-DD"))?;
    let day: u32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid expiry '{expiry}', expected YYYY-MM-DD"))?;
    if parts.next().is_some() || !valid_date(year, month, day) {
        return Err(format!("invalid expiry '{expiry}', expected YYYY-MM-DD"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(days_from_civil(year, month, day) < (now / 86_400) as i64)
}

fn valid_date(year: i32, month: u32, day: u32) -> bool {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= days
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i32::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::Severity;

    /// Build a finding with the given category and target for matching tests.
    fn finding(category: &str, target: Option<&str>) -> Finding {
        Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: category.to_string(),
            message: "irrelevant to matching".to_string(),
            type_name: target.map(|t| t.split('.').next().unwrap().to_string()),
            target: target.map(|t| t.to_string()),
            root_target: None,
        }
    }

    #[test]
    fn empty_config_suppresses_nothing() {
        let config = SuppressionConfig::default();
        assert!(!config.is_suppressed(&finding("Struct Field Type Changed", Some("Data.amount"))));
    }

    #[test]
    fn exact_match_on_category_and_target_suppresses() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            reason   = "Planned migration"
            "#,
        )
        .unwrap();

        let f = finding("Struct Field Type Changed", Some("Data.amount"));
        let rule = config.matching_rule(&f).expect("should match exactly");
        assert_eq!(rule.reason.as_deref(), Some("Planned migration"));
    }

    #[test]
    fn different_target_in_same_category_is_not_suppressed() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        // Same category, sibling field -> must NOT over-apply.
        assert!(!config.is_suppressed(&finding("Struct Field Type Changed", Some("Data.balance"))));
    }

    #[test]
    fn different_category_same_target_is_not_suppressed() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        // Same target, different category -> must NOT match.
        assert!(!config.is_suppressed(&finding("Struct Field Removed", Some("Data.amount"))));
    }

    #[test]
    fn rule_without_target_matches_only_targetless_findings() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Environment"
            "#,
        )
        .unwrap();

        // A targetless finding in that category matches.
        assert!(config.is_suppressed(&finding("Environment", None)));
        // A finding that *has* a target in the same category does not.
        assert!(!config.is_suppressed(&finding("Environment", Some("Whatever"))));
    }

    #[test]
    fn function_target_matches_bare_name() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"
            reason   = "Dropped after v2 cutover"
            "#,
        )
        .unwrap();

        assert!(config.is_suppressed(&finding("Function Removed", Some("legacy_init"))));
        assert!(!config.is_suppressed(&finding("Function Removed", Some("transfer"))));
    }

    #[test]
    fn validate_accepts_a_config_of_known_categories() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"

            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"
            "#,
        )
        .unwrap();

        let validation = config.validate();
        assert!(validation.is_valid());
        assert!(validation.unknown_categories.is_empty());
    }

    #[test]
    fn validate_flags_a_rule_with_an_unknown_category() {
        // "Struct Field Reordded" is a misspelling of "Struct Field Reordered";
        // the tool never emits it, so the rule could never match.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"

            [[suppress]]
            category = "Struct Field Reordded"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        let validation = config.validate();
        assert!(!validation.is_valid());
        assert_eq!(validation.unknown_categories.len(), 1);
        // Reported as the 2nd rule, with the offending category.
        assert_eq!(validation.unknown_categories[0].0, 2);
        assert_eq!(validation.unknown_categories[0].1, "Struct Field Reordded");
    }

    #[test]
    fn is_known_category_matches_the_emitted_set() {
        assert!(is_known_category("Struct Field Removed"));
        assert!(is_known_category("Environment"));
        assert!(!is_known_category("Totally Made Up Category"));
    }

    #[test]
    fn malformed_config_is_a_clear_specific_error() {
        // A key with spaces is not valid TOML.
        let err = SuppressionConfig::from_toml_str("this is not = valid").unwrap_err();
        let message = err.to_string();
        assert!(
            message.to_lowercase().contains("suppression config"),
            "error should name the suppression config, got: {message}"
        );
    }
}
