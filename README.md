# Soroban Upgrade Safeguard 🛡️

![Soroban Upgrade Safeguard Demo](assets/demo.png)

A powerful CLI tool to analyze and validate Soroban smart contract upgrades on the Stellar network. It detects breaking changes in storage layout, function signatures, and event schemas before you deploy.

## Features

- **Storage Layout Protection**: Detects field removals, reorderings, and type changes in structs and enums that would corrupt on-chain data.
- **Function Signature Validation**: Flags changes in function names, parameters, and return types that break integration with existing clients/contracts.
- **Event Schema Analysis**: Heuristically identifies event-related types and ensures their structure remains backwards compatible for indexers.
- **Cascading Break Detection**: Uses dependency graphing to track how a change in a low-level type affects all parent structures.
- **Rich CLI Output**: Beautiful, color-coded reports with actionable severity levels (Critical, Warning, Info).
- **CI/CD Friendly**: Exits with a non-zero code if critical breaking changes are detected.
- **Suppression Config**: Acknowledge known, intentional breaking changes (e.g. a planned migration) in a `.safeguard.toml` so they no longer fail the run — while still listing them in the report.
- **Interface Hash**: A stable, order-independent SHA-256 over the normalised spec. Two builds with the same hash expose the same interface, which makes it a cheap cache key and a direct answer to "did this change the interface?".
- **Spec Extraction**: `extract` dumps a single build's decoded interface as JSON, so you can inspect a WASM or archive its interface without separate Stellar tooling.
- **Interface Lockfiles**: Commit a reviewable interface snapshot and make CI fail when a candidate build drifts from it.
- **Re-renderable Reports**: `render` turns a saved JSON report back into text or Markdown, so a stored verdict can be presented any number of ways without the original WASM files.
- **Multi-Format Output**: Emit the same report as JSON, Markdown, and text simultaneously — each to its own file or stdout — in a single run.
- **Watch Mode**: Continuously monitor input WASM files for changes and automatically re-run the comparison on every build.
- **Provenance Metadata**: Every report includes the tool version, a timestamp, and input identifiers for full auditability (`--no-timestamp` for deterministic snapshot testing).
- **Signed Attestations**: Bind reports, artifacts, extracted specs, policy, and verdicts in canonical in-toto statements with offline DSSE verification.
- **GitHub Action**: Reusable action that posts the Markdown report as a PR comment and updates it in-place on subsequent pushes.

## Installation

```bash
cargo install --path .
```

## Usage

Compare two WASM contract builds to see if the upgrade is safe:

```bash
soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>
```

### Example

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm
```

### Inspecting a single build

```bash
# The full decoded interface as JSON
soroban-upgrade-safeguard extract ./wasm/v1.wasm

# Just the interface hash, for scripting and cache keys
soroban-upgrade-safeguard extract ./wasm/v1.wasm --hash-only
```

### Pinning an interface with a lockfile

Generate a lockfile from the build whose public interface you intend to protect:

```bash
soroban-upgrade-safeguard lockfile ./wasm/v1.wasm \
  --output ./wasm/contract.interface.lock.json
```

Commit the resulting JSON file. It contains the interface hash and the structured
functions and user-defined types, with stable ordering and without build-specific
paths. When an interface change is intentional, regenerate it with `--force` and
review the lockfile diff as part of the same change:

```bash
soroban-upgrade-safeguard lockfile ./wasm/v2.wasm \
  --output ./wasm/contract.interface.lock.json --force
```

Use the committed lockfile as a CI gate for a candidate build:

```bash
soroban-upgrade-safeguard ./wasm/candidate.wasm \
  --interface-lockfile ./wasm/contract.interface.lock.json \
  --format json
```

The command exits successfully when the exported interface matches. A drift exits
non-zero and reports the same categorized findings as a normal two-build comparison.
Lockfile checks cover the exported interface only; use the regular comparison mode
for environment metadata, host imports, runtime surface, storage schemas, or
empirical validation.

### Re-rendering a saved report

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format json > report.json
soroban-upgrade-safeguard render report.json --format markdown
```

### Signing and verifying reports

```bash
soroban-upgrade-safeguard attest report.json \
  --old-wasm old.wasm --new-wasm new.wasm \
  --private-key signing-key.pk8 --key-id release-key \
  --output report.dsse.json

soroban-upgrade-safeguard verify-attestation report.dsse.json \
  --trusted-key release-key=public-key.raw \
  --report report.json --old-wasm old.wasm --new-wasm new.wasm
```

See the [attestation guide](docs/attestations.md) for predicate details,
resolved policy binding, offline verification, and key-handling guidance.

Use `-` for one positional WASM to read it from stdin, for example when a build
artifact is piped from another command:

```bash
cat ./wasm/v2.wasm | soroban-upgrade-safeguard ./wasm/v1.wasm -
```

Only one positional input may be `-`; using `-` for both `OLD_WASM` and
`NEW_WASM` is rejected because stdin can only be consumed once.

### Suppressing known breaking changes

If a breaking change is deliberate and already accounted for, list it in a
`.safeguard.toml` so it no longer fails the run. Matching is exact (by
`category` and `target`), and suppressed findings are still shown in the report,
marked `[SUPPRESSED]`:

```toml
[[suppress]]
category = "Struct Field Removed"
target   = "ConfigData.threshold"
reason   = "Planned storage migration in v2."
```

The tool auto-loads `.safeguard.toml` from the current directory, or use
`--config <PATH>` to point at another file. See
[`.safeguard.example.toml`](.safeguard.example.toml) for a documented template
and the [documentation](docs/documentation.md#suppressing-known-breaking-changes)
for the full `target` convention.

### Multiple output formats

Emit the same report in several formats and destinations in a single run:

```bash
# Write JSON to a file, Markdown to another, and print text to stdout
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --output json:report.json \
  --output markdown:report.md

# Write to stdout only (default)
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm

# Explicit stdout format with file output
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format text \
  --output json:ci-report.json
```

### Watch mode

Re-run the comparison automatically when input WASM files change:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --watch
```

Watch mode:
- Monitors both WASM files for changes using filesystem notifications.
- Debounces rapid writes (e.g. from build tools) with a 300ms window.
- Clears the terminal screen and re-renders the report on each change.
- Handles transient missing files gracefully (e.g. build tools that delete and recreate).
- Keeps the process running regardless of comparison verdict (non-zero exit codes do NOT exit the watcher).
- Exit with `Ctrl+C`.

### Comparing many contracts at once

A manifest lists the pairs one run compares:

```bash
soroban-upgrade-safeguard --manifest release.toml
```

```toml
include = ["common/policy.toml"]   # share a policy across manifests

[defaults]
base_dir = "artifacts"             # relative paths resolve against the manifest
strict   = false

[[pairs]]
old    = "token_v1.wasm"
new    = "token_v2.wasm"
name   = "token"
old_storage_schema = "schemas/token_v1.json"
new_storage_schema = "schemas/token_v2.json"
strict = true                      # this one contract is held to a stricter bar

[pairs.policy]
gate_event_indexer = true
```

Settings resolve as `built-in < CLI < included defaults < root [defaults] < pair`,
except `--strict`/`--explain`, which a manifest may enable but never disable.
To see exactly where each value came from without running any comparison:

```bash
soroban-upgrade-safeguard --manifest release.toml --explain-manifest
```

See [Batch Manifests](docs/batch_manifests.md) for the full schema, includes,
schema coverage rules, path rules, and JSON provenance.

### Deterministic output for snapshot testing

Use `--no-timestamp` to suppress the timestamp in report provenance,
enabling reproducible snapshot tests:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format json --no-timestamp > report.json
```

### GitHub Action

A reusable GitHub Action is provided to run the safeguard tool and post
the Markdown report as a pull request comment. It updates the comment
in-place on subsequent pushes.

**Workflow example** (`.github/workflows/safeguard-report.yml`):

```yaml
name: Soroban Upgrade Safety Report

on:
  pull_request:
    paths:
      - 'wasm/**/*.wasm'

jobs:
  safeguard-report:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Build safeguard
        run: cargo build --release
      - name: Add to PATH
        run: echo "${{ github.workspace }}/target/release" >> "$GITHUB_PATH"
      - name: Run Soroban Upgrade Safeguard
        uses: ./.github/actions/soroban-upgrade-safeguard
        with:
          old-wasm: ./wasm/v1.wasm
          new-wasm: ./wasm/v2.wasm
          token: ${{ secrets.GITHUB_TOKEN }}
          args: --strict --explain
```

The action uses the GitHub CLI (`gh`) to manage comments. It searches for
an existing comment containing the hidden marker
`<!-- soroban-upgrade-safeguard-report -->` and updates it, or creates a new
one if none exists. The action requires `pull-requests: write` permission.

If run on a forked PR without write permissions, the action logs a warning
and exits gracefully — the report is still generated but the comment is not
posted.

## How it Works

The tool parses the `contractspecv0` custom sections from both WASM files, decodes the XDR representations of the contract's interface, and performs a deep structural comparison. It builds a type dependency map to identify when a simple change in a shared struct might cascade into breaking multiple storage entries.

## Severity Levels

- **🔴 CRITICAL**: Breaking changes that WILL cause data corruption, serialization panics, or broken integrations. **Do not deploy.**
- **🟡 WARNING**: Changes that might affect external systems but won't necessarily corrupt local storage (e.g., adding elective parameters if supported).
- **🔵 INFO**: Informational logs about additions or non-breaking modifications.

## Documentation

More detailed guides live in the [docs](docs/) folder:

- [Documentation](docs/documentation.md): full explanation of how the analysis pipeline works, severity levels, cascading layout breaks, and CI integration.
- [Finding Category Reference](docs/finding-categories.md): every category emitted by the tool, with severity, trigger, and remediation guidance — the exact strings to use in suppression rules.
- [Batch Manifests](docs/batch_manifests.md): the manifest schema, composing manifests with `include`, shared `[defaults]`, per-pair overrides, precedence, and resolution provenance.
- [Contributing](docs/contributing.md): development setup, project structure, testing, and how to add new detection rules.
- [Signed Attestations](docs/attestations.md): DSSE signing, the in-toto predicate, offline verification, and security guidance.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
