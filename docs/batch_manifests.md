# Batch Manifests

A batch manifest lists the contract pairs one run compares:

```bash
soroban-upgrade-safeguard --manifest release.toml
```

The minimal form is a flat list of pairs, and it is still valid:

```toml
[[pairs]]
old  = "artifacts/token_v1.wasm"
new  = "artifacts/token_v2.wasm"
name = "token"
```

On top of that, a manifest can pull in other manifests (`include`), declare
settings shared by every pair (`[defaults]`), and override those settings on a
single pair. That lets a twenty-contract manifest give one contract its own
policy without splitting the run, and lets several manifests share one policy
block instead of each restating it.

- [Schema](#schema)
- [Precedence](#precedence)
- [Includes](#includes)
- [Path resolution](#path-resolution)
- [Errors](#errors)
- [Provenance](#provenance)
- [What is not wired up](#what-is-not-wired-up)

## Schema

TOML and JSON are both accepted, in the root manifest and in every included
file, chosen per file — a TOML root may include a JSON fragment and vice versa.

```toml
include = ["common/policy.toml", "teams/pool.toml"]   # depth-first, in order

[defaults]
base_dir = "artifacts"        # relative old/new resolve against this
config   = ".safeguard.toml"  # suppression config applied to each pair
strict   = false
explain  = false
ascii    = false
no_timestamp = false

[defaults.policy]             # which axes gate the verdict
gate_storage_layout  = true
gate_call_abi        = true
gate_event_indexer   = false
gate_source_level    = false
gate_runtime_surface = true

[defaults.limits]             # resolved and reported; see "What is not wired up"
max_xdr_depth = 64
max_xdr_len   = 33554432
max_entries   = 100000
max_walk_depth = 128

[[pairs]]
old  = "token_v1.wasm"
new  = "token_v2.wasm"
name = "token"
old_storage_schema = "schemas/token_v1.json"
new-storage-schema = "schemas/token_v2.json"
strict = true                 # per-pair override
config = "token.safeguard.toml"

[pairs.policy]                # per-pair gating
gate_event_indexer = true

[[dependencies]]              # accepted and reported; not propagated
caller    = "pool"
callee    = "token"
functions = ["transfer"]
```

Every field a pair accepts, `[defaults]` accepts too, and vice versa — except
`old`, `new`, and `name`, which only make sense on a pair.

| Field | Where | Meaning |
| :--- | :--- | :--- |
| `include` | top level | Other manifests to compose in, depth-first, in order. |
| `base_dir` | `[defaults]`, pair | Directory that relative `old`/`new` resolve against. **File-scoped** — see [Path resolution](#path-resolution). |
| `config` | `[defaults]`, pair | Suppression config (`.safeguard.toml`) applied to the pair. |
| `strict` | `[defaults]`, pair | Fail on warnings as well as criticals. |
| `explain` | `[defaults]`, pair | Include remediation text in the report. |
| `ascii` | `[defaults]`, pair | ASCII markers instead of emoji. |
| `no_timestamp` | `[defaults]`, pair | Omit timestamps, for snapshot testing. |
| `[policy]` | `[defaults]`, pair | Which compatibility axes gate the verdict. One key per axis: `gate_storage_layout`, `gate_call_abi`, `gate_event_indexer`, `gate_source_level`, `gate_runtime_surface`. |
| `[limits]` | `[defaults]`, pair | Resource limits. Resolved and reported only. |
| `old`, `new`, `name` | pair | The two builds and the report identity. |
| `old_storage_schema`, `new_storage_schema` | pair | Optional old/new storage schemas. Both must be supplied together. |

Unknown keys are a **hard error**, everywhere — top level, `[defaults]`, and on a
pair. Composition multiplies files, and a `strictt = true` silently dropped in a
fragment is exactly the failure this format must not allow.

## Precedence

Two rules, because one does not fit both kinds of setting.

### Valued settings — last writer wins

`config`, `policy.*`, and `limits.*`:

```
built-in default  <  CLI flag  <  included defaults  <  root [defaults]  <  pair field
```

The CLI sits *below* the manifest deliberately. `--config` is the run-level
fallback; a manifest naming a config is the more specific statement, and a pair
naming one is more specific still.

`--no-config` is the single exception: an explicit escape hatch that outranks
every layer and applies no suppression config to any pair.

The implicit `.safeguard.toml` lookup — the file the tool has always picked up
from the working directory when nothing named a config — sits at the *built-in*
level, so any manifest that names its own `config` overrides it.

### Escalation booleans — OR-chain

`strict`, `explain`, `ascii`, and `no_timestamp`: any layer may turn them **on**,
no layer may turn them **off**.

```bash
# Fails on warnings even though the manifest says strict = false.
soroban-upgrade-safeguard --manifest release.toml --strict
```

This mirrors how `no_color` already resolves in `src/config.rs`, and it keeps a
manifest from silently weakening a safety gate the CI operator asked for. A pair
may still escalate on its own — `strict = true` on one pair is honored even when
the rest of the run is lenient.

`policy.gate_*` are booleans but are **valued**, not escalation: a manifest must
be able to turn a gate *off*, which is the entire point of `[policy]`. Turning a
gate off changes the verdict, not visibility — the findings are still counted and
still appear in the report.

## Includes

`include` composes depth-first, in order: a file's includes contribute before the
file's own `[defaults]` and `[[pairs]]`. Given

```toml
# root.toml
include = ["a.toml"]   # a.toml itself includes b.toml
```

the composed pair order is `b`, `a`, `root`, and `[defaults]` layers apply in
that same order — so `root.toml` wins over `a.toml`, which wins over `b.toml`.

An included file uses the same schema as a root manifest, so any manifest can be
used as a fragment and any fragment can be run on its own.

Report output follows manifest order. JSON batch output uses an ordered
`results` array; each entry includes its name, paths, coverage, and report (or
the pair-level error).

Include chains are bounded at **8** levels deep and may not cycle; both are hard
errors that print the full chain.

## Path resolution

Every relative path — `include` targets, `base_dir`, `config`, a pair's
`old`/`new`, and its storage schemas — resolves against **the directory of the file that wrote it**, never
the process working directory. A fragment can therefore be moved, vendored, or
included from anywhere and still find its own artifacts:

```bash
# Works identically from any directory.
cd /somewhere/else
soroban-upgrade-safeguard --manifest ~/repo/release.toml
```

> **Behavior change.** Before composition, a pair's `old`/`new` resolved against
> the process working directory, so a manifest only worked when run from the
> right place. Manifests using absolute paths are unaffected. Manifests using
> relative paths now resolve them relative to the manifest — which is what they
> almost certainly meant, but it is a change worth knowing about when upgrading.

`base_dir` is **file-scoped** rather than part of the global valued chain. A
pair's `old`/`new` resolve against, in order:

1. the pair's own `base_dir`, else
2. the `[defaults].base_dir` of the file that defined that pair, else
3. that file's own directory.

A root manifest's `base_dir` therefore governs the root's own pairs and does not
reach into an included fragment. Folding it globally would let a root silently
redirect a fragment's artifact lookups, which would defeat the point of writing
the fragment as a self-contained unit.

Absolute paths are used as-is, on Unix and Windows alike.

## Errors

All of these fail the run before any comparison happens, so a broken manifest
never leaves partial reports on disk.

| Condition | What the error tells you |
| :--- | :--- |
| Include cycle | The full chain, `a.toml → b.toml → a.toml`. |
| Include depth > 8 | The chain and the cap. |
| Duplicate pair identity | The name and **both** files that define it. |
| Unknown field | The offending key and the file it is in. |
| Neither TOML nor JSON | **Both** parser errors, with line and column. |
| Missing include target | The target and the file that referred to it. |

A pair's identity is its explicit `name`, or the file name of `new` when `name`
is omitted — unchanged from before. Duplicate detection now runs ahead of
execution rather than mid-loop, so a collision fails with nothing written.

### Storage schema coverage

Storage schemas are pair-local, so schema-backed and interface-only pairs can
coexist in one manifest:

```toml
[[pairs]]
old = "artifacts/token_v1.wasm"
new = "artifacts/token_v2.wasm"
name = "token"
old_storage_schema = "schemas/token_v1.json"
new_storage_schema = "schemas/token_v2.json"
```

Schema files use the same declaration shape as single-pair analysis:

```json
{
  "declarations": [
    {
      "name": "balance",
      "function": "balance",
      "operation": "get",
      "durability": "persistent",
      "key_type": "Address",
      "value_type": "i128"
    }
  ]
}
```

The equivalent TOML is:

```toml
[[declarations]]
name = "balance"
function = "balance"
operation = "get"
durability = "persistent"
key_type = "Address"
value_type = "i128"
```

`schema-backed` means both schemas loaded and were reconciled. `interface-only`
means no schemas were declared, so storage was not verified. A partial,
missing, or invalid schema is a pair-level error and fails the aggregate
verdict without stopping unrelated pairs. Directory scans remain
interface-only because they do not discover schemas.

## Provenance

Because a setting can now come from any of five places, both the JSON report and
a dedicated flag show where each one actually came from.

`--explain-manifest` resolves the composition, prints it, and exits `0` without
comparing anything. It needs no WASM files, so a manifest can be reviewed on its
own:

```bash
soroban-upgrade-safeguard --manifest release.toml --explain-manifest
```

```
Manifest resolution
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
root:    /repo/release.toml
sources:
  - /repo/common/policy.toml
  - /repo/release.toml

pairs (1):

  [1] token
      defined in: /repo/release.toml
      old:        /repo/artifacts/token_v1.wasm
      new:        /repo/artifacts/token_v2.wasm
      config                     = (none)       (built-in)
      strict                     = true         (cli)
      explain                    = false        (built-in)
      policy.gate_call_abi       = false        (/repo/release.toml)
      policy.gate_event_indexer  = true         (/repo/common/policy.toml)
      limits.max_xdr_depth       = 32           (/repo/common/policy.toml)
```

A batch run with `--format json` carries the same information under a `manifest`
key, alongside `is_safe` / `strict` / `total_pairs` / `results`:

```jsonc
{
  "is_safe": false,
  "manifest": {
    "root": "/repo/release.toml",
    "sources": ["/repo/common/policy.toml", "/repo/release.toml"],
    "pairs": [
      {
        "name": "token",
        "defined_in": "/repo/release.toml",
        "old": "/repo/artifacts/token_v1.wasm",
        "new": "/repo/artifacts/token_v2.wasm",
        "settings": {
          "strict": { "value": true, "origin": "cli" },
          "policy": {
            "gate_call_abi": { "value": false, "origin": "/repo/release.toml" }
          }
        }
      }
    ],
    "dependencies": []
  },
  "results": [
    {
      "name": "token",
      "coverage": "schema-backed",
      "old": "/repo/artifacts/token_v1.wasm",
      "new": "/repo/artifacts/token_v2.wasm",
      "report": { "...": "..." }
    }
  ]
}
```

`origin` is `built-in`, `cli`, or the path of the manifest file that set the
value. Directory-scan runs (`--old-dir`/`--new-dir`) have no composition to
describe and omit the `manifest` key entirely rather than emitting an empty one.

## What is not wired up

Three things resolve and appear in provenance but do not yet change behavior.
They are documented here so the gap is visible rather than surprising.

**`[limits]` is not enforced.** The values resolve, fold, and report correctly,
but `parser.rs` still decodes with `Limits::none()` — `ResourcePolicy` is not
threaded into the decode path anywhere in the tool. Wiring it touches the
untrusted-input boundary and introduces exit-code-2 behavior that batch mode does
not currently handle, which deserves its own change.

**`[[dependencies]]` is accepted but not propagated.** `src/dependency.rs` has
documented a top-level `[[dependencies]]` block as manifest syntax since before
anything parsed it — the old manifest struct had no such field and silently
discarded it. Rejecting it now, as an unknown field, would turn a
silently-ignored-but-documented block into a hard error and break any manifest
written from those docs. So it parses, composes across includes, and appears in
provenance, while cross-contract propagation stays unwired exactly as before.

**Per-pair RPC and storage schemas are not supported.** Batch mode loads local
files only; `--contract-id`/`--rpc-url` are not per-pair settings. Storage
schemas remain [unsupported in batch mode](documentation.md), since one manifest
cannot describe several contracts' layouts. Both are rejected as unknown fields
rather than silently ignored.
