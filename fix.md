Description
There is no way to pin a contract's expected interface and have CI fail if a build drifts
from it. Every check is relative to another build supplied at run time, so a project cannot
assert "this contract's public interface is exactly this, and any deviation must be
reviewed" without keeping an old WASM around to compare against.

A committed interface lockfile makes the interface itself a reviewable, version-controlled
artifact. A change to the lockfile shows up in a diff as a deliberate interface change, and
a build that drifts from it without updating it fails the gate.

Suggested approach
Add a mode that compares a build against a committed spec lockfile rather than against
another build, and a way to generate or update that lockfile from a build. This builds
directly on extracting a spec as a durable artifact and on the interface hash, which is the
natural cheap form of the lockfile's core check. Be explicit about the workflow: how a
contributor regenerates the lockfile when an interface change is intended, and how the diff
of the lockfile is meant to be reviewed. Reuse the existing diff engine so a drift is
described with the same findings a normal comparison produces.

Acceptance criteria

A build can be checked against a committed interface lockfile, failing on drift with
the usual findings.

There is a documented way to generate and update the lockfile when a change is
intended.

The lockfile is a reviewable, version-controlled artifact whose diff is meaningful.

The mode is documented and covered by tests for a matching and a drifting build.
Getting started
Fork this repository, clone your fork, and add this repo as upstream:

git clone https://github.com/<your-username>/soroban-upgrade-safeguard.git
cd soroban-upgrade-safeguard
git remote add upstream https://github.com/ShippedLabs/soroban-upgrade-safeguard.git
Create a branch for this issue:

git checkout -b feat/interface-lockfile
Suggested commit message:

feat: support an interface lockfile
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then
open a pull request from your fork against main and link this issue. See
docs/contributing.md for the full contribution guide.