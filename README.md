# GraphScope

[![Rust CI](../../actions/workflows/rust-ci.yml/badge.svg)](../../actions/workflows/rust-ci.yml)
[![AlmaLinux 10 CI](../../actions/workflows/almalinux-10.yml/badge.svg)](../../actions/workflows/almalinux-10.yml)
[![Storage Readiness](../../actions/workflows/storage-readiness.yml/badge.svg)](../../actions/workflows/storage-readiness.yml)
[![Pytest](../../actions/workflows/pytest.yml/badge.svg)](../../actions/workflows/pytest.yml)
[![Docs](../../actions/workflows/docs.yml/badge.svg)](../../actions/workflows/docs.yml)
[![Supply Chain](../../actions/workflows/supply-chain.yml/badge.svg)](../../actions/workflows/supply-chain.yml)
![Rust 2024](https://img.shields.io/badge/Rust-2024-orange?logo=rust)
![AlmaLinux 10](https://img.shields.io/badge/AlmaLinux-10-262577?logo=almalinux)
![CloudLinux OS](https://img.shields.io/badge/CloudLinux-OS-1f6feb)
![TuxCare](https://img.shields.io/badge/TuxCare-supply--chain-0b7)
![SQLite Adapter](https://img.shields.io/badge/SQLite-adapter%20feature-044a64?logo=sqlite)
![RocksDB Adapter](https://img.shields.io/badge/RocksDB-adapter%20feature-5f4b8b)
![RPM DNF](https://img.shields.io/badge/RPM%2FDNF-modeled-b31b1b)
![pip Poetry](https://img.shields.io/badge/pip%2FPoetry-modeled-3776ab?logo=python)
![Maven Gradle](https://img.shields.io/badge/Maven%2FGradle-modeled-c71a36?logo=apachemaven)
![npm](https://img.shields.io/badge/npm-modeled-cb3837?logo=npm)
![Go Modules](https://img.shields.io/badge/Go%20modules-modeled-00add8?logo=go)
![Cargo](https://img.shields.io/badge/Cargo-modeled-orange?logo=rust)
![Adapter Matrix](https://img.shields.io/badge/adapter%20matrix-executable-0969da)
![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-0b7)
![CycloneDX Ingest](https://img.shields.io/badge/CycloneDX-ingest-0b7)
![SPDX](https://img.shields.io/badge/SPDX-2.3-4398d1)
![VEX](https://img.shields.io/badge/VEX-export-6f42c1)
![Policy Engine](https://img.shields.io/badge/policy-engine-d73a49)
![SLA Summary](https://img.shields.io/badge/SLA-summary-0969da)
![Risk Dashboard](https://img.shields.io/badge/risk%20dashboard-MVP-0969da)
![Invalidation Planner](https://img.shields.io/badge/invalidation-planner-8250df)
![File Store](https://img.shields.io/badge/file%20store-durable%20MVP-0a7)
![Event Log](https://img.shields.io/badge/event%20log-durable%20MVP-7952b3)
![pytest CI](https://img.shields.io/badge/pytest-CI-0a9edc?logo=pytest)
![Tests](https://img.shields.io/badge/tests-179%20passing-brightgreen)
![License](https://img.shields.io/badge/license-unlicensed-lightgrey)
![Dependency Free](https://img.shields.io/badge/runtime%20deps-0-success)

GraphScope is a unified dependency graph system for AlmaLinux OS, CloudLinux OS,
and TuxCare supply-chain intelligence.

It ingests software projects, operating-system packages, language package
metadata, lockfiles, SBOMs, advisories, and runtime context, then calculates the
full dependency graph that actually applies to a customer environment.

The project is designed for one business question:

> What software do we really depend on, in this exact environment, and what risk
> or maintenance obligation follows from that dependency?

## Why Is It Useful / What Is It Useful For?

CloudLinux and TuxCare operate in a world where the same application may resolve
to different dependencies depending on distribution, architecture, Python or JVM
version, optional GPU support, FIPS policy, enabled package repositories, and
package-manager behavior.

GraphScope treats those differences as first-class data rather than flattening
them into a lossy SBOM. The goal is to power:

- precise CVE and ELS exposure analysis,
- faster TuxCare patch impact assessment,
- CloudLinux and AlmaLinux ecosystem dependency intelligence,
- customer-specific remediation plans,
- package lifecycle and rebuild planning,
- supply-chain inventory across RPM, Python, Java, JavaScript, Go, and Rust.

## Current Repository Contents

This repository contains a dependency-free Rust MVP and a complete architecture
package:

- universal package, version, scope, condition, and provenance model,
- executable hypergraph/projection model for requirement clauses, alternatives,
  resolved occurrences, and traversal indexes,
- context-aware resolver with ecosystem-specific version selection policy,
- normalized evidence records plus parser coverage for pip requirements, Go
  modules, Cargo.lock, npm package-lock, Maven POM dependencies, Gradle
  dependency declarations, RPM runtime inventories, and CycloneDX SBOM
  components,
- auto-detecting evidence ingestion workflow for manifests, lockfiles, and RPM
  inventories,
- executable adapter coverage matrix for RPM, Python, Maven, Gradle, npm, Go,
  and Cargo MVP capabilities,
- transitive dependency graph output,
- stable JSON graph snapshots with resolver decision traces,
- conflict, skipped-dependency, and candidate-selection diagnostics,
- graph query APIs for dependency paths, reverse dependencies, explanations, and
  graph diffs,
- advisory impact reports with evidence-backed dependency paths,
- in-memory resolver job queue and graph store for customer/product snapshots,
- tenant access policy primitives for customer isolation,
- dependency-free durable file store for immutable graph snapshot JSON and
  snapshot indexes,
- dependency-free change-event log for replayable invalidation inputs,
- incremental invalidation planning for package, repository, advisory, and
  policy changes,
- customer policy evaluation for allowed sources, signing, denied packages,
  wildcard requirements, and coverage,
- CycloneDX-style SBOM, SPDX-style SBOM, VEX-style status, SLA summary, and
  remediation report exports,
- product risk dashboard aggregation for customer-facing portfolio summaries,
- demo dataset for a TuxCare/CloudLinux style product stack,
- checked-in demo artifacts for snapshots, SBOMs, reports, risk summaries,
  durable storage, event logs, and evidence ingestion,
- real-world AlmaLinux 10 RPM inventory evidence captured from a running VPS,
- tests for version ranges, environment markers, optional features, Maven-style
  exclusions, Go minimal-version selection, cycle handling, parser fixtures,
  impact reports, exports, and platform workflows,
- business strategy and production architecture documentation.

## Quick Start

```sh
cargo test
cargo run -- demo
cargo run -- snapshot
cargo run -- impact
cargo run -- report
cargo run -- sbom
cargo run -- spdx
cargo run -- vex
cargo run -- policy
cargo run -- sla
cargo run -- dashboard
cargo run -- invalidate
cargo run -- evidence tests/fixtures/npm/package-lock.json
cargo run -- evidence tests/fixtures/sbom/cyclonedx.json
cargo run -- evidence examples/real-world/almalinux-10-rpm.list
cargo run -- adapters
cargo run -- access
cargo run -- persist /tmp/graphscope-store
cargo run -- events /tmp/graphscope-store
cargo run -- explain
cargo run -- diff
```

The demo resolves a synthetic TuxCare stack across RPM, Python, Maven, npm, Go,
and Cargo packages for a CloudLinux x86_64 production context with GPU support.

## Demo Artifacts

Generated demo outputs are checked in under
[examples/demo-artifacts](examples/demo-artifacts/README.md). They include:

- stable graph snapshot JSON,
- CycloneDX, SPDX, and VEX exports,
- advisory impact and remediation report output,
- SLA and risk dashboard JSON,
- adapter coverage, tenant access, invalidation, and graph diff output,
- durable file-store snapshot/index and replayable event log,
- normalized evidence output from the CycloneDX fixture.

## Real-World Evidence

The repository also includes sanitized observed package evidence from a real
AlmaLinux 10.2 x86_64 VPS:
[examples/real-world](examples/real-world/README.md).

That example includes `/etc/os-release`, enabled DNF repositories, a package-only
RPM inventory, and GraphScope's normalized evidence output. It is real runtime
inventory evidence, while the TuxCare product dependency graph remains a
synthetic demo scenario.

## MVP Workflows

- `demo`: resolved graph, active edges, skipped dependencies, conflicts, and
  resolver trace.
- `impact`: advisory findings with dependency paths and remediation actions.
- `report`: customer-ready remediation Markdown.
- `sbom`: CycloneDX-style inventory view generated from the resolved graph.
- `spdx`: SPDX-style inventory and relationship view generated from the graph.
- `vex`: VEX-style affected/not-affected statements from graph impact results.
- `policy`: customer policy violations for source, signature, version, and
  coverage rules.
- `sla`: risk and remediation summary combining advisory and policy findings.
- `dashboard`: product risk dashboard aggregated from SLA summaries.
- `invalidate`: impacted graph snapshots for package, repository, advisory, and
  policy changes.
- `evidence <path>`: auto-detect and normalize a manifest, lockfile, or RPM
  inventory into evidence records.
- `adapters`: ecosystem adapter coverage and production gaps.
- `access`: tenant access policy and authorized graph lookup demo.
- `persist <dir>`: resolve and persist the demo graph snapshot into a durable
  file-backed store.
- `events <dir>`: persist sample invalidation events into a replayable file log.
- `explain`: why a demo dependency is present, including paths and trace events.
- `diff`: graph comparison across production and production+GPU contexts.

## Design Principles

1. Preserve package-manager semantics.
   GraphScope stores universal facts, but resolver adapters must mimic the
   package manager that owns a dependency declaration.

2. Keep environment context explicit.
   A dependency edge is only true under the context that activated it.

3. Separate declared, locked, resolved, and observed dependencies.
   All four are useful and none should overwrite the others.

4. Make RPM and OS lifecycle data first-class.
   AlmaLinux, CloudLinux, ELS, live patching, repository channels, weak
   dependencies, module streams, and errata need the same status as language
   package metadata.

5. Build for graph queries at scale.
   Resolver workers create deterministic graph snapshots; graph storage serves
   impact, reachability, drift, and policy questions.

## Documentation

- [Business Strategy](docs/business-strategy.md)
- [Language And Package Manager Analysis](docs/language-analysis.md)
- [Architecture](docs/architecture.md)
- [Hypergraph Model](docs/hypergraph-model.md)
- [Resolution Algorithm](docs/resolution-algorithm.md)
- [Roadmap](docs/roadmap.md)
- [Test Inventory](docs/test-inventory.md)

## MVP Scope

The Rust code is an executable MVP: it proves the core model, resolver,
explainability, impact, policy, invalidation, durable storage, platform, and
export surfaces while staying small enough to review. Production ingestion
adapters for `dnf`, `rpm`, `pip`, Poetry, Maven, Gradle, npm, Go modules, Cargo,
registry APIs, and lockfile parsers are described in the architecture docs.
