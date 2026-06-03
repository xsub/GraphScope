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
![pytest CI](https://img.shields.io/badge/pytest-CI-0a9edc?logo=pytest)
![Tests](https://img.shields.io/badge/tests-94%20passing-brightgreen)
![License](https://img.shields.io/badge/license-unlicensed-lightgrey)
![Dependency Free](https://img.shields.io/badge/runtime%20deps-0-success)

GraphScope is a unified dependency graph system for AlmaLinux OS, CloudLinux OS,
and TuxCare supply-chain intelligence.

It ingests software projects, operating-system packages, language package
metadata, lockfiles, SBOMs, advisories, and runtime context, then calculates the
full dependency graph that actually applies to a customer environment.

The project is designed for one business question:

```text
What software do we really depend on, in this exact environment, and what risk
or maintenance obligation follows from that dependency?
```

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

This repository contains a dependency-free Rust prototype and a complete
architecture package:

- universal package, version, scope, condition, and provenance model,
- context-aware resolver with ecosystem-specific version selection policy,
- normalized evidence records and lockfile evidence parsers,
- transitive dependency graph output,
- stable JSON graph snapshots for golden tests and audit views,
- conflict and skipped-dependency diagnostics,
- demo dataset for a TuxCare/CloudLinux style product stack,
- tests for version ranges, environment markers, optional features, Maven-style
  exclusions, Go minimal-version selection, and cycle handling,
- business strategy and production architecture documentation.

## Quick Start

```sh
cargo test
cargo run -- demo
cargo run -- snapshot
```

The demo resolves a synthetic TuxCare stack across RPM, Python, Maven, npm, Go,
and Cargo packages for a CloudLinux x86_64 production context with GPU support.

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
- [Resolution Algorithm](docs/resolution-algorithm.md)
- [Roadmap](docs/roadmap.md)
- [Test Inventory](docs/test-inventory.md)

## Prototype Scope

The Rust code is a staff-level design executable: it proves the core model and
resolution loop while staying small enough to review. Production ingestion
adapters for `dnf`, `rpm`, `pip`, Poetry, Maven, Gradle, npm, Go modules, Cargo,
registry APIs, and lockfile parsers are described in the architecture docs.
