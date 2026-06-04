# Capability Matrix

This matrix keeps public claims aligned with implemented behavior.

Status values:

- `implemented`: production behavior exists in the Rust code with tests.
- `fixture parser`: checked-in parser or model coverage exists, but native
  package-manager fidelity is not complete.
- `oracle adapter`: package-manager output is called or imported as the authority.
- `planned`: contract or feature flag exists, implementation is not complete.
- `blocked`: cannot be completed without external credentials, private metadata,
  or unavailable platform state.

## Current MVP

| Surface | Status | Evidence | Production Gap |
| --- | --- | --- | --- |
| Hypergraph/projection model | implemented | `src/hypergraph.rs` | Feed all parsed evidence through clauses before resolution. |
| Shared resolver trace | implemented | `src/resolver.rs` | Native ecosystem adapters must supply exact candidates and mediation. |
| File snapshot store | implemented | `src/storage.rs` | Not a concurrent authoritative database. |
| Change event log | implemented | `src/storage.rs` | No external event bus or transactional database yet. |
| Policy/report/export views | implemented | `src/policy.rs`, `src/export.rs` | Schema validators and richer external metadata are deferred. |
| CycloneDX ingestion | fixture parser | `parse_cyclonedx_sbom` | Full dependency graph and vulnerability extensions. |
| RPM/DNF | fixture parser | `parse_rpm_inventory`, demo resolver rules | DNF/libsolv oracle, repo metadata, provides/conflicts/weak-dep solving. |
| pip/Poetry | fixture parser | `parse_pip_requirements_lock`, model markers | pip/Poetry/uv resolver output, wheel tags, indexes, extras/groups. |
| Maven | fixture parser | `parse_maven_pom_dependencies` | Effective POM, dependency management, inheritance, dependency tree oracle. |
| Gradle | fixture parser | `parse_gradle_dependencies` | DependencyInsight/configuration graph, variants, capabilities, lockfiles. |
| npm | fixture parser | `parse_npm_package_lock` | Peer propagation, overrides, optional/platform filters. |
| Go modules | fixture parser | `parse_go_mod_requirements`, MVS policy | `go list -m all`, `go mod graph`, replace/exclude/build tags. |
| Cargo | fixture parser | `parse_cargo_lock_packages` | `cargo metadata`, feature unification, target cfg, patches. |
| SQLite storage | planned | Cargo feature surface and roadmap | `rusqlite` schema, transactions, restart/concurrency tests. |
| RocksDB cache | planned | Cargo feature surface and roadmap | Deferred until parsed-fact volume proves SQLite insufficient. |

## Guardrail

README badges and docs must not claim native package-manager fidelity, SQLite
storage, or RocksDB cache implementation until the matrix status changes to
`implemented` or `oracle adapter` with backing tests.
