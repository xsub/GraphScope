# Roadmap

This roadmap turns the current executable MVP into the most complete practical
MVP for CloudLinux, AlmaLinux, and TuxCare dependency intelligence.

Input note: `/Users/pawel/_DEV/GraphScope/REVIEW-FINDINGS.md` was not present in
the repository when this roadmap was written. The plan below incorporates the
review findings from the current project audit:

- evidence ingestion is not yet connected to graph resolution;
- package-manager-native behavior is documented but mostly not implemented;
- the version model is too generic for RPM, Python, JavaScript, Java, Go, and
  Cargo correctness;
- relations such as `Provides`, `Conflicts`, `Obsoletes`, `Bundles`, and dynamic
  loading are modeled but not enforced;
- snapshots now include occurrence projections, but still need richer
  provenance, metadata, conditions, confidence, and policy identity;
- fixture parsers still need mature parsers for XML, TOML, package-manager
  output, and non-trivial lockfile shapes;
- file and SQLite storage are MVP durability, not concurrent platform storage;
- badges and feature flags can still overstate RocksDB and native adapter
  readiness if the capability matrix is not kept current.

## Public Ecosystem Anchors

These facts shape the MVP target and should be treated as acceptance criteria,
not background decoration.

- AlmaLinux 10 is an RPM/DNF ecosystem with signed release assets, repository
  channels, architecture-specific packages, and x86-64-v2/x86-64-v3 differences.
  AlmaLinux 10 release notes call out the third-party package compatibility
  distinction for x86-64-v3 and the limited default-OS-package use case for
  x86-64-v2 systems:
  <https://wiki.almalinux.org/release-notes/10.0.html>.
- AlmaLinux errata expose advisory data through updateinfo, JSON, and OVAL
  streams. The graph must join packages to ALSA, ALBA, and ALEA advisories,
  severity, release date, and updated packages:
  <https://wiki.almalinux.org/documentation/errata.html>.
- RPM dependencies are capability based. `Requires` can match package names or
  `Provides`; versions use epoch-version-release; `Conflicts` blocks installable
  combinations; weak dependencies guide solvers and must not be flattened into
  ordinary hard runtime dependencies:
  <https://rpm-software-management.github.io/rpm/manual/dependencies.html>.
- DNF and DNF5 depend on current repository metadata, architecture policy, module
  filtering, weak dependency options, repository GPG checks, and solver behavior.
  The newest version is guaranteed only for directly requested packages in DNF5,
  while dependency packages may be older when needed to satisfy constraints:
  <https://dnf5.readthedocs.io/en/stable/dnf5.8.html>.
- DNF modular filtering can remove inactive module-stream packages from the
  available package set and can also filter non-modular packages with the same
  name or provides:
  <https://dnf.readthedocs.io/en/stable/command_ref.html>.
- libsolv is the right model for native RPM correctness because it reads rpmmd
  repositories and solves package dependencies with SAT-style dependency
  resolution:
  <https://github.com/openSUSE/libsolv>.
- CloudLinux 10 repository behavior includes SWNG, a new HTTPS mirror layout,
  the `cl-mirrors` endpoint, partial mirrors, and accessible `repodata/repomd.xml`
  metadata:
  <https://docs.cloudlinux.com/cloudlinuxos/repositories_and_mirrors/>.
- CloudLinux 10 ALT-ELS repositories provide selector packages for PHP, Python,
  NodeJS, and Ruby. Access is license/token dependent through DNF variables, so
  repository availability is part of customer context:
  <https://docs.cloudlinux.com/cloudlinuxos/cloudlinux_os_components/>.
- TuxCare Enterprise Support for AlmaLinux adds Extended Security Updates for
  selected minor releases and FIPS-compliant patches for kernel, OpenSSL,
  libcrypt, NSS, and GnuTLS:
  <https://docs.tuxcare.com/enterprise-support-for-almalinux/>.
- KernelCare/Live Patching adds a runtime patch-state overlay. A vulnerable RPM
  version can be present while a live patch changes the actual exposure answer:
  <https://docs.tuxcare.com/live-patching-services/>.

## Design Reset

The next work should keep the code compact, but remove constraints that prevent
truthful results.

- Continue removing the dependency-free constraint for parsers and storage.
  Use small, mature crates where they remove brittle string parsing:
  `serde_json`, `toml`, `quick-xml` or `roxmltree`, `semver`, and `rusqlite`.
- Keep the resolver core small.
  Do not turn the shared resolver into a fake universal package manager. Let
  adapters enumerate candidates, constraints, conflicts, and selected edges using
  ecosystem-native evidence.
- Use package-manager output before native bindings.
  For the first robust MVP, DNF/libdnf/libsolv can be an oracle through a command
  adapter on AlmaLinux/CloudLinux. Direct bindings can follow only after the data
  contract is stable.
- Use a hypergraph for semantics and ordinary graphs for resolved traversal.
  Unresolved requirements, providers, conflicts, alternatives, and context belong
  in `RequirementClause` records. Customer-facing dependency paths, reverse
  impact, reports, and exports belong on resolved occurrence graph projections.
- Prefer SQLite before RocksDB.
  SQLite is enough for MVP durability, testability, and query visibility. RocksDB
  remains a later high-volume parsed-fact cache, not the first storage backend.
- Make claims match code.
  Badges and README language must say `planned`, `contract`, or `adapter surface`
  when a backend or resolver is not implemented.

## Phase 0: Truthful Baseline

Status: next documentation and CI cleanup.

Goal: remove false confidence before adding more code.

- Keep the SQLite badge backed by `SqliteGraphStore` tests and keep the RocksDB
  badge planned until a real cache backend exists.
- Add a capability matrix that distinguishes:
  `implemented`, `fixture parser`, `oracle adapter`, `planned`, and `blocked`.
- Update `README.md` so `demo` is clearly synthetic and
  `examples/real-world` is clearly observed inventory evidence, not a resolved
  production graph.
- Add tests that fail if README claims native package-manager fidelity before an
  adapter provides it.
- Exit criteria:
  - no badge or README sentence implies unimplemented storage or solver behavior;
  - roadmap, architecture, adapter matrix, and tests agree on scope.

## Phase 1: Evidence To Resolution

Status: highest priority implementation gap.

Goal: turn parsed evidence into a real graph input instead of a printed summary.

- Add `ProjectEvidence` with separate collections for declared dependencies,
  locked packages, observed packages, repository facts, advisories, and context.
- Convert parsed evidence into typed `RequirementClause` records before turning it
  into resolver inputs. The hypergraph must preserve alternatives, providers,
  conflicts, weak/optional/peer semantics, conditions, and native evidence.
- Add `EvidenceRepositoryBuilder` that converts evidence records into:
  - root requirements;
  - package candidates;
  - dependency requirements;
  - source metadata;
  - evidence IDs.
- Add `graphscope resolve-evidence <path...>` that accepts multiple files and
  emits a snapshot, not only an evidence summary.
- Preserve declared, locked, resolved, and observed evidence as separate layers.
  Lockfiles can seed candidates; runtime inventories can create observed overlays;
  repository metadata remains the source for installable graph resolution.
- Exit criteria:
  - a project with checked-in pip, npm, Maven, Go, Cargo, SBOM, and RPM evidence
    can produce a graph snapshot;
  - every selected node and edge points back to evidence record IDs;
  - existing `evidence` CLI remains a cheap inspection command.

## Phase 2: AlmaLinux And CloudLinux RPM MVP

Status: first native ecosystem priority.

Goal: make the OS package graph credible for AlmaLinux 9/10, CloudLinux 9/10,
ELS, KernelCare, and TuxCare workflows.

- Add an RPM coordinate model:
  - name, epoch, version, release, architecture;
  - source RPM;
  - repository ID and base URL;
  - module stream where applicable;
  - signature and checksum state;
  - install reason and runtime observed state.
- Add capability identities in addition to package names:
  - package provides;
  - file provides;
  - SONAME and ABI-style dependencies;
  - virtual capabilities.
- Add relation semantics:
  - `Requires` selects installable providers;
  - `Provides` satisfies requirements without becoming an ordinary dependency;
  - `Conflicts` creates a conflict diagnostic;
  - `Obsoletes` and `Replaces` affect candidate eligibility;
  - weak dependencies become policy-controlled optional edges.
- Build a DNF oracle adapter first:
  - run on AlmaLinux/CloudLinux where available;
  - capture `dnf repoquery`, `dnf install --assumeno`, `dnf updateinfo`, and
    repository metadata snapshots;
  - record command, DNF version, repo IDs, metadata timestamps, options, and
    stderr/stdout digest as evidence.
- Add repository context:
  - BaseOS, AppStream, CRB, EPEL where present;
  - CloudLinux SWNG and mirrorlist state;
  - CloudLinux ALT-ELS selector repositories and token availability;
  - TuxCare ESU channels;
  - `install_weak_deps`, `best`, `module_hotfixes`, module stream state, and
    architecture policy.
- Add errata and patch overlays:
  - AlmaLinux updateinfo/errata JSON/OVAL;
  - TuxCare ESU advisories;
  - KernelCare live patch state for kernels and userspace live patch products.
- Exit criteria:
  - resolving selected RPM roots matches DNF oracle output for golden fixtures;
  - AlmaLinux 10 VPS inventory can be joined with repo metadata and advisories;
  - graph explanations can answer whether a package is installed, installable,
    weakly recommended, blocked by conflict, obsolete, or live-patched.

## Phase 3: Robust Parsers Without Overengineering

Status: remove brittle parser constraints.

Goal: parse common real project files safely enough for MVP while avoiding a
hand-rolled package manager.

- Replace JSON string scanning with `serde_json`.
  Apply to npm package-lock and CycloneDX.
- Replace XML line scanning with an XML parser.
  Apply to Maven POM and basic dependency-management extraction.
- Replace TOML line scanning with a TOML parser.
  Apply to Cargo.lock and `pyproject.toml` when Poetry support is added.
- Keep Gradle parsing conservative.
  Prefer `gradle dependencies` or dependency lock output when available. Treat
  raw `build.gradle` source parsing as best-effort declared evidence only.
- Add parser confidence levels:
  - `Locked` for lockfiles;
  - `Declared` for manifests;
  - `Resolved` for package-manager output;
  - `Observed` for runtime inventories;
  - `Partial` for best-effort source parsing.
- Exit criteria:
  - minified JSON, pretty JSON, XML namespaces, and multi-line values are handled;
  - invalid inputs produce structured errors with locator and line/path context;
  - parser tests include real-world shaped fixtures, not only tiny examples.

## Phase 4: Language Adapter MVP

Status: second priority after RPM.

Goal: support 5+ ecosystems without pretending one resolver fits all.

- Python:
  - parse PEP 508 markers, extras, groups, and PEP 440 versions;
  - use pip/Poetry/uv lock or report output as oracle evidence;
  - model wheel tags and source index priority as context.
- npm:
  - use package-lock dependency edges, integrity, resolved URLs, peer dependencies,
    optional dependencies, overrides, and platform filters;
  - keep parallel slots for nested dependencies.
- Maven:
  - prefer effective POM or `mvn dependency:tree` output;
  - model scopes, exclusions, optional dependencies, dependency management, and
    nearest-definition mediation.
- Gradle:
  - prefer `dependencies`, `dependencyInsight`, or lockfiles;
  - model configurations, variants, capabilities, platforms, and attributes as
    adapter evidence.
- Go:
  - use `go list -m all` and `go mod graph`;
  - model MVS, replace, exclude, module path major versions, build tags, GOOS,
    and GOARCH.
- Cargo:
  - use `cargo metadata`;
  - model features, target cfg, build/dev dependencies, patches, alternate
    registries, and semver-incompatible parallel versions.
- Exit criteria:
  - each ecosystem has at least one oracle-backed fixture;
  - adapter output enters the same evidence-to-resolution path;
  - resolver traces name the adapter rule that selected or skipped an edge.

## Phase 5: Snapshot And Query Contract

Status: required for customer-grade evidence.

Goal: snapshots must preserve enough data to audit business answers.

MVP progress: `GraphSnapshot` now emits resolved `occurrences` and
`occurrence_edges`, and `GraphQuery::occurrence_paths_to` returns
evidence-carrying occurrence paths. The remaining work is richer metadata,
adapter identity, policy identity, and repository snapshot identity.

- Expand graph snapshots to include:
  - package source, checksum, signature, purl, license, architecture, source RPM;
  - edge conditions, features, exclusions, relation, scope, confidence, and
    evidence IDs;
  - occurrence IDs for slot-local, bundled, or repeated package instances;
  - resolver adapter name and version;
  - repository metadata IDs and timestamps;
  - policy ID and policy hash when policy affects the answer.
- Fix multi-version query ambiguity.
  Queries must return package refs or slots when more than one version of a
  package exists in a graph.
- Add graph views:
  - resolved occurrence graph projection;
  - resolved installable graph;
  - observed runtime graph;
  - advisory overlay;
  - policy overlay;
  - live patch overlay.
- Keep traversal indexes behind the projection contract:
  - adjacency lists for cold MVP queries;
  - CSR for forward traversal when snapshots get large;
  - CSC for reverse impact;
  - selective reachability labels only for hot workloads with measured need.
- Exit criteria:
  - `explain` can show why a dependency is present or absent using structured
    evidence, not only free-text strings;
  - SBOM, SPDX, VEX, and remediation reports are generated as views over the same
    graph snapshot.

## Phase 6: Storage MVP

Status: replace demo durability with real MVP durability.

Goal: keep storage simple, correct, and testable.

MVP progress: `SqliteGraphStore` now stores immutable snapshot JSON, lookup
indexes, and replayable change events with idempotent snapshot persistence and
restart tests. Remaining work is evidence-record tables, resolver job tables,
schema migrations, retention, pooling, and broader concurrency coverage.

- Implement SQLite storage first:
  - evidence sources and raw artifact digests;
  - normalized evidence records;
  - resolver jobs;
  - immutable snapshots;
  - nodes, edges, skipped dependencies, conflicts, and trace events;
  - invalidation events with monotonic IDs.
- Keep file snapshot export as a human-readable artifact, not the authoritative
  concurrent store.
- Add atomic writes and transactions for all durable state.
- Defer RocksDB until parsed fact volume proves SQLite insufficient.
- Exit criteria:
  - multiple resolver jobs can persist without corrupting indexes;
  - replayed invalidation events produce deterministic rerun plans;
  - tests cover restart, duplicate ingest, and concurrent append behavior.

## Phase 7: AlmaLinux/CloudLinux Demo That Is Not Artificial

Status: final MVP demonstration.

Goal: deliver a demo that uses real OS evidence and package-manager output.

- On the AlmaLinux 10 VPS, collect:
  - `/etc/os-release`;
  - `dnf repolist --all`;
  - repository metadata digests;
  - installed RPM NEVRA inventory;
  - selected `dnf repoquery` dependency trees;
  - updateinfo/advisory data where available.
- Create a reproducible fixture package set:
  - one core OS package;
  - one package with weak dependencies;
  - one package with virtual/file provides;
  - one package tied to errata;
  - one architecture-sensitive case.
- Add a CloudLinux-focused fixture using public docs and checked-in sanitized
  metadata:
  - SWNG repository identity;
  - ALT-ELS selector repository availability;
  - ELS/FIPS/KernelCare profiles.
- Exit criteria:
  - `graphscope resolve-evidence examples/real-world/...` produces a real graph;
  - demo artifacts identify which data came from the host, repo metadata,
    advisories, and synthetic product fixtures;
  - customer-facing outputs do not rely on artificial dependencies for the main
    OS package story.

## Phase 8: CI And Conformance

Status: expand tests while keeping them cheap.

Goal: prevent drift between claims, docs, and implemented behavior.

- Add test classes:
  - parser conformance;
  - DNF oracle comparison;
  - snapshot golden tests;
  - adapter capability contract tests;
  - storage restart and concurrency tests;
  - report/export schema smoke tests;
  - AlmaLinux native CI smoke tests.
- Run native AlmaLinux tests in CI container and periodically on the VPS when
  repository behavior matters.
- Mark tests as `offline`, `native`, or `networked` so CI remains predictable.
- Exit criteria:
  - all public claims map to tests;
  - adapter gaps are visible in machine-readable capability output;
  - generated demo artifacts are refreshed by a script and verified in CI.

## MVP Completion Criteria

The project can call itself a complete MVP when all of these are true:

- It resolves at least one real AlmaLinux RPM dependency graph from observed
  inventory plus repository/advisory evidence.
- It resolves or imports usable graphs for at least five ecosystems through
  package-manager-backed evidence, not only handcrafted repository data.
- It distinguishes declared, locked, resolved, observed, advisory, policy, and
  live patch evidence.
- It preserves enough provenance to explain every selected, skipped, conflicting,
  or policy-blocked edge.
- It stores snapshots and events durably with transactional semantics.
- It exports customer-ready SBOM, SPDX, VEX, impact, SLA, and remediation views
  without making those formats the internal source of truth.
- It has an honest capability matrix and no badges that imply missing
  implementations.

## Deferred Work

These are important, but not needed for the complete MVP.

- Dedicated graph database.
- Global transitive closure materialization.
- PCSR, LSMGraph, ChunkGraph, DAG compression, and advanced reachability indexes
  until production graph size and query telemetry justify them.
- RocksDB high-volume parsed fact cache.
- Full web UI.
- Direct libsolv/libdnf bindings if the DNF oracle adapter is sufficient for MVP.
- Full Gradle source-language parsing.
- Automatic internet-wide registry mirroring.
- ML or AI summarization of graph explanations.

## Open Decisions

- Should the RPM adapter first call DNF as an external oracle, bind libdnf5, or
  bind libsolv directly?
- Which CloudLinux repository and token facts can be stored without exposing
  customer secrets?
- How much KernelCare patch state belongs in the dependency graph versus a runtime
  patch overlay?
- Should policy changes be part of the context hash, snapshot metadata, or both?
- Which export schema validators should be added once dependencies are allowed?
