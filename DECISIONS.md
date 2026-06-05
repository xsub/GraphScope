# Design Decisions

This document records the main design decisions taken while building the
GraphScope MVP for AlmaLinux OS, CloudLinux OS, and TuxCare dependency
intelligence.

The goal is not to preserve every discussion detail. The goal is to make the
current architecture understandable, reviewable, and honest about what is
implemented versus what remains a production adapter gap.

## 1. Use A Typed Dependency Hypergraph As The Semantic Source Of Truth

Status: accepted.

Decision: model unresolved dependency declarations as typed, context-conditioned
hypergraph clauses, not as plain package-to-package edges.

Why: dependency declarations are not always binary edges. RPM capabilities,
virtual provides, conflicts, weak dependencies, Maven exclusions, Gradle
variants, npm peers, Python extras, Go build tags, Cargo features, bundled code,
dynamic loading, and platform markers all need richer structure than a simple
directed graph can carry.

Consequences:

- `RequirementClause` and `DependencyAlternative` preserve native package-manager
  meaning before resolution.
- Context predicates decide whether a clause is active before candidate
  selection.
- A graph database or SBOM can consume the result, but neither is the canonical
  source for resolver semantics.

Tradeoff: the model is more explicit than a plain graph, but it avoids false
accuracy from flattening package-manager rules too early.

## 2. Resolve First, Then Traverse Resolved Occurrence Projections

Status: accepted.

Decision: customer-facing graph questions run on resolved occurrence
projections, not on unresolved declarations.

Why: questions such as "is this package present?", "who is affected?", and "why
is this package in the graph?" only make sense after a package manager, lockfile,
repository snapshot, and environment context have selected concrete package
versions.

Consequences:

- `ResolvedGraphProjection` builds forward and reverse indexes over selected
  occurrences.
- Traversal APIs can answer dependency closure, reverse impact, paths, graph
  diffs, SBOM exports, VEX, reports, SLA summaries, and dashboards.
- Occurrence identity is kept separate from package identity so parallel
  versions, bundled copies, and local slots can be represented.

Tradeoff: the MVP currently derives occurrence projection from resolver output.
The production direction is to carry occurrence identity directly through
resolution.

## 3. Make Resolution Context Part Of The Graph Key

Status: accepted.

Decision: distro, architecture, runtime version, repository channel, enabled
features, profile, policy, and package-manager mode are first-class inputs to
resolution and snapshot identity.

Why: the same project can have different dependencies on AlmaLinux versus
CloudLinux, x86_64 versus aarch64, production versus test, GPU versus non-GPU,
ELS-enabled versus standard repositories, or FIPS versus non-FIPS environments.

Consequences:

- `ResolutionContext` has a stable key used by snapshots and stores.
- Inactive dependencies are recorded with skipped reasons instead of silently
  discarded.
- Graph diffs can compare environment-specific dependency changes.

Tradeoff: context increases snapshot cardinality, so production storage must use
deduplication, caching, and invalidation planning.

## 4. Preserve Declared, Locked, Resolved, And Observed Evidence Separately

Status: accepted.

Decision: do not merge all dependency inputs into one generic dependency list.
Keep declared manifests, lockfiles, resolved package-manager output, SBOMs, RPM
runtime inventories, and observed host/container facts as separate evidence
shapes.

Why: each evidence type answers a different question. A manifest says what was
requested, a lockfile says what was pinned, a resolver says what is selected, an
SBOM says what a build or inventory contains, and runtime evidence says what was
observed in an environment.

Consequences:

- Evidence records retain shape, source, confidence, and stable IDs.
- `resolve-evidence` can build resolver inputs while preserving provenance.
- Reports can explain whether a package was declared, locked, resolved, observed,
  or only exported by an SBOM.

Tradeoff: this is more bookkeeping than a single parsed list, but it prevents
incorrect business conclusions from mixing evidence layers.

## 5. Use Package-Manager Semantics Through Adapters And Oracles

Status: accepted.

Decision: the shared resolver owns graph assembly, determinism, diagnostics, and
trace output, while ecosystem adapters own candidate enumeration and
package-manager-specific mediation.

Why: pip, Poetry, Maven, Gradle, npm, Go modules, Cargo, RPM, and DNF do not
resolve dependencies the same way. A fake universal resolver would create
plausible but wrong results.

Consequences:

- The adapter matrix documents which behavior is implemented, fixture-backed,
  contract-level, or planned.
- The MVP implements core policies such as highest-compatible selection, Go
  minimal-version selection, Maven-style exclusions, npm/Cargo parallel slots,
  context predicates, conflicts, skipped edges, and traces.
- Production RPM correctness should start with DNF/libsolv oracle output on
  AlmaLinux/CloudLinux before direct native bindings are attempted.

Tradeoff: adapters add integration work, but correctness depends on matching the
owning package manager.

## 6. Prioritize RPM/DNF, AlmaLinux, CloudLinux, And TuxCare Reality

Status: accepted.

Decision: keep RPM/DNF, repository channels, errata, ELS, CloudLinux mirrors,
ALT-ELS packages, KernelCare/live patch overlays, and TuxCare advisory workflows
as first-class product requirements.

Why: the project is not a generic toy dependency graph. Its business value is
precise dependency intelligence for AlmaLinux OS, CloudLinux OS, and TuxCare
customers.

Consequences:

- RPM coordinates include room for epoch-version-release, architecture, source
  RPM, repository, signature, capabilities, and virtual provides.
- Advisory impact, remediation, SLA, policy, and dashboard APIs are part of the
  MVP surface.
- Real AlmaLinux 10 runtime inventory evidence is checked in separately from the
  synthetic demo product graph.

Tradeoff: the MVP remains cross-ecosystem, but OS package correctness is the
first production-quality adapter priority.

## 7. Keep The Core Rust MVP Compact And Executable

Status: accepted.

Decision: implement the core model, resolver, queries, exports, storage
contracts, demos, and tests in Rust as a compact executable MVP.

Why: the architecture should be reviewable and testable. A smaller core makes it
easier to validate graph semantics before adding platform services, large
storage systems, and native package-manager integrations.

Consequences:

- Public Rust APIs and CLI workflows exercise the same model.
- Tests cover version constraints, context predicates, parsers, resolver
  behavior, hypergraph projection, impact, policy, storage, exports, and platform
  workflows.
- The benchmark command gives graph creation and traversal an explicit
  performance harness.

Tradeoff: the MVP is not yet a distributed service. Production deployment still
needs worker orchestration, durable metadata stores, adapter services, authz, and
operational observability.

## 8. Store Immutable Snapshots And Replayable Events

Status: accepted.

Decision: resolved graph outputs are immutable snapshots. Changes are represented
by new snapshots and replayable events rather than in-place graph mutation.

Why: dependency intelligence is audit-sensitive. Security, support, and customer
reports need to know which resolver version, context, evidence, repository
state, advisory state, and policy state produced an answer.

Consequences:

- File and SQLite stores persist snapshot JSON plus compact indexes.
- Event logs feed invalidation planning for package, repository, advisory, and
  policy changes.
- Snapshot IDs and context keys make graph comparison and reproducibility
  practical.

Tradeoff: immutable snapshots can duplicate data. Production storage should add
compression, deduplication, and query indexes rather than weakening the audit
contract.

## 9. Prefer SQLite For MVP Durability; Defer RocksDB

Status: accepted.

Decision: implement SQLite and file-backed stores for MVP durability, and keep
RocksDB as a later high-volume parsed-fact cache.

Why: SQLite is enough for restart-safe tests, demos, and visible queries. It is
also easier to inspect and validate while the model is still changing.

Consequences:

- `SqliteGraphStore` backs the SQLite capability claim.
- File stores remain useful for deterministic artifacts and simple demos.
- RocksDB badges and docs must describe planned or deferred cache use unless a
  real backend is implemented.

Tradeoff: SQLite is not the final high-throughput metadata cache, but it is the
right MVP persistence layer.

## 10. Treat SBOM, SPDX, VEX, Reports, SLA, And Dashboards As Views

Status: accepted.

Decision: export formats and business reports are generated from resolved graph
snapshots instead of becoming separate authoritative models.

Why: CycloneDX, SPDX, VEX, remediation reports, SLA summaries, and dashboards are
valuable outputs, but each is a projection for a specific audience. The source
of truth remains the resolved graph plus provenance.

Consequences:

- Exports stay consistent with resolver decisions and context.
- Advisory and policy findings share dependency paths and reverse-dependency
  queries.
- Customer-facing reports can explain their evidence lineage.

Tradeoff: some export-specific fields need mapping and enrichment, but the
project avoids divergent inventories.

## 11. Make Explainability A Core Resolver Feature

Status: accepted.

Decision: every selected, skipped, and conflicting dependency decision should be
traceable.

Why: CloudLinux, AlmaLinux, and TuxCare workflows need answers that engineers,
support teams, security teams, and customers can trust. A graph without
explanations is not enough for remediation, CVE triage, or policy disputes.

Consequences:

- Resolver trace events record requester, target, slot, constraints, candidates,
  rejected candidates, selected candidate, outcome, and resolver rule.
- Query APIs can answer "why is this present?" and "why was this skipped?"
- Conflict diagnostics preserve enough context to route remediation work.

Tradeoff: traces add storage volume. Production should bound and compress traces
without losing audit-critical fields.

## 12. Keep Claims Matched To Implemented Capability

Status: accepted.

Decision: README badges, docs, artifacts, and demos must distinguish implemented
MVP behavior from fixture parser coverage, adapter contracts, planned native
adapters, and synthetic examples.

Why: overclaiming resolver fidelity would create bad business expectations. The
project should be ambitious, but it must remain truthful about what is executable
today.

Consequences:

- The README calls out synthetic demo data separately from real AlmaLinux runtime
  inventory evidence.
- The capability matrix and roadmap identify native adapter gaps.
- Tests and checked-in artifacts are used to keep public claims grounded.

Tradeoff: careful wording can look less flashy, but it protects credibility.

## 13. Use Deterministic Benchmarks For Graph Creation And Traversal

Status: accepted.

Decision: add a deterministic synthetic benchmark for graph creation and
traversal.

Why: graph algorithm changes need their own performance harness. Without a
stable workload, resolver and traversal improvements cannot be compared cleanly.

Consequences:

- `graphscope benchmark [layers width fanout max_paths]` measures repository
  construction, resolver graph creation, query indexing, dependency closure,
  occurrence projection, occurrence closure, and capped path enumeration.
- Tests assert the deterministic benchmark graph shape.
- Future performance work can compare algorithmic changes without relying on
  business demo timing.

Tradeoff: the benchmark is intentionally synthetic. It measures graph algorithm
behavior, not full package-manager adapter cost.

## 14. Keep KISS As A Design Constraint, Not A Reason To Flatten Semantics

Status: accepted.

Decision: keep code readable and compact, but do not simplify away facts that
change dependency truth.

Why: package-manager behavior is inherently detailed. The right simplification is
clear boundaries between evidence, clauses, resolution, projection, query,
storage, and exports. The wrong simplification is pretending all dependencies
are identical edges.

Consequences:

- The resolver core stays small.
- Specialized semantics move to model types, context predicates, and adapters.
- Refactors should remove bloat and duplication while preserving correctness
  fields.

Tradeoff: this requires discipline. Small code that lies is worse than slightly
larger code that preserves the dependency semantics users need.

## Current Production Gaps Accepted By These Decisions

These decisions explain the current MVP, but they do not claim production
completion. The most important remaining gaps are:

- evidence-to-hypergraph wiring for every parser shape;
- DNF/libsolv oracle adapter and RPM repository metadata ingestion;
- richer PEP 440, PEP 508, Maven, Gradle, npm, Go, Cargo, and RPM version and
  resolver semantics;
- direct occurrence identity inside the resolver;
- production metadata storage, migrations, concurrency, and compaction;
- larger conformance suites against package-manager-native output;
- scale tests with real repository metadata and customer-shaped project sets.

The current implementation is therefore best understood as a truthful executable
MVP plus architecture contract, not as the final production resolver platform.
