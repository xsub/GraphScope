# Roadmap

## Phase 0: Architecture And Executable Model

Status: implemented in this repository.

- Universal dependency model.
- Context-aware generic resolver.
- Ecosystem selection policy hooks.
- Demo graph across RPM, Python, Maven, npm, Go, and Cargo.
- Initial conformance-style unit tests.
- Architecture, business strategy, and algorithm documentation.

## Phase 1: Resolver Correctness Foundation

Status: MVP implemented; production ecosystem adapters remain follow-up work.

- Build fixture corpus for RPM, pip, Poetry, Maven, Gradle, npm, Go, and Cargo.
  Initial RPM inventory, pip, Maven POM, Gradle, npm package-lock, Go, and Cargo
  fixtures are implemented.
- Add manifest, lockfile, inventory parsers and normalized evidence records.
  Initial pip pinned requirements, Go module requirements, Cargo.lock package
  parsing, npm package-lock parsing, Maven dependency parsing, Gradle dependency
  parsing, RPM inventory parsing, and normalized evidence catalog are
  implemented.
- Add auto-detecting evidence ingestion workflow for supported fixture formats.
  Implemented through `parse_evidence` and `graphscope evidence <path>`.
- Add executable adapter coverage matrix for supported ecosystems.
  Implemented through `adapter_profiles` and `graphscope adapters`.
- Integrate libsolv or DNF metadata for RPM resolution.
- Add Maven effective-POM and Gradle dependency insight ingestion.
- Add npm package-lock and peer dependency propagation.
- Add Go module graph and MVS adapter.
- Add Cargo feature unification and target dependency adapter.
- Emit graph snapshots as stable JSON for golden tests.
  Implemented for resolver output and exposed through `graphscope snapshot`.
- Emit resolver decision traces for selected, skipped, and conflicting
  requirements.
  Implemented in `ResolveResult.trace`, stable snapshot JSON, and the demo CLI.

## Phase 2: CloudLinux/TuxCare Product Slice

Status: MVP implemented for graph impact workflows.

- Model AlmaLinux and CloudLinux repository channels, architectures, module
  streams, ELS channels, KernelCare/live-patch metadata, and errata.
  MVP context modeling includes distro, architecture, repository channels, ELS,
  KernelCare, weak dependencies, and optional GPU features.
- Ingest TuxCare advisory and patch metadata.
  MVP advisory records and demo advisories are implemented.
- Build reverse-dependency and impact-analysis APIs.
  Implemented through `GraphQuery::reverse_dependencies` and `ImpactReport`.
- Add customer-context graph comparison: CloudLinux versus AlmaLinux, ELS enabled
  versus disabled, x86_64 versus aarch64, FIPS versus standard.
  MVP graph diff API and demo GPU-context comparison are implemented.
- Produce internal CVE impact reports with evidence paths.
  Implemented through `graphscope impact` and `graphscope report`.

## Phase 3: Platform Scale

Status: MVP implemented with in-memory control-plane primitives.

- Add resolver work queue and stateless resolver worker service.
  Implemented through `ResolverWorkQueue` and `ResolverService`.
- Add durable evidence store and immutable graph snapshot store.
  MVP in-memory graph store and dependency-free durable file snapshot store are
  implemented; production SQLite/RocksDB adapters remain follow-up.
- Add graph closure cache and reverse-dependency indexes.
  MVP query APIs compute closure and reverse dependencies from snapshots.
- Add incremental invalidation based on repository/advisory/package changes.
  MVP invalidation planning is implemented for package, advisory, repository,
  and policy changes. A durable file event log is implemented for replayable
  invalidation inputs; production event buses remain follow-up.
- Add multi-tenant access controls and customer data isolation.
  MVP graph records are keyed by tenant, product, and context hash. Tenant
  access policy primitives and authorized lookups are implemented through
  `TenantAccessPolicy`, `InMemoryGraphStore::authorized_get`, and
  `graphscope access`.
- Add API and UI for "why is this dependency present?" investigations.
  Implemented as `GraphQuery::explain_package` and `graphscope explain`.

## Phase 4: Customer-Facing Intelligence

Status: MVP implemented for generated views and reports.

- Export CycloneDX, SPDX, and VEX views.
  CycloneDX-style, SPDX-style, and VEX-style views are implemented.
- Generate customer remediation reports.
  Implemented through `RemediationReport` and `graphscope report`.
- Add policy engine for allowed registries, pinned versions, unsupported EOL
  dependencies, and CloudLinux/TuxCare coverage.
  MVP policy evaluation is implemented for source allowlists, signing
  requirements, denied packages, wildcard requirements, and package coverage.
- Add SLA dashboards for exposure, patch status, and lifecycle risk.
  MVP SLA risk summaries and product risk dashboard aggregates are implemented
  for advisory and policy findings; production web dashboards remain follow-up.

## Open Decisions

- Whether production graph storage should use a dedicated graph database or a
  compressed adjacency plus columnar analytics model.
- Which RPM resolver integration is safest: direct libsolv bindings, DNF service
  subprocess isolation, or precomputed repository resolution traces.
- How much customer runtime inventory should be joined into the same graph versus
  stored as a separate observed-state overlay.
- How to version resolver behavior so customer-facing reports remain reproducible
  while resolver correctness improves.
