# Roadmap

## Phase 0: Architecture And Executable Model

Status: implemented in this repository.

- Universal dependency model.
- Context-aware generic resolver.
- Ecosystem selection policy hooks.
- Demo graph across RPM, Python, Maven, npm, Go, and Cargo.
- Initial conformance-style unit tests.
- Staff-level architecture, business strategy, and algorithm documentation.

## Phase 1: Resolver Correctness Foundation

- Build fixture corpus for RPM, pip, Poetry, Maven, Gradle, npm, Go, and Cargo.
- Add lockfile parsers and normalized evidence records.
- Integrate libsolv or DNF metadata for RPM resolution.
- Add Maven effective-POM and Gradle dependency insight ingestion.
- Add npm package-lock and peer dependency propagation.
- Add Go module graph and MVS adapter.
- Add Cargo feature unification and target dependency adapter.
- Emit graph snapshots as stable JSON for golden tests.

## Phase 2: CloudLinux/TuxCare Product Slice

- Model AlmaLinux and CloudLinux repository channels, architectures, module
  streams, ELS channels, KernelCare/live-patch metadata, and errata.
- Ingest TuxCare advisory and patch metadata.
- Build reverse-dependency and impact-analysis APIs.
- Add customer-context graph comparison: CloudLinux versus AlmaLinux, ELS enabled
  versus disabled, x86_64 versus aarch64, FIPS versus standard.
- Produce internal CVE impact reports with evidence paths.

## Phase 3: Platform Scale

- Add resolver work queue and stateless resolver worker service.
- Add durable evidence store and immutable graph snapshot store.
- Add graph closure cache and reverse-dependency indexes.
- Add incremental invalidation based on repository/advisory/package changes.
- Add multi-tenant access controls and customer data isolation.
- Add API and UI for "why is this dependency present?" investigations.

## Phase 4: Customer-Facing Intelligence

- Export CycloneDX, SPDX, and VEX views.
- Generate customer remediation reports.
- Add policy engine for allowed registries, pinned versions, unsupported EOL
  dependencies, and CloudLinux/TuxCare coverage.
- Add SLA dashboards for exposure, patch status, and lifecycle risk.

## Open Decisions

- Whether production graph storage should use a dedicated graph database or a
  compressed adjacency plus columnar analytics model.
- Which RPM resolver integration is safest: direct libsolv bindings, DNF service
  subprocess isolation, or precomputed repository resolution traces.
- How much customer runtime inventory should be joined into the same graph versus
  stored as a separate observed-state overlay.
- How to version resolver behavior so customer-facing reports remain reproducible
  while resolver correctness improves.
