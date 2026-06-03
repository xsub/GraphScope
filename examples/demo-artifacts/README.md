# Demo Artifacts

These files are generated from the GraphScope CLI demo dataset and checked in so
reviewers can inspect the MVP outputs without running the binary first.

Regenerate them from the repository root with:

```sh
cargo run --quiet -- demo > examples/demo-artifacts/demo.txt
cargo run --quiet -- snapshot > examples/demo-artifacts/snapshot.json
cargo run --quiet -- impact > examples/demo-artifacts/impact.txt
cargo run --quiet -- report > examples/demo-artifacts/remediation-report.md
cargo run --quiet -- sbom > examples/demo-artifacts/sbom.cyclonedx.json
cargo run --quiet -- spdx > examples/demo-artifacts/sbom.spdx.json
cargo run --quiet -- vex > examples/demo-artifacts/vex.json
cargo run --quiet -- policy > examples/demo-artifacts/policy.txt
cargo run --quiet -- sla > examples/demo-artifacts/sla.json
cargo run --quiet -- dashboard > examples/demo-artifacts/dashboard.json
cargo run --quiet -- invalidate > examples/demo-artifacts/invalidation.txt
cargo run --quiet -- adapters > examples/demo-artifacts/adapters.txt
cargo run --quiet -- access > examples/demo-artifacts/access.txt
cargo run --quiet -- diff > examples/demo-artifacts/diff.txt
cargo run --quiet -- evidence tests/fixtures/sbom/cyclonedx.json > examples/demo-artifacts/cyclonedx-evidence.txt
cargo run --quiet -- persist examples/demo-artifacts/durable-store > examples/demo-artifacts/persist.txt
cargo run --quiet -- events examples/demo-artifacts/durable-store > examples/demo-artifacts/events.txt
```

## Files

- `demo.txt`: resolved graph, skipped dependencies, conflicts, and resolver trace.
- `snapshot.json`: stable graph snapshot JSON.
- `impact.txt`: advisory impact findings with dependency paths.
- `remediation-report.md`: customer-ready remediation report.
- `sbom.cyclonedx.json`: CycloneDX-style SBOM export.
- `sbom.spdx.json`: SPDX-style SBOM export.
- `vex.json`: VEX-style vulnerability status export.
- `policy.txt`: customer policy evaluation output.
- `sla.json`: single-product risk and remediation summary.
- `dashboard.json`: portfolio risk dashboard aggregate.
- `invalidation.txt`: planned graph re-runs for metadata changes.
- `adapters.txt`: executable ecosystem adapter coverage matrix.
- `access.txt`: tenant access policy and authorized lookup demo.
- `diff.txt`: graph comparison across production and production+GPU contexts.
- `cyclonedx-evidence.txt`: normalized evidence parsed from a CycloneDX fixture.
- `persist.txt`: durable file-store persistence summary.
- `events.txt`: durable change-event log append summary.
- `durable-store/index.tsv`: persisted snapshot index.
- `durable-store/events.tsv`: replayable change-event log.
- `durable-store/snapshots/*.json`: immutable persisted graph snapshot.
