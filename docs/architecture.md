# GraphScope Architecture

GraphScope is organized around a deliberately simple split:

- The kernel layer records facts and performs constant-time guard checks.
- Userspace builds meaning by replaying facts into a causality graph.
- Protection decisions are derived from facts, trust, baseline, and rule outputs.

## Runtime Flow

```text
eBPF / BPF LSM
  -> ring buffers and BPF maps
  -> Rust collector
  -> event journal
  -> graph engine
  -> trust engine
  -> rule engine
  -> baseline engine
  -> investigation interfaces
```

## Current Prototype

The repository currently implements the userspace core:

- `event`: normalized runtime facts.
- `graph`: entity and relationship model with causality traversal.
- `rules`: constant-time guard-rule equivalents for early prototyping.
- `trust`: package/build provenance verdicts.
- `baseline`: expected behavior learning and drift detection.
- `storage`: journal and kernel policy store traits with in-memory adapters.
- `investigation`: "why did this happen?" query layer.

The in-memory graph is intentionally dependency-light. A future Petgraph-backed
implementation can live behind the same graph-facing APIs once external
dependencies are introduced.

## Kernel Boundary

The kernel side should only perform:

- observation
- filtering
- aggregation
- critical guard checks

The kernel side should not perform:

- graph traversal
- historical queries
- trust path reconstruction
- AI inference

This keeps BPF programs bounded, auditable, and compatible with verifier
constraints.

## Storage Boundary

GraphScope uses three persistence concepts:

- Hot graph: active in-memory causality graph.
- Event journal: append-only replayable event stream.
- Metadata store: baseline, trust, package, and investigation snapshots.

The prototype provides in-memory traits first. RocksDB and SQLite adapters can
be added without changing the higher-level engines.
