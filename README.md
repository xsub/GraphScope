# GraphScope

GraphScope is a Linux Runtime Causality Platform built around a Universal
Relationship Graph.

GraphScope is not an EDR.

GraphScope is not a SIEM.

GraphScope is not a monitoring platform.

GraphScope models relationships between software, processes, files, sockets,
trust artifacts, supply-chain metadata, and isolation boundaries. The core
product question remains:

```text
Why did this happen?
```

But the graph is broader than runtime provenance alone. It is designed to join:

- dependency graphs
- build provenance graphs
- runtime causality graphs
- trust graphs
- isolation graphs

## Status

This repository contains an initial Rust userspace prototype. It is not yet an
eBPF collector or host protection agent, but the model now points at the broader
GraphScope direction: a universal graph that can connect source code to runtime
security events.

Implemented:

- Runtime event model for process, file, network, credential, SELinux, package,
  container, service, BPF, kernel module, and security-event facts.
- Supply-chain event model for source repositories, dependencies, build
  artifacts, RPM packages, installed files, and SBOM components.
- In-memory universal relationship graph with typed nodes and relationships.
- Causality traversal for "why did this happen?" investigations.
- Trust path reconstruction from source or RPM provenance to runtime files.
- Hard-guard rule findings marked as kernel-executable guard logic.
- Baseline engine for userspace soft-rule style behavior drift.
- Replayable in-memory event journal, kernel policy store, and metadata store
  traits.
- CLI demo that reconstructs a suspicious nginx-to-payload-to-security-event
  chain and prints trust paths.

## Quick Start

```sh
cargo test
cargo run -- demo
```

The demo links supply-chain and runtime facts:

```text
Source Repository
  -> Dependency
  -> Build Artifact
  -> RPM
  -> Installed File
  -> Running Process
  -> Runtime Activity
  -> Security Event
```

It emits baseline drift, hard guard findings, trust verdicts, trust paths, and a
causal path.

## Core Design Constraint

GraphScope must remain operational under:

- fork bombs
- network floods
- high-load application servers
- container-dense environments

Therefore:

- graph traversal never occurs inside the kernel
- historical queries never occur inside the kernel
- trust path reconstruction never occurs inside the kernel
- AI never executes inside the kernel
- kernel logic must remain O(1)

## Data Architecture

GraphScope uses four storage layers:

1. BPF Maps
   Purpose: kernel policy cache and fast security decisions.
2. Petgraph in RAM
   Purpose: active runtime graph and hot causality queries.
3. RocksDB
   Purpose: append-only event journal and replay.
4. SQLite
   Purpose: baseline, trust metadata, configuration, and investigation snapshots.

The prototype currently uses dependency-light in-memory implementations while
preserving the boundaries for these adapters.

## Universal Graph Model

All entities are represented as nodes.

Examples:

- Process
- File
- Socket
- SELinux Context
- Namespace
- Container
- RPM Package
- Build Artifact
- Source Repository
- Dependency
- SBOM Component
- Security Event

Relationships are represented as edges.

Examples:

- `spawned`
- `depends_on`
- `built_from`
- `installed_from`
- `owns`
- `opened`
- `connected`
- `transitioned`
- `trusted_by`
- `caused`

## Kernel Security Model

GraphScope separates hard guards from soft rules.

Hard guards execute inside the kernel and must be constant-time:

- `unexpected_uid0_transition`
- `unexpected_capability_gain`
- `execution_from_tmp_as_root`
- `unexpected_bpf_program_load`

Soft rules execute in userspace:

- `nginx_spawned_shell`
- `unusual_destination`
- `first_seen_path`
- baseline deviations

## Investigation Model

Every alert must answer:

- What happened?
- Why did it happen?
- What caused it?
- What trust assumptions were violated?
- Which graph path led here?

A valid alert is not a log entry. A valid alert is a reconstructed causality path
with trust context.

## Future Supply Chain Integration

GraphScope is designed to integrate with build provenance and SBOM systems.

Long-term graph:

```text
Source Code
  -> Dependency
  -> Build
  -> Artifact
  -> RPM
  -> Installed File
  -> Running Process
  -> Runtime Activity
  -> Security Event
```

GraphScope must support traversing this chain end-to-end.

## Roadmap

1. Add a real collector interface and binary event encoding.
2. Add libbpf CO-RE probes for exec, fork, file, network, credential, and LSM events.
3. Replace in-memory journal and metadata stores with RocksDB and SQLite adapters.
4. Add Petgraph-backed graph storage and richer traversal queries.
5. Add Ratatui investigation views.
6. Add package verification through RPM metadata and file digests.
7. Add BPF map synchronization for trusted executables and denied actions.
8. Add SELinux AVC ingestion and context-transition analysis.
9. Add container provenance.
10. Add namespace provenance.
11. Add eBPF program provenance.
12. Add kernel module provenance.
13. Add build provenance integration.
14. Add SBOM integration.
15. Add trust path reconstruction for complete source-to-runtime chains.
