# GraphScope Architecture

GraphScope is a runtime causality engine backed by a Universal Relationship
Graph. The graph joins runtime activity, trust metadata, build provenance,
dependencies, SBOM components, packages, isolation boundaries, and security
events.

The architecture is deliberately split:

- Kernel code records facts and performs constant-time hard guards.
- Userspace builds meaning by replaying facts into the graph.
- Investigation results are reconstructed graph paths, not log messages.

## Architectural Goal

GraphScope is not an EDR, SIEM, or monitoring platform.

GraphScope models why runtime behavior happened by connecting:

- software provenance
- dependency relationships
- package ownership
- runtime process causality
- file and socket activity
- trust assumptions
- isolation boundaries
- kernel security events

## Runtime Flow

```text
eBPF / BPF LSM
  -> ring buffers and BPF maps
  -> Rust collector
  -> RocksDB event journal
  -> Petgraph hot graph
  -> SQLite metadata store
  -> trust engine
  -> hard guard and soft rule outputs
  -> baseline engine
  -> investigation interfaces
```

## Core Design Constraint

The system must remain operational under fork bombs, network floods,
high-load application servers, and container-dense environments.

Therefore the kernel side must never perform:

- graph traversal
- historical queries
- trust path reconstruction
- AI inference

Kernel logic must remain O(1). Expensive graph operations are userspace work.

## Data Architecture

GraphScope uses four storage layers:

| Layer | Technology | Purpose |
| --- | --- | --- |
| 1 | BPF Maps | Kernel policy cache and fast security decisions |
| 2 | Petgraph in RAM | Active runtime graph and hot causality queries |
| 3 | RocksDB | Append-only event journal and replay capability |
| 4 | SQLite | Baseline, trust metadata, configuration, and investigation snapshots |

The current prototype keeps these boundaries but implements them in memory:

- `CausalityGraph`: hot graph.
- `InMemoryEventJournal`: event journal stand-in.
- `InMemoryKernelPolicyStore`: BPF map stand-in.
- `InMemoryMetadataStore`: SQLite metadata stand-in.

## Universal Graph Model

All entities are nodes.

Current node types include:

- `Process`
- `File`
- `Socket`
- `User`
- `SELinux Context`
- `Namespace`
- `Container`
- `Image`
- `Service`
- `RPM Package`
- `Build Artifact`
- `Source Repository`
- `Dependency`
- `SBOM Component`
- `BPF Program`
- `Kernel Module`
- `Security Event`

Relationships are edges.

Current relationship types include:

- `spawned`
- `opened`
- `modified`
- `connected`
- `inherited`
- `authenticated`
- `transitioned`
- `loaded`
- `executed`
- `depends_on`
- `built_from`
- `installed_from`
- `owns`
- `caused`
- `trusted_by`
- `denied_by`

This model is intentionally compatible with dependency graphs, build provenance
graphs, runtime causality graphs, trust graphs, and isolation graphs.

## Kernel Security Model

GraphScope separates hard guards from soft rules.

Hard guards execute inside the kernel:

- `unexpected_uid0_transition`
- `unexpected_capability_gain`
- `execution_from_tmp_as_root`
- `unexpected_bpf_program_load`
- `unexpected_kernel_module_load`

Soft rules execute in userspace:

- `nginx_spawned_shell`
- `unusual_destination`
- `first_seen_path`
- baseline deviations
- trust path violations

Hard guards must remain O(1). Soft rules may use graph traversal, replayed
history, baselines, package metadata, and trust paths.

## Investigation Model

Every alert must answer:

- What happened?
- Why did it happen?
- What caused it?
- What trust assumptions were violated?
- Which graph path led here?

A valid alert is a reconstructed causality path with trust context.

Example:

```text
Source Repository
  -> Dependency
  -> Build Artifact
  -> RPM
  -> Installed File
  -> Process
  -> Security Event
```

## Future Phases

Phase 11: Container provenance.

Phase 12: Namespace provenance.

Phase 13: eBPF provenance.

Phase 14: Kernel module provenance.

Phase 15: Build provenance integration.

Phase 16: SBOM integration.

Phase 17: Trust path reconstruction.
