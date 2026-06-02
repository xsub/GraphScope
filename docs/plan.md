# GraphScope Plan

This is the current plan for GraphScope after the shift from Runtime Provenance
Explorer to Linux Runtime Causality Platform.

## Product Definition

GraphScope is a Universal Relationship Graph for Linux runtime causality,
provenance, trust, protection, and investigation.

It is not an EDR, SIEM, or monitoring product. Those systems may consume
GraphScope findings, but GraphScope's own output is a reconstructed graph path.

## Non-Negotiable Constraints

- Kernel logic remains O(1).
- Kernel code never performs graph traversal.
- Kernel code never performs historical queries.
- Kernel code never performs trust path reconstruction.
- Kernel code never executes AI inference.
- Userspace owns graph traversal, trust analysis, baselines, and investigations.

## Current Implementation Direction

The current prototype implements the userspace shape:

- normalized facts as events
- universal node and edge model
- runtime causality graph
- supply-chain provenance nodes
- hard guard findings
- userspace baseline findings
- trust path reconstruction
- alert investigation as graph paths

## Universal Relationship Graph Scope

The graph must support:

- dependency relationships
- build provenance
- package ownership
- runtime process causality
- file activity
- socket activity
- SELinux context transitions
- namespace and container boundaries
- BPF program and kernel module provenance
- SBOM components
- trust assumptions
- security events

## Storage Plan

Layer 1: BPF Maps.

Purpose: kernel policy cache and fast security decisions.

Layer 2: Petgraph in RAM.

Purpose: active runtime graph.

Layer 3: RocksDB.

Purpose: append-only event journal.

Layer 4: SQLite.

Purpose: baseline, trust metadata, configuration, and investigation snapshots.

## Alert Contract

Every alert must include:

- what happened
- why it happened
- what caused it
- violated trust assumptions
- the graph path that led there

An alert without a path is not a GraphScope alert.

## Next Build Phases

1. Stabilize the universal graph schema.
2. Add typed soft rules separate from kernel hard guards.
3. Add RPM metadata ingestion and digest verification.
4. Add RocksDB event journal adapter.
5. Add SQLite metadata adapter.
6. Add Petgraph-backed graph adapter.
7. Add container provenance.
8. Add namespace provenance.
9. Add eBPF program provenance.
10. Add kernel module provenance.
11. Add build provenance ingestion.
12. Add SBOM ingestion.
13. Add end-to-end trust path policy evaluation.
