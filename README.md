# GraphScope

GraphScope is a Linux runtime causality, trust, and protection platform.

It continuously models operating-system activity as a graph of processes, files,
sockets, users, SELinux contexts, packages, containers, services, and
kernel-level security events. The core product question is:

```text
Why did this happen?
```

The long-term goal is a runtime digital twin for Linux systems: facts collected
close to the kernel, meaning built in userspace, and protection decisions derived
from causality.

## Status

This repository now contains an initial Rust prototype of the userspace core.
It is not yet an eBPF collector or host protection agent. The current code
establishes the model and execution path that those components can feed.

Implemented:

- Runtime event model for process, file, network, credential, SELinux, package,
  container, service, BPF, and kernel module facts.
- In-memory causality graph with typed nodes and relationships.
- Causality traversal for "why did this happen?" investigations.
- Trust engine for package/build provenance signals.
- Rule engine for kernel-guard-style detections.
- Baseline engine for expected parent, file, and network behavior.
- Replayable in-memory event journal and policy-store traits.
- CLI demo that reconstructs a suspicious nginx-to-payload-to-socket chain.

## Quick Start

```sh
cargo test
cargo run -- demo
```

The demo replays a small event stream:

```text
systemd -> nginx -> bash -> curl -> /tmp/payload -> 1.2.3.4:443
```

It emits guard findings, baseline drift, trust verdicts, and a causal path.

## Design Philosophy

Facts first.

Meaning later.

Protection last.

The kernel collects facts. Userspace builds meaning. Graphs are the source of
truth; logs are supporting evidence. AI may explain findings in the future, but
AI never becomes the source of truth.

## Target Platform

Initial target:

- AlmaLinux 10
- RHEL-compatible distributions

Future targets:

- Fedora
- Rocky Linux
- Oracle Linux
- CentOS Stream

## Intended Stack

Kernel layer:

- eBPF
- BPF LSM
- libbpf CO-RE
- ring buffers
- BPF maps

Userspace:

- Rust
- Tokio
- Petgraph
- SQLite
- RocksDB
- Ratatui

The prototype currently avoids external dependencies so the foundation remains
easy to build in restricted environments. The module boundaries are ready for
Petgraph, RocksDB, SQLite, Tokio, and Ratatui adapters.

## Architecture

```text
Kernel
  -> Event Collection
  -> Kernel Policy Layer
  -> Rust Collector
  -> Event Journal
  -> Graph Engine
  -> Trust Engine
  -> Rule Engine
  -> Baseline Engine
  -> Investigation Engine
  -> CLI / TUI / GUI
```

See [docs/architecture.md](docs/architecture.md) for the implementation layout
and boundary decisions.

## Core Questions

GraphScope is designed to answer:

- Why did this process start?
- Why did this process become root?
- Why was this file modified?
- Why did this outbound connection happen?
- Why did this SELinux violation occur?
- Why was this container allowed to perform this action?
- Why is this executable trusted?
- Why is this process considered suspicious?

## Roadmap

1. Add a real collector interface and binary event encoding.
2. Add libbpf CO-RE probes for exec, fork, file, network, credential, and LSM events.
3. Replace in-memory journal and metadata stores with RocksDB and SQLite adapters.
4. Add Petgraph-backed graph storage and richer traversal queries.
5. Add Ratatui investigation views.
6. Add package verification through RPM metadata and file digests.
7. Add BPF map synchronization for trusted executables and denied actions.
8. Add SELinux AVC ingestion and context-transition analysis.
