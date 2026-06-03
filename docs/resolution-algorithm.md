# Resolution Algorithm

The resolver converts a root project or package plus a `ResolutionContext` into
an immutable dependency graph snapshot. The algorithm must preserve ecosystem
semantics while exposing one universal graph contract.

## Inputs

- Root package or project dependencies.
- Candidate package metadata from manifests, lockfiles, registries, RPM repodata,
  module metadata, SBOMs, and runtime inventory.
- Resolution context: distro, architecture, package channels, profiles, language
  versions, enabled features, optional dependency policy, and package-manager
  mode.
- Resolver adapter rules for candidate selection and conflict mediation.

## Output

- Resolved package nodes.
- Activated dependency edges.
- Skipped dependency records with reasons.
- Conflict diagnostics.
- Resolver trace and evidence references.
- Snapshot metadata: resolver version, context hash, source timestamps, and
  registry/repository metadata versions.

## Generic Work Queue

The prototype uses this generic loop:

```text
queue = root dependency requirements
constraints = empty
selected = empty
graph = empty

while queue is not empty:
    requirement = queue.pop()

    if target is excluded by an ancestor edge:
        record skipped dependency
        continue

    if requirement is inactive in the current context:
        record skipped dependency
        continue

    add requirement to the constraint set for the target selection slot

    candidate = select package version using ecosystem policy
    if no candidate satisfies all active constraints:
        record conflict diagnostic
        continue

    if candidate differs from previous selection:
        update selected node
        enqueue candidate dependencies

    add edge from requester to candidate
```

The generic engine does not pretend every ecosystem resolves the same way.
Ecosystem adapters customize candidate enumeration, slot identity, version
selection, conflict mediation, edge activation, and dependency expansion.

## Selection Policies

Initial policies:

- Highest compatible candidate for most semver-style package managers.
- Minimal compatible candidate for Go Minimal Version Selection.
- Single-version package slot for RPM, Maven-like mediated graphs, Go, and most
  Python lockfile views.
- Parallel package slots for npm-style dependency subtrees.

Production policies to add:

- DNF/libsolv-backed RPM decisions.
- Maven nearest-definition mediation.
- Gradle variant-aware attribute matching.
- npm peer dependency constraint propagation.
- Cargo feature unification and semver-incompatible parallel crate versions.
- Poetry source priority and dependency group behavior.

## Context Evaluation

Every dependency edge is activated by predicates:

- OS and distro;
- architecture;
- language/runtime version;
- package-manager profile;
- optional feature or extra;
- repository/channel policy;
- build tags or target triples.

Inactive edges are recorded, not discarded. This matters for customer
explanations such as "the GPU library is not installed because this image is
aarch64" or "the macOS watcher dependency is irrelevant on CloudLinux."

## Conflict Handling

A conflict is not only a failed build. It is a business signal:

- incompatible package constraints;
- missing package in a repository channel;
- disallowed registry source;
- checksum/signature mismatch;
- architecture-incompatible artifact;
- blocked package by customer policy;
- resolver adapter mismatch or unsupported feature.

GraphScope should store conflicts with enough detail to route them:

- customer/project;
- ecosystem;
- package identity;
- all contributing constraints;
- context hash;
- adapter version;
- suggested remediation when known.

## Scaling The Resolver

Resolution is embarrassingly parallel across roots and contexts, but metadata
access patterns dominate cost. The production resolver should:

- keep per-ecosystem metadata mirrors close to workers;
- memoize package candidate lists by package ID, context, and repository state;
- memoize resolved subgraphs when the same root and context recur;
- shard queues by ecosystem and customer priority;
- deduplicate identical dependency subgraphs across products;
- use bounded traces and structured diagnostics to avoid log-scale explosions;
- re-run only impacted snapshots after repository, advisory, or policy changes.

## Correctness Program

Each ecosystem adapter needs conformance fixtures:

- official package-manager examples;
- known edge cases from CloudLinux/TuxCare support history;
- lockfile round-trips;
- repository-channel comparison cases;
- architecture and distro matrix tests;
- resolver-version golden snapshots;
- intentionally conflicting graphs.

Correctness is a product feature. A graph that is 95 percent accurate can still
create expensive false positives for vulnerability triage and customer reports.
