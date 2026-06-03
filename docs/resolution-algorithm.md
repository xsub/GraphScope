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

## Resolution Usability Contract

The resolver is the product surface that turns raw dependency evidence into
answers people can trust. A user should not need to understand every package
manager rule to ask:

- "Why is this package present?"
- "Why is this package absent in this environment?"
- "Which constraint or repository decision caused this conflict?"
- "What changed between CloudLinux x86_64, AlmaLinux aarch64, and an ELS
  context?"

For that to work, resolution is not only graph traversal. It is a deterministic
decision pipeline that records every active edge, skipped edge, selected
candidate, conflict, and resolver rule in a way that can be replayed and shown
to engineers, support teams, customers, and security tooling.

## Implemented Resolver Control Flow

The executable implementation lives in `src/resolver.rs`. The shared engine owns
scheduling, state, determinism, diagnostics, graph assembly, and decision trace
emission. Ecosystem-specific behavior is already represented by resolver options
for selection policy and version multiplicity, and the architecture keeps room
for production adapters to replace candidate enumeration and mediation with
package-manager-native logic.

The current resolver performs these concrete operations:

1. Builds a deterministic FIFO queue of `PendingRequirement` values from the
   root requirements.
2. Carries requester package, parent trace event, dependency depth, parent slot,
   and inherited exclusions with every queued item.
3. Records inherited exclusions as `SkippedDependency` records and
   `ResolverTraceOutcome::Skipped` trace events.
4. Evaluates `DependencyRequirement::is_active(context)` before candidate
   selection so scope, optional feature, profile, distro, architecture,
   repository, and language-runtime predicates are applied before graph edges
   are emitted.
5. Builds a `SelectionKey` from package identity plus ecosystem multiplicity:
   one global package slot for RPM, Python, Maven, Gradle, and Go; parent-local
   slots for npm and Cargo-style parallel versions.
6. Accumulates `ConstraintOrigin` records per selection slot, preserving
   requester, depth, requirement, and evidence.
7. Enumerates repository candidates, records all candidates considered, records
   candidates rejected by active constraints, and selects the compatible
   candidate according to the ecosystem policy.
8. Emits `ConflictDiagnostic` plus `ResolverTraceOutcome::Conflict` when no
   candidate satisfies the active slot constraints.
9. Upserts the selected node, deduplicates the active edge, emits
   `ResolverTraceOutcome::Selected`, and enqueues the selected candidate's
   dependencies with the selected event as their trace parent.
10. Prunes unreachable or stale selected nodes and edges after the queue drains,
    so replaced selections do not remain in the final graph.

This keeps the core compact while still allowing each package-manager family to
be exact where it matters. npm can keep parallel dependency subtrees, Go can use
Minimal Version Selection, Maven can mediate nearest definitions, Gradle can
match variants, Cargo can unify features, Poetry can honor source priority, and
DNF/libsolv can resolve native RPM capability rules against repository state.

## Usability Guarantees

A resolved snapshot should provide these guarantees before it is useful for
CloudLinux, AlmaLinux, TuxCare, or customer-facing workflows:

- Every answer is context-bound.
  The context hash includes distro, architecture, repositories, language
  runtimes, profiles, enabled features, and customer policy.

- Every selected package is explainable.
  Nodes record who selected them, which slot they occupied, which constraints
  applied, and which evidence source supplied the candidate.

- Every active edge is actionable.
  Edges keep relation, scope, activation predicates, resolver rule, selected
  candidate, and evidence reference so graph queries can distinguish runtime
  exposure from build, test, development, optional, weak, peer, provided, and
  system relationships.

- Every skipped edge is still visible.
  Inactive dependencies are recorded with reasons such as platform mismatch,
  disabled optional feature, excluded transitive dependency, profile mismatch,
  repository policy, or unsupported adapter behavior.

- Every conflict is routable.
  Conflict diagnostics include the target package, selection slot, contributing
  constraints, candidate source, context hash, adapter version, and a remediation
  hint when the adapter can infer one.

- Every output is reproducible.
  Resolver version, evidence timestamps, repository metadata versions, lockfile
  identities, and context hash are part of the snapshot metadata.

- Every ecosystem can stay native.
  Universal graph fields are shared, but adapter hooks prevent GraphScope from
  flattening RPM, pip, Poetry, Maven, Gradle, npm, Go, and Cargo into a fake
  semver-only resolver.

## Implemented Decision Trace

`ResolveResult.trace` is a first-class output. Every processed requirement emits
a `ResolverTraceEvent` with:

- deterministic event ID;
- parent event ID for dependency-path reconstruction;
- requester package and requested target;
- selection slot when candidate selection was reached;
- requirement and evidence string;
- active constraints at the decision point;
- candidates considered and candidates rejected by constraints;
- selected package reference when resolution succeeded;
- outcome: selected, skipped, or conflict;
- resolver rule string that records selection policy, version multiplicity, and
  slot.

`GraphSnapshot::from_resolve_result` serializes the trace into the stable JSON
snapshot emitted by `graphscope snapshot`. The CLI demo also prints a compact
`Resolver trace` section so an operator can inspect selected, skipped, and
conflicting decisions without adding a debugger.

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
