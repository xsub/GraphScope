# Hypergraph Model

Best current decision: GraphScope should use a typed context-conditioned
hypergraph as the semantic source of truth, then build resolved occurrence graph
projections for traversal, impact analysis, reports, and exports.

In short: resolve first, traverse projections.

## Why This Model

A project does not have one dependency graph in the abstract. It has a family of
valid graphs that depend on package-manager rules, resolver version, registry or
repository timestamp, OS, architecture, runtime versions, enabled features,
extras, weak dependency policy, lockfiles, and customer policy.

That means the hard part is not BFS. The hard part is deciding which graph exists
for a specific `ResolveRun`. Once that resolved graph exists, ordinary traversal
is useful again.

The strongest model for this repository is:

- unresolved requirement space: typed context-conditioned hypergraph;
- resolver output: resolved occurrence graph projection;
- query layer: adjacency lists now, CSR and CSC projections when graph volume and
  latency justify them;
- security depth: optional FASTEN-style call graph overlay later, because package
  presence and vulnerable-code reachability are different questions.

## Goal Fit

This model fits `PROJECT_GOALS.md` better than the alternatives because it keeps
each hard requirement in the right layer:

- thousands of applications: immutable `ResolveRun` snapshots can be partitioned
  by tenant, product, root, ecosystem, and context hash, then indexed for repeated
  impact queries;
- variable dependency definitions: `RequirementClause` stores relation, scope,
  alternatives, provider capability, conflict meaning, optional/weak/peer state,
  dynamic loading, bundled code, and native evidence;
- context awareness: activation predicates and resolver context decide which
  clauses are eligible before resolution and before traversal;
- tool variance: package-manager adapters or oracle output enumerate candidates,
  constraints, conflicts, and selected occurrences without forcing one universal
  fake resolver;
- full dependency trees: once a context-bound resolution is complete,
  `ResolvedGraphProjection` gives deterministic forward closure, reverse impact,
  and path explanations.

## Decision Matrix

| Option | Verdict | Why |
| --- | --- | --- |
| Plain package-version graph | Reject | Too lossy for providers, conflicts, optional features, peer dependencies, weak RPM relations, bundled/local copies, and context-conditioned edges. |
| Graph database as source of truth | Reject | Useful for exploration, but it does not naturally own resolver semantics, hyperedges, native clauses, or package-manager provenance. |
| SBOM-first model | Reject | Useful as an export and ingest source, but SBOMs usually describe a build or inventory view, not the unresolved resolver semantics that created it. |
| Package-manager-only snapshots | Partial | Accurate per ecosystem, but insufficient as the universal cross-ecosystem model for CloudLinux/TuxCare impact, policy, and reporting. |
| Generic SAT/SMT solver first | Defer | Valuable as a backstop for hard cases, but the MVP should first call or mimic native package-manager behavior and preserve adapter evidence. |
| Typed hypergraph plus resolved occurrence projections | Choose | Preserves semantics before solving, gives deterministic graph traversal after solving, and scales naturally into CSR/CSC/query indexes. |

So the top solution is not to replace the current direction. The top solution is
to continue it and wire more inputs through it: evidence to clauses, clauses to
native adapters, adapters to resolved occurrences, occurrences to indexed query
views.

## Algorithm Shape

1. Ingest raw evidence from manifests, lockfiles, RPM inventories, repository
   metadata, package-manager output, SBOMs, advisories, runtime observations, and
   customer policy.
2. Normalize evidence into `RequirementClause`, `DependencyAlternative`, package
   candidate, artifact, advisory, and provenance records without discarding native
   syntax.
3. Build a `ResolveRun` from root requirements, resolver adapter identity,
   resolver version, repository or registry snapshot, lockfile identity,
   environment, and policy hash.
4. Evaluate clause activation predicates against the context before candidate
   selection.
5. Let ecosystem adapters enumerate candidates and mediation rules. For
   AlmaLinux and CloudLinux RPM correctness, start with a DNF/libsolv oracle
   adapter before direct bindings.
6. Select candidates, detect conflicts, record skipped clauses, and emit a
   compact decision trace.
7. Materialize `ResolvedOccurrence` nodes and `ResolvedOccurrenceEdge` records.
8. Build forward and reverse adjacency lists for cold MVP queries.
9. Add CSR and CSC snapshot projections when graph size makes scans expensive.
10. Add selective reachability labels only for measured hot queries.

## Source Of Truth

Do not use a graph database as the source of truth for resolver semantics.

A graph database or graph-query layer can be useful for interactive exploration,
debugging, and UI workflows, but it should consume projections. The authoritative
record must preserve clauses and context that ordinary binary edges flatten away:

- requirement clauses with ecosystem-native text and canonical IR;
- alternatives and providers, such as RPM virtual capabilities and file provides;
- relation type: requires, recommends, suggests, provides, conflicts, replaces,
  bundles, links, loads dynamically;
- scope: runtime, compile, build, test, development, optional, peer, provided,
  system, weak;
- activation predicates: distro, architecture, runtime version, feature, extra,
  target, repository channel, build profile, and customer policy;
- provenance: manifest, lockfile, package-manager output, rpmmd metadata, SBOM,
  advisory, runtime inventory, or manual assertion;
- resolver/run context: package-manager name and version, registry or repository
  snapshot, lockfile identity, root, environment, and policy hash.

The MVP Rust API now reflects this direction through `DependencyHypergraph`,
`RequirementClause`, `DependencyAlternative`, `ResolvedOccurrence`, and
`ResolvedGraphProjection`.

## Requirement Hypergraph

The unresolved layer is a hypergraph because a single dependency clause may point
to a set of possible targets instead of one already-selected node. Examples:

- RPM `Requires: editor` can be satisfied by one of several packages providing the
  capability.
- Python extras and PEP 508 environment markers can activate a dependency only
  for a particular environment.
- npm peer dependencies constrain the shape of the surrounding graph.
- Maven exclusions and Gradle variants alter which transitive edges are even
  eligible.
- Cargo features and target dependencies change the dependency set by build
  target.

This layer is for building and solving, not for answering product questions by
plain reachability. Traversing unresolved clauses can answer "which declarations
mention this package or capability?", but it cannot answer "is this package in
the customer runtime graph?" without resolution.

## Resolved Occurrence Projection

The resolved snapshot should use occurrence nodes, not only package-version
nodes. A `ResolvedOccurrence` represents a package version in a particular slot,
artifact, local/bundled identity, and context. This matters because several
ecosystems can install parallel versions or local bundled copies that share a
package name and sometimes even a package version.

For the current MVP, `ResolvedGraphProjection::from_resolve_result` adapts the
existing resolver output into occurrence nodes and builds forward and reverse
adjacency indexes. This is intentionally small. The next model expansion should
carry occurrence identity directly through the resolver instead of deriving it
from `PackageRef`.

## Traversal Strategy

Resolve first, traverse projections.

Cold MVP queries can use deterministic adjacency lists:

- forward dependencies from root to transitive dependency closure;
- reverse dependencies from package occurrence to affected roots;
- paths for explainability;
- graph diffs between resolved snapshots.

The first scale upgrade is a pair of immutable snapshot projections:

- CSR for outgoing traversal and dependency closure;
- CSC for reverse impact and dependent lookups.

After there is production query data, add selective indexes for hot questions
instead of globally materializing every transitive closure. Good later candidates
are SCC condensation, reachability labeling, O'Reach-style partial indexes, and
BL/minBL-style label reduction. These belong behind the projection contract, not
inside the resolver.

## What Not To Build Yet

- No Neo4j-style property graph as the canonical store.
- No full custom SAT solver before the DNF/libsolv oracle and package-manager
  output adapters prove where generic solving is actually needed.
- No global transitive closure table as the default storage model.
- No PCSR, LSMGraph, ChunkGraph, or DAG compression until snapshot size and update
  patterns justify them.
- No call-graph overlay in the first MVP. Keep the package graph correct first,
  then add FASTEN-style method/function reachability for exploitability.

## MVP Acceptance Criteria

The model is good enough for the next implementation phase when:

- parsed evidence enters `RequirementClause` records before resolution;
- package-manager adapters can emit provider/alternative/conflict clauses;
- resolved snapshots contain occurrence IDs, not ambiguous package IDs alone;
- query APIs accept occurrence IDs or return all matching occurrences when
  package identity is ambiguous;
- forward and reverse traversal are built from the resolved projection;
- SBOM, SPDX, VEX, remediation, SLA, and dashboard outputs remain views over the
  same resolved snapshot.

## Sources

- HyperRes, "Solving Package Management via Hypergraph Dependency Resolution":
  <https://arxiv.org/abs/2506.10803>
- Package Calculus, "Package Managers a la Carte":
  <https://arxiv.org/abs/2602.18602>
- ACM Queue, "The Surprise of Multiple Dependency Graphs":
  <https://queue.acm.org/detail.cfm?id=3723000>
- deps.dev API:
  <https://docs.deps.dev/api/v3alpha/>
- deps.dev BigQuery schema:
  <https://docs.deps.dev/bigquery/v1/>
- PEP 508:
  <https://peps.python.org/pep-0508/>
- Graph reachability indexing survey:
  <https://arxiv.org/html/2311.03542v2>
- FASTEN:
  <https://github.com/fasten-project/fasten>
