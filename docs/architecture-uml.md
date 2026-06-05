# Architecture UML

GitHub renders Mermaid diagrams in Markdown, so this document uses Mermaid
UML-style class and sequence diagrams instead of external PlantUML assets.

The diagrams show the current GraphScope MVP contract: evidence is preserved,
context determines the valid graph, resolution emits immutable snapshots, and
query/reporting surfaces consume resolved projections.

## Domain Class View

```mermaid
classDiagram
direction LR

class EvidenceRecord {
  +id
  +kind
  +source
  +subject
  +confidence
}

class ProjectEvidence {
  +declared_dependencies
  +locked_packages
  +observed_packages
  +to_hypergraph()
  +to_repository_input()
}

class DependencyHypergraph {
  +clauses
  +clauses_for_source()
  +active_clauses()
}

class RequirementClause {
  +source
  +relation
  +scope
  +requirement
  +activation
  +evidence
}

class DependencyAlternative {
  +target
  +capability
  +requirement
}

class ResolutionContext {
  +distro
  +architecture
  +profiles
  +features
  +repositories
  +stable_key()
}

class PackageRepository {
  <<trait>>
  +candidates(package)
}

class Resolver {
  +resolve(roots, context)
}

class ResolveResult {
  +nodes
  +edges
  +skipped
  +conflicts
  +trace
}

class ResolvedGraphProjection {
  +occurrences
  +edges
  +forward_index
  +reverse_index
  +dependency_closure_from()
  +paths_to_package_capped()
}

class GraphSnapshot {
  +id
  +context_hash
  +resolver_version
  +json
}

class GraphQuery {
  +dependency_closure()
  +reverse_dependents()
  +paths_to_capped()
  +explain()
}

class FileGraphStore {
  +persist()
  +find_by_context()
}

class SqliteGraphStore {
  +persist()
  +find_by_context()
  +append_event()
}

ProjectEvidence "1" o-- "*" EvidenceRecord : preserves
ProjectEvidence --> DependencyHypergraph : builds clauses
DependencyHypergraph "1" o-- "*" RequirementClause : owns
RequirementClause "1" o-- "*" DependencyAlternative : alternatives
RequirementClause --> ResolutionContext : activation predicates
Resolver --> PackageRepository : reads candidates
Resolver --> ResolutionContext : evaluates context
Resolver --> ResolveResult : emits
ResolveResult --> ResolvedGraphProjection : projects
ResolveResult --> GraphSnapshot : serializes
ResolvedGraphProjection --> GraphQuery : indexed traversal
GraphSnapshot --> FileGraphStore : durable MVP
GraphSnapshot --> SqliteGraphStore : durable MVP
```

## Runtime Component View

```mermaid
flowchart LR
    Raw["Raw evidence\nmanifests, lockfiles, SBOMs, RPM inventory, advisories"]
    Ingest["Ingestion and parser dispatch\nsrc/ingest.rs, src/lockfile.rs"]
    Evidence["Normalized evidence catalog\nsrc/evidence.rs"]
    Hypergraph["Typed dependency hypergraph\nsrc/hypergraph.rs"]
    Context["ResolutionContext\nOS, arch, repos, profile, features, policy"]
    Repository["PackageRepository\ncandidate versions and metadata"]
    Resolver["Context-aware resolver\nsrc/resolver.rs"]
    Snapshot["Immutable graph snapshot\nsrc/snapshot.rs"]
    Projection["Resolved occurrence projection\nforward and reverse indexes"]
    Query["GraphQuery\npaths, closure, dependents, explanations, diff"]
    Outputs["SBOM, SPDX, VEX, remediation, SLA, dashboard, policy"]
    Store["File and SQLite graph stores\nsnapshots plus replayable events"]

    Raw --> Ingest --> Evidence
    Evidence --> Hypergraph
    Evidence --> Repository
    Hypergraph --> Resolver
    Repository --> Resolver
    Context --> Resolver
    Resolver --> Snapshot
    Resolver --> Projection
    Projection --> Query
    Query --> Outputs
    Snapshot --> Store
    Store --> Query
```

## Resolution Sequence

```mermaid
sequenceDiagram
    actor Operator
    participant CLI as graphscope CLI
    participant Ingest as Evidence ingestion
    participant Evidence as ProjectEvidence
    participant Repo as PackageRepository
    participant Resolver as Resolver
    participant Projection as ResolvedGraphProjection
    participant Query as GraphQuery
    participant Store as GraphStore

    Operator->>CLI: resolve-evidence files...
    CLI->>Ingest: detect and parse evidence
    Ingest->>Evidence: emit declared, locked, observed records
    Evidence->>Repo: build candidate repository and roots
    Evidence->>Resolver: provide root requirements
    CLI->>Resolver: resolve(roots, ResolutionContext)
    Resolver->>Repo: enumerate candidates per package
    Resolver->>Resolver: evaluate context, constraints, exclusions, slots
    Resolver-->>CLI: ResolveResult with nodes, edges, skipped, conflicts, trace
    CLI->>Projection: build occurrence projection
    CLI->>Query: index resolved graph
    Query-->>CLI: paths, dependents, explanations, diffs
    CLI->>Store: persist immutable snapshot and events
    CLI-->>Operator: snapshot, reports, policy, impact, exports
```

## Design Reading

The architecture follows these project decisions:

- [Design Decisions](../DECISIONS.md): accepted decisions and tradeoffs.
- [Architecture](architecture.md): production layering and service boundaries.
- [Hypergraph Model](hypergraph-model.md): source-of-truth model and projection
  strategy.
- [Resolution Algorithm](resolution-algorithm.md): resolver control flow,
  explainability, and scale strategy.
- [Capability Matrix](capability-matrix.md): implemented versus planned adapter
  capability.

The research-backed rationale is summarized in
[Modeling And Traversing A Multimodal Dependency Hypergraph](../Modeling_and_Traversing_a_Multimodal_Dependency_Hypergraph.txt):
dependency resolution should preserve unresolved clauses and context first, then
materialize resolved graph projections for traversal and reporting.
