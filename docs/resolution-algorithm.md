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

## Adapter-Driven Control Loop

The shared engine owns scheduling, state, determinism, diagnostics, and graph
assembly. Ecosystem adapters own package-manager semantics: candidate
enumeration, version ordering, virtual provides, source priority, conflict
mediation, feature activation, variant matching, lockfile authority, and
dependency expansion.

```text
work = root requirements with requester = root
state = {
    constraints_by_selection_slot,
    selected_candidate_by_slot,
    graph_edges,
    skipped_requirements,
    conflicts,
    bounded_trace,
}

while work has pending requirements:
    item = next deterministic work item
    adapter = adapter_for(item.target.ecosystem)

    if item.target is excluded by an inherited rule:
        skipped += explain("excluded by ancestor edge", item)
        continue

    activation = adapter.evaluate_activation(item.requirement, context)
    if activation is inactive:
        skipped += explain(activation.reason, item)
        continue

    slot = adapter.selection_slot(item.requirement, item.requester, context)
    constraints_by_selection_slot[slot] += item.requirement with evidence

    candidates = adapter.enumerate_candidates(item.target, context, evidence_store)
    selected = adapter.select_candidate(candidates, constraints_by_selection_slot[slot], context)

    if selected is none:
        conflicts += explain_unsatisfied_constraints(slot, constraints, candidates)
        continue

    graph_edges += edge(item.requester, selected, item.requirement, adapter.rule_id)

    if selected changed for slot or selected was not expanded in this slot:
        selected_candidate_by_slot[slot] = selected
        work += adapter.expand_dependencies(selected, context, inherited_rules)

return finalize_snapshot(
    prune_unreachable_and_unselected_nodes(state),
    context_hash,
    resolver_version,
    evidence_references,
)
```

This structure keeps the core simple while allowing each package-manager family
to be exact where it matters. npm can keep parallel dependency subtrees, Go can
use Minimal Version Selection, Maven can mediate nearest definitions, Gradle can
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

## Decision Trace Shape

The trace should be compact enough to store for thousands of applications but
specific enough to answer support questions. Each trace event should include:

- stable event ID;
- parent event ID for dependency-path reconstruction;
- requester package and requested target;
- selection slot;
- active constraints at the decision point;
- candidates considered and candidates rejected;
- adapter rule ID and adapter version;
- evidence references;
- result: selected, skipped, conflict, replaced, or already satisfied.

Trace events should be bounded and sampled only after preserving the decision
path for selected, skipped, and conflicting dependencies. A small graph with a
hard conflict should be more explainable than a large graph with no surprises.

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
