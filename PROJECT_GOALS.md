# Project Goals

## Real-World Challenge: Building A Unified Dependency Graph

One of our core goals is to map the software supply chain for thousands of applications.
GraphScope ingests projects and calculates their full dependency trees for the
AlmaLinux OS, CloudLinux OS, and TuxCare ecosystem.

## Complexity To Handle

- Variable definitions: "dependency" means something different in every language
  and packaging ecosystem. The system must preserve static versus dynamic
  linking, compile-time versus runtime scopes, optional and weak relations,
  virtual providers, conflicts, bundles, and version ranges such as `^1.2.0`.
- Context awareness: dependencies change based on environment, including GPU
  support, Windows versus Linux, distro version, architecture, repository channel,
  language runtime, FIPS, ELS, KernelCare, enabled features, and customer policy.
- Tool variance: the system must mimic or call package-manager logic for pip,
  Poetry, Maven, Gradle, npm, Go, Cargo, RPM/DNF, and related ecosystem tools
  when correctness depends on native resolver behavior.

## Mission

- Research and strategy: analyze how 5+ languages and OS package managers handle
  packages, then design a universal model that stores those semantics efficiently
  without flattening them into one fake dependency type.
- Algorithm design: create logic to automatically resolve complex dependency
  trees at scale, record explainable decisions, and serve fast forward and
  reverse impact queries over resolved snapshots.

## Current Top Solution

The current best solution is a typed, context-conditioned dependency hypergraph
as the semantic source of truth, with resolved occurrence graph projections for
traversal, impact, reporting, and export.

This keeps package-manager semantics in the model, uses native adapters or oracle
output where needed, and avoids turning a graph database or SBOM export format
into the source of truth.
