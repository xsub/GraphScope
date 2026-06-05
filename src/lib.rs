//! Public GraphScope API for dependency evidence, resolution, queries, and exports.

pub mod adapter;
pub mod advisory;
pub mod benchmark;
pub mod demo;
pub mod evidence;
pub mod export;
pub mod hypergraph;
pub mod ingest;
mod json;
pub mod lockfile;
pub mod model;
pub mod platform;
pub mod policy;
pub mod query;
pub mod repository;
pub mod resolver;
pub mod snapshot;
pub mod storage;

pub use adapter::{
    AdapterCapability, AdapterProfile, AdapterResolutionContract, AdapterResolutionMode,
    AdapterStatus, adapter_profile, adapter_profiles, adapter_resolution_contract,
    adapter_resolution_contracts,
};
pub use advisory::{Advisory, AdvisorySeverity, ImpactFinding, ImpactReport, VexStatus};
pub use benchmark::{AlgorithmBenchmarkConfig, AlgorithmBenchmarkReport, run_algorithm_benchmark};
pub use demo::{demo_advisories, demo_policy_set, demo_repository};
pub use evidence::{
    EvidenceCatalog, EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceRepositoryBuilder,
    EvidenceRepositoryInput, EvidenceSource, EvidenceSubject, EvidenceSummary, ProjectEvidence,
};
pub use export::{CycloneDxView, RemediationReport, RiskDashboard, SlaSummary, SpdxView, VexView};
pub use hypergraph::{
    ClauseId, ClauseSemantics, ClauseSource, DependencyAlternative, DependencyHypergraph,
    OccurrenceId, OccurrencePath, RequirementClause, ResolvedGraphProjection, ResolvedOccurrence,
    ResolvedOccurrenceEdge, occurrence_id,
};
pub use ingest::{EvidenceFormat, IngestError, parse_evidence};
pub use lockfile::{
    parse_cargo_lock_packages, parse_cyclonedx_sbom, parse_go_mod_requirements,
    parse_gradle_dependencies, parse_maven_pom_dependencies, parse_npm_package_lock,
    parse_pip_requirements_lock, parse_rpm_inventory,
};
pub use model::{
    Architecture, ArtifactMetadata, BuildProfile, ContextPredicate, DependencyRelation,
    DependencyRequirement, DependencyScope, DistroFlavor, Ecosystem, OperatingSystem, PackageId,
    PackageRef, PackageSource, PackageVersion, ResolutionContext, RpmCapability, RpmCapabilityKind,
    RpmOracleEvidence, RpmPackageCoordinate, Version, VersionRequirement,
};
pub use platform::{
    AccessDecision, ChangeEvent, GraphRecord, InMemoryGraphStore, InvalidationPlan, ResolverJob,
    ResolverService, ResolverWorkQueue, TenantAccessPolicy, TenantRole,
};
pub use policy::{PolicyEvaluation, PolicyRule, PolicySet, PolicySeverity, PolicyViolation};
pub use query::{
    DependencyPath, EdgeKey, GraphDiff, GraphQuery, PackageExplanation, PackageVersionChange,
    PathSearchOptions, ResolvedGraphIndex,
};
pub use repository::{InMemoryRepository, PackageRepository};
pub use resolver::{
    ConflictDiagnostic, ResolveResult, ResolvedEdge, ResolvedNode, Resolver, ResolverOptions,
    ResolverTraceEvent, ResolverTraceOutcome, SelectionPolicy, SkippedDependency,
    VersionMultiplicity,
};
pub use snapshot::GraphSnapshot;
#[cfg(feature = "sqlite")]
pub use storage::SqliteGraphStore;
pub use storage::{FileChangeEventLog, FileGraphStore, StoredChangeEvent, StoredSnapshotRecord};
