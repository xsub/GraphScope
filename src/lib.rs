pub mod demo;
pub mod model;
pub mod repository;
pub mod resolver;

pub use demo::demo_repository;
pub use model::{
    Architecture, ArtifactMetadata, BuildProfile, ContextPredicate, DependencyRelation,
    DependencyRequirement, DependencyScope, DistroFlavor, Ecosystem, OperatingSystem, PackageId,
    PackageRef, PackageSource, PackageVersion, ResolutionContext, Version, VersionRequirement,
};
pub use repository::{InMemoryRepository, PackageRepository};
pub use resolver::{
    ConflictDiagnostic, ResolveResult, ResolvedEdge, ResolvedNode, Resolver, ResolverOptions,
    SelectionPolicy, SkippedDependency, VersionMultiplicity,
};
