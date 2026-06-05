//! Adapter capability and resolver-contract metadata for supported ecosystems.

use std::fmt;

use crate::ingest::EvidenceFormat;
use crate::model::Ecosystem;
use crate::resolver::{SelectionPolicy, VersionMultiplicity};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdapterCapability {
    ManifestParsing,
    LockfileParsing,
    RuntimeInventoryParsing,
    VersionRangeSelection,
    ContextActivation,
    OptionalDependencies,
    Exclusions,
    ParallelVersionSlots,
    MinimalVersionSelection,
    RepositoryContext,
    StableEvidence,
    SbomNormalization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdapterStatus {
    Implemented,
    FixtureParser,
    OracleAdapter,
    Planned,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdapterResolutionMode {
    NativeOracleRequired,
    LockfileReplay,
    ManifestMediation,
    RuntimeInventoryObservation,
    SbomImport,
}

impl fmt::Display for AdapterResolutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeOracleRequired => write!(f, "native oracle required"),
            Self::LockfileReplay => write!(f, "lockfile replay"),
            Self::ManifestMediation => write!(f, "manifest mediation"),
            Self::RuntimeInventoryObservation => write!(f, "runtime inventory observation"),
            Self::SbomImport => write!(f, "SBOM import"),
        }
    }
}

impl fmt::Display for AdapterStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implemented => write!(f, "implemented"),
            Self::FixtureParser => write!(f, "fixture parser"),
            Self::OracleAdapter => write!(f, "oracle adapter"),
            Self::Planned => write!(f, "planned"),
            Self::Blocked => write!(f, "blocked"),
        }
    }
}

impl fmt::Display for AdapterCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestParsing => write!(f, "manifest parsing"),
            Self::LockfileParsing => write!(f, "lockfile parsing"),
            Self::RuntimeInventoryParsing => write!(f, "runtime inventory parsing"),
            Self::VersionRangeSelection => write!(f, "version range selection"),
            Self::ContextActivation => write!(f, "context activation"),
            Self::OptionalDependencies => write!(f, "optional dependencies"),
            Self::Exclusions => write!(f, "exclusions"),
            Self::ParallelVersionSlots => write!(f, "parallel version slots"),
            Self::MinimalVersionSelection => write!(f, "minimal version selection"),
            Self::RepositoryContext => write!(f, "repository context"),
            Self::StableEvidence => write!(f, "stable evidence"),
            Self::SbomNormalization => write!(f, "SBOM normalization"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterResolutionContract {
    pub ecosystem: Ecosystem,
    pub package_manager: &'static str,
    pub mode: AdapterResolutionMode,
    pub selection_policy: SelectionPolicy,
    pub multiplicity: VersionMultiplicity,
    pub native_oracle_commands: Vec<&'static str>,
    pub semantic_rules: Vec<&'static str>,
    pub context_inputs: Vec<&'static str>,
}

impl AdapterResolutionContract {
    pub fn needs_native_oracle(&self) -> bool {
        self.mode == AdapterResolutionMode::NativeOracleRequired
    }

    pub fn includes_rule(&self, needle: &str) -> bool {
        self.semantic_rules.iter().any(|rule| rule.contains(needle))
    }

    pub fn includes_context_input(&self, input: &str) -> bool {
        self.context_inputs.contains(&input)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterProfile {
    pub ecosystem: Ecosystem,
    pub package_manager: &'static str,
    pub status: AdapterStatus,
    pub evidence_formats: Vec<EvidenceFormat>,
    pub capabilities: Vec<AdapterCapability>,
    pub production_gaps: Vec<&'static str>,
}

impl AdapterProfile {
    pub fn supports(&self, capability: AdapterCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn accepts_format(&self, format: EvidenceFormat) -> bool {
        self.evidence_formats.contains(&format)
    }
}

pub fn adapter_profiles() -> Vec<AdapterProfile> {
    let mut profiles = vec![
        AdapterProfile {
            ecosystem: Ecosystem::Other("sbom".to_string()),
            package_manager: "CycloneDX",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::CycloneDxSbom],
            capabilities: vec![
                AdapterCapability::SbomNormalization,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["full CycloneDX dependency graph and vulnerability extensions"],
        },
        AdapterProfile {
            ecosystem: Ecosystem::Rpm,
            package_manager: "DNF/RPM",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::RpmInventory],
            capabilities: vec![
                AdapterCapability::RuntimeInventoryParsing,
                AdapterCapability::RepositoryContext,
                AdapterCapability::ContextActivation,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["libsolv/DNF transaction semantics"],
        },
        AdapterProfile {
            ecosystem: Ecosystem::Python,
            package_manager: "pip/Poetry",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::PipRequirements],
            capabilities: vec![
                AdapterCapability::LockfileParsing,
                AdapterCapability::VersionRangeSelection,
                AdapterCapability::ContextActivation,
                AdapterCapability::OptionalDependencies,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["pip/Poetry resolver backtracking and wheel tag selection"],
        },
        AdapterProfile {
            ecosystem: Ecosystem::Maven,
            package_manager: "Maven",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::MavenPom],
            capabilities: vec![
                AdapterCapability::ManifestParsing,
                AdapterCapability::VersionRangeSelection,
                AdapterCapability::ContextActivation,
                AdapterCapability::Exclusions,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["effective POM inheritance and dependency management"],
        },
        AdapterProfile {
            ecosystem: Ecosystem::Gradle,
            package_manager: "Gradle",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::GradleBuild],
            capabilities: vec![
                AdapterCapability::ManifestParsing,
                AdapterCapability::VersionRangeSelection,
                AdapterCapability::ContextActivation,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["dependency insight and configuration graph ingestion"],
        },
        AdapterProfile {
            ecosystem: Ecosystem::Npm,
            package_manager: "npm",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::NpmPackageLock],
            capabilities: vec![
                AdapterCapability::LockfileParsing,
                AdapterCapability::VersionRangeSelection,
                AdapterCapability::ContextActivation,
                AdapterCapability::OptionalDependencies,
                AdapterCapability::ParallelVersionSlots,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["peer dependency propagation and overrides"],
        },
        AdapterProfile {
            ecosystem: Ecosystem::Go,
            package_manager: "Go modules",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::GoMod],
            capabilities: vec![
                AdapterCapability::LockfileParsing,
                AdapterCapability::MinimalVersionSelection,
                AdapterCapability::ContextActivation,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["replace/exclude/build tags from the full module graph"],
        },
        AdapterProfile {
            ecosystem: Ecosystem::Cargo,
            package_manager: "Cargo",
            status: AdapterStatus::FixtureParser,
            evidence_formats: vec![EvidenceFormat::CargoLock],
            capabilities: vec![
                AdapterCapability::LockfileParsing,
                AdapterCapability::VersionRangeSelection,
                AdapterCapability::ContextActivation,
                AdapterCapability::OptionalDependencies,
                AdapterCapability::StableEvidence,
            ],
            production_gaps: vec!["feature unification, target cfg, and patch sections"],
        },
    ];

    profiles.sort_by_key(|profile| profile.ecosystem.to_string());
    profiles
}

pub fn adapter_profile(ecosystem: &Ecosystem) -> Option<AdapterProfile> {
    adapter_profiles()
        .into_iter()
        .find(|profile| &profile.ecosystem == ecosystem)
}

pub fn adapter_resolution_contracts() -> Vec<AdapterResolutionContract> {
    let mut contracts = vec![
        AdapterResolutionContract {
            ecosystem: Ecosystem::Other("sbom".to_string()),
            package_manager: "CycloneDX",
            mode: AdapterResolutionMode::SbomImport,
            selection_policy: SelectionPolicy::HighestCompatible,
            multiplicity: VersionMultiplicity::OnePerPackage,
            native_oracle_commands: vec![],
            semantic_rules: vec![
                "trust resolved component evidence only when the SBOM records dependencies",
                "treat component PURLs as coordinates and preserve external references",
            ],
            context_inputs: vec!["bomFormat", "specVersion", "component purl"],
        },
        AdapterResolutionContract {
            ecosystem: Ecosystem::Rpm,
            package_manager: "DNF/RPM",
            mode: AdapterResolutionMode::NativeOracleRequired,
            selection_policy: SelectionPolicy::HighestCompatible,
            multiplicity: VersionMultiplicity::OnePerPackage,
            native_oracle_commands: vec![
                "rpm -qa --qf '%{EPOCHNUM}:%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'",
                "dnf repoquery --requires --resolve --alldeps <package>",
                "dnf repoquery --whatprovides <capability>",
            ],
            semantic_rules: vec![
                "resolve package, file, soname, and virtual provides",
                "honor enabled repositories, module streams, architecture, distro release, and weak dependency policy",
                "preserve installed inventory separately from repository candidates",
            ],
            context_inputs: vec![
                "distro",
                "releasever",
                "architecture",
                "enabled repositories",
                "module streams",
                "install_weak_deps",
            ],
        },
        AdapterResolutionContract {
            ecosystem: Ecosystem::Python,
            package_manager: "pip/Poetry",
            mode: AdapterResolutionMode::NativeOracleRequired,
            selection_policy: SelectionPolicy::HighestCompatible,
            multiplicity: VersionMultiplicity::OnePerPackage,
            native_oracle_commands: vec![
                "python -m pip install --dry-run --report <report.json> -r <requirements>",
                "poetry lock --no-update",
            ],
            semantic_rules: vec![
                "evaluate PEP 508 environment markers before adding edges",
                "activate extras and Poetry dependency groups as graph context",
                "select distributions by index priority, wheel tags, Python version, ABI, and platform",
            ],
            context_inputs: vec![
                "python version",
                "platform tags",
                "extras",
                "dependency groups",
                "package indexes",
            ],
        },
        AdapterResolutionContract {
            ecosystem: Ecosystem::Maven,
            package_manager: "Maven",
            mode: AdapterResolutionMode::NativeOracleRequired,
            selection_policy: SelectionPolicy::HighestCompatible,
            multiplicity: VersionMultiplicity::OnePerPackage,
            native_oracle_commands: vec!["mvn help:effective-pom", "mvn dependency:tree -Dverbose"],
            semantic_rules: vec![
                "apply dependencyManagement, parent inheritance, scopes, optional flags, and exclusions",
                "mediate conflicts with Maven nearest-definition behavior",
                "preserve classifiers and repositories when present",
            ],
            context_inputs: vec![
                "JDK version",
                "active profiles",
                "repositories",
                "dependencyManagement",
            ],
        },
        AdapterResolutionContract {
            ecosystem: Ecosystem::Gradle,
            package_manager: "Gradle",
            mode: AdapterResolutionMode::NativeOracleRequired,
            selection_policy: SelectionPolicy::HighestCompatible,
            multiplicity: VersionMultiplicity::OnePerPackage,
            native_oracle_commands: vec![
                "gradle dependencies --configuration <configuration>",
                "gradle dependencyInsight --configuration <configuration> --dependency <module>",
            ],
            semantic_rules: vec![
                "resolve per configuration with variant attributes and capabilities",
                "apply platforms, constraints, substitutions, rich versions, and conflict resolution",
                "preserve selected variant attributes as edge context",
            ],
            context_inputs: vec![
                "configuration",
                "variant attributes",
                "JDK version",
                "repositories",
            ],
        },
        AdapterResolutionContract {
            ecosystem: Ecosystem::Npm,
            package_manager: "npm",
            mode: AdapterResolutionMode::LockfileReplay,
            selection_policy: SelectionPolicy::HighestCompatible,
            multiplicity: VersionMultiplicity::ParallelPerParent,
            native_oracle_commands: vec![
                "npm ls --all --json",
                "npm explain --json <package>",
                "npm install --package-lock-only --dry-run",
            ],
            semantic_rules: vec![
                "preserve nested node_modules paths as parallel version slots",
                "evaluate optional OS, CPU, peer dependency, override, and workspace behavior",
                "treat package-lock integrity and resolved URL as supply-chain evidence",
            ],
            context_inputs: vec!["os", "cpu", "node version", "npm version", "workspaces"],
        },
        AdapterResolutionContract {
            ecosystem: Ecosystem::Go,
            package_manager: "Go modules",
            mode: AdapterResolutionMode::NativeOracleRequired,
            selection_policy: SelectionPolicy::MinimalCompatible,
            multiplicity: VersionMultiplicity::OnePerPackage,
            native_oracle_commands: vec![
                "go list -m -json all",
                "go mod graph",
                "go list -deps -json ./...",
            ],
            semantic_rules: vec![
                "apply Minimal Version Selection",
                "honor replace, exclude, retract, module graph pruning, and build tags",
                "separate module requirements from package import graph evidence",
            ],
            context_inputs: vec!["go version", "GOOS", "GOARCH", "build tags"],
        },
        AdapterResolutionContract {
            ecosystem: Ecosystem::Cargo,
            package_manager: "Cargo",
            mode: AdapterResolutionMode::NativeOracleRequired,
            selection_policy: SelectionPolicy::HighestCompatible,
            multiplicity: VersionMultiplicity::ParallelPerParent,
            native_oracle_commands: vec![
                "cargo metadata --format-version 1 --locked",
                "cargo tree --edges features,no-dev",
            ],
            semantic_rules: vec![
                "unify features across selected crate versions",
                "honor target cfg, build dependencies, dev dependencies, patches, and alternate registries",
                "allow parallel semver-incompatible crate versions",
            ],
            context_inputs: vec!["target triple", "features", "profile", "registry sources"],
        },
    ];

    contracts.sort_by_key(|contract| contract.ecosystem.to_string());
    contracts
}

pub fn adapter_resolution_contract(ecosystem: &Ecosystem) -> Option<AdapterResolutionContract> {
    adapter_resolution_contracts()
        .into_iter()
        .find(|contract| &contract.ecosystem == ecosystem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_profiles_cover_supported_evidence_formats() {
        let profiles = adapter_profiles();

        for format in [
            EvidenceFormat::PipRequirements,
            EvidenceFormat::GoMod,
            EvidenceFormat::CargoLock,
            EvidenceFormat::NpmPackageLock,
            EvidenceFormat::MavenPom,
            EvidenceFormat::GradleBuild,
            EvidenceFormat::RpmInventory,
            EvidenceFormat::CycloneDxSbom,
        ] {
            assert!(
                profiles
                    .iter()
                    .any(|profile| profile.accepts_format(format)),
                "missing adapter profile for {format}"
            );
        }
    }

    #[test]
    fn adapter_profiles_report_ecosystem_specific_capabilities() {
        let python = adapter_profile(&Ecosystem::Python).unwrap();
        let maven = adapter_profile(&Ecosystem::Maven).unwrap();
        let npm = adapter_profile(&Ecosystem::Npm).unwrap();
        let go = adapter_profile(&Ecosystem::Go).unwrap();
        let rpm = adapter_profile(&Ecosystem::Rpm).unwrap();

        assert!(python.supports(AdapterCapability::VersionRangeSelection));
        assert!(maven.supports(AdapterCapability::Exclusions));
        assert!(npm.supports(AdapterCapability::ParallelVersionSlots));
        assert!(go.supports(AdapterCapability::MinimalVersionSelection));
        assert!(rpm.supports(AdapterCapability::RepositoryContext));
    }

    #[test]
    fn adapter_profiles_mark_fixture_parsers_separately_from_native_resolvers() {
        let profiles = adapter_profiles();

        assert!(profiles.iter().all(|profile| {
            profile.status != AdapterStatus::Implemented || profile.production_gaps.is_empty()
        }));
        assert!(
            profiles
                .iter()
                .any(|profile| profile.status == AdapterStatus::FixtureParser)
        );
        assert_eq!(
            adapter_profile(&Ecosystem::Rpm).unwrap().status,
            AdapterStatus::FixtureParser
        );
    }

    #[test]
    fn adapter_profiles_have_stable_cli_order() {
        let profiles = adapter_profiles();
        let names = profiles
            .iter()
            .map(|profile| profile.ecosystem.to_string())
            .collect::<Vec<_>>();
        let mut sorted = names.clone();
        sorted.sort();

        assert_eq!(names, sorted);
    }

    #[test]
    fn adapter_resolution_contracts_cover_every_profile() {
        let contracts = adapter_resolution_contracts();

        for profile in adapter_profiles() {
            assert!(
                contracts
                    .iter()
                    .any(|contract| contract.ecosystem == profile.ecosystem),
                "missing resolution contract for {}",
                profile.package_manager
            );
        }
    }

    #[test]
    fn adapter_resolution_contracts_encode_package_manager_semantics() {
        let rpm = adapter_resolution_contract(&Ecosystem::Rpm).unwrap();
        let maven = adapter_resolution_contract(&Ecosystem::Maven).unwrap();
        let gradle = adapter_resolution_contract(&Ecosystem::Gradle).unwrap();
        let npm = adapter_resolution_contract(&Ecosystem::Npm).unwrap();
        let go = adapter_resolution_contract(&Ecosystem::Go).unwrap();
        let cargo = adapter_resolution_contract(&Ecosystem::Cargo).unwrap();

        assert!(rpm.includes_rule("provides"));
        assert!(maven.includes_rule("nearest-definition"));
        assert!(gradle.includes_rule("variant attributes"));
        assert_eq!(npm.multiplicity, VersionMultiplicity::ParallelPerParent);
        assert_eq!(go.selection_policy, SelectionPolicy::MinimalCompatible);
        assert!(cargo.includes_rule("features"));
    }

    #[test]
    fn adapter_resolution_contracts_expose_native_oracle_commands_and_context() {
        let python = adapter_resolution_contract(&Ecosystem::Python).unwrap();
        let cargo = adapter_resolution_contract(&Ecosystem::Cargo).unwrap();
        let sbom = adapter_resolution_contract(&Ecosystem::Other("sbom".to_string())).unwrap();

        assert!(python.needs_native_oracle());
        assert!(
            python
                .native_oracle_commands
                .iter()
                .any(|command| command.contains("--report"))
        );
        assert!(cargo.includes_context_input("target triple"));
        assert_eq!(sbom.mode, AdapterResolutionMode::SbomImport);
        assert!(sbom.native_oracle_commands.is_empty());
    }
}
