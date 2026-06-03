use std::fmt;

use crate::ingest::EvidenceFormat;
use crate::model::Ecosystem;

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
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterProfile {
    pub ecosystem: Ecosystem,
    pub package_manager: &'static str,
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
            ecosystem: Ecosystem::Rpm,
            package_manager: "DNF/RPM",
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
}
