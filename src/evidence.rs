use std::collections::BTreeMap;

use crate::model::{DependencyRequirement, Ecosystem, PackageId, PackageRef};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceKind {
    Manifest,
    Lockfile,
    RepositoryMetadata,
    Sbom,
    RuntimeObservation,
    Advisory,
    ResolverTrace,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceConfidence {
    Declared,
    Locked,
    Resolved,
    Observed,
    Inferred,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceSource {
    pub kind: EvidenceKind,
    pub ecosystem: Option<Ecosystem>,
    pub locator: String,
    pub digest: Option<String>,
}

impl EvidenceSource {
    pub fn new(
        kind: EvidenceKind,
        ecosystem: Option<Ecosystem>,
        locator: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            ecosystem,
            locator: locator.into(),
            digest: None,
        }
    }

    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    fn stable_key(&self) -> String {
        format!(
            "{:?}|{:?}|{}|{}",
            self.kind,
            self.ecosystem,
            self.locator,
            self.digest.as_deref().unwrap_or("")
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceSubject {
    Package(PackageRef),
    Dependency {
        requester: Option<PackageRef>,
        requirement: DependencyRequirement,
    },
    Advisory {
        advisory_id: String,
        package: PackageId,
    },
    Context(String),
}

impl EvidenceSubject {
    fn stable_key(&self) -> String {
        match self {
            EvidenceSubject::Package(package) => format!("package|{package}"),
            EvidenceSubject::Dependency {
                requester,
                requirement,
            } => format!(
                "dependency|{}|{}|{}|{}|{}|{}",
                requester
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "root".to_string()),
                requirement.target,
                requirement.requirement,
                requirement.relation,
                requirement.scope,
                requirement.evidence
            ),
            EvidenceSubject::Advisory {
                advisory_id,
                package,
            } => format!("advisory|{advisory_id}|{package}"),
            EvidenceSubject::Context(context) => format!("context|{context}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub id: String,
    pub source: EvidenceSource,
    pub subject: EvidenceSubject,
    pub confidence: EvidenceConfidence,
    pub summary: String,
}

impl EvidenceRecord {
    pub fn new(
        source: EvidenceSource,
        subject: EvidenceSubject,
        confidence: EvidenceConfidence,
        summary: impl Into<String>,
    ) -> Self {
        let summary = summary.into();
        let stable = format!(
            "{}|{}|{:?}|{}",
            source.stable_key(),
            subject.stable_key(),
            confidence,
            summary
        );
        Self {
            id: format!("ev-{:016x}", stable_hash(&stable)),
            source,
            subject,
            confidence,
            summary,
        }
    }

    pub fn package(
        source: EvidenceSource,
        package: PackageRef,
        confidence: EvidenceConfidence,
        summary: impl Into<String>,
    ) -> Self {
        Self::new(
            source,
            EvidenceSubject::Package(package),
            confidence,
            summary,
        )
    }

    pub fn dependency(
        source: EvidenceSource,
        requester: Option<PackageRef>,
        requirement: DependencyRequirement,
        confidence: EvidenceConfidence,
        summary: impl Into<String>,
    ) -> Self {
        Self::new(
            source,
            EvidenceSubject::Dependency {
                requester,
                requirement,
            },
            confidence,
            summary,
        )
    }

    pub fn package_ref(&self) -> Option<&PackageRef> {
        match &self.subject {
            EvidenceSubject::Package(package) => Some(package),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvidenceCatalog {
    records: Vec<EvidenceRecord>,
}

impl EvidenceCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, record: EvidenceRecord) {
        if !self.records.iter().any(|existing| existing.id == record.id) {
            self.records.push(record);
            self.records.sort_by(|left, right| left.id.cmp(&right.id));
        }
    }

    pub fn extend(&mut self, records: impl IntoIterator<Item = EvidenceRecord>) {
        for record in records {
            self.add(record);
        }
    }

    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }

    pub fn by_package(&self, package: &PackageId) -> Vec<&EvidenceRecord> {
        self.records
            .iter()
            .filter(|record| match &record.subject {
                EvidenceSubject::Package(package_ref) => &package_ref.id == package,
                EvidenceSubject::Dependency { requirement, .. } => &requirement.target == package,
                EvidenceSubject::Advisory {
                    package: advisory_package,
                    ..
                } => advisory_package == package,
                EvidenceSubject::Context(_) => false,
            })
            .collect()
    }

    pub fn by_source_kind(&self, kind: EvidenceKind) -> Vec<&EvidenceRecord> {
        self.records
            .iter()
            .filter(|record| record.source.kind == kind)
            .collect()
    }

    pub fn locked_packages(&self) -> Vec<PackageRef> {
        self.records
            .iter()
            .filter(|record| record.confidence == EvidenceConfidence::Locked)
            .filter_map(EvidenceRecord::package_ref)
            .cloned()
            .collect()
    }

    pub fn summary(&self) -> EvidenceSummary {
        EvidenceSummary::from_catalog(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub total_records: usize,
    pub package_records: usize,
    pub dependency_records: usize,
    pub advisory_records: usize,
    pub context_records: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub by_ecosystem: BTreeMap<String, usize>,
    pub by_confidence: BTreeMap<String, usize>,
}

impl EvidenceSummary {
    pub fn from_catalog(catalog: &EvidenceCatalog) -> Self {
        let mut summary = Self {
            total_records: catalog.records.len(),
            ..Self::default()
        };

        for record in &catalog.records {
            *summary
                .by_kind
                .entry(format!("{:?}", record.source.kind))
                .or_default() += 1;
            if let Some(ecosystem) = &record.source.ecosystem {
                *summary
                    .by_ecosystem
                    .entry(ecosystem.to_string())
                    .or_default() += 1;
            }
            *summary
                .by_confidence
                .entry(format!("{:?}", record.confidence))
                .or_default() += 1;

            match &record.subject {
                EvidenceSubject::Package(_) => summary.package_records += 1,
                EvidenceSubject::Dependency { .. } => summary.dependency_records += 1,
                EvidenceSubject::Advisory { .. } => summary.advisory_records += 1,
                EvidenceSubject::Context(_) => summary.context_records += 1,
            }
        }

        summary
    }
}

pub(crate) fn stable_hash(input: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DependencyRequirement, PackageId, Version, VersionRequirement};

    #[test]
    fn evidence_record_id_is_stable_for_identical_inputs() {
        let source = EvidenceSource::new(
            EvidenceKind::Lockfile,
            Some(Ecosystem::Python),
            "requirements.lock",
        );
        let package = PackageRef::new(PackageId::python("requests"), Version::parse("2.32.3"));

        let left = EvidenceRecord::package(
            source.clone(),
            package.clone(),
            EvidenceConfidence::Locked,
            "pinned package",
        );
        let right = EvidenceRecord::package(
            source,
            package,
            EvidenceConfidence::Locked,
            "pinned package",
        );

        assert_eq!(left.id, right.id);
    }

    #[test]
    fn catalog_deduplicates_records_by_id() {
        let source = EvidenceSource::new(EvidenceKind::Lockfile, Some(Ecosystem::Go), "go.mod");
        let package = PackageRef::new(PackageId::go("golang.org/x/net"), Version::parse("0.24.0"));
        let record = EvidenceRecord::package(
            source,
            package,
            EvidenceConfidence::Locked,
            "go requirement",
        );
        let mut catalog = EvidenceCatalog::new();

        catalog.add(record.clone());
        catalog.add(record);

        assert_eq!(catalog.records().len(), 1);
    }

    #[test]
    fn catalog_queries_records_by_package() {
        let source =
            EvidenceSource::new(EvidenceKind::Lockfile, Some(Ecosystem::Cargo), "Cargo.lock");
        let package = PackageId::cargo("petgraph");
        let record = EvidenceRecord::package(
            source,
            PackageRef::new(package.clone(), Version::parse("0.6.5")),
            EvidenceConfidence::Locked,
            "locked crate",
        );
        let mut catalog = EvidenceCatalog::new();
        catalog.add(record);

        assert_eq!(catalog.by_package(&package).len(), 1);
    }

    #[test]
    fn catalog_returns_locked_packages() {
        let source = EvidenceSource::new(
            EvidenceKind::Lockfile,
            Some(Ecosystem::Python),
            "requirements.lock",
        );
        let package = PackageRef::new(PackageId::python("urllib3"), Version::parse("2.2.2"));
        let mut catalog = EvidenceCatalog::new();
        catalog.add(EvidenceRecord::package(
            source,
            package.clone(),
            EvidenceConfidence::Locked,
            "locked package",
        ));

        assert_eq!(catalog.locked_packages(), vec![package]);
    }

    #[test]
    fn catalog_summary_counts_records_by_shape_and_source() {
        let package_source = EvidenceSource::new(
            EvidenceKind::Lockfile,
            Some(Ecosystem::Npm),
            "package-lock.json",
        );
        let dependency_source =
            EvidenceSource::new(EvidenceKind::Manifest, Some(Ecosystem::Maven), "pom.xml");
        let mut catalog = EvidenceCatalog::new();
        catalog.add(EvidenceRecord::package(
            package_source,
            PackageRef::new(
                PackageId::npm(None::<String>, "react"),
                Version::parse("18.3.1"),
            ),
            EvidenceConfidence::Locked,
            "locked npm package",
        ));
        catalog.add(EvidenceRecord::dependency(
            dependency_source,
            None,
            DependencyRequirement::new(
                PackageId::maven("org.slf4j", "slf4j-api"),
                VersionRequirement::parse("2.0.13"),
            ),
            EvidenceConfidence::Declared,
            "declared Maven dependency",
        ));

        let summary = catalog.summary();

        assert_eq!(summary.total_records, 2);
        assert_eq!(summary.package_records, 1);
        assert_eq!(summary.dependency_records, 1);
        assert_eq!(summary.by_kind["Lockfile"], 1);
        assert_eq!(summary.by_kind["Manifest"], 1);
        assert_eq!(summary.by_ecosystem["npm"], 1);
        assert_eq!(summary.by_confidence["Declared"], 1);
    }
}
