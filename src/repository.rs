//! Package candidate repository abstraction and in-memory MVP implementation.

use std::collections::BTreeMap;

use crate::model::{PackageId, PackageVersion};

pub trait PackageRepository {
    fn candidates(&self, package: &PackageId) -> Vec<PackageVersion>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InMemoryRepository {
    packages: BTreeMap<PackageId, Vec<PackageVersion>>,
}

impl InMemoryRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, package: PackageVersion) {
        let versions = self.packages.entry(package.id.clone()).or_default();
        versions.push(package);
        versions.sort_by(|left, right| left.version.cmp(&right.version));
    }

    pub fn with(mut self, package: PackageVersion) -> Self {
        self.add(package);
        self
    }

    pub fn package_count(&self) -> usize {
        self.packages.values().map(Vec::len).sum()
    }
}

impl PackageRepository for InMemoryRepository {
    fn candidates(&self, package: &PackageId) -> Vec<PackageVersion> {
        self.packages.get(package).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PackageId, PackageVersion};

    #[test]
    fn empty_repository_returns_no_candidates() {
        let repository = InMemoryRepository::new();

        assert!(repository.candidates(&PackageId::rpm("missing")).is_empty());
    }

    #[test]
    fn added_candidates_are_sorted_by_version() {
        let package = PackageId::python("requests");
        let mut repository = InMemoryRepository::new();
        repository.add(PackageVersion::new(package.clone(), "2.32.0"));
        repository.add(PackageVersion::new(package.clone(), "2.31.0"));
        repository.add(PackageVersion::new(package.clone(), "2.33.0"));

        let versions = repository
            .candidates(&package)
            .into_iter()
            .map(|candidate| candidate.version.raw)
            .collect::<Vec<_>>();

        assert_eq!(versions, vec!["2.31.0", "2.32.0", "2.33.0"]);
    }

    #[test]
    fn with_builder_adds_package_and_returns_repository() {
        let repository = InMemoryRepository::new()
            .with(PackageVersion::new(PackageId::cargo("petgraph"), "0.6.5"));

        assert_eq!(repository.package_count(), 1);
    }

    #[test]
    fn package_count_counts_all_versions_across_packages() {
        let mut repository = InMemoryRepository::new();
        repository.add(PackageVersion::new(PackageId::rpm("openssl-libs"), "3.0.0"));
        repository.add(PackageVersion::new(PackageId::rpm("openssl-libs"), "3.2.2"));
        repository.add(PackageVersion::new(PackageId::python("urllib3"), "2.2.2"));

        assert_eq!(repository.package_count(), 3);
    }
}
