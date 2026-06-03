use std::fmt;

use crate::model::{PackageId, PackageRef, VersionRequirement};
use crate::query::{DependencyPath, GraphQuery};
use crate::resolver::ResolveResult;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvisorySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for AdvisorySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvisorySeverity::Low => write!(f, "low"),
            AdvisorySeverity::Medium => write!(f, "medium"),
            AdvisorySeverity::High => write!(f, "high"),
            AdvisorySeverity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VexStatus {
    Affected,
    NotAffected,
}

impl fmt::Display for VexStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VexStatus::Affected => write!(f, "affected"),
            VexStatus::NotAffected => write!(f, "not_affected"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub title: String,
    pub package: PackageId,
    pub affected_versions: VersionRequirement,
    pub severity: AdvisorySeverity,
    pub fixed_versions: Option<VersionRequirement>,
    pub summary: String,
}

impl Advisory {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        package: PackageId,
        affected_versions: VersionRequirement,
        severity: AdvisorySeverity,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            package,
            affected_versions,
            severity,
            fixed_versions: None,
            summary: String::new(),
        }
    }

    pub fn fixed_by(mut self, fixed_versions: VersionRequirement) -> Self {
        self.fixed_versions = Some(fixed_versions);
        self
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    pub fn affects(&self, package: &PackageRef) -> bool {
        package.id == self.package && self.affected_versions.matches(&package.version)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpactFinding {
    pub advisory: Advisory,
    pub package: PackageRef,
    pub status: VexStatus,
    pub dependency_paths: Vec<DependencyPath>,
    pub reverse_dependents: Vec<PackageRef>,
    pub remediation: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpactReport {
    pub product: String,
    pub findings: Vec<ImpactFinding>,
    pub unaffected: Vec<Advisory>,
}

impl ImpactReport {
    pub fn from_result(
        product: impl Into<String>,
        result: &ResolveResult,
        advisories: &[Advisory],
    ) -> Self {
        let product = product.into();
        let query = GraphQuery::new(result);
        let mut findings = Vec::new();
        let mut unaffected = Vec::new();

        for advisory in advisories {
            let impacted = result
                .nodes
                .keys()
                .filter(|package| advisory.affects(package))
                .cloned()
                .collect::<Vec<_>>();

            if impacted.is_empty() {
                unaffected.push(advisory.clone());
                continue;
            }

            for package in impacted {
                findings.push(ImpactFinding {
                    advisory: advisory.clone(),
                    dependency_paths: query.paths_to(&package.id, 64),
                    reverse_dependents: query.reverse_dependencies(&package.id),
                    remediation: remediation(advisory),
                    package,
                    status: VexStatus::Affected,
                });
            }
        }

        findings.sort_by(|left, right| {
            (
                severity_rank(&left.advisory.severity),
                left.advisory.id.clone(),
                left.package.to_string(),
            )
                .cmp(&(
                    severity_rank(&right.advisory.severity),
                    right.advisory.id.clone(),
                    right.package.to_string(),
                ))
        });
        unaffected.sort_by(|left, right| left.id.cmp(&right.id));

        Self {
            product,
            findings,
            unaffected,
        }
    }

    pub fn is_affected(&self) -> bool {
        !self.findings.is_empty()
    }
}

fn remediation(advisory: &Advisory) -> String {
    match &advisory.fixed_versions {
        Some(version) => format!("upgrade {} to {}", advisory.package, version),
        None => format!("review {} patch or TuxCare coverage", advisory.package),
    }
}

fn severity_rank(severity: &AdvisorySeverity) -> u8 {
    match severity {
        AdvisorySeverity::Critical => 0,
        AdvisorySeverity::High => 1,
        AdvisorySeverity::Medium => 2,
        AdvisorySeverity::Low => 3,
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{
        DependencyRequirement, PackageId, PackageVersion, ResolutionContext, VersionRequirement,
    };
    use crate::repository::InMemoryRepository;
    use crate::resolver::Resolver;

    use super::*;

    #[test]
    fn advisory_matches_selected_package_version() {
        let package = PackageRef::new(PackageId::python("urllib3"), crate::Version::parse("2.2.2"));
        let advisory = Advisory::new(
            "CVE-1",
            "urllib3 issue",
            PackageId::python("urllib3"),
            VersionRequirement::parse("<2.2.3"),
            AdvisorySeverity::High,
        );

        assert!(advisory.affects(&package));
    }

    #[test]
    fn impact_report_includes_dependency_paths_and_dependents() {
        let app = PackageId::internal("app");
        let requests = PackageId::python("requests");
        let urllib3 = PackageId::python("urllib3");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(requests.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(
            PackageVersion::new(requests.clone(), "2.32.3").with_dependencies(vec![
                DependencyRequirement::new(urllib3.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(urllib3.clone(), "2.2.2"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let advisory = Advisory::new(
            "CVE-2026-0001",
            "urllib3 exposure",
            urllib3,
            VersionRequirement::parse("<2.2.3"),
            AdvisorySeverity::Critical,
        )
        .fixed_by(VersionRequirement::parse(">=2.2.3"));

        let report = ImpactReport::from_result("demo", &result, &[advisory]);

        assert!(report.is_affected());
        assert_eq!(report.findings.len(), 1);
        assert!(
            report.findings[0].dependency_paths[0]
                .display()
                .contains("python:requests@2.32.3")
        );
        assert!(
            report.findings[0]
                .reverse_dependents
                .iter()
                .any(|package| package.id == requests)
        );
        assert!(report.findings[0].remediation.contains(">=2.2.3"));
    }

    #[test]
    fn impact_report_records_unaffected_advisories() {
        let app = PackageId::internal("app");
        let mut repo = InMemoryRepository::new();
        repo.add(PackageVersion::new(app.clone(), "1.0"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let advisory = Advisory::new(
            "CVE-2026-0002",
            "missing package",
            PackageId::rpm("openssl-libs"),
            VersionRequirement::any(),
            AdvisorySeverity::Medium,
        );

        let report = ImpactReport::from_result("demo", &result, &[advisory]);

        assert!(!report.is_affected());
        assert_eq!(report.unaffected.len(), 1);
    }

    #[test]
    fn impact_report_orders_highest_severity_first() {
        let app = PackageId::internal("app");
        let low_dep = PackageId::python("low");
        let critical_dep = PackageId::python("critical");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(low_dep.clone(), VersionRequirement::any()),
                DependencyRequirement::new(critical_dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(low_dep.clone(), "1.0"));
        repo.add(PackageVersion::new(critical_dep.clone(), "1.0"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let advisories = vec![
            Advisory::new(
                "LOW-1",
                "low",
                low_dep,
                VersionRequirement::any(),
                AdvisorySeverity::Low,
            ),
            Advisory::new(
                "CRIT-1",
                "critical",
                critical_dep,
                VersionRequirement::any(),
                AdvisorySeverity::Critical,
            ),
        ];

        let report = ImpactReport::from_result("demo", &result, &advisories);

        assert_eq!(report.findings[0].advisory.id, "CRIT-1");
    }
}
