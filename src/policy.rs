//! Customer policy evaluation for package sources, signatures, coverage, and rules.

use std::collections::BTreeSet;
use std::fmt;

use crate::model::{Ecosystem, PackageId, PackageRef, PackageSource};
use crate::resolver::{ResolveResult, ResolvedEdge};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicySeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for PolicySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicySeverity::Info => write!(f, "info"),
            PolicySeverity::Warning => write!(f, "warning"),
            PolicySeverity::Error => write!(f, "error"),
            PolicySeverity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRule {
    AllowSources {
        ecosystem: Option<Ecosystem>,
        allowed_sources: BTreeSet<String>,
        severity: PolicySeverity,
    },
    RequireSigned {
        ecosystem: Option<Ecosystem>,
        severity: PolicySeverity,
    },
    DenyPackage {
        package: PackageId,
        reason: String,
        severity: PolicySeverity,
    },
    DenyWildcardRequirement {
        ecosystem: Option<Ecosystem>,
        severity: PolicySeverity,
    },
    RequireCoverage {
        ecosystem: Option<Ecosystem>,
        covered_packages: BTreeSet<PackageId>,
        severity: PolicySeverity,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyViolation {
    pub rule: String,
    pub severity: PolicySeverity,
    pub package: Option<PackageRef>,
    pub edge: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub violations: Vec<PolicyViolation>,
}

impl PolicyEvaluation {
    pub fn is_compliant(&self) -> bool {
        !self.violations.iter().any(|violation| {
            matches!(
                violation.severity,
                PolicySeverity::Error | PolicySeverity::Critical
            )
        })
    }

    pub fn by_severity(&self, severity: PolicySeverity) -> Vec<&PolicyViolation> {
        self.violations
            .iter()
            .filter(|violation| violation.severity == severity)
            .collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySet {
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    pub fn evaluate(&self, result: &ResolveResult) -> PolicyEvaluation {
        let mut violations = Vec::new();
        for rule in &self.rules {
            match rule {
                PolicyRule::AllowSources {
                    ecosystem,
                    allowed_sources,
                    severity,
                } => evaluate_allowed_sources(
                    result,
                    ecosystem.as_ref(),
                    allowed_sources,
                    severity,
                    &mut violations,
                ),
                PolicyRule::RequireSigned {
                    ecosystem,
                    severity,
                } => evaluate_signed(result, ecosystem.as_ref(), severity, &mut violations),
                PolicyRule::DenyPackage {
                    package,
                    reason,
                    severity,
                } => evaluate_denied_package(result, package, reason, severity, &mut violations),
                PolicyRule::DenyWildcardRequirement {
                    ecosystem,
                    severity,
                } => evaluate_wildcard_edges(result, ecosystem.as_ref(), severity, &mut violations),
                PolicyRule::RequireCoverage {
                    ecosystem,
                    covered_packages,
                    severity,
                } => evaluate_coverage(
                    result,
                    ecosystem.as_ref(),
                    covered_packages,
                    severity,
                    &mut violations,
                ),
            }
        }

        violations.sort_by(|left, right| {
            (
                severity_rank(&left.severity),
                left.package.as_ref().map(ToString::to_string),
                left.rule.clone(),
                left.message.clone(),
            )
                .cmp(&(
                    severity_rank(&right.severity),
                    right.package.as_ref().map(ToString::to_string),
                    right.rule.clone(),
                    right.message.clone(),
                ))
        });
        PolicyEvaluation { violations }
    }
}

fn evaluate_allowed_sources(
    result: &ResolveResult,
    ecosystem: Option<&Ecosystem>,
    allowed_sources: &BTreeSet<String>,
    severity: &PolicySeverity,
    violations: &mut Vec<PolicyViolation>,
) {
    for node in result.nodes.values() {
        if !ecosystem_matches(ecosystem, &node.package.id.ecosystem) {
            continue;
        }
        let source = source_locator(&node.metadata.source);
        if !allowed_sources.contains(&source) {
            violations.push(PolicyViolation {
                rule: "allow-sources".to_string(),
                severity: severity.clone(),
                package: Some(node.package.clone()),
                edge: None,
                message: format!("source {source} is not allowed"),
            });
        }
    }
}

fn evaluate_signed(
    result: &ResolveResult,
    ecosystem: Option<&Ecosystem>,
    severity: &PolicySeverity,
    violations: &mut Vec<PolicyViolation>,
) {
    for node in result.nodes.values() {
        if ecosystem_matches(ecosystem, &node.package.id.ecosystem) && !node.metadata.signed {
            violations.push(PolicyViolation {
                rule: "require-signed".to_string(),
                severity: severity.clone(),
                package: Some(node.package.clone()),
                edge: None,
                message: "selected package is not signed".to_string(),
            });
        }
    }
}

fn evaluate_denied_package(
    result: &ResolveResult,
    package: &PackageId,
    reason: &str,
    severity: &PolicySeverity,
    violations: &mut Vec<PolicyViolation>,
) {
    for node in result
        .nodes
        .values()
        .filter(|node| node.package.id == *package)
    {
        violations.push(PolicyViolation {
            rule: "deny-package".to_string(),
            severity: severity.clone(),
            package: Some(node.package.clone()),
            edge: None,
            message: reason.to_string(),
        });
    }
}

fn evaluate_wildcard_edges(
    result: &ResolveResult,
    ecosystem: Option<&Ecosystem>,
    severity: &PolicySeverity,
    violations: &mut Vec<PolicyViolation>,
) {
    for edge in &result.edges {
        if ecosystem_matches(ecosystem, &edge.requirement.target.ecosystem)
            && edge.requirement.requirement.clauses.is_empty()
        {
            violations.push(PolicyViolation {
                rule: "deny-wildcard-requirement".to_string(),
                severity: severity.clone(),
                package: Some(edge.to.clone()),
                edge: Some(edge_display(edge)),
                message: "dependency requirement uses wildcard version".to_string(),
            });
        }
    }
}

fn evaluate_coverage(
    result: &ResolveResult,
    ecosystem: Option<&Ecosystem>,
    covered_packages: &BTreeSet<PackageId>,
    severity: &PolicySeverity,
    violations: &mut Vec<PolicyViolation>,
) {
    for node in result.nodes.values() {
        if ecosystem_matches(ecosystem, &node.package.id.ecosystem)
            && !covered_packages.contains(&node.package.id)
        {
            violations.push(PolicyViolation {
                rule: "require-coverage".to_string(),
                severity: severity.clone(),
                package: Some(node.package.clone()),
                edge: None,
                message: "package is not covered by policy metadata".to_string(),
            });
        }
    }
}

fn ecosystem_matches(expected: Option<&Ecosystem>, actual: &Ecosystem) -> bool {
    expected.is_none_or(|expected| expected == actual)
}

fn source_locator(source: &PackageSource) -> String {
    match source {
        PackageSource::Registry(url) => format!("registry:{url}"),
        PackageSource::Repository(name) => format!("repository:{name}"),
        PackageSource::Lockfile(path) => format!("lockfile:{path}"),
        PackageSource::Sdist(url) => format!("sdist:{url}"),
        PackageSource::Wheel(url) => format!("wheel:{url}"),
        PackageSource::RpmRepo { repo, .. } => format!("rpm-repo:{repo}"),
        PackageSource::Internal(name) => format!("internal:{name}"),
        PackageSource::Unknown => "unknown".to_string(),
    }
}

fn edge_display(edge: &ResolvedEdge) -> String {
    let from = edge
        .from
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "root".to_string());
    format!("{} -> {}", from, edge.to)
}

fn severity_rank(severity: &PolicySeverity) -> u8 {
    match severity {
        PolicySeverity::Critical => 0,
        PolicySeverity::Error => 1,
        PolicySeverity::Warning => 2,
        PolicySeverity::Info => 3,
    }
}

#[cfg(test)]
mod tests {
    use crate::demo::demo_repository;
    use crate::model::{
        DependencyRequirement, Ecosystem, PackageId, PackageVersion, ResolutionContext,
        VersionRequirement,
    };
    use crate::repository::InMemoryRepository;
    use crate::resolver::Resolver;

    use super::*;

    #[test]
    fn policy_detects_disallowed_sources() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);
        let policy = PolicySet::new(vec![PolicyRule::AllowSources {
            ecosystem: Some(Ecosystem::Python),
            allowed_sources: BTreeSet::from([
                "registry:https://internal.example/simple".to_string()
            ]),
            severity: PolicySeverity::Error,
        }]);

        let evaluation = policy.evaluate(&result);

        assert!(!evaluation.is_compliant());
        assert!(
            evaluation
                .violations
                .iter()
                .any(|violation| violation.message.contains("pypi.org"))
        );
    }

    #[test]
    fn policy_requires_signed_packages_for_ecosystem() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);
        let policy = PolicySet::new(vec![PolicyRule::RequireSigned {
            ecosystem: Some(Ecosystem::Python),
            severity: PolicySeverity::Warning,
        }]);

        let evaluation = policy.evaluate(&result);

        assert!(!evaluation.violations.is_empty());
        assert!(evaluation.is_compliant());
    }

    #[test]
    fn policy_detects_wildcard_requirements() {
        let app = PackageId::internal("app");
        let dep = PackageId::rpm("openssl-libs");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep, "3.2.2"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let policy = PolicySet::new(vec![PolicyRule::DenyWildcardRequirement {
            ecosystem: Some(Ecosystem::Rpm),
            severity: PolicySeverity::Error,
        }]);

        let evaluation = policy.evaluate(&result);

        assert!(!evaluation.is_compliant());
        assert_eq!(evaluation.violations[0].rule, "deny-wildcard-requirement");
    }

    #[test]
    fn policy_detects_denied_and_uncovered_packages() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);
        let policy = PolicySet::new(vec![
            PolicyRule::DenyPackage {
                package: PackageId::python("urllib3"),
                reason: "EOL package line".to_string(),
                severity: PolicySeverity::Critical,
            },
            PolicyRule::RequireCoverage {
                ecosystem: Some(Ecosystem::Rpm),
                covered_packages: BTreeSet::from([PackageId::rpm("kernelcare-agent")]),
                severity: PolicySeverity::Warning,
            },
        ]);

        let evaluation = policy.evaluate(&result);

        assert!(
            evaluation
                .violations
                .iter()
                .any(|violation| violation.rule == "deny-package")
        );
        assert!(
            evaluation
                .violations
                .iter()
                .any(|violation| violation.rule == "require-coverage")
        );
    }
}
