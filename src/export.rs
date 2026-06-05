use crate::advisory::{ImpactReport, VexStatus};
use crate::json::JsonValue as Json;
use crate::policy::{PolicyEvaluation, PolicySeverity};
use crate::query::GraphQuery;
use crate::resolver::ResolveResult;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycloneDxView {
    pub name: String,
    pub json: String,
}

impl CycloneDxView {
    pub fn from_result(name: impl Into<String>, result: &ResolveResult) -> Self {
        let name = name.into();
        let mut packages = result.nodes.keys().cloned().collect::<Vec<_>>();
        packages.sort();
        let query = GraphQuery::new(result);

        Self {
            json: Json::object([
                ("bomFormat", Json::string("CycloneDX")),
                ("specVersion", Json::string("1.6")),
                (
                    "metadata",
                    Json::object([(
                        "component",
                        Json::object([
                            ("type", Json::string("application")),
                            ("name", Json::string(name.clone())),
                        ]),
                    )]),
                ),
                (
                    "components",
                    Json::array(packages.iter().map(|package| {
                        Json::object([
                            ("type", Json::string("library")),
                            ("bom-ref", Json::string(package.to_string())),
                            ("name", Json::string(package.id.name.clone())),
                            ("version", Json::string(package.version.to_string())),
                            (
                                "purl",
                                Json::string(format!("pkg:{}", package.id.purl_like())),
                            ),
                        ])
                    })),
                ),
                (
                    "dependencies",
                    Json::array(packages.iter().map(|package| {
                        let depends_on = query
                            .direct_dependencies(package)
                            .into_iter()
                            .map(|dependency| dependency.to_string());
                        Json::object([
                            ("ref", Json::string(package.to_string())),
                            ("dependsOn", Json::string_array(depends_on)),
                        ])
                    })),
                ),
            ])
            .to_json(),
            name,
        }
    }

    pub fn to_json(&self) -> &str {
        &self.json
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpdxView {
    pub name: String,
    pub json: String,
}

impl SpdxView {
    pub fn from_result(name: impl Into<String>, result: &ResolveResult) -> Self {
        let name = name.into();
        let mut packages = result.nodes.keys().cloned().collect::<Vec<_>>();
        packages.sort();
        let query = GraphQuery::new(result);
        let relationships = packages.iter().flat_map(|package| {
            query
                .direct_dependency_edges(package)
                .into_iter()
                .map(|edge| {
                    Json::object([
                        (
                            "spdxElementId",
                            Json::string(format!(
                                "SPDXRef-Package-{}",
                                spdx_id(&package.to_string())
                            )),
                        ),
                        ("relationshipType", Json::string("DEPENDS_ON")),
                        (
                            "relatedSpdxElement",
                            Json::string(format!(
                                "SPDXRef-Package-{}",
                                spdx_id(&edge.to.to_string())
                            )),
                        ),
                    ])
                })
                .collect::<Vec<_>>()
        });

        Self {
            json: Json::object([
                ("spdxVersion", Json::string("SPDX-2.3")),
                ("dataLicense", Json::string("CC0-1.0")),
                ("SPDXID", Json::string("SPDXRef-DOCUMENT")),
                ("name", Json::string(name.clone())),
                (
                    "documentNamespace",
                    Json::string(format!("https://graphscope.local/spdx/{}", spdx_id(&name))),
                ),
                (
                    "packages",
                    Json::array(packages.iter().map(|package| {
                        Json::object([
                            (
                                "SPDXID",
                                Json::string(format!(
                                    "SPDXRef-Package-{}",
                                    spdx_id(&package.to_string())
                                )),
                            ),
                            ("name", Json::string(package.id.name.clone())),
                            ("versionInfo", Json::string(package.version.to_string())),
                            ("downloadLocation", Json::string("NOASSERTION")),
                            ("filesAnalyzed", Json::bool(false)),
                        ])
                    })),
                ),
                ("relationships", Json::array(relationships)),
            ])
            .to_json(),
            name,
        }
    }

    pub fn to_json(&self) -> &str {
        &self.json
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VexView {
    pub product: String,
    pub json: String,
}

impl VexView {
    pub fn from_impact_report(report: &ImpactReport) -> Self {
        let affected = report.findings.iter().map(|finding| {
            Json::object([
                ("vulnerability", Json::string(finding.advisory.id.clone())),
                ("product", Json::string(report.product.clone())),
                ("component", Json::string(finding.package.to_string())),
                ("status", Json::string(finding.status.to_string())),
                (
                    "justification",
                    Json::string("dependency graph contains affected selected package"),
                ),
                ("action", Json::string(finding.remediation.clone())),
            ])
        });
        let unaffected = report.unaffected.iter().map(|advisory| {
            Json::object([
                ("vulnerability", Json::string(advisory.id.clone())),
                ("product", Json::string(report.product.clone())),
                ("component", Json::string(advisory.package.to_string())),
                ("status", Json::string(VexStatus::NotAffected.to_string())),
                (
                    "justification",
                    Json::string("affected package was not selected in this graph"),
                ),
            ])
        });

        Self {
            product: report.product.clone(),
            json: Json::object([
                ("format", Json::string("GraphScope VEX")),
                ("version", Json::string("1")),
                ("statements", Json::array(affected.chain(unaffected))),
            ])
            .to_json(),
        }
    }

    pub fn to_json(&self) -> &str {
        &self.json
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlaSummary {
    pub product: String,
    pub affected_findings: usize,
    pub critical_findings: usize,
    pub policy_errors: usize,
    pub policy_warnings: usize,
    pub remediation_actions: usize,
    pub risk_score: u16,
}

impl SlaSummary {
    pub fn from_impact_and_policy(
        product: impl Into<String>,
        impact: &ImpactReport,
        policy: &PolicyEvaluation,
    ) -> Self {
        let product = product.into();
        let affected_findings = impact.findings.len();
        let critical_findings = impact
            .findings
            .iter()
            .filter(|finding| finding.advisory.severity.to_string() == "critical")
            .count();
        let policy_errors = policy
            .violations
            .iter()
            .filter(|violation| {
                matches!(
                    violation.severity,
                    PolicySeverity::Error | PolicySeverity::Critical
                )
            })
            .count();
        let policy_warnings = policy
            .violations
            .iter()
            .filter(|violation| violation.severity == PolicySeverity::Warning)
            .count();
        let remediation_actions = affected_findings + policy_errors;
        let risk_score = ((critical_findings as u16) * 40)
            .saturating_add((affected_findings as u16) * 10)
            .saturating_add((policy_errors as u16) * 15)
            .saturating_add((policy_warnings as u16) * 3)
            .min(100);

        Self {
            product,
            affected_findings,
            critical_findings,
            policy_errors,
            policy_warnings,
            remediation_actions,
            risk_score,
        }
    }

    pub fn to_json(&self) -> String {
        Json::object([
            ("product", Json::string(self.product.clone())),
            ("affected_findings", Json::number(self.affected_findings)),
            ("critical_findings", Json::number(self.critical_findings)),
            ("policy_errors", Json::number(self.policy_errors)),
            ("policy_warnings", Json::number(self.policy_warnings)),
            (
                "remediation_actions",
                Json::number(self.remediation_actions),
            ),
            ("risk_score", Json::number(self.risk_score)),
        ])
        .to_json()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskDashboard {
    pub product_count: usize,
    pub affected_products: usize,
    pub high_risk_products: usize,
    pub total_affected_findings: usize,
    pub total_policy_errors: usize,
    pub total_policy_warnings: usize,
    pub total_remediation_actions: usize,
    pub max_risk_score: u16,
    pub highest_risk_product: Option<String>,
}

impl RiskDashboard {
    pub fn from_summaries(summaries: &[SlaSummary]) -> Self {
        let product_count = summaries.len();
        let affected_products = summaries
            .iter()
            .filter(|summary| summary.affected_findings > 0 || summary.policy_errors > 0)
            .count();
        let high_risk_products = summaries
            .iter()
            .filter(|summary| summary.risk_score >= 50)
            .count();
        let total_affected_findings = summaries
            .iter()
            .map(|summary| summary.affected_findings)
            .sum();
        let total_policy_errors = summaries.iter().map(|summary| summary.policy_errors).sum();
        let total_policy_warnings = summaries
            .iter()
            .map(|summary| summary.policy_warnings)
            .sum();
        let total_remediation_actions = summaries
            .iter()
            .map(|summary| summary.remediation_actions)
            .sum();
        let mut ranked = summaries.iter().collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .risk_score
                .cmp(&left.risk_score)
                .then_with(|| left.product.cmp(&right.product))
        });
        let max_risk_score = ranked.first().map_or(0, |summary| summary.risk_score);
        let highest_risk_product = ranked.first().map(|summary| summary.product.clone());

        Self {
            product_count,
            affected_products,
            high_risk_products,
            total_affected_findings,
            total_policy_errors,
            total_policy_warnings,
            total_remediation_actions,
            max_risk_score,
            highest_risk_product,
        }
    }

    pub fn risk_band(&self) -> &'static str {
        match self.max_risk_score {
            0..=20 => "low",
            21..=50 => "medium",
            51..=80 => "high",
            _ => "critical",
        }
    }

    pub fn to_json(&self) -> String {
        Json::object([
            ("format", Json::string("GraphScope Risk Dashboard")),
            ("product_count", Json::number(self.product_count)),
            ("affected_products", Json::number(self.affected_products)),
            ("high_risk_products", Json::number(self.high_risk_products)),
            (
                "total_affected_findings",
                Json::number(self.total_affected_findings),
            ),
            (
                "total_policy_errors",
                Json::number(self.total_policy_errors),
            ),
            (
                "total_policy_warnings",
                Json::number(self.total_policy_warnings),
            ),
            (
                "total_remediation_actions",
                Json::number(self.total_remediation_actions),
            ),
            ("max_risk_score", Json::number(self.max_risk_score)),
            ("risk_band", Json::string(self.risk_band())),
            (
                "highest_risk_product",
                Json::optional_string(self.highest_risk_product.as_deref()),
            ),
        ])
        .to_json()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemediationReport {
    pub product: String,
    pub markdown: String,
}

impl RemediationReport {
    pub fn from_impact_report(report: &ImpactReport) -> Self {
        let mut markdown = String::new();
        markdown.push_str(&format!("# Remediation Report: {}\n\n", report.product));

        if report.findings.is_empty() {
            markdown.push_str("No affected selected packages were found.\n");
        } else {
            for finding in &report.findings {
                markdown.push_str(&format!(
                    "## {} ({})\n\n",
                    finding.advisory.id, finding.advisory.severity
                ));
                markdown.push_str(&format!("- Package: `{}`\n", finding.package));
                markdown.push_str(&format!("- Status: `{}`\n", finding.status));
                markdown.push_str(&format!("- Remediation: {}\n", finding.remediation));
                markdown.push_str("- Evidence paths:\n");
                for path in &finding.dependency_paths {
                    markdown.push_str(&format!("  - `{}`\n", path.display()));
                }
                markdown.push('\n');
            }
        }

        Self {
            product: report.product.clone(),
            markdown,
        }
    }

    pub fn to_markdown(&self) -> &str {
        &self.markdown
    }
}

fn spdx_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::advisory::{Advisory, AdvisorySeverity, ImpactReport};
    use crate::model::{
        DependencyRequirement, PackageId, PackageVersion, ResolutionContext, VersionRequirement,
    };
    use crate::repository::InMemoryRepository;
    use crate::resolver::Resolver;

    use super::*;

    #[test]
    fn cyclonedx_view_exports_components_and_dependencies() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("requests");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep, "2.32.3"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        let bom = CycloneDxView::from_result("demo", &result);

        assert!(bom.to_json().contains("\"bomFormat\":\"CycloneDX\""));
        assert!(bom.to_json().contains("python:requests@2.32.3"));
        assert!(bom.to_json().contains("\"dependencies\""));
    }

    #[test]
    fn spdx_view_exports_packages_and_relationships() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("requests");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep, "2.32.3"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        let spdx = SpdxView::from_result("demo", &result);

        assert!(spdx.to_json().contains("\"spdxVersion\":\"SPDX-2.3\""));
        assert!(
            spdx.to_json()
                .contains("\"relationshipType\":\"DEPENDS_ON\"")
        );
        assert!(spdx.to_json().contains("requests"));
    }

    #[test]
    fn vex_view_exports_affected_and_unaffected_statements() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("urllib3");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "2.2.2"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let advisories = vec![
            Advisory::new(
                "CVE-1",
                "urllib3",
                dep,
                VersionRequirement::parse("<2.2.3"),
                AdvisorySeverity::High,
            ),
            Advisory::new(
                "CVE-2",
                "openssl",
                PackageId::rpm("openssl-libs"),
                VersionRequirement::any(),
                AdvisorySeverity::Medium,
            ),
        ];
        let report = ImpactReport::from_result("demo", &result, &advisories);

        let vex = VexView::from_impact_report(&report);

        assert!(vex.to_json().contains("\"status\":\"affected\""));
        assert!(vex.to_json().contains("\"status\":\"not_affected\""));
    }

    #[test]
    fn remediation_report_includes_paths_and_actions() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("urllib3");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "2.2.2"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let advisory = Advisory::new(
            "CVE-1",
            "urllib3",
            dep,
            VersionRequirement::parse("<2.2.3"),
            AdvisorySeverity::High,
        );
        let impact = ImpactReport::from_result("demo", &result, &[advisory]);

        let report = RemediationReport::from_impact_report(&impact);

        assert!(report.to_markdown().contains("# Remediation Report"));
        assert!(report.to_markdown().contains("Evidence paths"));
    }

    #[test]
    fn sla_summary_combines_impact_and_policy_counts() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("urllib3");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "2.2.2"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let advisory = Advisory::new(
            "CVE-1",
            "urllib3",
            dep,
            VersionRequirement::parse("<2.2.3"),
            AdvisorySeverity::Critical,
        );
        let impact = ImpactReport::from_result("demo", &result, &[advisory]);
        let policy = crate::policy::PolicyEvaluation {
            violations: vec![crate::policy::PolicyViolation {
                rule: "deny-package".to_string(),
                severity: crate::policy::PolicySeverity::Error,
                package: None,
                edge: None,
                message: "blocked".to_string(),
            }],
        };

        let summary = SlaSummary::from_impact_and_policy("demo", &impact, &policy);

        assert_eq!(summary.affected_findings, 1);
        assert_eq!(summary.critical_findings, 1);
        assert_eq!(summary.policy_errors, 1);
        assert!(summary.to_json().contains("\"risk_score\""));
    }

    #[test]
    fn risk_dashboard_aggregates_sla_summaries() {
        let dashboard = RiskDashboard::from_summaries(&[
            SlaSummary {
                product: "customer-a/portal".to_string(),
                affected_findings: 2,
                critical_findings: 1,
                policy_errors: 1,
                policy_warnings: 1,
                remediation_actions: 3,
                risk_score: 75,
            },
            SlaSummary {
                product: "customer-b/api".to_string(),
                affected_findings: 0,
                critical_findings: 0,
                policy_errors: 0,
                policy_warnings: 2,
                remediation_actions: 0,
                risk_score: 6,
            },
        ]);

        assert_eq!(dashboard.product_count, 2);
        assert_eq!(dashboard.affected_products, 1);
        assert_eq!(dashboard.high_risk_products, 1);
        assert_eq!(dashboard.total_remediation_actions, 3);
        assert_eq!(
            dashboard.highest_risk_product,
            Some("customer-a/portal".to_string())
        );
        assert_eq!(dashboard.risk_band(), "high");
        assert!(dashboard.to_json().contains("GraphScope Risk Dashboard"));
    }

    #[test]
    fn risk_dashboard_handles_empty_summary_set() {
        let dashboard = RiskDashboard::from_summaries(&[]);

        assert_eq!(dashboard.product_count, 0);
        assert_eq!(dashboard.max_risk_score, 0);
        assert_eq!(dashboard.highest_risk_product, None);
        assert!(
            dashboard
                .to_json()
                .contains("\"highest_risk_product\":null")
        );
    }
}
