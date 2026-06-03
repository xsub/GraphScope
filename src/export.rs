use crate::advisory::{ImpactReport, VexStatus};
use crate::policy::{PolicyEvaluation, PolicySeverity};
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

        let components = packages
            .iter()
            .map(|package| {
                format!(
                    "{{\"type\":\"library\",\"bom-ref\":\"{}\",\"name\":\"{}\",\"version\":\"{}\",\"purl\":\"pkg:{}\"}}",
                    escape_json(&package.to_string()),
                    escape_json(&package.id.name),
                    escape_json(&package.version.to_string()),
                    escape_json(&package.id.purl_like())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let dependencies = packages
            .iter()
            .map(|package| {
                let depends_on = result
                    .edges
                    .iter()
                    .filter(|edge| edge.from.as_ref() == Some(package))
                    .map(|edge| edge.to.to_string())
                    .collect::<Vec<_>>();
                format!(
                    "{{\"ref\":\"{}\",\"dependsOn\":[{}]}}",
                    escape_json(&package.to_string()),
                    json_string_array(depends_on.iter().map(String::as_str))
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        Self {
            json: format!(
                "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"metadata\":{{\"component\":{{\"type\":\"application\",\"name\":\"{}\"}}}},\"components\":[{}],\"dependencies\":[{}]}}",
                escape_json(&name),
                components,
                dependencies
            ),
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
        let package_json = packages
            .iter()
            .map(|package| {
                format!(
                    "{{\"SPDXID\":\"SPDXRef-Package-{}\",\"name\":\"{}\",\"versionInfo\":\"{}\",\"downloadLocation\":\"NOASSERTION\",\"filesAnalyzed\":false}}",
                    spdx_id(&package.to_string()),
                    escape_json(&package.id.name),
                    escape_json(&package.version.to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let relationship_json = result
            .edges
            .iter()
            .filter_map(|edge| {
                edge.from.as_ref().map(|from| {
                    format!(
                        "{{\"spdxElementId\":\"SPDXRef-Package-{}\",\"relationshipType\":\"DEPENDS_ON\",\"relatedSpdxElement\":\"SPDXRef-Package-{}\"}}",
                        spdx_id(&from.to_string()),
                        spdx_id(&edge.to.to_string())
                    )
                })
            })
            .collect::<Vec<_>>()
            .join(",");

        Self {
            json: format!(
                "{{\"spdxVersion\":\"SPDX-2.3\",\"dataLicense\":\"CC0-1.0\",\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"{}\",\"documentNamespace\":\"https://graphscope.local/spdx/{}\",\"packages\":[{}],\"relationships\":[{}]}}",
                escape_json(&name),
                spdx_id(&name),
                package_json,
                relationship_json
            ),
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
        let affected = report
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{{\"vulnerability\":\"{}\",\"product\":\"{}\",\"component\":\"{}\",\"status\":\"{}\",\"justification\":\"dependency graph contains affected selected package\",\"action\":\"{}\"}}",
                    escape_json(&finding.advisory.id),
                    escape_json(&report.product),
                    escape_json(&finding.package.to_string()),
                    finding.status,
                    escape_json(&finding.remediation)
                )
            })
            .collect::<Vec<_>>();
        let unaffected = report
            .unaffected
            .iter()
            .map(|advisory| {
                format!(
                    "{{\"vulnerability\":\"{}\",\"product\":\"{}\",\"component\":\"{}\",\"status\":\"{}\",\"justification\":\"affected package was not selected in this graph\"}}",
                    escape_json(&advisory.id),
                    escape_json(&report.product),
                    escape_json(&advisory.package.to_string()),
                    VexStatus::NotAffected
                )
            })
            .collect::<Vec<_>>();
        let statements = affected
            .into_iter()
            .chain(unaffected)
            .collect::<Vec<_>>()
            .join(",");

        Self {
            product: report.product.clone(),
            json: format!(
                "{{\"format\":\"GraphScope VEX\",\"version\":\"1\",\"statements\":[{}]}}",
                statements
            ),
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
        format!(
            "{{\"product\":\"{}\",\"affected_findings\":{},\"critical_findings\":{},\"policy_errors\":{},\"policy_warnings\":{},\"remediation_actions\":{},\"risk_score\":{}}}",
            escape_json(&self.product),
            self.affected_findings,
            self.critical_findings,
            self.policy_errors,
            self.policy_warnings,
            self.remediation_actions,
            self.risk_score
        )
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
        let highest = self
            .highest_risk_product
            .as_ref()
            .map(|product| format!("\"{}\"", escape_json(product)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"format\":\"GraphScope Risk Dashboard\",\"product_count\":{},\"affected_products\":{},\"high_risk_products\":{},\"total_affected_findings\":{},\"total_policy_errors\":{},\"total_policy_warnings\":{},\"total_remediation_actions\":{},\"max_risk_score\":{},\"risk_band\":\"{}\",\"highest_risk_product\":{}}}",
            self.product_count,
            self.affected_products,
            self.high_risk_products,
            self.total_affected_findings,
            self.total_policy_errors,
            self.total_policy_warnings,
            self.total_remediation_actions,
            self.max_risk_score,
            self.risk_band(),
            highest
        )
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

fn json_string_array<'a>(values: impl IntoIterator<Item = impl AsRef<str> + 'a>) -> String {
    values
        .into_iter()
        .map(|value| format!("\"{}\"", escape_json(value.as_ref())))
        .collect::<Vec<_>>()
        .join(",")
}

fn spdx_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
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
