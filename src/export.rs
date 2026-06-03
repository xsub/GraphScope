use crate::advisory::{ImpactReport, VexStatus};
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
}
