use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use graphscope::{
    DependencyRequirement, Ecosystem, EvidenceConfidence, GraphSnapshot, PackageId, PackageVersion,
    Resolver, VersionRequirement, demo_repository, parse_cargo_lock_packages, parse_cyclonedx_sbom,
    parse_evidence, parse_go_mod_requirements, parse_gradle_dependencies,
    parse_maven_pom_dependencies, parse_npm_package_lock, parse_pip_requirements_lock,
    parse_rpm_inventory,
};

#[test]
fn public_api_resolves_demo_graph_without_conflicts() {
    let (repository, roots, context) = demo_repository();
    let result = Resolver::new(repository).resolve(roots, &context);

    assert!(result.conflicts.is_empty());
    assert!(result.contains_package(&PackageId::rpm("kernelcare-agent")));
}

#[test]
fn public_api_can_build_and_resolve_custom_repository() {
    let app = PackageId::internal("custom-app");
    let dependency = PackageId::cargo("petgraph");
    let mut repository = graphscope::InMemoryRepository::new();
    repository.add(
        PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
            DependencyRequirement::new(dependency.clone(), VersionRequirement::parse("^0.6.0")),
        ]),
    );
    repository.add(PackageVersion::new(dependency.clone(), "0.6.5"));

    let result = Resolver::new(repository).resolve(
        vec![DependencyRequirement::new(app, VersionRequirement::any())],
        &graphscope::ResolutionContext::cloudlinux_production_x86_64(),
    );

    assert!(result.contains_package(&dependency));
}

#[test]
fn public_api_reports_conflict_for_missing_candidate() {
    let missing = PackageId::python("missing");
    let result = Resolver::new(graphscope::InMemoryRepository::new()).resolve(
        vec![DependencyRequirement::new(
            missing.clone(),
            VersionRequirement::parse(">=1.0"),
        )],
        &graphscope::ResolutionContext::cloudlinux_production_x86_64(),
    );

    assert_eq!(result.conflicts.len(), 1);
    assert_eq!(result.conflicts[0].package, missing);
}

#[test]
fn public_api_exposes_skipped_dependency_reason() {
    let package = PackageId::npm(None::<String>, "fsevents");
    let mut repository = graphscope::InMemoryRepository::new();
    repository.add(PackageVersion::new(package.clone(), "2.3.3"));

    let result = Resolver::new(repository).resolve(
        vec![
            DependencyRequirement::new(package, VersionRequirement::any()).when(
                graphscope::ContextPredicate::OsIs(graphscope::OperatingSystem::Macos),
            ),
        ],
        &graphscope::ResolutionContext::cloudlinux_production_x86_64(),
    );

    assert_eq!(result.skipped.len(), 1);
    assert!(
        result.skipped[0]
            .reason
            .contains("context predicate did not match")
    );
}

#[test]
fn cli_demo_outputs_dependency_graph_sections() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("demo")
        .output()
        .expect("demo command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Selected packages"));
    assert!(stdout.contains("Activated edges"));
    assert!(stdout.contains("Skipped dependencies"));
    assert!(stdout.contains("Conflicts"));
    assert!(stdout.contains("Resolver trace"));
}

#[test]
fn cli_help_outputs_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("help")
        .output()
        .expect("help command should run");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

#[test]
fn cli_snapshot_outputs_stable_json_sections() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("snapshot")
        .output()
        .expect("snapshot command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"snapshot_id\""));
    assert!(stdout.contains("\"context_hash\""));
    assert!(stdout.contains("\"nodes\""));
    assert!(stdout.contains("\"edges\""));
    assert!(stdout.contains("\"trace\""));
}

#[test]
fn cli_impact_outputs_advisory_findings() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("impact")
        .output()
        .expect("impact command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Advisory impact"));
    assert!(stdout.contains("CVE-2026-GS-0001"));
    assert!(stdout.contains("path:"));
}

#[test]
fn cli_report_outputs_remediation_markdown() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("report")
        .output()
        .expect("report command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# Remediation Report"));
    assert!(stdout.contains("Evidence paths"));
}

#[test]
fn cli_sbom_outputs_cyclonedx_view() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("sbom")
        .output()
        .expect("sbom command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"bomFormat\":\"CycloneDX\""));
    assert!(stdout.contains("tuxcare-supply-chain-platform"));
}

#[test]
fn cli_spdx_outputs_spdx_view() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("spdx")
        .output()
        .expect("spdx command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"spdxVersion\":\"SPDX-2.3\""));
    assert!(stdout.contains("\"relationshipType\":\"DEPENDS_ON\""));
    assert!(stdout.contains("tuxcare-supply-chain-platform"));
}

#[test]
fn cli_vex_outputs_status_statements() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("vex")
        .output()
        .expect("vex command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"format\":\"GraphScope VEX\""));
    assert!(stdout.contains("\"status\":\"affected\""));
    assert!(stdout.contains("\"status\":\"not_affected\""));
}

#[test]
fn cli_policy_outputs_policy_violations() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("policy")
        .output()
        .expect("policy command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Policy evaluation"));
    assert!(stdout.contains("Compliant: false"));
    assert!(stdout.contains("deny-package"));
    assert!(stdout.contains("require-signed"));
}

#[test]
fn cli_sla_outputs_risk_summary() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("sla")
        .output()
        .expect("sla command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"product\":\"tuxcare-demo\""));
    assert!(stdout.contains("\"policy_errors\""));
    assert!(stdout.contains("\"remediation_actions\""));
    assert!(stdout.contains("\"risk_score\""));
}

#[test]
fn cli_dashboard_outputs_risk_dashboard() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("dashboard")
        .output()
        .expect("dashboard command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"format\":\"GraphScope Risk Dashboard\""));
    assert!(stdout.contains("\"product_count\":1"));
    assert!(stdout.contains("\"highest_risk_product\":\"customer-a/tuxcare-demo\""));
}

#[test]
fn cli_invalidate_outputs_invalidation_plan() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("invalidate")
        .output()
        .expect("invalidate command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Invalidation plan"));
    assert!(stdout.contains("rerun customer-a/tuxcare-demo/ctx-"));
    assert!(stdout.contains("package changed: python:urllib3"));
    assert!(stdout.contains("repository channel changed: cloudlinux-baseos"));
    assert!(stdout.contains("policy changed: default-policy"));
}

#[test]
fn cli_evidence_outputs_normalized_summary() {
    let path = format!(
        "{}/tests/fixtures/npm/package-lock.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("evidence")
        .arg(path)
        .output()
        .expect("evidence command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Evidence summary"));
    assert!(stdout.contains("Records: 3"));
    assert!(stdout.contains("Ecosystems:"));
    assert!(stdout.contains("package npm:react@18.3.1"));
}

#[test]
fn cli_adapters_outputs_adapter_coverage() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("adapters")
        .output()
        .expect("adapters command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Adapter coverage"));
    assert!(stdout.contains("python via pip/Poetry"));
    assert!(stdout.contains("rpm via DNF/RPM"));
    assert!(stdout.contains("minimal version selection"));
}

#[test]
fn cli_access_outputs_tenant_isolation() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("access")
        .output()
        .expect("access command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Tenant access demo"));
    assert!(stdout.contains("allowed: principal analyst@cloudlinux has analyst access"));
    assert!(stdout.contains("denied: principal analyst@cloudlinux has no access"));
    assert!(stdout.contains("authorized snapshot: snap-"));
}

#[test]
fn cli_persist_writes_file_store_snapshot() {
    let store_dir = std::env::temp_dir().join(format!(
        "graphscope-cli-persist-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("persist")
        .arg(&store_dir)
        .output()
        .expect("persist command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Persisted snapshot"));
    assert!(stdout.contains("customer-a"));
    assert!(store_dir.join("index.tsv").is_file());
    assert_eq!(
        std::fs::read_dir(store_dir.join("snapshots"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn cli_events_writes_change_event_log() {
    let store_dir = std::env::temp_dir().join(format!(
        "graphscope-cli-events-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("events")
        .arg(&store_dir)
        .output()
        .expect("events command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Persisted change events"));
    assert!(stdout.contains("package changed: python:urllib3"));
    assert!(stdout.contains("policy changed: default-policy"));
    assert!(store_dir.join("events.tsv").is_file());
}

#[test]
fn cli_explain_outputs_dependency_paths() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("explain")
        .output()
        .expect("explain command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Package explanation"));
    assert!(stdout.contains("python:urllib3"));
    assert!(stdout.contains("Path:"));
}

#[test]
fn cli_diff_outputs_context_difference() {
    let output = Command::new(env!("CARGO_BIN_EXE_graphscope"))
        .arg("diff")
        .output()
        .expect("diff command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Graph diff"));
    assert!(stdout.contains("python:nvidia-ml-py"));
}

#[test]
fn fixture_pip_lockfile_parses_locked_packages() {
    let input = include_str!("fixtures/pip/requirements.lock");
    let catalog =
        parse_pip_requirements_lock(input, "tests/fixtures/pip/requirements.lock").unwrap();

    assert_eq!(catalog.locked_packages().len(), 3);
    assert!(
        catalog
            .locked_packages()
            .iter()
            .any(|package| package.id == PackageId::python("requests"))
    );
}

#[test]
fn fixture_go_mod_parses_locked_modules() {
    let input = include_str!("fixtures/go/go.mod");
    let catalog = parse_go_mod_requirements(input, "tests/fixtures/go/go.mod").unwrap();

    assert_eq!(catalog.locked_packages().len(), 2);
    assert!(
        catalog
            .locked_packages()
            .iter()
            .any(|package| package.id == PackageId::go("golang.org/x/net"))
    );
}

#[test]
fn fixture_cargo_lock_parses_locked_crates() {
    let input = include_str!("fixtures/cargo/Cargo.lock");
    let catalog = parse_cargo_lock_packages(input, "tests/fixtures/cargo/Cargo.lock").unwrap();

    assert_eq!(catalog.locked_packages().len(), 1);
    assert_eq!(
        catalog.locked_packages()[0].id,
        PackageId::cargo("petgraph")
    );
}

#[test]
fn fixture_npm_package_lock_parses_locked_packages() {
    let input = include_str!("fixtures/npm/package-lock.json");
    let catalog = parse_npm_package_lock(input, "tests/fixtures/npm/package-lock.json").unwrap();

    assert_eq!(catalog.locked_packages().len(), 3);
    assert!(
        catalog
            .locked_packages()
            .iter()
            .any(|package| package.id == PackageId::npm(None::<String>, "react"))
    );
    assert!(
        catalog.locked_packages().iter().any(|package| {
            package.id == PackageId::npm(Some("cloudlinux".to_string()), "theme")
        })
    );
}

#[test]
fn fixture_maven_pom_parses_declared_dependencies() {
    let input = include_str!("fixtures/maven/pom.xml");
    let catalog = parse_maven_pom_dependencies(input, "tests/fixtures/maven/pom.xml").unwrap();

    assert_eq!(catalog.records().len(), 3);
    assert_eq!(
        catalog
            .by_package(&PackageId::maven(
                "com.fasterxml.jackson.core",
                "jackson-databind"
            ))
            .len(),
        1
    );
}

#[test]
fn fixture_gradle_build_parses_declared_dependencies() {
    let input = include_str!("fixtures/gradle/build.gradle");
    let catalog = parse_gradle_dependencies(input, "tests/fixtures/gradle/build.gradle").unwrap();

    assert_eq!(catalog.records().len(), 3);
    assert_eq!(
        catalog
            .by_package(&PackageId::new(
                Ecosystem::Gradle,
                Some("org.slf4j".to_string()),
                "slf4j-api"
            ))
            .len(),
        1
    );
}

#[test]
fn fixture_rpm_inventory_parses_observed_packages() {
    let input = include_str!("fixtures/rpm/rpm-qa.txt");
    let catalog = parse_rpm_inventory(input, "tests/fixtures/rpm/rpm-qa.txt").unwrap();

    assert_eq!(catalog.records().len(), 3);
    assert!(
        catalog
            .records()
            .iter()
            .all(|record| record.confidence == EvidenceConfidence::Observed)
    );
    assert_eq!(catalog.by_package(&PackageId::rpm("openssl-libs")).len(), 1);
}

#[test]
fn fixture_cyclonedx_sbom_parses_components() {
    let input = include_str!("fixtures/sbom/cyclonedx.json");
    let catalog = parse_cyclonedx_sbom(input, "tests/fixtures/sbom/cyclonedx.json").unwrap();

    assert_eq!(catalog.summary().package_records, 3);
    assert_eq!(catalog.by_package(&PackageId::python("urllib3")).len(), 1);
    assert_eq!(
        catalog
            .by_package(&PackageId::maven(
                "com.fasterxml.jackson.core",
                "jackson-databind"
            ))
            .len(),
        1
    );
}

#[test]
fn public_api_auto_parses_maven_pom_fixture() {
    let input = include_str!("fixtures/maven/pom.xml");
    let catalog = parse_evidence(input, "tests/fixtures/maven/pom.xml").unwrap();

    assert_eq!(catalog.summary().dependency_records, 3);
    assert_eq!(
        catalog
            .by_package(&PackageId::maven("org.slf4j", "slf4j-api"))
            .len(),
        1
    );
}

#[test]
fn public_api_auto_parses_rpm_inventory_fixture() {
    let input = include_str!("fixtures/rpm/rpm-qa.txt");
    let catalog = parse_evidence(input, "tests/fixtures/rpm/rpm-qa.txt").unwrap();

    assert_eq!(catalog.summary().package_records, 3);
    assert_eq!(
        catalog
            .by_package(&PackageId::rpm("kernelcare-agent"))
            .len(),
        1
    );
}

#[test]
fn public_api_auto_parses_cyclonedx_sbom_fixture() {
    let input = include_str!("fixtures/sbom/cyclonedx.json");
    let catalog = parse_evidence(input, "tests/fixtures/sbom/cyclonedx.json").unwrap();

    assert_eq!(catalog.summary().by_kind["Sbom"], 3);
    assert_eq!(
        catalog
            .by_package(&PackageId::npm(Some("cloudlinux".to_string()), "theme"))
            .len(),
        1
    );
}

#[test]
fn public_api_creates_stable_snapshot_from_resolved_graph() {
    let (repository, roots, context) = demo_repository();
    let result = Resolver::new(repository).resolve(roots, &context);
    let snapshot = GraphSnapshot::from_resolve_result("demo", "test", &context, &result);
    let json = snapshot.to_json_pretty();

    assert!(snapshot.id.starts_with("snap-"));
    assert!(snapshot.context_hash.starts_with("ctx-"));
    assert!(json.contains("tuxcare-supply-chain-platform"));
}
