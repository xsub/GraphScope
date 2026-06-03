use std::process::Command;

use graphscope::{
    DependencyRequirement, PackageId, PackageVersion, Resolver, VersionRequirement, demo_repository,
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
