use std::collections::BTreeSet;

use crate::advisory::{Advisory, AdvisorySeverity};
use crate::model::{
    Architecture, ArtifactMetadata, BuildProfile, ContextPredicate, DependencyRelation,
    DependencyRequirement, DependencyScope, Ecosystem, PackageId, PackageSource, PackageVersion,
    ResolutionContext, VersionRequirement,
};
use crate::policy::{PolicyRule, PolicySet, PolicySeverity};
use crate::repository::InMemoryRepository;

pub fn demo_repository() -> (
    InMemoryRepository,
    Vec<DependencyRequirement>,
    ResolutionContext,
) {
    let root = PackageId::internal("tuxcare-supply-chain-platform");
    let kernelcare = PackageId::rpm("kernelcare-agent");
    let scanner = PackageId::python("tuxcare-vuln-scanner");
    let vuln_service = PackageId::maven("com.cloudlinux.tuxcare", "vulnerability-service");
    let portal_ui = PackageId::npm(None::<String>, "tuxcare-portal-ui");
    let telemetry = PackageId::go("cloudlinux.com/tuxcare/telemetry-collector");
    let rpm_diff = PackageId::cargo("rpm-diff-engine");

    let mut repo = InMemoryRepository::new();

    repo.add(
        PackageVersion::new(root.clone(), "1.0.0")
            .with_metadata(ArtifactMetadata::internal("product-catalog"))
            .with_dependencies(vec![
                dep(kernelcare.clone(), ">=3.1,<4.0")
                    .scope(DependencyScope::Runtime)
                    .evidence("product-catalog.yaml:kernelcare-agent"),
                dep(scanner.clone(), "^1.4.0")
                    .scope(DependencyScope::Runtime)
                    .evidence("product-catalog.yaml:tuxcare-vuln-scanner"),
                dep(vuln_service.clone(), ">=2.0,<3.0")
                    .scope(DependencyScope::Runtime)
                    .evidence("product-catalog.yaml:vulnerability-service"),
                dep(portal_ui.clone(), "^5.0.0")
                    .scope(DependencyScope::Build)
                    .evidence("product-catalog.yaml:portal-ui"),
                dep(telemetry.clone(), ">=0.8.0,<1.0.0")
                    .scope(DependencyScope::Runtime)
                    .evidence("product-catalog.yaml:telemetry-collector"),
                dep(rpm_diff.clone(), "^0.3.0")
                    .scope(DependencyScope::Build)
                    .evidence("product-catalog.yaml:rpm-diff-engine"),
            ]),
    );

    add_rpm_packages(&mut repo, kernelcare);
    add_python_packages(&mut repo, scanner);
    add_java_packages(&mut repo, vuln_service);
    add_npm_packages(&mut repo, portal_ui);
    add_go_packages(&mut repo, telemetry);
    add_cargo_packages(&mut repo, rpm_diff);

    let roots = vec![dep(root, "*").evidence("demo root")];
    let context = ResolutionContext::cloudlinux_production_x86_64()
        .with_optional()
        .with_feature("gpu");

    (repo, roots, context)
}

pub fn demo_advisories() -> Vec<Advisory> {
    vec![
        Advisory::new(
            "CVE-2026-GS-0001",
            "OpenSSL lifecycle exposure in kernelcare dependency path",
            PackageId::rpm("openssl-libs"),
            VersionRequirement::parse("<3.2.3"),
            AdvisorySeverity::High,
        )
        .fixed_by(VersionRequirement::parse(">=3.2.3"))
        .summary("Selected OpenSSL runtime package is below the target maintenance version."),
        Advisory::new(
            "CVE-2026-GS-0002",
            "urllib3 scanner dependency exposure",
            PackageId::python("urllib3"),
            VersionRequirement::parse("<2.2.3"),
            AdvisorySeverity::Critical,
        )
        .fixed_by(VersionRequirement::parse(">=2.2.3"))
        .summary("urllib3 is reachable through the TuxCare scanner dependency path."),
        Advisory::new(
            "CVE-2026-GS-0003",
            "macOS watcher package not selected on CloudLinux",
            PackageId::npm(None::<String>, "fsevents"),
            VersionRequirement::any(),
            AdvisorySeverity::Medium,
        )
        .summary("This advisory is present to demonstrate not-affected VEX output."),
    ]
}

pub fn demo_policy_set() -> PolicySet {
    PolicySet::new(vec![
        PolicyRule::AllowSources {
            ecosystem: Some(Ecosystem::Python),
            allowed_sources: BTreeSet::from(["registry:https://pypi.org/simple".to_string()]),
            severity: PolicySeverity::Error,
        },
        PolicyRule::RequireSigned {
            ecosystem: Some(Ecosystem::Rpm),
            severity: PolicySeverity::Error,
        },
        PolicyRule::RequireSigned {
            ecosystem: Some(Ecosystem::Python),
            severity: PolicySeverity::Warning,
        },
        PolicyRule::DenyPackage {
            package: PackageId::python("urllib3"),
            reason: "unsupported package line requires remediation tracking".to_string(),
            severity: PolicySeverity::Critical,
        },
        PolicyRule::DenyWildcardRequirement {
            ecosystem: Some(Ecosystem::Maven),
            severity: PolicySeverity::Warning,
        },
    ])
}

fn add_rpm_packages(repo: &mut InMemoryRepository, kernelcare: PackageId) {
    let openssl = PackageId::rpm("openssl-libs");
    let libdnf = PackageId::rpm("libdnf");
    let kernel_headers = PackageId::rpm("kernel-headers");
    let els_release = PackageId::rpm("tuxcare-els-release");

    repo.add(
        rpm(kernelcare, "3.1.4", "tuxcare-kernelcare", "1.el9", "x86_64").with_dependencies(vec![
            dep(openssl.clone(), ">=3.0,<4.0")
                .scope(DependencyScope::Runtime)
                .evidence("rpm:kernelcare-agent Requires: openssl-libs"),
            dep(libdnf.clone(), ">=0.69,<1.0")
                .scope(DependencyScope::Runtime)
                .evidence("rpm:kernelcare-agent Requires: libdnf"),
            dep(kernel_headers.clone(), ">=5.14")
                .scope(DependencyScope::Weak)
                .relation(DependencyRelation::Recommends)
                .when(ContextPredicate::ProfileEnabled(BuildProfile::KernelCare))
                .evidence("rpm:kernelcare-agent Recommends: kernel-headers"),
            dep(els_release.clone(), "*")
                .scope(DependencyScope::System)
                .when(ContextPredicate::DistroIs(
                    crate::model::DistroFlavor::CloudLinux,
                ))
                .evidence("rpm:kernelcare-agent Requires: tuxcare-els-release"),
        ]),
    );
    repo.add(rpm(
        openssl,
        "3.2.2",
        "cloudlinux-baseos",
        "3.el9",
        "x86_64",
    ));
    repo.add(rpm(
        libdnf,
        "0.73.1",
        "cloudlinux-baseos",
        "1.el9",
        "x86_64",
    ));
    repo.add(rpm(
        kernel_headers,
        "5.14.0",
        "cloudlinux-baseos",
        "427.el9",
        "x86_64",
    ));
    repo.add(rpm(els_release, "9.0", "tuxcare-els", "1.el9", "x86_64"));
}

fn add_python_packages(repo: &mut InMemoryRepository, scanner: PackageId) {
    let requests = PackageId::python("requests");
    let urllib3 = PackageId::python("urllib3");
    let certifi = PackageId::python("certifi");
    let grpcio = PackageId::python("grpcio");
    let nvidia = PackageId::python("nvidia-ml-py");
    let typing_extensions = PackageId::python("typing-extensions");

    repo.add(pypi(scanner, "1.4.2").with_dependencies(vec![
            dep(requests.clone(), "^2.31.0")
                .scope(DependencyScope::Runtime)
                .evidence("pyproject.toml:dependencies.requests"),
            dep(grpcio.clone(), "^1.62.0")
                .scope(DependencyScope::Runtime)
                .evidence("pyproject.toml:dependencies.grpcio"),
            dep(nvidia.clone(), "^12.0.0")
                .optional()
                .feature("gpu")
                .when(ContextPredicate::ArchIs(Architecture::X86_64))
                .evidence("pyproject.toml:extras.gpu"),
            dep(typing_extensions.clone(), ">=4.7")
                .scope(DependencyScope::Runtime)
                .when(ContextPredicate::LanguageVersionMatches {
                    ecosystem: Ecosystem::Python,
                    requirement: VersionRequirement::parse("<3.11"),
                })
                .evidence("pyproject.toml:python_version<'3.11'"),
        ]));
    repo.add(pypi(requests.clone(), "2.32.3").with_dependencies(vec![
            dep(urllib3.clone(), ">=1.26,<3.0")
                .scope(DependencyScope::Runtime)
                .evidence("requests METADATA Requires-Dist: urllib3"),
            dep(certifi.clone(), ">=2024.2.2")
                .scope(DependencyScope::Runtime)
                .evidence("requests METADATA Requires-Dist: certifi"),
        ]));
    repo.add(pypi(requests, "2.31.0"));
    repo.add(pypi(urllib3, "2.2.2"));
    repo.add(pypi(certifi, "2024.7.4"));
    repo.add(pypi(grpcio, "1.64.1"));
    repo.add(pypi(nvidia, "12.555.43"));
    repo.add(pypi(typing_extensions, "4.12.2"));
}

fn add_java_packages(repo: &mut InMemoryRepository, vuln_service: PackageId) {
    let slf4j = PackageId::maven("org.slf4j", "slf4j-api");
    let logback = PackageId::maven("ch.qos.logback", "logback-classic");
    let commons_logging = PackageId::maven("commons-logging", "commons-logging");
    let jackson = PackageId::maven("com.fasterxml.jackson.core", "jackson-databind");

    repo.add(maven(vuln_service, "2.3.0").with_dependencies(vec![
            dep(slf4j.clone(), ">=2.0,<3.0")
                .scope(DependencyScope::Compile)
                .evidence("pom.xml:dependencies:slf4j-api"),
            dep(logback.clone(), ">=1.4,<2.0")
                .scope(DependencyScope::Runtime)
                .exclude(commons_logging.clone())
                .evidence("pom.xml:dependencies:logback-classic exclusion commons-logging"),
            dep(jackson.clone(), ">=2.17,<3.0")
                .scope(DependencyScope::Runtime)
                .evidence("pom.xml:dependencies:jackson-databind"),
        ]));
    repo.add(maven(slf4j.clone(), "2.0.13"));
    repo.add(maven(logback, "1.5.6").with_dependencies(vec![
            dep(slf4j, ">=2.0,<3.0").scope(DependencyScope::Runtime),
            dep(commons_logging.clone(), "*")
                .scope(DependencyScope::Runtime)
                .evidence("legacy transitive dependency excluded by root edge"),
        ]));
    repo.add(maven(commons_logging, "1.2"));
    repo.add(maven(jackson, "2.17.2"));
}

fn add_npm_packages(repo: &mut InMemoryRepository, portal_ui: PackageId) {
    let react = PackageId::npm(None::<String>, "react");
    let vite = PackageId::npm(None::<String>, "vite");
    let fsevents = PackageId::npm(None::<String>, "fsevents");
    let scheduler = PackageId::npm(None::<String>, "scheduler");

    repo.add(npm(portal_ui, "5.1.0").with_dependencies(vec![
            dep(react.clone(), "^18.2.0")
                .scope(DependencyScope::Runtime)
                .evidence("package-lock.json:dependencies.react"),
            dep(vite.clone(), "^5.0.0")
                .scope(DependencyScope::Development)
                .evidence("package.json:devDependencies.vite"),
            dep(fsevents.clone(), "^2.3.0")
                .optional()
                .when(ContextPredicate::OsIs(crate::model::OperatingSystem::Macos))
                .evidence("package.json:optionalDependencies.fsevents"),
        ]));
    repo.add(npm(react, "18.3.1").with_dependencies(vec![
            dep(scheduler.clone(), "^0.23.0")
                .scope(DependencyScope::Runtime)
                .evidence("package-lock.json:react -> scheduler"),
        ]));
    repo.add(npm(vite, "5.4.0"));
    repo.add(npm(fsevents, "2.3.3"));
    repo.add(npm(scheduler, "0.23.2"));
}

fn add_go_packages(repo: &mut InMemoryRepository, telemetry: PackageId) {
    let xnet = PackageId::go("golang.org/x/net");
    let protobuf = PackageId::go("google.golang.org/protobuf");

    repo.add(go(telemetry, "0.8.0").with_dependencies(vec![
            dep(xnet.clone(), ">=0.24.0")
                .scope(DependencyScope::Runtime)
                .evidence("go.mod:require golang.org/x/net v0.24.0"),
            dep(protobuf.clone(), ">=1.33.0")
                .scope(DependencyScope::Runtime)
                .evidence("go.mod:require google.golang.org/protobuf v1.33.0"),
        ]));
    repo.add(go(xnet.clone(), "0.24.0"));
    repo.add(go(xnet, "0.26.0"));
    repo.add(go(protobuf, "1.33.0"));
}

fn add_cargo_packages(repo: &mut InMemoryRepository, rpm_diff: PackageId) {
    let petgraph = PackageId::cargo("petgraph");
    let rpm_rs = PackageId::cargo("rpm-rs");

    repo.add(cargo(rpm_diff, "0.3.2").with_dependencies(vec![
            dep(petgraph.clone(), "^0.6.0")
                .scope(DependencyScope::Build)
                .evidence("Cargo.lock:petgraph"),
            dep(rpm_rs.clone(), "^0.1.0")
                .scope(DependencyScope::Build)
                .when(ContextPredicate::OsIs(crate::model::OperatingSystem::Linux))
                .evidence("Cargo.toml:target.'cfg(unix)'.dependencies.rpm-rs"),
        ]));
    repo.add(cargo(petgraph, "0.6.5"));
    repo.add(cargo(rpm_rs, "0.1.2"));
}

fn dep(package: PackageId, requirement: &str) -> DependencyRequirement {
    DependencyRequirement::new(package, VersionRequirement::parse(requirement))
}

fn rpm(
    package: PackageId,
    version: &str,
    repo_name: &str,
    release: &str,
    arch: &str,
) -> PackageVersion {
    PackageVersion::new(package, version).with_metadata(ArtifactMetadata {
        source: PackageSource::RpmRepo {
            repo: repo_name.to_string(),
            epoch: None,
            release: release.to_string(),
            arch: arch.to_string(),
        },
        checksum: Some(format!("sha256:rpm-{version}")),
        signed: true,
        purl: None,
        license: Some("mixed".to_string()),
    })
}

fn pypi(package: PackageId, version: &str) -> PackageVersion {
    PackageVersion::new(package.clone(), version).with_metadata(ArtifactMetadata {
        source: PackageSource::Registry("https://pypi.org/simple".to_string()),
        checksum: Some(format!("sha256:pypi-{}-{version}", package.name)),
        signed: false,
        purl: Some(format!("pkg:pypi/{}@{version}", package.name)),
        license: None,
    })
}

fn maven(package: PackageId, version: &str) -> PackageVersion {
    PackageVersion::new(package.clone(), version).with_metadata(ArtifactMetadata {
        source: PackageSource::Registry("https://repo.maven.apache.org/maven2".to_string()),
        checksum: Some(format!("sha256:maven-{}-{version}", package.name)),
        signed: false,
        purl: Some(match &package.namespace {
            Some(group) => format!("pkg:maven/{}/{}@{version}", group, package.name),
            None => format!("pkg:maven/{}@{version}", package.name),
        }),
        license: None,
    })
}

fn npm(package: PackageId, version: &str) -> PackageVersion {
    PackageVersion::new(package.clone(), version).with_metadata(ArtifactMetadata {
        source: PackageSource::Registry("https://registry.npmjs.org".to_string()),
        checksum: Some(format!("sha512:npm-{}-{version}", package.name)),
        signed: false,
        purl: Some(format!("pkg:npm/{}@{version}", package.name)),
        license: None,
    })
}

fn go(package: PackageId, version: &str) -> PackageVersion {
    PackageVersion::new(package.clone(), version).with_metadata(ArtifactMetadata {
        source: PackageSource::Registry("https://proxy.golang.org".to_string()),
        checksum: Some(format!("h1:go-{}-{version}", package.name)),
        signed: false,
        purl: Some(format!("pkg:golang/{}@{version}", package.name)),
        license: None,
    })
}

fn cargo(package: PackageId, version: &str) -> PackageVersion {
    PackageVersion::new(package.clone(), version).with_metadata(ArtifactMetadata {
        source: PackageSource::Registry("https://crates.io".to_string()),
        checksum: Some(format!("sha256:cargo-{}-{version}", package.name)),
        signed: false,
        purl: Some(format!("pkg:cargo/{}@{version}", package.name)),
        license: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DependencyScope;
    use crate::resolver::Resolver;

    #[test]
    fn demo_repository_contains_expected_candidate_count() {
        let (repository, roots, _context) = demo_repository();

        assert_eq!(repository.package_count(), 31);
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn demo_context_enables_gpu_optional_dependency() {
        let (_repository, _roots, context) = demo_repository();

        assert!(context.include_optional);
        assert!(context.enabled_features.contains("gpu"));
        assert!(context.includes_scope(&DependencyScope::Optional));
    }

    #[test]
    fn demo_graph_resolves_without_conflicts() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);

        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn demo_graph_includes_core_cloudlinux_and_tuxcare_packages() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);

        assert!(result.contains_package(&PackageId::rpm("kernelcare-agent")));
        assert!(result.contains_package(&PackageId::rpm("tuxcare-els-release")));
        assert!(result.contains_package(&PackageId::python("tuxcare-vuln-scanner")));
        assert!(result.contains_package(&PackageId::maven(
            "com.cloudlinux.tuxcare",
            "vulnerability-service"
        )));
    }

    #[test]
    fn demo_graph_activates_gpu_extra_on_x86_64() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);

        assert!(result.contains_package(&PackageId::python("nvidia-ml-py")));
    }

    #[test]
    fn demo_graph_skips_python_backport_on_python_311() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);

        assert!(!result.contains_package(&PackageId::python("typing-extensions")));
        assert!(
            result
                .skipped
                .iter()
                .any(|skipped| skipped.target == PackageId::python("typing-extensions"))
        );
    }

    #[test]
    fn demo_graph_skips_npm_development_dependency_in_production() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);

        assert!(!result.contains_package(&PackageId::npm(None::<String>, "vite")));
        assert!(
            result
                .skipped
                .iter()
                .any(|skipped| skipped.reason.contains("scope development excluded"))
        );
    }

    #[test]
    fn demo_graph_skips_macos_optional_dependency_on_linux() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);

        assert!(!result.contains_package(&PackageId::npm(None::<String>, "fsevents")));
        assert!(result.skipped.iter().any(|skipped| {
            skipped.target == PackageId::npm(None::<String>, "fsevents")
                && skipped.reason.contains("context predicate did not match")
        }));
    }

    #[test]
    fn demo_graph_honors_maven_exclusion() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);

        assert!(!result.contains_package(&PackageId::maven("commons-logging", "commons-logging")));
    }

    #[test]
    fn demo_graph_uses_go_minimal_version_selection() {
        let (repository, roots, context) = demo_repository();
        let result = Resolver::new(repository).resolve(roots, &context);
        let net = PackageId::go("golang.org/x/net");

        assert_eq!(
            result
                .selected_version(&net)
                .map(|package| package.version.raw.as_str()),
            Some("0.24.0")
        );
    }
}
