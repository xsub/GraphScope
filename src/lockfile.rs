use std::fmt;

use crate::evidence::{
    EvidenceCatalog, EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceSource,
};
use crate::model::{
    DependencyRequirement, DependencyScope, Ecosystem, PackageId, PackageRef, Version,
    VersionRequirement,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockfileParseError {
    pub line: usize,
    pub message: String,
}

impl LockfileParseError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for LockfileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

pub fn parse_pip_requirements_lock(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let source = EvidenceSource::new(EvidenceKind::Lockfile, Some(Ecosystem::Python), locator);
    let mut catalog = EvidenceCatalog::new();

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        let Some((name, rest)) = line.split_once("==") else {
            return Err(LockfileParseError::new(
                line_number,
                "expected pinned requirement in name==version form",
            ));
        };

        let name = strip_extras(name.trim());
        let version = rest.split([';', ' ', '\t']).next().unwrap_or("").trim();
        if name.is_empty() || version.is_empty() {
            return Err(LockfileParseError::new(
                line_number,
                "pinned requirement is missing package name or version",
            ));
        }

        let package = PackageRef::new(PackageId::python(name), Version::parse(version));
        catalog.add(EvidenceRecord::package(
            source.clone(),
            package,
            EvidenceConfidence::Locked,
            format!("pip pinned requirement: {line}"),
        ));
    }

    Ok(catalog)
}

pub fn parse_go_mod_requirements(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let source = EvidenceSource::new(EvidenceKind::Lockfile, Some(Ecosystem::Go), locator);
    let mut catalog = EvidenceCatalog::new();
    let mut in_require_block = false;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if line == "require (" {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }

        let requirement = if in_require_block {
            Some(line)
        } else {
            line.strip_prefix("require ").map(str::trim)
        };

        let Some(requirement) = requirement else {
            continue;
        };

        let mut parts = requirement.split_whitespace();
        let Some(module_path) = parts.next() else {
            return Err(LockfileParseError::new(
                line_number,
                "missing Go module path",
            ));
        };
        let Some(version) = parts.next() else {
            return Err(LockfileParseError::new(
                line_number,
                "missing Go module version",
            ));
        };

        let version = version.strip_prefix('v').unwrap_or(version);
        let package = PackageRef::new(PackageId::go(module_path), Version::parse(version));
        catalog.add(EvidenceRecord::package(
            source.clone(),
            package,
            EvidenceConfidence::Locked,
            format!("go module requirement: {module_path} v{version}"),
        ));
    }

    Ok(catalog)
}

pub fn parse_cargo_lock_packages(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let source = EvidenceSource::new(EvidenceKind::Lockfile, Some(Ecosystem::Cargo), locator);
    let mut catalog = EvidenceCatalog::new();
    let mut current = CargoPackageBlock::default();
    let mut in_package = false;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "[[package]]" {
            flush_cargo_package(&mut catalog, &source, &mut current, line_number)?;
            current = CargoPackageBlock::default();
            in_package = true;
            continue;
        }

        if !in_package {
            continue;
        }

        if let Some(value) = parse_toml_string_field(line, "name") {
            current.name = Some(value);
        } else if let Some(value) = parse_toml_string_field(line, "version") {
            current.version = Some(value);
        } else if let Some(value) = parse_toml_string_field(line, "source") {
            current.source = Some(value);
        } else if let Some(value) = parse_toml_string_field(line, "checksum") {
            current.checksum = Some(value);
        }
    }

    flush_cargo_package(
        &mut catalog,
        &source,
        &mut current,
        input.lines().count() + 1,
    )?;
    Ok(catalog)
}

pub fn parse_npm_package_lock(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let source = EvidenceSource::new(EvidenceKind::Lockfile, Some(Ecosystem::Npm), locator);
    let mut catalog = EvidenceCatalog::new();
    let mut current_package = None::<String>;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if let Some(path) = parse_json_object_key(line)
            && let Some(package) = path.strip_prefix("node_modules/")
        {
            current_package = Some(package.to_string());
        }

        let Some(version) = parse_json_string_field(line, "version") else {
            continue;
        };
        let Some(package_name) = current_package.take() else {
            continue;
        };
        if package_name.is_empty() || version.is_empty() {
            return Err(LockfileParseError::new(
                line_number,
                "npm package-lock entry is missing package name or version",
            ));
        }

        let package = PackageRef::new(
            npm_package_id(&package_name),
            Version::parse(version.as_str()),
        );
        catalog.add(EvidenceRecord::package(
            source.clone(),
            package,
            EvidenceConfidence::Locked,
            format!("npm package-lock entry: {package_name}@{version}"),
        ));
    }

    Ok(catalog)
}

pub fn parse_maven_pom_dependencies(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let source = EvidenceSource::new(EvidenceKind::Manifest, Some(Ecosystem::Maven), locator);
    let mut catalog = EvidenceCatalog::new();
    let mut current = MavenDependencyBlock::default();
    let mut in_dependency = false;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.contains("<dependency>") {
            current = MavenDependencyBlock::default();
            in_dependency = true;
        }
        if !in_dependency {
            continue;
        }

        if let Some(value) = extract_xml_tag(line, "groupId") {
            current.group = Some(value);
        }
        if let Some(value) = extract_xml_tag(line, "artifactId") {
            current.artifact = Some(value);
        }
        if let Some(value) = extract_xml_tag(line, "version") {
            current.version = Some(value);
        }
        if let Some(value) = extract_xml_tag(line, "scope") {
            current.scope = Some(value);
        }
        if let Some(value) = extract_xml_tag(line, "optional") {
            current.optional = value == "true";
        }

        if line.contains("</dependency>") {
            flush_maven_dependency(&mut catalog, &source, &mut current, line_number)?;
            in_dependency = false;
        }
    }

    Ok(catalog)
}

pub fn parse_gradle_dependencies(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let source = EvidenceSource::new(EvidenceKind::Manifest, Some(Ecosystem::Gradle), locator);
    let mut catalog = EvidenceCatalog::new();

    for raw_line in input.lines() {
        let line = strip_slash_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some(notation) = first_quoted_value(line) else {
            continue;
        };
        let parts = notation.split(':').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|part| part.trim().is_empty()) {
            continue;
        }

        let configuration = line
            .split([' ', '('])
            .next()
            .unwrap_or("implementation")
            .trim();
        let group = parts[0].trim();
        let artifact = parts[1].trim();
        let version = parts[2].trim();
        let target = PackageId::new(Ecosystem::Gradle, Some(group.to_string()), artifact);
        let requirement =
            DependencyRequirement::new(target.clone(), VersionRequirement::parse(version))
                .scope(gradle_scope(configuration))
                .evidence(format!("Gradle {configuration}: {notation}"));

        catalog.add(EvidenceRecord::dependency(
            source.clone(),
            None,
            requirement,
            EvidenceConfidence::Declared,
            format!("Gradle declared dependency: {target}:{version}"),
        ));
    }

    Ok(catalog)
}

pub fn parse_rpm_inventory(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let source = EvidenceSource::new(
        EvidenceKind::RuntimeObservation,
        Some(Ecosystem::Rpm),
        locator,
    );
    let mut catalog = EvidenceCatalog::new();

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, version)) = parse_rpm_inventory_line(line) else {
            return Err(LockfileParseError::new(
                line_number,
                "expected RPM inventory line with name and version",
            ));
        };
        let package = PackageRef::new(
            PackageId::rpm(name.clone()),
            Version::parse(version.clone()),
        );
        catalog.add(EvidenceRecord::package(
            source.clone(),
            package,
            EvidenceConfidence::Observed,
            format!("RPM inventory package: {name}-{version}"),
        ));
    }

    Ok(catalog)
}

#[derive(Default)]
struct CargoPackageBlock {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
}

fn flush_cargo_package(
    catalog: &mut EvidenceCatalog,
    source: &EvidenceSource,
    current: &mut CargoPackageBlock,
    line: usize,
) -> Result<(), LockfileParseError> {
    if current.name.is_none() && current.version.is_none() {
        return Ok(());
    }

    let name = current
        .name
        .take()
        .ok_or_else(|| LockfileParseError::new(line, "Cargo.lock package block missing name"))?;
    let version = current
        .version
        .take()
        .ok_or_else(|| LockfileParseError::new(line, "Cargo.lock package block missing version"))?;
    let summary = match (&current.source, &current.checksum) {
        (Some(source), Some(checksum)) => {
            format!("Cargo.lock package from {source} with {checksum}")
        }
        (Some(source), None) => format!("Cargo.lock package from {source}"),
        (None, Some(checksum)) => format!("Cargo.lock package with {checksum}"),
        (None, None) => "Cargo.lock package".to_string(),
    };
    let package = PackageRef::new(PackageId::cargo(name), Version::parse(version));

    catalog.add(EvidenceRecord::package(
        source.clone(),
        package,
        EvidenceConfidence::Locked,
        summary,
    ));
    current.source = None;
    current.checksum = None;
    Ok(())
}

#[derive(Default)]
struct MavenDependencyBlock {
    group: Option<String>,
    artifact: Option<String>,
    version: Option<String>,
    scope: Option<String>,
    optional: bool,
}

fn flush_maven_dependency(
    catalog: &mut EvidenceCatalog,
    source: &EvidenceSource,
    current: &mut MavenDependencyBlock,
    line: usize,
) -> Result<(), LockfileParseError> {
    let group = current
        .group
        .take()
        .ok_or_else(|| LockfileParseError::new(line, "Maven dependency missing groupId"))?;
    let artifact = current
        .artifact
        .take()
        .ok_or_else(|| LockfileParseError::new(line, "Maven dependency missing artifactId"))?;
    let version = current.version.take();
    let scope = current
        .scope
        .take()
        .unwrap_or_else(|| "compile".to_string());
    let target = PackageId::maven(group, artifact);
    let requirement = version
        .as_ref()
        .map_or_else(VersionRequirement::any, |version| {
            VersionRequirement::parse(version.as_str())
        });
    let mut dependency = DependencyRequirement::new(target.clone(), requirement)
        .scope(maven_scope(&scope))
        .evidence(format!(
            "Maven dependency declaration: {}:{}",
            target,
            version.as_deref().unwrap_or("*")
        ));
    if current.optional {
        dependency = dependency.optional();
    }

    catalog.add(EvidenceRecord::dependency(
        source.clone(),
        None,
        dependency,
        EvidenceConfidence::Declared,
        format!(
            "Maven declared dependency: {}:{}",
            target,
            version.as_deref().unwrap_or("*")
        ),
    ));
    current.optional = false;
    Ok(())
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(value, _comment)| value)
}

fn strip_slash_comment(line: &str) -> &str {
    line.split_once("//")
        .map_or(line, |(value, _comment)| value)
}

fn strip_extras(name: &str) -> &str {
    name.split_once('[')
        .map_or(name, |(package, _extras)| package)
}

fn parse_toml_string_field(line: &str, field: &str) -> Option<String> {
    let prefix = format!("{field} = ");
    let value = line.strip_prefix(&prefix)?.trim();
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    Some(value.to_string())
}

fn parse_json_object_key(line: &str) -> Option<String> {
    let line = line.trim();
    let line = line.strip_suffix('{')?.trim();
    let line = line.strip_suffix(':')?.trim();
    let value = line.strip_prefix('"')?.strip_suffix('"')?;
    Some(value.to_string())
}

fn parse_json_string_field(line: &str, field: &str) -> Option<String> {
    let prefix = format!("\"{field}\":");
    let value = line.trim().strip_prefix(&prefix)?.trim();
    let value = value.trim_end_matches(',').trim();
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    Some(value.to_string())
}

fn extract_xml_tag(line: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let (_, value) = line.split_once(&start_tag)?;
    let (value, _) = value.split_once(&end_tag)?;
    Some(value.trim().to_string())
}

fn first_quoted_value(line: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let Some((_, rest)) = line.split_once(quote) else {
            continue;
        };
        let Some((value, _)) = rest.split_once(quote) else {
            continue;
        };
        if !value.is_empty() && value.contains(':') {
            return Some(value.to_string());
        }
    }
    None
}

fn npm_package_id(package_name: &str) -> PackageId {
    if let Some(scoped) = package_name.strip_prefix('@')
        && let Some((scope, name)) = scoped.split_once('/')
    {
        return PackageId::npm(Some(scope.to_string()), name);
    }
    PackageId::npm(None::<String>, package_name)
}

fn maven_scope(scope: &str) -> DependencyScope {
    match scope {
        "test" => DependencyScope::Test,
        "provided" => DependencyScope::Provided,
        "runtime" => DependencyScope::Runtime,
        "system" => DependencyScope::System,
        _ => DependencyScope::Compile,
    }
}

fn gradle_scope(configuration: &str) -> DependencyScope {
    match configuration {
        "testImplementation" | "testRuntimeOnly" => DependencyScope::Test,
        "compileOnly" | "annotationProcessor" => DependencyScope::Compile,
        "runtimeOnly" => DependencyScope::Runtime,
        _ => DependencyScope::Compile,
    }
}

fn parse_rpm_inventory_line(line: &str) -> Option<(String, String)> {
    let mut fields = line.split_whitespace();
    if let (Some(name), Some(version)) = (fields.next(), fields.next()) {
        return Some((name.to_string(), strip_rpm_arch(version).to_string()));
    }

    let parts = line.rsplitn(3, '-').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let release = strip_rpm_arch(parts[0]);
    let version = parts[1];
    let name = parts[2];
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    Some((name.to_string(), format!("{version}-{release}")))
}

fn strip_rpm_arch(value: &str) -> &str {
    for arch in [
        ".x86_64", ".aarch64", ".ppc64le", ".s390x", ".noarch", ".src",
    ] {
        if let Some(stripped) = value.strip_suffix(arch) {
            return stripped;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pip_pinned_requirements_as_locked_evidence() {
        let catalog = parse_pip_requirements_lock(
            r#"
            requests==2.32.3
            urllib3[secure]==2.2.2 ; python_version >= "3.11"
            "#,
            "requirements.lock",
        )
        .unwrap();

        let locked = catalog.locked_packages();
        assert_eq!(locked.len(), 2);
        assert!(
            locked
                .iter()
                .any(|package| package.id == PackageId::python("urllib3")
                    && package.version == Version::parse("2.2.2"))
        );
    }

    #[test]
    fn rejects_unpinned_pip_requirement_lines() {
        let error = parse_pip_requirements_lock("requests>=2", "requirements.lock").unwrap_err();

        assert_eq!(error.line, 1);
        assert!(error.message.contains("name==version"));
    }

    #[test]
    fn parses_go_mod_single_and_block_requirements() {
        let catalog = parse_go_mod_requirements(
            r#"
            module example.com/app
            require golang.org/x/net v0.24.0
            require (
              google.golang.org/protobuf v1.33.0
            )
            "#,
            "go.mod",
        )
        .unwrap();

        let locked = catalog.locked_packages();
        assert_eq!(locked.len(), 2);
        assert!(locked.iter().any(|package| {
            package.id == PackageId::go("golang.org/x/net")
                && package.version == Version::parse("0.24.0")
        }));
    }

    #[test]
    fn parses_cargo_lock_package_blocks() {
        let catalog = parse_cargo_lock_packages(
            r#"
            version = 4

            [[package]]
            name = "petgraph"
            version = "0.6.5"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            checksum = "sha256-demo"
            "#,
            "Cargo.lock",
        )
        .unwrap();

        let locked = catalog.locked_packages();
        assert_eq!(locked.len(), 1);
        assert_eq!(locked[0].id, PackageId::cargo("petgraph"));
        assert_eq!(locked[0].version, Version::parse("0.6.5"));
    }

    #[test]
    fn rejects_cargo_lock_package_without_version() {
        let error = parse_cargo_lock_packages(
            r#"
            [[package]]
            name = "petgraph"
            "#,
            "Cargo.lock",
        )
        .unwrap_err();

        assert!(error.message.contains("missing version"));
    }

    #[test]
    fn parses_npm_package_lock_packages() {
        let catalog = parse_npm_package_lock(
            r#"
            {
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "portal", "version": "1.0.0" },
                "node_modules/react": {
                  "version": "18.3.1"
                },
                "node_modules/@cloudlinux/ui": {
                  "version": "5.1.0"
                }
              }
            }
            "#,
            "package-lock.json",
        )
        .unwrap();

        let locked = catalog.locked_packages();
        assert_eq!(locked.len(), 2);
        assert!(locked.iter().any(|package| {
            package.id == PackageId::npm(None::<String>, "react")
                && package.version == Version::parse("18.3.1")
        }));
        assert!(locked.iter().any(|package| {
            package.id == PackageId::npm(Some("cloudlinux".to_string()), "ui")
                && package.version == Version::parse("5.1.0")
        }));
    }

    #[test]
    fn parses_maven_pom_declared_dependencies() {
        let catalog = parse_maven_pom_dependencies(
            r#"
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.slf4j</groupId>
                  <artifactId>slf4j-api</artifactId>
                  <version>2.0.13</version>
                </dependency>
                <dependency>
                  <groupId>junit</groupId>
                  <artifactId>junit</artifactId>
                  <scope>test</scope>
                </dependency>
              </dependencies>
            </project>
            "#,
            "pom.xml",
        )
        .unwrap();

        assert_eq!(catalog.records().len(), 2);
        assert_eq!(
            catalog
                .by_package(&PackageId::maven("org.slf4j", "slf4j-api"))
                .len(),
            1
        );
        assert!(catalog.records().iter().any(|record| {
            matches!(
                &record.subject,
                crate::evidence::EvidenceSubject::Dependency { requirement, .. }
                    if requirement.scope == DependencyScope::Test
                        && requirement.requirement == VersionRequirement::any()
            )
        }));
    }

    #[test]
    fn rejects_maven_dependency_without_coordinates() {
        let error = parse_maven_pom_dependencies(
            r#"
            <dependency>
              <groupId>org.slf4j</groupId>
            </dependency>
            "#,
            "pom.xml",
        )
        .unwrap_err();

        assert!(error.message.contains("artifactId"));
    }

    #[test]
    fn parses_gradle_dependency_declarations() {
        let catalog = parse_gradle_dependencies(
            r#"
            dependencies {
                implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
                runtimeOnly 'org.slf4j:slf4j-api:2.0.13'
                testImplementation("junit:junit:4.13.2")
            }
            "#,
            "build.gradle",
        )
        .unwrap();

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
        assert!(catalog.records().iter().any(|record| {
            matches!(
                &record.subject,
                crate::evidence::EvidenceSubject::Dependency { requirement, .. }
                    if requirement.scope == DependencyScope::Test
            )
        }));
    }

    #[test]
    fn parses_rpm_inventory_observed_packages() {
        let catalog = parse_rpm_inventory(
            r#"
            kernelcare-agent 3.1.4-1.el9.x86_64
            openssl-libs-3.2.2-1.el9.x86_64
            "#,
            "rpm -qa",
        )
        .unwrap();

        let observed = catalog
            .records()
            .iter()
            .filter(|record| record.confidence == EvidenceConfidence::Observed)
            .count();
        assert_eq!(observed, 2);
        assert_eq!(catalog.by_package(&PackageId::rpm("openssl-libs")).len(), 1);
    }

    #[test]
    fn rejects_rpm_inventory_without_version() {
        let error = parse_rpm_inventory("kernelcare-agent", "rpm -qa").unwrap_err();

        assert!(error.message.contains("name and version"));
    }
}
