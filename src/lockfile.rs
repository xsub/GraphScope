use std::fmt;

use crate::evidence::{
    EvidenceCatalog, EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceSource,
};
use crate::model::{Ecosystem, PackageId, PackageRef, Version};

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

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(value, _comment)| value)
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
}
