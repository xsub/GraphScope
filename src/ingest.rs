//! Evidence format detection and parser dispatch for supported project inputs.

use std::fmt;
use std::path::Path;

use crate::evidence::EvidenceCatalog;
use crate::lockfile::{
    LockfileParseError, parse_cargo_lock_packages, parse_cyclonedx_sbom, parse_go_mod_requirements,
    parse_gradle_dependencies, parse_maven_pom_dependencies, parse_npm_package_lock,
    parse_pip_requirements_lock, parse_rpm_inventory,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceFormat {
    PipRequirements,
    GoMod,
    CargoLock,
    NpmPackageLock,
    MavenPom,
    GradleBuild,
    RpmInventory,
    CycloneDxSbom,
}

impl fmt::Display for EvidenceFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceFormat::PipRequirements => write!(f, "pip requirements"),
            EvidenceFormat::GoMod => write!(f, "go.mod"),
            EvidenceFormat::CargoLock => write!(f, "Cargo.lock"),
            EvidenceFormat::NpmPackageLock => write!(f, "npm package-lock"),
            EvidenceFormat::MavenPom => write!(f, "Maven POM"),
            EvidenceFormat::GradleBuild => write!(f, "Gradle build"),
            EvidenceFormat::RpmInventory => write!(f, "RPM inventory"),
            EvidenceFormat::CycloneDxSbom => write!(f, "CycloneDX SBOM"),
        }
    }
}

impl EvidenceFormat {
    pub fn detect(locator: &str) -> Option<Self> {
        let file_name = Path::new(locator)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(locator)
            .to_ascii_lowercase();

        match file_name.as_str() {
            "requirements.txt" | "requirements.lock" => Some(Self::PipRequirements),
            "go.mod" => Some(Self::GoMod),
            "cargo.lock" => Some(Self::CargoLock),
            "package-lock.json" => Some(Self::NpmPackageLock),
            "pom.xml" => Some(Self::MavenPom),
            "build.gradle" | "build.gradle.kts" => Some(Self::GradleBuild),
            "rpm-qa.txt" | "rpm-inventory.txt" | "rpm-list.txt" => Some(Self::RpmInventory),
            "bom.json" | "cyclonedx.json" => Some(Self::CycloneDxSbom),
            _ if file_name.contains("rpm") && file_name.ends_with(".list") => {
                Some(Self::RpmInventory)
            }
            _ if file_name.ends_with(".cdx.json") => Some(Self::CycloneDxSbom),
            _ => None,
        }
    }

    pub fn parse(&self, input: &str, locator: &str) -> Result<EvidenceCatalog, IngestError> {
        match self {
            EvidenceFormat::PipRequirements => {
                parse_with(locator, || parse_pip_requirements_lock(input, locator))
            }
            EvidenceFormat::GoMod => {
                parse_with(locator, || parse_go_mod_requirements(input, locator))
            }
            EvidenceFormat::CargoLock => {
                parse_with(locator, || parse_cargo_lock_packages(input, locator))
            }
            EvidenceFormat::NpmPackageLock => {
                parse_with(locator, || parse_npm_package_lock(input, locator))
            }
            EvidenceFormat::MavenPom => {
                parse_with(locator, || parse_maven_pom_dependencies(input, locator))
            }
            EvidenceFormat::GradleBuild => {
                parse_with(locator, || parse_gradle_dependencies(input, locator))
            }
            EvidenceFormat::RpmInventory => {
                parse_with(locator, || parse_rpm_inventory(input, locator))
            }
            EvidenceFormat::CycloneDxSbom => {
                parse_with(locator, || parse_cyclonedx_sbom(input, locator))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestError {
    pub locator: String,
    pub message: String,
}

impl IngestError {
    fn new(locator: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            locator: locator.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.locator, self.message)
    }
}

pub fn parse_evidence(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, IngestError> {
    let locator = locator.into();
    let format = EvidenceFormat::detect(&locator).ok_or_else(|| {
        IngestError::new(
            locator.clone(),
            "unsupported evidence format; expected requirements.txt, go.mod, Cargo.lock, package-lock.json, pom.xml, build.gradle, rpm-qa.txt, or bom.json",
        )
    })?;
    format.parse(input, &locator)
}

fn parse_with(
    locator: &str,
    parse: impl FnOnce() -> Result<EvidenceCatalog, LockfileParseError>,
) -> Result<EvidenceCatalog, IngestError> {
    parse().map_err(|error| IngestError::new(locator, error.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::model::PackageId;

    use super::*;

    #[test]
    fn detects_supported_evidence_formats() {
        assert_eq!(
            EvidenceFormat::detect("requirements.txt"),
            Some(EvidenceFormat::PipRequirements)
        );
        assert_eq!(
            EvidenceFormat::detect("service/go.mod"),
            Some(EvidenceFormat::GoMod)
        );
        assert_eq!(
            EvidenceFormat::detect("Cargo.lock"),
            Some(EvidenceFormat::CargoLock)
        );
        assert_eq!(
            EvidenceFormat::detect("ui/package-lock.json"),
            Some(EvidenceFormat::NpmPackageLock)
        );
        assert_eq!(
            EvidenceFormat::detect("pom.xml"),
            Some(EvidenceFormat::MavenPom)
        );
        assert_eq!(
            EvidenceFormat::detect("build.gradle.kts"),
            Some(EvidenceFormat::GradleBuild)
        );
        assert_eq!(
            EvidenceFormat::detect("customer-rpm.list"),
            Some(EvidenceFormat::RpmInventory)
        );
        assert_eq!(
            EvidenceFormat::detect("sbom/app.cdx.json"),
            Some(EvidenceFormat::CycloneDxSbom)
        );
    }

    #[test]
    fn parse_evidence_dispatches_npm_package_lock() {
        let catalog = parse_evidence(
            r#"
            {
              "packages": {
                "node_modules/react": {
                  "version": "18.3.1"
                }
              }
            }
            "#,
            "package-lock.json",
        )
        .unwrap();

        assert_eq!(catalog.locked_packages().len(), 1);
        assert_eq!(
            catalog.locked_packages()[0].id,
            PackageId::npm(None::<String>, "react")
        );
    }

    #[test]
    fn parse_evidence_rejects_unknown_format() {
        let error = parse_evidence("name = demo", "pyproject.toml").unwrap_err();

        assert!(error.message.contains("unsupported evidence format"));
    }

    #[test]
    fn parse_evidence_dispatches_cyclonedx_sbom() {
        let catalog = parse_evidence(
            r#"{"bomFormat":"CycloneDX","components":[{"name":"urllib3","version":"2.2.2","purl":"pkg:pypi/urllib3@2.2.2"}]}"#,
            "bom.json",
        )
        .unwrap();

        assert_eq!(catalog.summary().package_records, 1);
        assert_eq!(catalog.by_package(&PackageId::python("urllib3")).len(), 1);
    }
}
