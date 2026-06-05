//! Core package, version, dependency, context, and provenance model types.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Internal,
    Rpm,
    Python,
    Maven,
    Gradle,
    Npm,
    Go,
    Cargo,
    NuGet,
    RubyGems,
    Other(String),
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::Internal => write!(f, "internal"),
            Ecosystem::Rpm => write!(f, "rpm"),
            Ecosystem::Python => write!(f, "python"),
            Ecosystem::Maven => write!(f, "maven"),
            Ecosystem::Gradle => write!(f, "gradle"),
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Go => write!(f, "go"),
            Ecosystem::Cargo => write!(f, "cargo"),
            Ecosystem::NuGet => write!(f, "nuget"),
            Ecosystem::RubyGems => write!(f, "rubygems"),
            Ecosystem::Other(value) => write!(f, "{value}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub namespace: Option<String>,
    pub name: String,
}

impl PackageId {
    pub fn new(
        ecosystem: Ecosystem,
        namespace: impl Into<Option<String>>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem,
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    pub fn internal(name: impl Into<String>) -> Self {
        Self::new(Ecosystem::Internal, None::<String>, name)
    }

    pub fn rpm(name: impl Into<String>) -> Self {
        Self::new(Ecosystem::Rpm, None::<String>, name)
    }

    pub fn python(name: impl Into<String>) -> Self {
        Self::new(
            Ecosystem::Python,
            None::<String>,
            normalize_python_name(name.into()),
        )
    }

    pub fn maven(group: impl Into<String>, artifact: impl Into<String>) -> Self {
        Self::new(Ecosystem::Maven, Some(group.into()), artifact)
    }

    pub fn npm(scope: impl Into<Option<String>>, name: impl Into<String>) -> Self {
        Self::new(Ecosystem::Npm, scope, name)
    }

    pub fn go(module_path: impl Into<String>) -> Self {
        Self::new(Ecosystem::Go, None::<String>, module_path)
    }

    pub fn cargo(name: impl Into<String>) -> Self {
        Self::new(Ecosystem::Cargo, None::<String>, name)
    }

    pub fn purl_like(&self) -> String {
        match &self.namespace {
            Some(namespace) => format!("{}/{}:{}", self.ecosystem, namespace, self.name),
            None => format!("{}:{}", self.ecosystem, self.name),
        }
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.namespace {
            Some(namespace) => write!(f, "{}:{}/{}", self.ecosystem, namespace, self.name),
            None => write!(f, "{}:{}", self.ecosystem, self.name),
        }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct Version {
    pub raw: String,
    parts: Vec<u64>,
    suffix: Option<String>,
}

impl Version {
    pub fn parse(input: impl Into<String>) -> Self {
        let raw = input.into();
        let mut parts = Vec::new();
        let mut suffix = None;

        for token in raw.split(['.', '-', '+', '_']) {
            if token.is_empty() {
                continue;
            }
            if token.chars().all(|ch| ch.is_ascii_digit()) && suffix.is_none() {
                parts.push(token.parse::<u64>().unwrap_or(0));
            } else {
                suffix = Some(match suffix {
                    Some(existing) => format!("{existing}.{token}"),
                    None => token.to_ascii_lowercase(),
                });
            }
        }

        if parts.is_empty() {
            parts.push(0);
        }

        Self { raw, parts, suffix }
    }

    pub fn parts(&self) -> &[u64] {
        &self.parts
    }

    fn bump_major(&self) -> Version {
        let mut parts = self.parts.clone();
        parts.resize(3, 0);
        parts[0] += 1;
        parts[1] = 0;
        parts[2] = 0;
        Version::parse(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    }

    fn bump_minor(&self) -> Version {
        let mut parts = self.parts.clone();
        parts.resize(3, 0);
        parts[1] += 1;
        parts[2] = 0;
        Version::parse(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    }

    fn bump_patch(&self) -> Version {
        let mut parts = self.parts.clone();
        parts.resize(3, 0);
        parts[2] += 1;
        Version::parse(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Hash for Version {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut parts = self.parts.clone();
        while parts.last() == Some(&0) && parts.len() > 1 {
            parts.pop();
        }
        parts.hash(state);
        self.suffix.hash(state);
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let width = self.parts.len().max(other.parts.len());
        for index in 0..width {
            let left = *self.parts.get(index).unwrap_or(&0);
            let right = *other.parts.get(index).unwrap_or(&0);
            match left.cmp(&right) {
                Ordering::Equal => {}
                order => return order,
            }
        }

        match (&self.suffix, &other.suffix) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageRef {
    pub id: PackageId,
    pub version: Version,
}

impl PackageRef {
    pub fn new(id: PackageId, version: Version) -> Self {
        Self { id, version }
    }
}

impl fmt::Display for PackageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.id, self.version)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RpmPackageCoordinate {
    pub name: String,
    pub epoch: Option<u64>,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub source_rpm: Option<String>,
    pub repository_id: Option<String>,
    pub module_stream: Option<String>,
}

impl RpmPackageCoordinate {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        release: impl Into<String>,
        arch: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            epoch: None,
            version: version.into(),
            release: release.into(),
            arch: arch.into(),
            source_rpm: None,
            repository_id: None,
            module_stream: None,
        }
    }

    pub fn from_inventory_line(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        if let (Some(name), Some(version_release_arch)) = (fields.next(), fields.next()) {
            return Self::from_name_and_version(name, version_release_arch);
        }

        let parts = line.rsplitn(3, '-').collect::<Vec<_>>();
        if parts.len() != 3 {
            return None;
        }
        let (release, arch) = split_rpm_release_arch(parts[0]);
        let (epoch, version) = split_rpm_epoch(parts[1]);
        let name = parts[2];
        if name.is_empty() || version.is_empty() || release.is_empty() {
            return None;
        }

        Some(Self {
            name: name.to_string(),
            epoch,
            version: version.to_string(),
            release: release.to_string(),
            arch: arch.to_string(),
            source_rpm: None,
            repository_id: None,
            module_stream: None,
        })
    }

    pub fn from_name_and_version(name: &str, version_release_arch: &str) -> Option<Self> {
        let (version_release, arch) = split_rpm_release_arch(version_release_arch);
        let parts = version_release.rsplitn(2, '-').collect::<Vec<_>>();
        if parts.len() != 2 {
            return None;
        }
        let release = parts[0];
        let (epoch, version) = split_rpm_epoch(parts[1]);
        if name.is_empty() || version.is_empty() || release.is_empty() {
            return None;
        }

        Some(Self {
            name: name.to_string(),
            epoch,
            version: version.to_string(),
            release: release.to_string(),
            arch: arch.to_string(),
            source_rpm: None,
            repository_id: None,
            module_stream: None,
        })
    }

    pub fn with_repository(mut self, repository_id: impl Into<String>) -> Self {
        self.repository_id = Some(repository_id.into());
        self
    }

    pub fn version_release(&self) -> String {
        match self.epoch {
            Some(epoch) => format!("{epoch}:{}-{}", self.version, self.release),
            None => format!("{}-{}", self.version, self.release),
        }
    }

    pub fn nevra(&self) -> String {
        format!("{}-{}.{}", self.name, self.version_release(), self.arch)
    }

    pub fn package_id(&self) -> PackageId {
        PackageId::rpm(self.name.clone())
    }

    pub fn package_ref(&self) -> PackageRef {
        PackageRef::new(self.package_id(), Version::parse(self.version_release()))
    }

    pub fn source(&self) -> PackageSource {
        PackageSource::RpmRepo {
            repo: self
                .repository_id
                .clone()
                .unwrap_or_else(|| "observed-runtime".to_string()),
            epoch: self.epoch,
            release: self.release.clone(),
            arch: self.arch.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RpmCapabilityKind {
    Package,
    File,
    Soname,
    Virtual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpmCapability {
    pub kind: RpmCapabilityKind,
    pub name: String,
    pub requirement: Option<VersionRequirement>,
}

impl RpmCapability {
    pub fn package(name: impl Into<String>) -> Self {
        Self::new(RpmCapabilityKind::Package, name)
    }

    pub fn file(path: impl Into<String>) -> Self {
        Self::new(RpmCapabilityKind::File, path)
    }

    pub fn soname(name: impl Into<String>) -> Self {
        Self::new(RpmCapabilityKind::Soname, name)
    }

    pub fn virtual_capability(name: impl Into<String>) -> Self {
        Self::new(RpmCapabilityKind::Virtual, name)
    }

    pub fn new(kind: RpmCapabilityKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            requirement: None,
        }
    }

    pub fn with_requirement(mut self, requirement: VersionRequirement) -> Self {
        self.requirement = Some(requirement);
        self
    }
}

impl fmt::Display for RpmCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            RpmCapabilityKind::Package => "package",
            RpmCapabilityKind::File => "file",
            RpmCapabilityKind::Soname => "soname",
            RpmCapabilityKind::Virtual => "virtual",
        };
        match &self.requirement {
            Some(requirement) => write!(f, "{kind}:{} {requirement}", self.name),
            None => write!(f, "{kind}:{}", self.name),
        }
    }
}

fn split_rpm_epoch(value: &str) -> (Option<u64>, &str) {
    if let Some((epoch, version)) = value.split_once(':') {
        return (epoch.parse::<u64>().ok(), version);
    }
    (None, value)
}

fn split_rpm_release_arch(value: &str) -> (&str, &str) {
    if let Some((release, arch)) = value.rsplit_once('.')
        && is_rpm_arch(arch)
    {
        return (release, arch);
    }
    (value, "unknown")
}

fn is_rpm_arch(value: &str) -> bool {
    matches!(
        value,
        "x86_64" | "aarch64" | "ppc64le" | "s390x" | "noarch" | "src"
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpmOracleEvidence {
    pub command: String,
    pub dnf_version: String,
    pub repositories: BTreeSet<String>,
    pub metadata_digest: Option<String>,
    pub options: BTreeMap<String, String>,
    pub stdout_digest: String,
    pub stderr_digest: Option<String>,
}

impl RpmOracleEvidence {
    pub fn stable_key(&self) -> String {
        let repositories = self
            .repositories
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let options = self
            .options
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "command={};dnf={};repos=[{}];metadata={};options=[{}];stdout={};stderr={}",
            self.command,
            self.dnf_version,
            repositories,
            self.metadata_digest.as_deref().unwrap_or(""),
            options,
            self.stdout_digest,
            self.stderr_digest.as_deref().unwrap_or("")
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionRequirement {
    pub clauses: Vec<VersionClause>,
}

impl VersionRequirement {
    pub fn any() -> Self {
        Self {
            clauses: Vec::new(),
        }
    }

    pub fn exact(version: impl Into<String>) -> Self {
        Self {
            clauses: vec![VersionClause::Exact(Version::parse(version))],
        }
    }

    pub fn caret(version: impl Into<String>) -> Self {
        Self {
            clauses: vec![VersionClause::Caret(Version::parse(version))],
        }
    }

    pub fn parse(input: impl Into<String>) -> Self {
        let input = input.into();
        let trimmed = input.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return Self::any();
        }

        let clauses = trimmed
            .split(',')
            .map(str::trim)
            .filter(|clause| !clause.is_empty())
            .map(parse_version_clause)
            .collect::<Vec<_>>();

        Self { clauses }
    }

    pub fn matches(&self, version: &Version) -> bool {
        self.clauses.iter().all(|clause| clause.matches(version))
    }
}

impl fmt::Display for VersionRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.clauses.is_empty() {
            write!(f, "*")
        } else {
            write!(
                f,
                "{}",
                self.clauses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionClause {
    Exact(Version),
    GreaterThan(Version),
    GreaterThanOrEqual(Version),
    LessThan(Version),
    LessThanOrEqual(Version),
    Caret(Version),
    Tilde(Version),
}

impl VersionClause {
    pub fn matches(&self, version: &Version) -> bool {
        match self {
            VersionClause::Exact(expected) => version == expected,
            VersionClause::GreaterThan(bound) => version > bound,
            VersionClause::GreaterThanOrEqual(bound) => version >= bound,
            VersionClause::LessThan(bound) => version < bound,
            VersionClause::LessThanOrEqual(bound) => version <= bound,
            VersionClause::Caret(base) => {
                let upper = caret_upper_bound(base);
                version >= base && version < &upper
            }
            VersionClause::Tilde(base) => {
                let upper = if base.parts.len() <= 1 {
                    base.bump_major()
                } else {
                    base.bump_minor()
                };
                version >= base && version < &upper
            }
        }
    }
}

impl fmt::Display for VersionClause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionClause::Exact(version) => write!(f, "={version}"),
            VersionClause::GreaterThan(version) => write!(f, ">{version}"),
            VersionClause::GreaterThanOrEqual(version) => write!(f, ">={version}"),
            VersionClause::LessThan(version) => write!(f, "<{version}"),
            VersionClause::LessThanOrEqual(version) => write!(f, "<={version}"),
            VersionClause::Caret(version) => write!(f, "^{version}"),
            VersionClause::Tilde(version) => write!(f, "~{version}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyScope {
    Runtime,
    Compile,
    Build,
    Test,
    Development,
    Optional,
    Peer,
    Provided,
    System,
    Weak,
}

impl fmt::Display for DependencyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DependencyScope::Runtime => write!(f, "runtime"),
            DependencyScope::Compile => write!(f, "compile"),
            DependencyScope::Build => write!(f, "build"),
            DependencyScope::Test => write!(f, "test"),
            DependencyScope::Development => write!(f, "development"),
            DependencyScope::Optional => write!(f, "optional"),
            DependencyScope::Peer => write!(f, "peer"),
            DependencyScope::Provided => write!(f, "provided"),
            DependencyScope::System => write!(f, "system"),
            DependencyScope::Weak => write!(f, "weak"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyRelation {
    Requires,
    Recommends,
    Suggests,
    Provides,
    Conflicts,
    Replaces,
    Bundles,
    Links,
    LoadsDynamically,
}

impl fmt::Display for DependencyRelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DependencyRelation::Requires => write!(f, "requires"),
            DependencyRelation::Recommends => write!(f, "recommends"),
            DependencyRelation::Suggests => write!(f, "suggests"),
            DependencyRelation::Provides => write!(f, "provides"),
            DependencyRelation::Conflicts => write!(f, "conflicts"),
            DependencyRelation::Replaces => write!(f, "replaces"),
            DependencyRelation::Bundles => write!(f, "bundles"),
            DependencyRelation::Links => write!(f, "links"),
            DependencyRelation::LoadsDynamically => write!(f, "loads-dynamically"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperatingSystem {
    Any,
    Linux,
    Windows,
    Macos,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DistroFlavor {
    Any,
    AlmaLinux,
    CloudLinux,
    Rhel,
    Fedora,
    Rocky,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Architecture {
    Any,
    X86_64,
    Aarch64,
    Ppc64le,
    S390x,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuildProfile {
    Production,
    Development,
    Test,
    Fips,
    Els,
    KernelCare,
    ELevate,
    Gpu,
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolutionContext {
    pub os: OperatingSystem,
    pub distro: DistroFlavor,
    pub arch: Architecture,
    pub distro_major_version: Option<u16>,
    pub profiles: BTreeSet<BuildProfile>,
    pub enabled_features: BTreeSet<String>,
    pub include_scopes: BTreeSet<DependencyScope>,
    pub include_optional: bool,
    pub language_versions: BTreeMap<Ecosystem, Version>,
    pub repository_channels: BTreeSet<String>,
}

impl ResolutionContext {
    pub fn cloudlinux_production_x86_64() -> Self {
        Self {
            os: OperatingSystem::Linux,
            distro: DistroFlavor::CloudLinux,
            arch: Architecture::X86_64,
            distro_major_version: Some(9),
            profiles: BTreeSet::from([
                BuildProfile::Production,
                BuildProfile::Els,
                BuildProfile::KernelCare,
            ]),
            enabled_features: BTreeSet::new(),
            include_scopes: BTreeSet::from([
                DependencyScope::Runtime,
                DependencyScope::Compile,
                DependencyScope::Build,
                DependencyScope::System,
                DependencyScope::Weak,
            ]),
            include_optional: false,
            language_versions: BTreeMap::from([
                (Ecosystem::Python, Version::parse("3.11")),
                (Ecosystem::Maven, Version::parse("17")),
                (Ecosystem::Gradle, Version::parse("17")),
                (Ecosystem::Go, Version::parse("1.22")),
                (Ecosystem::Cargo, Version::parse("1.78")),
            ]),
            repository_channels: BTreeSet::from([
                "cloudlinux-baseos".to_string(),
                "cloudlinux-appstream".to_string(),
                "tuxcare-els".to_string(),
            ]),
        }
    }

    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.enabled_features.insert(feature.into());
        self
    }

    pub fn with_optional(mut self) -> Self {
        self.include_optional = true;
        self.include_scopes.insert(DependencyScope::Optional);
        self
    }

    pub fn includes_scope(&self, scope: &DependencyScope) -> bool {
        self.include_scopes.contains(scope)
    }

    pub fn stable_key(&self) -> String {
        let profiles = self
            .profiles
            .iter()
            .map(build_profile_key)
            .collect::<Vec<_>>()
            .join(",");
        let features = self
            .enabled_features
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let scopes = self
            .include_scopes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let languages = self
            .language_versions
            .iter()
            .map(|(ecosystem, version)| format!("{ecosystem}:{version}"))
            .collect::<Vec<_>>()
            .join(",");
        let repositories = self
            .repository_channels
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "os={};distro={};arch={};major={:?};profiles=[{}];features=[{}];scopes=[{}];optional={};languages=[{}];repositories=[{}]",
            operating_system_key(&self.os),
            distro_flavor_key(&self.distro),
            architecture_key(&self.arch),
            self.distro_major_version,
            profiles,
            features,
            scopes,
            self.include_optional,
            languages,
            repositories
        )
    }
}

fn operating_system_key(value: &OperatingSystem) -> String {
    match value {
        OperatingSystem::Any => "any".to_string(),
        OperatingSystem::Linux => "linux".to_string(),
        OperatingSystem::Windows => "windows".to_string(),
        OperatingSystem::Macos => "macos".to_string(),
        OperatingSystem::Other(value) => format!("other:{value}"),
    }
}

fn distro_flavor_key(value: &DistroFlavor) -> String {
    match value {
        DistroFlavor::Any => "any".to_string(),
        DistroFlavor::AlmaLinux => "almalinux".to_string(),
        DistroFlavor::CloudLinux => "cloudlinux".to_string(),
        DistroFlavor::Rhel => "rhel".to_string(),
        DistroFlavor::Fedora => "fedora".to_string(),
        DistroFlavor::Rocky => "rocky".to_string(),
        DistroFlavor::Other(value) => format!("other:{value}"),
    }
}

fn architecture_key(value: &Architecture) -> String {
    match value {
        Architecture::Any => "any".to_string(),
        Architecture::X86_64 => "x86_64".to_string(),
        Architecture::Aarch64 => "aarch64".to_string(),
        Architecture::Ppc64le => "ppc64le".to_string(),
        Architecture::S390x => "s390x".to_string(),
        Architecture::Other(value) => format!("other:{value}"),
    }
}

fn build_profile_key(value: &BuildProfile) -> String {
    match value {
        BuildProfile::Production => "production".to_string(),
        BuildProfile::Development => "development".to_string(),
        BuildProfile::Test => "test".to_string(),
        BuildProfile::Fips => "fips".to_string(),
        BuildProfile::Els => "els".to_string(),
        BuildProfile::KernelCare => "kernelcare".to_string(),
        BuildProfile::ELevate => "elevate".to_string(),
        BuildProfile::Gpu => "gpu".to_string(),
        BuildProfile::Other(value) => format!("other:{value}"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextPredicate {
    OsIs(OperatingSystem),
    DistroIs(DistroFlavor),
    ArchIs(Architecture),
    DistroMajorIs(u16),
    ProfileEnabled(BuildProfile),
    FeatureEnabled(String),
    RepositoryChannelEnabled(String),
    LanguageVersionMatches {
        ecosystem: Ecosystem,
        requirement: VersionRequirement,
    },
    AnyOf(Vec<ContextPredicate>),
    AllOf(Vec<ContextPredicate>),
    Not(Box<ContextPredicate>),
}

impl ContextPredicate {
    pub fn matches(&self, context: &ResolutionContext) -> bool {
        match self {
            ContextPredicate::OsIs(expected) => os_matches(expected, &context.os),
            ContextPredicate::DistroIs(expected) => distro_matches(expected, &context.distro),
            ContextPredicate::ArchIs(expected) => arch_matches(expected, &context.arch),
            ContextPredicate::DistroMajorIs(expected) => {
                context.distro_major_version == Some(*expected)
            }
            ContextPredicate::ProfileEnabled(profile) => context.profiles.contains(profile),
            ContextPredicate::FeatureEnabled(feature) => context.enabled_features.contains(feature),
            ContextPredicate::RepositoryChannelEnabled(channel) => {
                context.repository_channels.contains(channel)
            }
            ContextPredicate::LanguageVersionMatches {
                ecosystem,
                requirement,
            } => context
                .language_versions
                .get(ecosystem)
                .is_some_and(|version| requirement.matches(version)),
            ContextPredicate::AnyOf(predicates) => predicates
                .iter()
                .any(|predicate| predicate.matches(context)),
            ContextPredicate::AllOf(predicates) => predicates
                .iter()
                .all(|predicate| predicate.matches(context)),
            ContextPredicate::Not(predicate) => !predicate.matches(context),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            ContextPredicate::OsIs(value) => format!("os={value:?}"),
            ContextPredicate::DistroIs(value) => format!("distro={value:?}"),
            ContextPredicate::ArchIs(value) => format!("arch={value:?}"),
            ContextPredicate::DistroMajorIs(value) => format!("distro_major={value}"),
            ContextPredicate::ProfileEnabled(value) => format!("profile={value:?}"),
            ContextPredicate::FeatureEnabled(value) => format!("feature={value}"),
            ContextPredicate::RepositoryChannelEnabled(value) => format!("repo={value}"),
            ContextPredicate::LanguageVersionMatches {
                ecosystem,
                requirement,
            } => format!("{ecosystem}_version={requirement}"),
            ContextPredicate::AnyOf(predicates) => format!(
                "any({})",
                predicates
                    .iter()
                    .map(ContextPredicate::describe)
                    .collect::<Vec<_>>()
                    .join(" OR ")
            ),
            ContextPredicate::AllOf(predicates) => format!(
                "all({})",
                predicates
                    .iter()
                    .map(ContextPredicate::describe)
                    .collect::<Vec<_>>()
                    .join(" AND ")
            ),
            ContextPredicate::Not(predicate) => format!("not({})", predicate.describe()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyRequirement {
    pub target: PackageId,
    pub requirement: VersionRequirement,
    pub relation: DependencyRelation,
    pub scope: DependencyScope,
    pub optional: bool,
    pub conditions: Vec<ContextPredicate>,
    pub features: BTreeSet<String>,
    pub exclusions: BTreeSet<PackageId>,
    pub evidence: String,
}

impl DependencyRequirement {
    pub fn new(target: PackageId, requirement: VersionRequirement) -> Self {
        Self {
            target,
            requirement,
            relation: DependencyRelation::Requires,
            scope: DependencyScope::Runtime,
            optional: false,
            conditions: Vec::new(),
            features: BTreeSet::new(),
            exclusions: BTreeSet::new(),
            evidence: "manual".to_string(),
        }
    }

    pub fn scope(mut self, scope: DependencyScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn relation(mut self, relation: DependencyRelation) -> Self {
        self.relation = relation;
        self
    }

    pub fn optional(mut self) -> Self {
        self.optional = true;
        self.scope = DependencyScope::Optional;
        self
    }

    pub fn when(mut self, condition: ContextPredicate) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn feature(mut self, feature: impl Into<String>) -> Self {
        self.features.insert(feature.into());
        self
    }

    pub fn exclude(mut self, package: PackageId) -> Self {
        self.exclusions.insert(package);
        self
    }

    pub fn evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = evidence.into();
        self
    }

    pub fn is_active(&self, context: &ResolutionContext) -> ActiveDecision {
        if !context.includes_scope(&self.scope) {
            return ActiveDecision::Skipped(format!("scope {} excluded by context", self.scope));
        }

        if self.optional && !context.include_optional && self.features.is_empty() {
            return ActiveDecision::Skipped("optional dependency not requested".to_string());
        }

        if self.optional
            && !self.features.is_empty()
            && !self
                .features
                .iter()
                .any(|feature| context.enabled_features.contains(feature))
        {
            return ActiveDecision::Skipped(format!(
                "optional feature not enabled: {}",
                self.features.iter().cloned().collect::<Vec<_>>().join(",")
            ));
        }

        for condition in &self.conditions {
            if !condition.matches(context) {
                return ActiveDecision::Skipped(format!(
                    "context predicate did not match: {}",
                    condition.describe()
                ));
            }
        }

        ActiveDecision::Active
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActiveDecision {
    Active,
    Skipped(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageSource {
    Registry(String),
    Repository(String),
    Lockfile(String),
    Sdist(String),
    Wheel(String),
    RpmRepo {
        repo: String,
        epoch: Option<u64>,
        release: String,
        arch: String,
    },
    Internal(String),
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub source: PackageSource,
    pub checksum: Option<String>,
    pub signed: bool,
    pub purl: Option<String>,
    pub license: Option<String>,
}

impl ArtifactMetadata {
    pub fn unknown() -> Self {
        Self {
            source: PackageSource::Unknown,
            checksum: None,
            signed: false,
            purl: None,
            license: None,
        }
    }

    pub fn internal(name: impl Into<String>) -> Self {
        Self {
            source: PackageSource::Internal(name.into()),
            checksum: None,
            signed: true,
            purl: None,
            license: Some("proprietary".to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageVersion {
    pub id: PackageId,
    pub version: Version,
    pub dependencies: Vec<DependencyRequirement>,
    pub metadata: ArtifactMetadata,
}

impl PackageVersion {
    pub fn new(id: PackageId, version: impl Into<String>) -> Self {
        Self {
            id,
            version: Version::parse(version),
            dependencies: Vec::new(),
            metadata: ArtifactMetadata::unknown(),
        }
    }

    pub fn with_dependencies(mut self, dependencies: Vec<DependencyRequirement>) -> Self {
        self.dependencies = dependencies;
        self
    }

    pub fn with_metadata(mut self, metadata: ArtifactMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn package_ref(&self) -> PackageRef {
        PackageRef::new(self.id.clone(), self.version.clone())
    }
}

fn parse_version_clause(input: &str) -> VersionClause {
    if let Some(version) = input.strip_prefix(">=") {
        VersionClause::GreaterThanOrEqual(Version::parse(version.trim()))
    } else if let Some(version) = input.strip_prefix("<=") {
        VersionClause::LessThanOrEqual(Version::parse(version.trim()))
    } else if let Some(version) = input.strip_prefix('>') {
        VersionClause::GreaterThan(Version::parse(version.trim()))
    } else if let Some(version) = input.strip_prefix('<') {
        VersionClause::LessThan(Version::parse(version.trim()))
    } else if let Some(version) = input.strip_prefix('=') {
        VersionClause::Exact(Version::parse(version.trim()))
    } else if let Some(version) = input.strip_prefix('^') {
        VersionClause::Caret(Version::parse(version.trim()))
    } else if let Some(version) = input.strip_prefix('~') {
        VersionClause::Tilde(Version::parse(version.trim()))
    } else {
        VersionClause::Exact(Version::parse(input.trim()))
    }
}

fn caret_upper_bound(base: &Version) -> Version {
    let mut parts = base.parts.clone();
    parts.resize(3, 0);

    if parts[0] > 0 {
        base.bump_major()
    } else if parts[1] > 0 {
        base.bump_minor()
    } else {
        base.bump_patch()
    }
}

fn normalize_python_name(value: String) -> String {
    value.replace(['_', '.'], "-").to_ascii_lowercase()
}

fn os_matches(expected: &OperatingSystem, actual: &OperatingSystem) -> bool {
    matches!(expected, OperatingSystem::Any) || expected == actual
}

fn distro_matches(expected: &DistroFlavor, actual: &DistroFlavor) -> bool {
    matches!(expected, DistroFlavor::Any) || expected == actual
}

fn arch_matches(expected: &Architecture, actual: &Architecture) -> bool {
    matches!(expected, Architecture::Any) || expected == actual
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn python_package_names_are_normalized() {
        assert_eq!(
            PackageId::python("Requests_Toolkit.Core").name,
            "requests-toolkit-core"
        );
    }

    #[test]
    fn package_display_includes_namespace_when_present() {
        let package = PackageId::maven("org.example", "demo");
        assert_eq!(package.to_string(), "maven:org.example/demo");
    }

    #[test]
    fn purl_like_format_distinguishes_plain_and_namespaced_packages() {
        assert_eq!(
            PackageId::rpm("openssl-libs").purl_like(),
            "rpm:openssl-libs"
        );
        assert_eq!(
            PackageId::maven("org.slf4j", "slf4j-api").purl_like(),
            "maven/org.slf4j:slf4j-api"
        );
    }

    #[test]
    fn rpm_coordinate_parses_nevra_inventory_shapes() {
        let spaced =
            RpmPackageCoordinate::from_inventory_line("kernelcare-agent 3.1.4-1.el9.x86_64")
                .unwrap();
        let compact =
            RpmPackageCoordinate::from_inventory_line("openssl-libs-1:3.2.2-1.el9.x86_64").unwrap();

        assert_eq!(spaced.name, "kernelcare-agent");
        assert_eq!(spaced.version_release(), "3.1.4-1.el9");
        assert_eq!(spaced.arch, "x86_64");
        assert_eq!(compact.epoch, Some(1));
        assert_eq!(
            compact.package_ref().to_string(),
            "rpm:openssl-libs@1:3.2.2-1.el9"
        );
        assert_eq!(
            compact.with_repository("baseos").source(),
            PackageSource::RpmRepo {
                repo: "baseos".to_string(),
                epoch: Some(1),
                release: "1.el9".to_string(),
                arch: "x86_64".to_string(),
            }
        );
    }

    #[test]
    fn rpm_capability_distinguishes_package_file_soname_and_virtual_provides() {
        let package = RpmCapability::package("openssl-libs")
            .with_requirement(VersionRequirement::parse(">=3.0"));
        let file = RpmCapability::file("/usr/bin/python3");
        let soname = RpmCapability::soname("libssl.so.3()(64bit)");
        let virtual_capability = RpmCapability::virtual_capability("webserver");

        assert_eq!(package.to_string(), "package:openssl-libs >=3.0");
        assert_eq!(file.to_string(), "file:/usr/bin/python3");
        assert_eq!(soname.to_string(), "soname:libssl.so.3()(64bit)");
        assert_eq!(virtual_capability.to_string(), "virtual:webserver");
    }

    #[test]
    fn rpm_oracle_evidence_key_records_solver_context() {
        let evidence = RpmOracleEvidence {
            command: "dnf repoquery --requires openssl-libs".to_string(),
            dnf_version: "dnf5 5.2.0".to_string(),
            repositories: BTreeSet::from(["baseos".to_string(), "appstream".to_string()]),
            metadata_digest: Some("repomd:abc123".to_string()),
            options: BTreeMap::from([
                ("best".to_string(), "true".to_string()),
                ("install_weak_deps".to_string(), "false".to_string()),
            ]),
            stdout_digest: "stdout:123".to_string(),
            stderr_digest: Some("stderr:empty".to_string()),
        };

        let key = evidence.stable_key();

        assert!(key.contains("dnf5 5.2.0"));
        assert!(key.contains("repos=[appstream,baseos]"));
        assert!(key.contains("install_weak_deps=false"));
        assert!(key.contains("stdout=stdout:123"));
    }

    #[test]
    fn version_ordering_uses_numeric_segments() {
        assert!(Version::parse("1.10.0") > Version::parse("1.2.9"));
    }

    #[test]
    fn stable_release_sorts_after_prerelease() {
        assert!(Version::parse("1.0.0") > Version::parse("1.0.0-rc1"));
    }

    #[test]
    fn normalized_versions_compare_and_hash_consistently() {
        let mut versions = HashSet::new();
        versions.insert(Version::parse("1.0"));

        assert_eq!(Version::parse("1.0"), Version::parse("1.0.0"));
        assert!(versions.contains(&Version::parse("1.0.0")));
    }

    #[test]
    fn caret_requirement_matches_semver_compatible_versions() {
        let requirement = VersionRequirement::parse("^1.2.0");
        assert!(requirement.matches(&Version::parse("1.9.9")));
        assert!(!requirement.matches(&Version::parse("2.0.0")));
    }

    #[test]
    fn zero_major_caret_is_conservative() {
        let requirement = VersionRequirement::parse("^0.2.3");
        assert!(requirement.matches(&Version::parse("0.2.9")));
        assert!(!requirement.matches(&Version::parse("0.3.0")));
    }

    #[test]
    fn comma_ranges_are_conjunctive() {
        let requirement = VersionRequirement::parse(">=1.4,<2.0");
        assert!(requirement.matches(&Version::parse("1.9.0")));
        assert!(!requirement.matches(&Version::parse("2.0.0")));
    }

    #[test]
    fn wildcard_and_empty_requirements_match_any_version() {
        assert!(VersionRequirement::parse("*").matches(&Version::parse("99.0.0")));
        assert!(VersionRequirement::parse("").matches(&Version::parse("0.0.1")));
    }

    #[test]
    fn exact_requirement_uses_normalized_equality() {
        let requirement = VersionRequirement::exact("1.0");

        assert!(requirement.matches(&Version::parse("1.0.0")));
        assert!(!requirement.matches(&Version::parse("1.0.1")));
    }

    #[test]
    fn comparison_clauses_include_and_exclude_boundaries() {
        let requirement = VersionRequirement::parse(">1.0,<=2.0");

        assert!(!requirement.matches(&Version::parse("1.0")));
        assert!(requirement.matches(&Version::parse("1.0.1")));
        assert!(requirement.matches(&Version::parse("2.0")));
        assert!(!requirement.matches(&Version::parse("2.0.1")));
    }

    #[test]
    fn tilde_requirement_limits_minor_version_when_minor_is_specified() {
        let requirement = VersionRequirement::parse("~1.2.3");

        assert!(requirement.matches(&Version::parse("1.2.9")));
        assert!(!requirement.matches(&Version::parse("1.3.0")));
    }

    #[test]
    fn tilde_requirement_limits_major_version_when_only_major_is_specified() {
        let requirement = VersionRequirement::parse("~1");

        assert!(requirement.matches(&Version::parse("1.9.9")));
        assert!(!requirement.matches(&Version::parse("2.0.0")));
    }

    #[test]
    fn version_requirement_display_preserves_clause_meaning() {
        assert_eq!(
            VersionRequirement::parse(">=1.0,<2.0").to_string(),
            ">=1.0,<2.0"
        );
        assert_eq!(VersionRequirement::any().to_string(), "*");
    }

    #[test]
    fn cloudlinux_context_includes_runtime_build_system_and_weak_scopes() {
        let context = ResolutionContext::cloudlinux_production_x86_64();

        assert!(context.includes_scope(&DependencyScope::Runtime));
        assert!(context.includes_scope(&DependencyScope::Build));
        assert!(context.includes_scope(&DependencyScope::System));
        assert!(context.includes_scope(&DependencyScope::Weak));
        assert!(!context.includes_scope(&DependencyScope::Development));
    }

    #[test]
    fn context_stable_key_tracks_environment_changes() {
        let base = ResolutionContext::cloudlinux_production_x86_64();
        let with_gpu = ResolutionContext::cloudlinux_production_x86_64().with_feature("gpu");

        assert_eq!(
            base.stable_key(),
            ResolutionContext::cloudlinux_production_x86_64().stable_key()
        );
        assert_ne!(base.stable_key(), with_gpu.stable_key());
        assert!(with_gpu.stable_key().contains("features=[gpu]"));
    }

    #[test]
    fn with_optional_enables_optional_resolution_scope() {
        let context = ResolutionContext::cloudlinux_production_x86_64().with_optional();

        assert!(context.include_optional);
        assert!(context.includes_scope(&DependencyScope::Optional));
    }

    #[test]
    fn any_context_predicates_match_specific_context_values() {
        let context = ResolutionContext::cloudlinux_production_x86_64();

        assert!(ContextPredicate::OsIs(OperatingSystem::Any).matches(&context));
        assert!(ContextPredicate::DistroIs(DistroFlavor::Any).matches(&context));
        assert!(ContextPredicate::ArchIs(Architecture::Any).matches(&context));
    }

    #[test]
    fn feature_profile_repo_and_distro_predicates_match_context() {
        let context = ResolutionContext::cloudlinux_production_x86_64().with_feature("gpu");

        assert!(ContextPredicate::FeatureEnabled("gpu".to_string()).matches(&context));
        assert!(ContextPredicate::ProfileEnabled(BuildProfile::KernelCare).matches(&context));
        assert!(
            ContextPredicate::RepositoryChannelEnabled("tuxcare-els".to_string()).matches(&context)
        );
        assert!(ContextPredicate::DistroMajorIs(9).matches(&context));
        assert!(!ContextPredicate::DistroMajorIs(8).matches(&context));
    }

    #[test]
    fn language_version_predicate_matches_runtime_version() {
        let context = ResolutionContext::cloudlinux_production_x86_64();

        assert!(
            ContextPredicate::LanguageVersionMatches {
                ecosystem: Ecosystem::Python,
                requirement: VersionRequirement::parse(">=3.11,<3.12"),
            }
            .matches(&context)
        );
    }

    #[test]
    fn composed_context_predicates_support_any_all_and_not() {
        let context = ResolutionContext::cloudlinux_production_x86_64();

        assert!(
            ContextPredicate::AnyOf(vec![
                ContextPredicate::OsIs(OperatingSystem::Windows),
                ContextPredicate::DistroIs(DistroFlavor::CloudLinux),
            ])
            .matches(&context)
        );
        assert!(
            ContextPredicate::AllOf(vec![
                ContextPredicate::OsIs(OperatingSystem::Linux),
                ContextPredicate::ArchIs(Architecture::X86_64),
            ])
            .matches(&context)
        );
        assert!(
            ContextPredicate::Not(Box::new(ContextPredicate::OsIs(OperatingSystem::Macos,)))
                .matches(&context)
        );
    }

    #[test]
    fn scope_excluded_dependency_is_inactive() {
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let dependency = DependencyRequirement::new(
            PackageId::npm(None::<String>, "vite"),
            VersionRequirement::any(),
        )
        .scope(DependencyScope::Development);

        assert!(matches!(
            dependency.is_active(&context),
            ActiveDecision::Skipped(reason) if reason.contains("scope development excluded")
        ));
    }

    #[test]
    fn optional_dependency_without_optional_context_is_inactive() {
        let context = ResolutionContext::cloudlinux_production_x86_64().with_optional();
        let dependency = DependencyRequirement::new(
            PackageId::python("nvidia-ml-py"),
            VersionRequirement::any(),
        )
        .optional()
        .feature("gpu");

        assert!(matches!(
            dependency.is_active(&context),
            ActiveDecision::Skipped(reason) if reason.contains("optional feature not enabled")
        ));
    }

    #[test]
    fn optional_feature_dependency_is_active_when_scope_and_feature_are_enabled() {
        let context = ResolutionContext::cloudlinux_production_x86_64()
            .with_optional()
            .with_feature("gpu");
        let dependency = DependencyRequirement::new(
            PackageId::python("nvidia-ml-py"),
            VersionRequirement::any(),
        )
        .optional()
        .feature("gpu");

        assert_eq!(dependency.is_active(&context), ActiveDecision::Active);
    }

    #[test]
    fn inactive_context_condition_reports_predicate_reason() {
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let dependency = DependencyRequirement::new(
            PackageId::npm(None::<String>, "fsevents"),
            VersionRequirement::any(),
        )
        .optional()
        .when(ContextPredicate::OsIs(OperatingSystem::Macos));

        assert!(matches!(
            dependency.is_active(&context.with_optional()),
            ActiveDecision::Skipped(reason) if reason.contains("context predicate did not match")
        ));
    }

    #[test]
    fn dependency_builder_records_relation_exclusion_and_evidence() {
        let excluded = PackageId::maven("commons-logging", "commons-logging");
        let dependency = DependencyRequirement::new(
            PackageId::maven("ch.qos.logback", "logback-classic"),
            VersionRequirement::parse(">=1.4,<2.0"),
        )
        .relation(DependencyRelation::Bundles)
        .exclude(excluded.clone())
        .evidence("pom.xml");

        assert_eq!(dependency.relation, DependencyRelation::Bundles);
        assert!(dependency.exclusions.contains(&excluded));
        assert_eq!(dependency.evidence, "pom.xml");
    }

    #[test]
    fn internal_artifact_metadata_is_signed_and_proprietary() {
        let metadata = ArtifactMetadata::internal("product-catalog");

        assert!(metadata.signed);
        assert_eq!(metadata.license.as_deref(), Some("proprietary"));
    }

    #[test]
    fn package_version_package_ref_round_trips_identity_and_version() {
        let package = PackageVersion::new(PackageId::cargo("petgraph"), "0.6.5");
        let package_ref = package.package_ref();

        assert_eq!(package_ref.id, PackageId::cargo("petgraph"));
        assert_eq!(package_ref.version, Version::parse("0.6.5"));
    }

    #[test]
    fn version_parts_expose_numeric_components() {
        assert_eq!(Version::parse("2.17.2").parts(), &[2, 17, 2]);
    }
}
