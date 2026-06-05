//! Conservative parsers for lockfiles, manifests, SBOMs, and RPM inventories.

use std::{collections::BTreeMap, fmt};

use crate::evidence::{
    EvidenceCatalog, EvidenceConfidence, EvidenceKind, EvidenceRecord, EvidenceSource,
};
use crate::model::{
    DependencyRequirement, DependencyScope, Ecosystem, PackageId, PackageRef, RpmPackageCoordinate,
    Version, VersionRequirement,
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

    let root = parse_json_root(input)?;
    let packages = root
        .field("packages")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| LockfileParseError::new(1, "npm package-lock is missing packages object"))?;

    for (path, entry) in packages {
        let Some(package_name) = path.strip_prefix("node_modules/") else {
            continue;
        };
        let Some(version) = entry.field("version").and_then(JsonValue::as_str) else {
            if entry.field("link").and_then(JsonValue::as_bool) == Some(true) {
                continue;
            }
            return Err(LockfileParseError::new(
                1,
                format!("npm package-lock entry {path} is missing version"),
            ));
        };
        if package_name.is_empty() {
            continue;
        };
        if version.is_empty() {
            return Err(LockfileParseError::new(
                1,
                format!("npm package-lock entry {path} has empty version"),
            ));
        }

        let package = PackageRef::new(npm_package_id(package_name), Version::parse(version));
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
        let Some(coordinate) = RpmPackageCoordinate::from_inventory_line(line) else {
            return Err(LockfileParseError::new(
                line_number,
                "expected RPM inventory line with name and version",
            ));
        };
        let package = coordinate.package_ref();
        catalog.add(EvidenceRecord::package(
            source.clone(),
            package,
            EvidenceConfidence::Observed,
            format!("RPM inventory package: {}", coordinate.nevra()),
        ));
    }

    Ok(catalog)
}

pub fn parse_cyclonedx_sbom(
    input: &str,
    locator: impl Into<String>,
) -> Result<EvidenceCatalog, LockfileParseError> {
    let locator = locator.into();
    let root = parse_json_root(input)?;
    let bom_format = root
        .field("bomFormat")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| LockfileParseError::new(1, "CycloneDX SBOM is missing bomFormat"))?;
    if bom_format != "CycloneDX" {
        return Err(LockfileParseError::new(
            1,
            "expected CycloneDX SBOM with bomFormat",
        ));
    }
    let source = EvidenceSource::new(EvidenceKind::Sbom, None, locator);
    let mut catalog = EvidenceCatalog::new();
    let components = root
        .field("components")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| LockfileParseError::new(1, "CycloneDX SBOM is missing components array"))?;

    for component in components {
        let component = component.as_object().ok_or_else(|| {
            LockfileParseError::new(1, "CycloneDX component entry must be a JSON object")
        })?;
        let name = component
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| LockfileParseError::new(1, "CycloneDX component missing name"))?;
        let purl = component.get("purl").and_then(JsonValue::as_str);
        let version = component
            .get("version")
            .and_then(JsonValue::as_str)
            .map(str::to_string)
            .or_else(|| purl.and_then(version_from_purl))
            .ok_or_else(|| LockfileParseError::new(1, "CycloneDX component missing version"))?;
        let package_id = purl
            .and_then(|purl| package_id_from_purl(purl, name))
            .unwrap_or_else(|| {
                PackageId::new(
                    Ecosystem::Other("cyclonedx".to_string()),
                    None::<String>,
                    name,
                )
            });
        let package = PackageRef::new(package_id.clone(), Version::parse(version.clone()));
        catalog.add(EvidenceRecord::package(
            source.clone(),
            package,
            EvidenceConfidence::Resolved,
            format!("CycloneDX component: {package_id}@{version}"),
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum JsonValue {
    Object(BTreeMap<String, JsonValue>),
    Array(Vec<JsonValue>),
    String(String),
    Number,
    Bool(bool),
    Null,
}

impl JsonValue {
    fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(value) => Some(value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(value) => Some(*value),
            _ => None,
        }
    }

    fn field(&self, name: &str) -> Option<&JsonValue> {
        self.as_object()?.get(name)
    }
}

fn parse_json_root(input: &str) -> Result<JsonValue, LockfileParseError> {
    let mut parser = JsonParser::new(input);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.peek_char().is_some() {
        return parser.error("unexpected trailing JSON content");
    }
    Ok(value)
}

struct JsonParser<'a> {
    input: &'a str,
    offset: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, offset: 0 }
    }

    fn parse_value(&mut self) -> Result<JsonValue, LockfileParseError> {
        self.skip_whitespace();
        match self.peek_char() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('t') => self.consume_literal("true", JsonValue::Bool(true)),
            Some('f') => self.consume_literal("false", JsonValue::Bool(false)),
            Some('n') => self.consume_literal("null", JsonValue::Null),
            Some('-' | '0'..='9') => self.parse_number(),
            Some(_) => self.error("expected JSON value"),
            None => self.error("unexpected end of JSON input"),
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, LockfileParseError> {
        self.expect_char('{')?;
        let mut object = BTreeMap::new();
        self.skip_whitespace();
        if self.peek_char() == Some('}') {
            self.bump_char();
            return Ok(JsonValue::Object(object));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect_char(':')?;
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_whitespace();
            match self.peek_char() {
                Some(',') => {
                    self.bump_char();
                }
                Some('}') => {
                    self.bump_char();
                    return Ok(JsonValue::Object(object));
                }
                Some(_) => return self.error("expected comma or closing brace in JSON object"),
                None => return self.error("unterminated JSON object"),
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, LockfileParseError> {
        self.expect_char('[')?;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.peek_char() == Some(']') {
            self.bump_char();
            return Ok(JsonValue::Array(values));
        }

        loop {
            values.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek_char() {
                Some(',') => {
                    self.bump_char();
                }
                Some(']') => {
                    self.bump_char();
                    return Ok(JsonValue::Array(values));
                }
                Some(_) => return self.error("expected comma or closing bracket in JSON array"),
                None => return self.error("unterminated JSON array"),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, LockfileParseError> {
        self.expect_char('"')?;
        let mut value = String::new();
        loop {
            let Some(ch) = self.bump_char() else {
                return self.error("unterminated JSON string");
            };
            match ch {
                '"' => return Ok(value),
                '\\' => value.push(self.parse_escape()?),
                ch if ch <= '\u{1f}' => {
                    return self.error("unescaped control character in JSON string");
                }
                other => value.push(other),
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, LockfileParseError> {
        let Some(ch) = self.bump_char() else {
            return self.error("unterminated JSON escape");
        };
        match ch {
            '"' => Ok('"'),
            '\\' => Ok('\\'),
            '/' => Ok('/'),
            'b' => Ok('\u{0008}'),
            'f' => Ok('\u{000c}'),
            'n' => Ok('\n'),
            'r' => Ok('\r'),
            't' => Ok('\t'),
            'u' => self.parse_unicode_escape(),
            _ => self.error("invalid JSON escape"),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, LockfileParseError> {
        let first = self.parse_hex4()?;
        let codepoint = if (0xd800..=0xdbff).contains(&first) {
            if self.peek_char() != Some('\\') {
                return self.error("missing low surrogate in JSON unicode escape");
            }
            self.bump_char();
            if self.peek_char() != Some('u') {
                return self.error("missing low surrogate in JSON unicode escape");
            }
            self.bump_char();
            let second = self.parse_hex4()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return self.error("invalid low surrogate in JSON unicode escape");
            }
            0x10000 + (((first as u32) - 0xd800) << 10) + ((second as u32) - 0xdc00)
        } else if (0xdc00..=0xdfff).contains(&first) {
            return self.error("unexpected low surrogate in JSON unicode escape");
        } else {
            first as u32
        };

        let Some(decoded) = char::from_u32(codepoint) else {
            return self.error("invalid JSON unicode escape");
        };
        Ok(decoded)
    }

    fn parse_hex4(&mut self) -> Result<u16, LockfileParseError> {
        let mut value = 0u16;
        for _ in 0..4 {
            let Some(ch) = self.bump_char() else {
                return self.error("unterminated JSON unicode escape");
            };
            let Some(digit) = ch.to_digit(16) else {
                return self.error("invalid JSON unicode escape");
            };
            value = (value * 16) + digit as u16;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<JsonValue, LockfileParseError> {
        if self.peek_char() == Some('-') {
            self.bump_char();
        }

        match self.peek_char() {
            Some('0') => {
                self.bump_char();
            }
            Some('1'..='9') => {
                self.bump_char();
                self.consume_digits();
            }
            _ => return self.error("invalid JSON number"),
        }

        if self.peek_char() == Some('.') {
            self.bump_char();
            if !self.consume_digits() {
                return self.error("invalid JSON number fraction");
            }
        }

        if matches!(self.peek_char(), Some('e' | 'E')) {
            self.bump_char();
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.bump_char();
            }
            if !self.consume_digits() {
                return self.error("invalid JSON number exponent");
            }
        }

        Ok(JsonValue::Number)
    }

    fn consume_digits(&mut self) -> bool {
        let start = self.offset;
        while matches!(self.peek_char(), Some('0'..='9')) {
            self.bump_char();
        }
        self.offset != start
    }

    fn consume_literal(
        &mut self,
        literal: &str,
        value: JsonValue,
    ) -> Result<JsonValue, LockfileParseError> {
        if self.input[self.offset..].starts_with(literal) {
            self.offset += literal.len();
            Ok(value)
        } else {
            self.error("invalid JSON literal")
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<(), LockfileParseError> {
        match self.bump_char() {
            Some(actual) if actual == expected => Ok(()),
            Some(_) => self.error(format!("expected JSON character {expected}")),
            None => self.error(format!("expected JSON character {expected}")),
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_char(), Some(' ' | '\n' | '\r' | '\t')) {
            self.bump_char();
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.offset..].chars().next()
    }

    fn bump_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.offset += ch.len_utf8();
        Some(ch)
    }

    fn line(&self) -> usize {
        self.input[..self.offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T, LockfileParseError> {
        Err(LockfileParseError::new(self.line(), message))
    }
}

fn version_from_purl(purl: &str) -> Option<String> {
    let base = purl.strip_prefix("pkg:")?.split('?').next()?;
    let (_, version) = base.rsplit_once('@')?;
    (!version.is_empty()).then(|| percent_decode(version))
}

fn package_id_from_purl(purl: &str, fallback_name: &str) -> Option<PackageId> {
    let base = purl.strip_prefix("pkg:")?.split('?').next()?;
    let (coordinates, _) = base.rsplit_once('@').unwrap_or((base, ""));
    let (ecosystem, path) = coordinates.split_once('/')?;
    let path = percent_decode(path);
    match ecosystem {
        "pypi" => Some(PackageId::python(
            path.rsplit('/').next().unwrap_or(fallback_name),
        )),
        "npm" => npm_package_from_purl(&path),
        "maven" => {
            let (group, artifact) = path.rsplit_once('/')?;
            Some(PackageId::maven(group.replace('/', "."), artifact))
        }
        "golang" => Some(PackageId::go(path)),
        "cargo" => Some(PackageId::cargo(
            path.rsplit('/').next().unwrap_or(fallback_name),
        )),
        "rpm" => Some(PackageId::rpm(
            path.rsplit('/').next().unwrap_or(fallback_name),
        )),
        other => Some(PackageId::new(
            Ecosystem::Other(other.to_string()),
            None::<String>,
            fallback_name.to_string(),
        )),
    }
}

fn npm_package_from_purl(path: &str) -> Option<PackageId> {
    if let Some(scoped) = path.strip_prefix('@') {
        let (scope, name) = scoped.split_once('/')?;
        return Some(PackageId::npm(Some(scope.to_string()), name));
    }
    Some(PackageId::npm(None::<String>, path.to_string()))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_string())
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
    fn parses_minified_npm_package_lock_packages_and_ignores_links() {
        let catalog = parse_npm_package_lock(
            r#"{"lockfileVersion":3,"packages":{"":{"name":"portal","version":"1.0.0"},"node_modules/react":{"version":"18.3.1"},"node_modules/@cloudlinux/ui":{"version":"5.1.0"},"node_modules/portal-link":{"link":true,"resolved":"."}}}"#,
            "package-lock.json",
        )
        .unwrap();

        let locked = catalog.locked_packages();
        assert_eq!(locked.len(), 2);
        assert!(
            locked
                .iter()
                .any(|package| package.id == PackageId::npm(None::<String>, "react"))
        );
        assert!(
            locked.iter().any(|package| {
                package.id == PackageId::npm(Some("cloudlinux".to_string()), "ui")
            })
        );
    }

    #[test]
    fn rejects_malformed_json_with_line_number() {
        let error = parse_npm_package_lock(
            r#"{
              "packages": {
                "node_modules/react": {"version": "18.3.1"}
            "#,
            "package-lock.json",
        )
        .unwrap_err();

        assert!(error.line >= 3);
        assert!(error.message.contains("unterminated"));
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
        assert!(
            catalog.by_package(&PackageId::rpm("openssl-libs"))[0]
                .summary
                .contains("openssl-libs-3.2.2-1.el9.x86_64")
        );
    }

    #[test]
    fn parses_cyclonedx_sbom_components() {
        let catalog = parse_cyclonedx_sbom(
            r#"
            {
              "bomFormat": "CycloneDX",
              "components": [
                {
                  "type": "library",
                  "name": "urllib3",
                  "version": "2.2.2",
                  "purl": "pkg:pypi/urllib3@2.2.2"
                },
                {
                  "type": "library",
                  "name": "@cloudlinux/theme",
                  "version": "5.1.0",
                  "purl": "pkg:npm/%40cloudlinux/theme@5.1.0"
                }
              ]
            }
            "#,
            "bom.json",
        )
        .unwrap();

        assert_eq!(catalog.records().len(), 2);
        assert_eq!(catalog.by_package(&PackageId::python("urllib3")).len(), 1);
        assert_eq!(
            catalog
                .by_package(&PackageId::npm(Some("cloudlinux".to_string()), "theme"))
                .len(),
            1
        );
        assert_eq!(catalog.summary().by_kind["Sbom"], 2);
    }

    #[test]
    fn parses_minified_cyclonedx_sbom_components_and_purl_versions() {
        let catalog = parse_cyclonedx_sbom(
            r#"{"bomFormat":"CycloneDX","components":[{"type":"library","name":"urllib3","purl":"pkg:pypi/urllib3@2.2.2"},{"type":"library","name":"@cloudlinux/theme","purl":"pkg:npm/%40cloudlinux/theme@5.1.0"}]}"#,
            "bom.json",
        )
        .unwrap();

        assert_eq!(catalog.records().len(), 2);
        assert_eq!(catalog.by_package(&PackageId::python("urllib3")).len(), 1);
        assert_eq!(
            catalog
                .by_package(&PackageId::npm(Some("cloudlinux".to_string()), "theme"))
                .len(),
            1
        );
    }

    #[test]
    fn rejects_rpm_inventory_without_version() {
        let error = parse_rpm_inventory("kernelcare-agent", "rpm -qa").unwrap_err();

        assert!(error.message.contains("name and version"));
    }
}
