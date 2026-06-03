# Language And Package Manager Analysis

GraphScope must model dependency semantics, not only dependency names. The same
edge may be runtime-only in one ecosystem, build-only in another, active only on
Linux, or replaced by a provided native capability on CloudLinux OS.

This analysis covers the initial production set: RPM, Python, Java, JavaScript,
Go, and Rust. The model is intentionally extensible for .NET, Ruby, PHP, and C/C++
native build systems.

## Universal Concepts

Every ecosystem-specific declaration is normalized into:

- package identity: ecosystem, namespace, name, distribution/channel, and purl;
- version domain: exact version, range, revision, epoch, stream, or pseudo-version;
- scope: runtime, compile, build, test, development, optional, weak, peer,
  provided, or system;
- relation: requires, recommends, suggests, conflicts, replaces, provides,
  bundles, links, or loads dynamically;
- activation context: OS, distro, architecture, language/runtime version, feature,
  profile, repository channel, and customer policy;
- resolver rule: how candidates are selected and how conflicts are mediated;
- evidence: manifest, lockfile, repository metadata, SBOM, observed runtime fact,
  or package-manager trace.

## RPM, DNF, AlmaLinux, CloudLinux, And TuxCare

RPM dependency metadata includes required capabilities, provided capabilities,
script requirements, file dependencies, rich dependencies, conflicts, obsoletes,
and weak dependencies. DNF/libsolv resolves against repository state, enabled
modules, architecture, install reason, repository priority, and weak dependency
policy.

GraphScope implications:

- RPM package identity must include epoch, version, release, architecture, source
  RPM, repository, module stream, and signing metadata.
- `Requires`, `Recommends`, `Suggests`, `Provides`, `Conflicts`, and `Obsoletes`
  are distinct edge types.
- Weak dependencies are valuable for fleet planning even when not installed.
- CloudLinux, AlmaLinux, ELS, KernelCare, and live-patch channels should be graph
  dimensions, not string tags.
- Native library dependencies must represent ABI and SONAME relationships, not
  only package names.

Official references:

- [RPM dependency manual](https://rpm-software-management.github.io/rpm/manual/dependencies.html)
- [RPM rich dependencies](https://rpm-software-management.github.io/rpm/manual/boolean_dependencies.html)

## Python: pip And Poetry

Python dependencies use PEP 508 specifiers, environment markers, extras, and
project metadata. pip resolves distributions from indexes while Poetry also has
dependency groups, extras, explicit sources, and lockfile behavior.

GraphScope implications:

- Environment markers such as Python version, platform, implementation, and
  extras become activation predicates.
- Extras should activate optional dependency groups without pretending they are
  always runtime dependencies.
- Poetry groups distinguish main, development, test, and optional product
  features.
- Index/source priority affects candidate selection and supply-chain trust.
- Wheels include platform and ABI tags; source distributions create build-time
  dependencies that may differ from runtime dependencies.

Official references:

- [Python dependency specifiers](https://packaging.python.org/en/latest/specifications/dependency-specifiers/)
- [pip dependency resolution](https://pip.pypa.io/en/stable/topics/dependency-resolution/)
- [Poetry dependency specification](https://python-poetry.org/docs/dependency-specification/)

## Java: Maven And Gradle

Maven uses scopes, optional dependencies, exclusions, dependency management, and
nearest-definition conflict mediation. Gradle adds variant-aware resolution,
attributes, capabilities, platforms, constraints, and rich component metadata.

GraphScope implications:

- Maven scopes map to compile, runtime, provided, test, and system edges.
- Optional and excluded transitive dependencies need edge-local semantics.
- Dependency management can change effective versions without adding direct
  dependencies.
- Gradle variants must preserve attributes such as target JVM, usage, platform,
  and capability.
- Java artifact identity must include group, artifact, classifier, extension,
  version, repository, and checksums.

Official references:

- [Maven dependency mechanism](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html)
- [Gradle dependency management](https://docs.gradle.org/current/userguide/core_dependency_management.html)
- [Gradle variant-aware resolution](https://docs.gradle.org/current/userguide/variant_aware_resolution.html)

## JavaScript: npm

npm has dependencies, dev dependencies, peer dependencies, optional dependencies,
bundled dependencies, platform filters, package-lock files, and semver ranges.
The node module tree may contain multiple versions of the same package in
different subtrees.

GraphScope implications:

- The graph model must allow parallel versions of the same package.
- Peer dependencies are constraints on the consumer environment, not ordinary
  transitive dependencies.
- Optional dependencies such as platform packages should be represented as
  skipped or active based on OS and CPU.
- Lockfiles provide resolved evidence and integrity hashes.
- Bundled dependencies need a separate relation because provenance and update
  behavior differ from registry-resolved packages.

Official references:

- [npm package.json](https://docs.npmjs.com/cli/v11/configuring-npm/package-json)
- [npm semver](https://docs.npmjs.com/cli/v11/using-npm/semver)

## Go Modules

Go modules use module paths, semantic import versioning, pseudo-versions, replace
and exclude directives, build tags, GOOS/GOARCH, and Minimal Version Selection.

GraphScope implications:

- The Go resolver must not blindly select the newest compatible version.
- Build tags and GOOS/GOARCH activate different imports.
- `replace` and `exclude` directives are first-class resolver evidence.
- Module path major-version suffixes are part of identity.
- Vendored modules and module proxy checksums need provenance edges.

Official reference:

- [Go modules reference](https://go.dev/ref/mod)

## Rust: Cargo

Cargo uses package names, crates.io source identity, semver requirements,
features, optional dependencies, target-specific dependencies, build
dependencies, dev dependencies, patches, replaces, and lockfiles. Cargo can
resolve multiple semver-incompatible versions of the same crate.

GraphScope implications:

- Features are graph activation signals and can change transitive dependencies.
- Target-specific dependencies must use OS/architecture predicates.
- Build dependencies are important for supply-chain exposure even when not
  shipped at runtime.
- Lockfiles provide package checksums and resolved source URLs.
- Patches and alternate registries are supply-chain trust events.

Official references:

- [Cargo specifying dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
- [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html)

## Cross-Ecosystem Requirements

The first production release should include conformance fixtures for:

- RPM weak dependencies, file provides, module streams, and architecture filters;
- Python environment markers, extras, wheels, and Poetry groups;
- Maven scopes, optional dependencies, exclusions, and dependency management;
- Gradle variants and capabilities;
- npm peer dependencies, optional platform packages, and nested versions;
- Go Minimal Version Selection, replace, exclude, and build tags;
- Cargo features, target dependencies, and parallel crate versions.
