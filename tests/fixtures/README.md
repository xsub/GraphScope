# Fixture Corpus

These fixtures are intentionally small conformance inputs for Phase 1 parser and
snapshot tests. They are not complete ecosystem fixtures yet; they establish the
stable contract future native adapters should emit.

- `pip/requirements.lock`: pinned Python requirements with extras and markers.
- `go/go.mod`: single-line and block Go module requirements.
- `cargo/Cargo.lock`: minimal Cargo lock package block with source and checksum.
- `npm/package-lock.json`: npm package-lock v3 packages, including a scoped package.
- `maven/pom.xml`: Maven dependency declarations with compile, runtime, and test scope.
- `gradle/build.gradle`: Gradle dependency configurations using string notation.
- `rpm/rpm-qa.txt`: RPM runtime inventory lines in query and NEVRA-like forms.
