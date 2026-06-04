from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]


def read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_cargo_features_expose_adapter_surfaces() -> None:
    cargo = tomllib.loads(read_text("Cargo.toml"))
    features = cargo["features"]

    for feature in [
        "rpm",
        "sqlite",
        "rocksdb",
        "python",
        "java",
        "javascript",
        "go",
        "cargo-adapter",
    ]:
        assert feature in features
        assert feature in features["all-adapters"]


def test_github_workflows_exist_for_readme_badges() -> None:
    for workflow in [
        "rust-ci.yml",
        "almalinux-10.yml",
        "storage-readiness.yml",
        "pytest.yml",
        "docs.yml",
        "supply-chain.yml",
    ]:
        assert (ROOT / ".github" / "workflows" / workflow).is_file()


def test_readme_badges_reference_ci_workflows_and_platforms() -> None:
    readme = read_text("README.md")

    for token in [
        "rust-ci.yml/badge.svg",
        "almalinux-10.yml/badge.svg",
        "storage-readiness.yml/badge.svg",
        "pytest.yml/badge.svg",
        "docs.yml/badge.svg",
        "supply-chain.yml/badge.svg",
        "AlmaLinux-10",
        "CloudLinux-OS",
        "SQLite-adapter",
        "RocksDB-adapter",
        "pytest-CI",
    ]:
        assert token in readme


def test_test_inventory_lists_rust_and_pytest_contract_tests() -> None:
    inventory = read_text("docs/test-inventory.md")
    lines = [line for line in inventory.splitlines() if line.startswith("- `")]

    assert len(lines) >= 76
    assert len(lines) == len(set(lines))
    assert "test_cargo_features_expose_adapter_surfaces" in inventory
    assert "cli_demo_outputs_dependency_graph_sections" in inventory


def test_demo_artifacts_are_checked_in_and_linked() -> None:
    readme = read_text("README.md")
    artifact_root = ROOT / "examples" / "demo-artifacts"

    assert "examples/demo-artifacts" in readme
    for path in [
        "README.md",
        "demo.txt",
        "snapshot.json",
        "impact.txt",
        "remediation-report.md",
        "sbom.cyclonedx.json",
        "sbom.spdx.json",
        "vex.json",
        "policy.txt",
        "sla.json",
        "dashboard.json",
        "invalidation.txt",
        "adapters.txt",
        "access.txt",
        "diff.txt",
        "cyclonedx-evidence.txt",
        "persist.txt",
        "events.txt",
        "durable-store/index.tsv",
        "durable-store/events.tsv",
    ]:
        assert (artifact_root / path).is_file(), path

    assert any((artifact_root / "durable-store" / "snapshots").glob("*.json"))


def test_real_world_almalinux_inventory_is_checked_in_and_linked() -> None:
    readme = read_text("README.md")
    artifact_root = ROOT / "examples" / "real-world"

    assert "examples/real-world" in readme
    for path in [
        "README.md",
        "os-release.txt",
        "dnf-repolist.txt",
        "almalinux-10-rpm.list",
        "almalinux-10-rpm-evidence.txt",
    ]:
        assert (artifact_root / path).is_file(), path

    inventory = read_text("examples/real-world/almalinux-10-rpm.list")
    evidence = read_text("examples/real-world/almalinux-10-rpm-evidence.txt")
    os_release = read_text("examples/real-world/os-release.txt")

    assert 'PRETTY_NAME="AlmaLinux 10.2 (Lavender Lion)"' in os_release
    assert len(inventory.splitlines()) >= 100
    assert "Records: 666" in evidence
    assert "- rpm: 666" in evidence
    assert "- Observed: 666" in evidence


def test_resolution_algorithm_documents_usability_contract() -> None:
    algorithm = read_text("docs/resolution-algorithm.md")

    for token in [
        "Resolution Usability Contract",
        "Implemented Resolver Control Flow",
        "Usability Guarantees",
        "Implemented Decision Trace",
        "ResolveResult.trace",
        "ResolverTraceEvent",
        "GraphSnapshot::from_resolve_result",
        "Why is this package present?",
        "Every skipped edge is still visible.",
        "Every ecosystem can stay native.",
    ]:
        assert token in algorithm


def test_resolution_algorithm_avoids_placeholder_control_flow() -> None:
    algorithm = read_text("docs/resolution-algorithm.md")
    old_loop_sentence = "The " + "pro" + "totype uses" + " this generic loop"

    for token in [
        "`" * 3,
        "work" + " =",
        "bounded" + "_trace",
        "while " + "work",
        "adapter" + "_for(",
        old_loop_sentence,
    ]:
        assert token not in algorithm


def test_hypergraph_model_documents_source_of_truth_and_projection() -> None:
    readme = read_text("README.md")
    architecture = read_text("docs/architecture.md")
    model = read_text("docs/hypergraph-model.md")
    roadmap = read_text("docs/roadmap.md")

    assert "docs/hypergraph-model.md" in readme
    for token in [
        "typed context-conditioned hypergraph",
        "resolved occurrence",
        "Do not use a graph database as the source of truth",
        "Resolve first, traverse projections",
        "CSR",
        "CSC",
        "FASTEN",
        "RequirementClause",
        "ResolvedGraphProjection",
    ]:
        assert token in model

    assert "Hypergraph Source Of Truth And Projections" in architecture
    assert "resolved occurrence graph projection" in roadmap
