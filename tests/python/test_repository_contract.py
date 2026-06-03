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
