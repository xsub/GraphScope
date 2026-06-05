use std::time::Instant;

use crate::{
    DependencyRequirement, GraphQuery, InMemoryRepository, PackageId, PackageVersion,
    PathSearchOptions, ResolutionContext, ResolvedGraphProjection, Resolver, VersionRequirement,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgorithmBenchmarkConfig {
    pub layers: usize,
    pub width: usize,
    pub fanout: usize,
    pub max_paths: usize,
}

impl Default for AlgorithmBenchmarkConfig {
    fn default() -> Self {
        Self {
            layers: 10,
            width: 32,
            fanout: 4,
            max_paths: 128,
        }
    }
}

impl AlgorithmBenchmarkConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.layers == 0 {
            return Err("layers must be greater than zero".to_string());
        }
        if self.width == 0 {
            return Err("width must be greater than zero".to_string());
        }
        if self.fanout == 0 {
            return Err("fanout must be greater than zero".to_string());
        }
        if self.fanout > self.width {
            return Err("fanout must be less than or equal to width".to_string());
        }
        if self.max_paths == 0 {
            return Err("max_paths must be greater than zero".to_string());
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmBenchmarkReport {
    pub config: AlgorithmBenchmarkConfig,
    pub package_versions: usize,
    pub roots: usize,
    pub resolved_nodes: usize,
    pub resolved_edges: usize,
    pub occurrence_nodes: usize,
    pub occurrence_edges: usize,
    pub dependency_closure_nodes: usize,
    pub occurrence_closure_nodes: usize,
    pub package_paths_found: usize,
    pub occurrence_paths_found: usize,
    pub build_repository_micros: u128,
    pub resolve_micros: u128,
    pub query_index_micros: u128,
    pub dependency_closure_micros: u128,
    pub projection_micros: u128,
    pub occurrence_closure_micros: u128,
    pub package_path_micros: u128,
    pub occurrence_path_micros: u128,
}

impl AlgorithmBenchmarkReport {
    pub fn total_micros(&self) -> u128 {
        self.build_repository_micros
            + self.resolve_micros
            + self.query_index_micros
            + self.dependency_closure_micros
            + self.projection_micros
            + self.occurrence_closure_micros
            + self.package_path_micros
            + self.occurrence_path_micros
    }

    pub fn to_text(&self) -> String {
        let config = self.config;
        [
            "GraphScope algorithm benchmark".to_string(),
            format!(
                "Workload: layers={} width={} fanout={} max_paths={}",
                config.layers, config.width, config.fanout, config.max_paths
            ),
            format!("Package versions: {}", self.package_versions),
            format!("Roots: {}", self.roots),
            format!("Resolved nodes: {}", self.resolved_nodes),
            format!("Resolved edges: {}", self.resolved_edges),
            format!("Occurrence nodes: {}", self.occurrence_nodes),
            format!("Occurrence edges: {}", self.occurrence_edges),
            format!(
                "Dependency closure nodes: {}",
                self.dependency_closure_nodes
            ),
            format!(
                "Occurrence closure nodes: {}",
                self.occurrence_closure_nodes
            ),
            format!("Package paths found: {}", self.package_paths_found),
            format!("Occurrence paths found: {}", self.occurrence_paths_found),
            "Timings microseconds:".to_string(),
            format!("  repository_build: {}", self.build_repository_micros),
            format!("  resolve_graph: {}", self.resolve_micros),
            format!("  query_index: {}", self.query_index_micros),
            format!("  dependency_closure: {}", self.dependency_closure_micros),
            format!("  occurrence_projection: {}", self.projection_micros),
            format!("  occurrence_closure: {}", self.occurrence_closure_micros),
            format!("  package_paths: {}", self.package_path_micros),
            format!("  occurrence_paths: {}", self.occurrence_path_micros),
            format!("  total: {}", self.total_micros()),
        ]
        .join("\n")
    }
}

pub fn run_algorithm_benchmark(
    config: AlgorithmBenchmarkConfig,
) -> Result<AlgorithmBenchmarkReport, String> {
    let config = config.validate()?;
    let started = Instant::now();
    let workload = SyntheticWorkload::build(config);
    let build_repository_micros = started.elapsed().as_micros();
    let package_versions = workload.repository.package_count();
    let roots = workload.roots.len();

    let started = Instant::now();
    let result = Resolver::new(workload.repository).resolve(workload.roots, &workload.context);
    let resolve_micros = started.elapsed().as_micros();

    let started = Instant::now();
    let query = GraphQuery::new(&result);
    let query_index_micros = started.elapsed().as_micros();

    let started = Instant::now();
    let dependency_closure_nodes = query.dependency_closure().len();
    let dependency_closure_micros = started.elapsed().as_micros();

    let started = Instant::now();
    let projection =
        ResolvedGraphProjection::from_resolve_result(workload.context.stable_key(), &result);
    let projection_micros = started.elapsed().as_micros();

    let root_occurrence = projection.roots().into_iter().next();
    let started = Instant::now();
    let occurrence_closure_nodes = root_occurrence
        .as_ref()
        .map(|root| projection.dependency_closure_from(root).len())
        .unwrap_or_default();
    let occurrence_closure_micros = started.elapsed().as_micros();

    let path_options = PathSearchOptions::new(config.layers + 1).with_max_paths(config.max_paths);
    let started = Instant::now();
    let package_paths_found = query
        .paths_to_capped(&workload.target_package, path_options)
        .len();
    let package_path_micros = started.elapsed().as_micros();

    let started = Instant::now();
    let occurrence_paths_found = projection
        .paths_to_package_capped(
            &workload.target_package,
            config.layers + 1,
            config.max_paths,
        )
        .len();
    let occurrence_path_micros = started.elapsed().as_micros();

    Ok(AlgorithmBenchmarkReport {
        config,
        package_versions,
        roots,
        resolved_nodes: result.nodes.len(),
        resolved_edges: result.edges.len(),
        occurrence_nodes: projection.occurrences.len(),
        occurrence_edges: projection.edges.len(),
        dependency_closure_nodes,
        occurrence_closure_nodes,
        package_paths_found,
        occurrence_paths_found,
        build_repository_micros,
        resolve_micros,
        query_index_micros,
        dependency_closure_micros,
        projection_micros,
        occurrence_closure_micros,
        package_path_micros,
        occurrence_path_micros,
    })
}

#[derive(Clone, Debug)]
struct SyntheticWorkload {
    repository: InMemoryRepository,
    roots: Vec<DependencyRequirement>,
    context: ResolutionContext,
    target_package: PackageId,
}

impl SyntheticWorkload {
    fn build(config: AlgorithmBenchmarkConfig) -> Self {
        let root = PackageId::internal("benchmark-root");
        let target_package = package_id(config.layers - 1, 0);
        let mut repository = InMemoryRepository::new();

        repository.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(
                (0..config.width)
                    .map(|index| {
                        DependencyRequirement::new(package_id(0, index), VersionRequirement::any())
                            .evidence(format!("benchmark root edge {index}"))
                    })
                    .collect(),
            ),
        );

        for layer in 0..config.layers {
            for index in 0..config.width {
                let mut package = PackageVersion::new(package_id(layer, index), "1.0");
                if layer + 1 < config.layers {
                    package = package.with_dependencies(
                        (0..config.fanout)
                            .map(|offset| {
                                let target_index = (index + offset) % config.width;
                                DependencyRequirement::new(
                                    package_id(layer + 1, target_index),
                                    VersionRequirement::any(),
                                )
                                .evidence(format!(
                                    "benchmark layer {layer} node {index} fanout {offset}"
                                ))
                            })
                            .collect(),
                    );
                }
                repository.add(package);
            }
        }

        Self {
            repository,
            roots: vec![
                DependencyRequirement::new(root, VersionRequirement::any())
                    .evidence("benchmark synthetic root"),
            ],
            context: ResolutionContext::cloudlinux_production_x86_64(),
            target_package,
        }
    }
}

fn package_id(layer: usize, index: usize) -> PackageId {
    PackageId::internal(format!("benchmark-l{layer}-n{index}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_config_rejects_invalid_shapes() {
        let invalid = AlgorithmBenchmarkConfig {
            layers: 1,
            width: 2,
            fanout: 3,
            max_paths: 8,
        };

        assert!(invalid.validate().is_err());
    }

    #[test]
    fn algorithm_benchmark_reports_deterministic_graph_shape() {
        let config = AlgorithmBenchmarkConfig {
            layers: 4,
            width: 8,
            fanout: 3,
            max_paths: 16,
        };
        let report = run_algorithm_benchmark(config).unwrap();

        assert_eq!(report.package_versions, 33);
        assert_eq!(report.roots, 1);
        assert_eq!(report.resolved_nodes, 33);
        assert_eq!(report.resolved_edges, 81);
        assert_eq!(report.occurrence_nodes, 33);
        assert_eq!(report.occurrence_edges, 81);
        assert_eq!(report.dependency_closure_nodes, 33);
        assert_eq!(report.occurrence_closure_nodes, 33);
        assert!(report.package_paths_found > 0);
        assert!(report.package_paths_found <= config.max_paths);
    }

    #[test]
    fn benchmark_text_contains_algorithm_metrics() {
        let report = run_algorithm_benchmark(AlgorithmBenchmarkConfig {
            layers: 2,
            width: 4,
            fanout: 2,
            max_paths: 8,
        })
        .unwrap();
        let text = report.to_text();

        assert!(text.contains("GraphScope algorithm benchmark"));
        assert!(text.contains("Resolved nodes:"));
        assert!(text.contains("Timings microseconds:"));
    }
}
