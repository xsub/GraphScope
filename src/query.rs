use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::hypergraph::{OccurrencePath, ResolvedGraphProjection};
use crate::model::{PackageId, PackageRef};
use crate::resolver::{ResolveResult, ResolvedEdge, ResolverTraceEvent};

const DEFAULT_MAX_PATHS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyPath {
    pub packages: Vec<PackageRef>,
    pub evidence: Vec<String>,
}

impl DependencyPath {
    pub fn display(&self) -> String {
        self.packages
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageExplanation {
    pub package: PackageRef,
    pub selected_by: BTreeSet<String>,
    pub paths: Vec<DependencyPath>,
    pub trace_events: Vec<ResolverTraceEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageVersionChange {
    pub package: PackageId,
    pub left_versions: Vec<PackageRef>,
    pub right_versions: Vec<PackageRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeKey {
    pub from: Option<PackageRef>,
    pub to: PackageRef,
    pub relation: String,
    pub scope: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphDiff {
    pub added_packages: Vec<PackageRef>,
    pub removed_packages: Vec<PackageRef>,
    pub changed_packages: Vec<PackageVersionChange>,
    pub added_edges: Vec<EdgeKey>,
    pub removed_edges: Vec<EdgeKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathSearchOptions {
    pub max_depth: usize,
    pub max_paths: usize,
}

impl PathSearchOptions {
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            max_paths: DEFAULT_MAX_PATHS,
        }
    }

    pub fn with_max_paths(mut self, max_paths: usize) -> Self {
        self.max_paths = max_paths;
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedGraphIndex {
    roots: Vec<PackageRef>,
    root_edges: BTreeMap<PackageRef, Vec<usize>>,
    forward_edges: BTreeMap<PackageRef, Vec<usize>>,
    reverse_edges: BTreeMap<PackageRef, Vec<usize>>,
    packages_by_id: BTreeMap<PackageId, Vec<PackageRef>>,
}

impl ResolvedGraphIndex {
    pub fn from_result(result: &ResolveResult) -> Self {
        let mut index = Self::default();

        for package in result.nodes.keys() {
            index
                .packages_by_id
                .entry(package.id.clone())
                .or_default()
                .push(package.clone());
        }

        for (edge_index, edge) in result.edges.iter().enumerate() {
            if let Some(from) = &edge.from {
                index
                    .forward_edges
                    .entry(from.clone())
                    .or_default()
                    .push(edge_index);
                index
                    .reverse_edges
                    .entry(edge.to.clone())
                    .or_default()
                    .push(edge_index);
            } else {
                index
                    .root_edges
                    .entry(edge.to.clone())
                    .or_default()
                    .push(edge_index);
            }
        }

        index.roots = index.root_edges.keys().cloned().collect();
        index.roots.sort();
        for packages in index.packages_by_id.values_mut() {
            packages.sort();
        }

        index
    }
}

pub struct GraphQuery<'a> {
    result: &'a ResolveResult,
    index: ResolvedGraphIndex,
}

impl<'a> GraphQuery<'a> {
    pub fn new(result: &'a ResolveResult) -> Self {
        Self {
            result,
            index: ResolvedGraphIndex::from_result(result),
        }
    }

    pub fn roots(&self) -> Vec<PackageRef> {
        self.index.roots.clone()
    }

    pub fn direct_dependencies(&self, package: &PackageRef) -> Vec<PackageRef> {
        let mut dependencies = self
            .edge_indexes_for(&self.index.forward_edges, package)
            .map(|edge| edge.to.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        dependencies.sort();
        dependencies
    }

    pub fn direct_dependency_edges(&self, package: &PackageRef) -> Vec<&ResolvedEdge> {
        self.edge_indexes_for(&self.index.forward_edges, package)
            .collect()
    }

    pub fn root_edges(&self, package: &PackageRef) -> Vec<&ResolvedEdge> {
        self.edge_indexes_for(&self.index.root_edges, package)
            .collect()
    }

    fn edge_indexes_for<'b>(
        &'b self,
        index: &'b BTreeMap<PackageRef, Vec<usize>>,
        package: &PackageRef,
    ) -> impl Iterator<Item = &'b ResolvedEdge> + 'b {
        index.get(package).into_iter().flat_map(|indexes| {
            indexes
                .iter()
                .map(|edge_index| &self.result.edges[*edge_index])
        })
    }

    fn packages_for_id(&self, package: &PackageId) -> impl Iterator<Item = &PackageRef> {
        self.index
            .packages_by_id
            .get(package)
            .into_iter()
            .flat_map(|packages| packages.iter())
    }

    fn root_evidence(&self, root: &PackageRef) -> Vec<String> {
        self.root_edges(root)
            .into_iter()
            .map(|edge| edge.requirement.evidence.clone())
            .collect()
    }

    fn incoming_edges(&self, package: &PackageRef) -> Vec<&ResolvedEdge> {
        self.edge_indexes_for(&self.index.reverse_edges, package)
            .collect()
    }

    fn outgoing_edges(&self, package: &PackageRef) -> Vec<&ResolvedEdge> {
        self.edge_indexes_for(&self.index.forward_edges, package)
            .collect()
    }

    pub fn selected_versions(&self, package: &PackageId) -> Vec<PackageRef> {
        self.packages_for_id(package).cloned().collect()
    }

    pub fn direct_dependents(&self, package: &PackageId) -> Vec<PackageRef> {
        let mut dependents = self
            .packages_for_id(package)
            .flat_map(|selected| self.incoming_edges(selected))
            .filter_map(|edge| edge.from.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        dependents.sort();
        dependents
    }

    pub fn dependency_closure(&self) -> Vec<PackageRef> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from(self.roots());

        while let Some(package) = queue.pop_front() {
            if visited.insert(package.clone()) {
                for dependency in self.direct_dependencies(&package) {
                    queue.push_back(dependency);
                }
            }
        }

        visited.into_iter().collect()
    }

    pub fn reverse_dependencies(&self, package: &PackageId) -> Vec<PackageRef> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from(self.direct_dependents(package));

        while let Some(dependent) = queue.pop_front() {
            if visited.insert(dependent.clone()) {
                for edge in self.incoming_edges(&dependent) {
                    if let Some(parent) = &edge.from {
                        queue.push_back(parent.clone());
                    }
                }
            }
        }

        visited.into_iter().collect()
    }

    pub fn paths_to(&self, package: &PackageId, max_depth: usize) -> Vec<DependencyPath> {
        self.paths_to_capped(package, PathSearchOptions::new(max_depth))
    }

    pub fn shortest_path_to(
        &self,
        package: &PackageId,
        max_depth: usize,
    ) -> Option<DependencyPath> {
        self.paths_to_capped(package, PathSearchOptions::new(max_depth).with_max_paths(1))
            .into_iter()
            .next()
    }

    pub fn paths_to_capped(
        &self,
        package: &PackageId,
        options: PathSearchOptions,
    ) -> Vec<DependencyPath> {
        if options.max_paths == 0 {
            return Vec::new();
        }

        let mut paths = Vec::new();
        let mut queue = self
            .roots()
            .into_iter()
            .map(|root| {
                let evidence = self.root_evidence(&root);
                (root.clone(), vec![root], evidence)
            })
            .collect::<VecDeque<_>>();

        while let Some((current, path, evidence)) = queue.pop_front() {
            if current.id == *package {
                paths.push(DependencyPath {
                    packages: path,
                    evidence,
                });
                if paths.len() >= options.max_paths {
                    break;
                }
                continue;
            }

            if path.len().saturating_sub(1) >= options.max_depth {
                continue;
            }

            for edge in self.outgoing_edges(&current) {
                if path.contains(&edge.to) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(edge.to.clone());
                let mut next_evidence = evidence.clone();
                next_evidence.push(edge.requirement.evidence.clone());
                queue.push_back((edge.to.clone(), next_path, next_evidence));
            }
        }

        paths.sort_by_key(DependencyPath::display);
        paths
    }

    pub fn explain_package(&self, package: &PackageId) -> Option<PackageExplanation> {
        let package_ref = self
            .result
            .nodes
            .keys()
            .find(|candidate| candidate.id == *package)
            .cloned()?;
        let selected_by = self
            .result
            .nodes
            .get(&package_ref)
            .map(|node| node.selected_by.clone())
            .unwrap_or_default();
        let trace_events = self
            .result
            .trace
            .iter()
            .filter(|event| {
                event.target == *package || event.selected.as_ref() == Some(&package_ref)
            })
            .cloned()
            .collect::<Vec<_>>();

        Some(PackageExplanation {
            package: package_ref,
            selected_by,
            paths: self.paths_to(package, 64),
            trace_events,
        })
    }

    pub fn skipped_reasons(&self, package: &PackageId) -> Vec<String> {
        self.result
            .skipped
            .iter()
            .filter(|skipped| skipped.target == *package)
            .map(|skipped| skipped.reason.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn occurrence_projection(&self, context_key: impl Into<String>) -> ResolvedGraphProjection {
        ResolvedGraphProjection::from_resolve_result(context_key, self.result)
    }

    pub fn occurrence_paths_to(
        &self,
        context_key: impl Into<String>,
        package: &PackageId,
        max_depth: usize,
    ) -> Vec<OccurrencePath> {
        self.occurrence_projection(context_key)
            .paths_to_package(package, max_depth)
    }
}

impl GraphDiff {
    pub fn between(left: &ResolveResult, right: &ResolveResult) -> Self {
        let left_packages = left.nodes.keys().cloned().collect::<BTreeSet<_>>();
        let right_packages = right.nodes.keys().cloned().collect::<BTreeSet<_>>();
        let added_packages = right_packages
            .difference(&left_packages)
            .cloned()
            .collect::<Vec<_>>();
        let removed_packages = left_packages
            .difference(&right_packages)
            .cloned()
            .collect::<Vec<_>>();
        let changed_packages = changed_packages(&left_packages, &right_packages);

        let left_edges = edge_keys(&left.edges);
        let right_edges = edge_keys(&right.edges);

        Self {
            added_packages,
            removed_packages,
            changed_packages,
            added_edges: right_edges.difference(&left_edges).cloned().collect(),
            removed_edges: left_edges.difference(&right_edges).cloned().collect(),
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.added_packages.is_empty()
            || !self.removed_packages.is_empty()
            || !self.changed_packages.is_empty()
            || !self.added_edges.is_empty()
            || !self.removed_edges.is_empty()
    }
}

fn edge_keys(edges: &[ResolvedEdge]) -> BTreeSet<EdgeKey> {
    edges
        .iter()
        .map(|edge| EdgeKey {
            from: edge.from.clone(),
            to: edge.to.clone(),
            relation: edge.requirement.relation.to_string(),
            scope: edge.requirement.scope.to_string(),
        })
        .collect()
}

fn changed_packages(
    left: &BTreeSet<PackageRef>,
    right: &BTreeSet<PackageRef>,
) -> Vec<PackageVersionChange> {
    let mut by_id = BTreeMap::<PackageId, (Vec<PackageRef>, Vec<PackageRef>)>::new();
    for package in left {
        by_id
            .entry(package.id.clone())
            .or_default()
            .0
            .push(package.clone());
    }
    for package in right {
        by_id
            .entry(package.id.clone())
            .or_default()
            .1
            .push(package.clone());
    }

    by_id
        .into_iter()
        .filter_map(|(package, (left_versions, right_versions))| {
            if left_versions.is_empty()
                || right_versions.is_empty()
                || left_versions == right_versions
            {
                None
            } else {
                Some(PackageVersionChange {
                    package,
                    left_versions,
                    right_versions,
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::model::{
        DependencyRequirement, DependencyScope, PackageId, PackageVersion, ResolutionContext,
        VersionRequirement,
    };
    use crate::repository::InMemoryRepository;
    use crate::resolver::Resolver;

    use super::*;

    #[test]
    fn query_finds_dependency_paths_and_reverse_dependents() {
        let app = PackageId::internal("app");
        let web = PackageId::python("web");
        let openssl = PackageId::rpm("openssl-libs");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(web.clone(), VersionRequirement::any())
                    .evidence("manifest:web"),
            ]),
        );
        repo.add(
            PackageVersion::new(web.clone(), "2.0").with_dependencies(vec![
                DependencyRequirement::new(openssl.clone(), VersionRequirement::any())
                    .scope(DependencyScope::Runtime)
                    .evidence("metadata:openssl"),
            ]),
        );
        repo.add(PackageVersion::new(openssl.clone(), "3.2.2"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let query = GraphQuery::new(&result);

        let paths = query.paths_to(&openssl, 8);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].display().contains("python:web@2.0"));
        assert!(
            query
                .reverse_dependencies(&openssl)
                .iter()
                .any(|package| package.id == web)
        );
    }

    #[test]
    fn query_caps_path_enumeration_and_returns_shortest_path() {
        let app = PackageId::internal("app");
        let left = PackageId::python("left");
        let right = PackageId::python("right");
        let shared = PackageId::python("shared");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(left, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::any())
                .evidence("left path"),
        ]));
        repo.add(PackageVersion::new(right, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::any())
                .evidence("right path"),
        ]));
        repo.add(PackageVersion::new(shared.clone(), "1.0"));
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let query = GraphQuery::new(&result);

        let capped = query.paths_to_capped(&shared, PathSearchOptions::new(8).with_max_paths(1));
        let shortest = query.shortest_path_to(&shared, 8).unwrap();

        assert_eq!(capped.len(), 1);
        assert_eq!(shortest.packages.len(), 3);
    }

    #[test]
    fn query_explains_selected_package_with_trace_events() {
        let app = PackageId::internal("app");
        let dep = PackageId::cargo("petgraph");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::parse("^0.6")),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "0.6.5"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let explanation = GraphQuery::new(&result).explain_package(&dep).unwrap();

        assert_eq!(explanation.package.id, dep);
        assert!(!explanation.paths.is_empty());
        assert!(!explanation.trace_events.is_empty());
    }

    #[test]
    fn query_returns_occurrence_paths_for_package() {
        let app = PackageId::internal("app");
        let dep = PackageId::npm(None::<String>, "left-pad");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any())
                    .evidence("package-lock.json:left-pad"),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "1.3.0"));

        let context = ResolutionContext::cloudlinux_production_x86_64();
        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &context,
        );
        let paths = GraphQuery::new(&result).occurrence_paths_to(context.stable_key(), &dep, 8);

        assert_eq!(paths.len(), 1);
        assert!(paths[0].occurrences.iter().all(|id| id.starts_with("occ:")));
        assert_eq!(paths[0].packages.last().unwrap().id, dep);
        assert!(
            paths[0]
                .evidence
                .iter()
                .any(|evidence| evidence.contains("package-lock.json:left-pad"))
        );
    }

    #[test]
    fn query_returns_skipped_reasons_for_inactive_dependency() {
        let app = PackageId::internal("app");
        let test_dep = PackageId::python("pytest");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(test_dep.clone(), VersionRequirement::any())
                    .scope(DependencyScope::Test),
            ]),
        );
        repo.add(PackageVersion::new(test_dep.clone(), "8.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let reasons = GraphQuery::new(&result).skipped_reasons(&test_dep);

        assert_eq!(reasons, vec!["scope test excluded by context".to_string()]);
    }

    #[test]
    fn diff_reports_added_removed_and_changed_packages() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("requests");
        let mut left_repo = InMemoryRepository::new();
        left_repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        left_repo.add(PackageVersion::new(dep.clone(), "2.31.0"));
        let mut right_repo = InMemoryRepository::new();
        right_repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        right_repo.add(PackageVersion::new(dep.clone(), "2.32.3"));

        let context = ResolutionContext::cloudlinux_production_x86_64();
        let left = Resolver::new(left_repo).resolve(
            vec![DependencyRequirement::new(
                app.clone(),
                VersionRequirement::any(),
            )],
            &context,
        );
        let right = Resolver::new(right_repo).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &context,
        );
        let diff = GraphDiff::between(&left, &right);

        assert!(diff.has_changes());
        assert_eq!(diff.changed_packages.len(), 1);
        assert_eq!(diff.changed_packages[0].package, dep);
    }
}
