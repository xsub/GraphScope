use crate::evidence::stable_hash;
use crate::hypergraph::ResolvedGraphProjection;
use crate::json::{JsonValue as Json, json_string, object_members};
use crate::model::{ResolutionContext, Version};
use crate::resolver::ResolveResult;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphSnapshot {
    pub id: String,
    pub name: String,
    pub resolver_version: String,
    pub context_hash: String,
    json_body: String,
}

impl GraphSnapshot {
    pub fn from_resolve_result(
        name: impl Into<String>,
        resolver_version: impl Into<String>,
        context: &ResolutionContext,
        result: &ResolveResult,
    ) -> Self {
        let name = name.into();
        let resolver_version = resolver_version.into();
        let context_json = context_json(context);
        let context_hash = format!("ctx-{:016x}", stable_hash(&context_json));
        let context_key = context.stable_key();
        let json_body = snapshot_body_json(
            &name,
            &resolver_version,
            &context_hash,
            &context_key,
            &context_json,
            result,
        );
        let id = format!("snap-{:016x}", stable_hash(&json_body));

        Self {
            id,
            name,
            resolver_version,
            context_hash,
            json_body,
        }
    }

    pub fn to_json_pretty(&self) -> String {
        format!(
            "{{\n  \"snapshot_id\": {},\n{}\n}}",
            json_string(&self.id),
            indent_body(&self.json_body)
        )
    }
}

fn snapshot_body_json(
    name: &str,
    resolver_version: &str,
    context_hash: &str,
    context_key: &str,
    context_json: &str,
    result: &ResolveResult,
) -> String {
    let mut nodes = result.nodes.values().collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.package.cmp(&right.package));

    let mut edges = result.edges.iter().collect::<Vec<_>>();
    edges.sort_by(|left, right| {
        (
            left.from.as_ref().map(ToString::to_string),
            left.to.to_string(),
            left.requirement.target.to_string(),
            left.requirement.evidence.clone(),
        )
            .cmp(&(
                right.from.as_ref().map(ToString::to_string),
                right.to.to_string(),
                right.requirement.target.to_string(),
                right.requirement.evidence.clone(),
            ))
    });

    let mut skipped = result.skipped.iter().collect::<Vec<_>>();
    skipped.sort_by(|left, right| {
        (
            left.requester.as_ref().map(ToString::to_string),
            left.target.to_string(),
            left.reason.clone(),
        )
            .cmp(&(
                right.requester.as_ref().map(ToString::to_string),
                right.target.to_string(),
                right.reason.clone(),
            ))
    });

    let mut conflicts = result.conflicts.iter().collect::<Vec<_>>();
    conflicts.sort_by(|left, right| {
        (
            left.package.to_string(),
            left.selection_slot.clone(),
            left.reason.clone(),
        )
            .cmp(&(
                right.package.to_string(),
                right.selection_slot.clone(),
                right.reason.clone(),
            ))
    });

    let projection = ResolvedGraphProjection::from_resolve_result(context_key, result);
    let mut occurrences = projection.occurrences.values().collect::<Vec<_>>();
    occurrences.sort_by(|left, right| left.id.cmp(&right.id));

    let mut occurrence_edges = projection.edges.iter().collect::<Vec<_>>();
    occurrence_edges.sort_by(|left, right| {
        (&left.from, &left.to, &left.clause_id, &left.evidence).cmp(&(
            &right.from,
            &right.to,
            &right.clause_id,
            &right.evidence,
        ))
    });

    object_members([
        ("name", Json::string(name)),
        ("resolver_version", Json::string(resolver_version)),
        ("context_hash", Json::string(context_hash)),
        ("context", Json::raw(context_json)),
        (
            "nodes",
            Json::array(nodes.iter().map(|node| {
                Json::object([
                    ("package", Json::string(node.package.to_string())),
                    ("depth", Json::number(node.depth)),
                    (
                        "selected_by",
                        Json::string_array(node.selected_by.iter().map(String::as_str)),
                    ),
                    (
                        "selection_slots",
                        Json::string_array(node.selection_slots.iter().map(String::as_str)),
                    ),
                ])
            })),
        ),
        (
            "edges",
            Json::array(edges.iter().map(|edge| {
                Json::object([
                    (
                        "from",
                        Json::optional_string(
                            edge.from.as_ref().map(ToString::to_string).as_deref(),
                        ),
                    ),
                    (
                        "from_slot",
                        Json::optional_string(edge.from_slot.as_deref()),
                    ),
                    ("to", Json::string(edge.to.to_string())),
                    ("to_slot", Json::string(edge.to_slot.clone())),
                    (
                        "relation",
                        Json::string(edge.requirement.relation.to_string()),
                    ),
                    ("scope", Json::string(edge.requirement.scope.to_string())),
                    (
                        "requirement",
                        Json::string(edge.requirement.requirement.to_string()),
                    ),
                    ("evidence", Json::string(edge.requirement.evidence.clone())),
                ])
            })),
        ),
        (
            "occurrences",
            Json::array(occurrences.iter().map(|occurrence| {
                Json::object([
                    ("id", Json::string(occurrence.id.clone())),
                    ("package", Json::string(occurrence.package.to_string())),
                    ("slot", Json::string(occurrence.slot.clone())),
                    ("context_key", Json::string(occurrence.context_key.clone())),
                    (
                        "artifact",
                        Json::optional_string(occurrence.artifact.as_deref()),
                    ),
                    (
                        "selected_by",
                        Json::string_array(occurrence.selected_by.iter().map(String::as_str)),
                    ),
                ])
            })),
        ),
        (
            "occurrence_edges",
            Json::array(occurrence_edges.iter().map(|edge| {
                Json::object([
                    ("from", Json::optional_string(edge.from.as_deref())),
                    ("to", Json::string(edge.to.clone())),
                    ("clause_id", Json::string(edge.clause_id.clone())),
                    ("relation", Json::string(edge.relation.to_string())),
                    ("scope", Json::string(edge.scope.to_string())),
                    ("evidence", Json::string(edge.evidence.clone())),
                ])
            })),
        ),
        (
            "skipped",
            Json::array(skipped.iter().map(|skipped| {
                Json::object([
                    (
                        "requester",
                        Json::optional_string(
                            skipped
                                .requester
                                .as_ref()
                                .map(ToString::to_string)
                                .as_deref(),
                        ),
                    ),
                    ("target", Json::string(skipped.target.to_string())),
                    ("reason", Json::string(skipped.reason.clone())),
                    (
                        "evidence",
                        Json::string(skipped.requirement.evidence.clone()),
                    ),
                ])
            })),
        ),
        (
            "conflicts",
            Json::array(conflicts.iter().map(|conflict| {
                Json::object([
                    ("package", Json::string(conflict.package.to_string())),
                    (
                        "selection_slot",
                        Json::string(conflict.selection_slot.clone()),
                    ),
                    ("reason", Json::string(conflict.reason.clone())),
                    (
                        "constraints",
                        Json::string_array(conflict.constraints.iter().map(String::as_str)),
                    ),
                ])
            })),
        ),
        (
            "trace",
            Json::array(result.trace.iter().map(|event| {
                Json::object([
                    ("id", Json::string(event.id.clone())),
                    (
                        "parent_id",
                        Json::optional_string(event.parent_id.as_deref()),
                    ),
                    (
                        "requester",
                        Json::optional_string(
                            event.requester.as_ref().map(ToString::to_string).as_deref(),
                        ),
                    ),
                    ("target", Json::string(event.target.to_string())),
                    (
                        "selection_slot",
                        Json::optional_string(event.selection_slot.as_deref()),
                    ),
                    (
                        "requirement",
                        Json::string(event.requirement.requirement.to_string()),
                    ),
                    ("outcome", Json::string(event.outcome.to_string())),
                    ("rule", Json::string(event.rule.clone())),
                    ("reason", Json::string(event.reason.clone())),
                    ("evidence", Json::string(event.evidence.clone())),
                    (
                        "active_constraints",
                        Json::string_array(event.active_constraints.iter().map(String::as_str)),
                    ),
                    (
                        "candidates_considered",
                        Json::string_array(
                            event.candidates_considered.iter().map(ToString::to_string),
                        ),
                    ),
                    (
                        "candidates_rejected",
                        Json::string_array(
                            event.candidates_rejected.iter().map(ToString::to_string),
                        ),
                    ),
                    (
                        "selected",
                        Json::optional_string(
                            event.selected.as_ref().map(ToString::to_string).as_deref(),
                        ),
                    ),
                ])
            })),
        ),
    ])
}

fn context_json(context: &ResolutionContext) -> String {
    let language_versions = context
        .language_versions
        .iter()
        .map(|(ecosystem, version)| (ecosystem.to_string(), version.clone()))
        .collect::<Vec<(String, Version)>>();

    Json::object([
        ("os", Json::string(format!("{:?}", context.os))),
        ("distro", Json::string(format!("{:?}", context.distro))),
        ("arch", Json::string(format!("{:?}", context.arch))),
        (
            "distro_major_version",
            context
                .distro_major_version
                .map(Json::number)
                .unwrap_or_else(Json::null),
        ),
        (
            "profiles",
            Json::string_array(context.profiles.iter().map(|value| format!("{value:?}"))),
        ),
        (
            "enabled_features",
            Json::string_array(context.enabled_features.iter().map(String::as_str)),
        ),
        (
            "include_scopes",
            Json::string_array(context.include_scopes.iter().map(ToString::to_string)),
        ),
        ("include_optional", Json::bool(context.include_optional)),
        (
            "language_versions",
            Json::array(language_versions.iter().map(|(ecosystem, version)| {
                Json::object([
                    ("ecosystem", Json::string(ecosystem.clone())),
                    ("version", Json::string(version.to_string())),
                ])
            })),
        ),
        (
            "repository_channels",
            Json::string_array(context.repository_channels.iter().map(String::as_str)),
        ),
    ])
    .to_json()
}

fn indent_body(body: &str) -> String {
    format!("  {body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DependencyRequirement, PackageId, PackageVersion, ResolutionContext, VersionRequirement,
    };
    use crate::repository::InMemoryRepository;
    use crate::resolver::Resolver;

    #[test]
    fn snapshot_id_is_stable_for_same_graph() {
        let root = PackageId::internal("app");
        let dep = PackageId::python("requests");
        let mut repository = InMemoryRepository::new();
        repository.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::parse("^2.31.0")),
            ]),
        );
        repository.add(PackageVersion::new(dep, "2.32.3"));
        let context = ResolutionContext::cloudlinux_production_x86_64();

        let result = Resolver::new(repository).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &context,
        );
        let left = GraphSnapshot::from_resolve_result("demo", "test", &context, &result);
        let right = GraphSnapshot::from_resolve_result("demo", "test", &context, &result);

        assert_eq!(left.id, right.id);
        assert_eq!(left.to_json_pretty(), right.to_json_pretty());
    }

    #[test]
    fn snapshot_json_contains_nodes_edges_skipped_and_conflicts() {
        let root = PackageId::internal("app");
        let missing = PackageId::python("missing");
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let result = Resolver::new(InMemoryRepository::new()).resolve(
            vec![DependencyRequirement::new(
                missing,
                VersionRequirement::any(),
            )],
            &context,
        );
        let snapshot = GraphSnapshot::from_resolve_result("conflict", "test", &context, &result);
        let json = snapshot.to_json_pretty();

        assert!(json.contains("\"snapshot_id\""));
        assert!(json.contains("\"nodes\""));
        assert!(json.contains("\"edges\""));
        assert!(json.contains("\"skipped\""));
        assert!(json.contains("\"conflicts\""));
        assert!(json.contains("\"trace\""));
        assert!(json.contains("python:missing"));
        assert!(json.contains("\"outcome\":\"conflict\""));
        assert!(!json.contains(&root.to_string()));
    }

    #[test]
    fn snapshot_json_contains_trace_decision_details() {
        let root = PackageId::internal("app");
        let dep = PackageId::python("requests");
        let mut repository = InMemoryRepository::new();
        repository.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::parse("^2.31.0"))
                    .evidence("pyproject.toml:requests"),
            ]),
        );
        repository.add(PackageVersion::new(dep, "2.32.3"));
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let result = Resolver::new(repository).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &context,
        );

        let json =
            GraphSnapshot::from_resolve_result("trace", "test", &context, &result).to_json_pretty();

        assert!(json.contains("\"parent_id\""));
        assert!(json.contains("\"active_constraints\""));
        assert!(json.contains("\"candidates_considered\""));
        assert!(json.contains("\"candidates_rejected\""));
        assert!(json.contains("pyproject.toml:requests"));
    }

    #[test]
    fn snapshot_json_contains_occurrence_projection() {
        let root = PackageId::internal("app");
        let dep = PackageId::python("requests");
        let mut repository = InMemoryRepository::new();
        repository.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::parse("^2.31.0"))
                    .evidence("pyproject.toml:requests"),
            ]),
        );
        repository.add(PackageVersion::new(dep, "2.32.3"));
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let result = Resolver::new(repository).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &context,
        );

        let json = GraphSnapshot::from_resolve_result("occurrences", "test", &context, &result)
            .to_json_pretty();

        assert!(json.contains("\"occurrences\""));
        assert!(json.contains("\"occurrence_edges\""));
        assert!(json.contains("\"id\":\"occ:"));
        assert!(json.contains("\"clause_id\":\"resolved-clause:"));
        assert!(json.contains("pyproject.toml:requests"));
    }

    #[test]
    fn snapshot_json_escapes_evidence_strings() {
        let root = PackageId::internal("app");
        let dep = PackageId::python("requests");
        let mut repository = InMemoryRepository::new();
        repository.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any())
                    .evidence("file \"quoted\"\nline"),
            ]),
        );
        repository.add(PackageVersion::new(dep, "2.32.3"));
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let result = Resolver::new(repository).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &context,
        );

        let json = GraphSnapshot::from_resolve_result("escape", "test", &context, &result)
            .to_json_pretty();

        assert!(json.contains("file \\\"quoted\\\"\\nline"));
    }

    #[test]
    fn snapshot_json_keeps_commas_inside_string_values() {
        let root = PackageId::internal("app");
        let dep = PackageId::go("golang.org/x/net");
        let mut repository = InMemoryRepository::new();
        repository.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(
                    dep.clone(),
                    VersionRequirement::parse(">=0.24.0,<1.0.0"),
                ),
            ]),
        );
        repository.add(PackageVersion::new(dep, "0.24.0"));
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let result = Resolver::new(repository).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &context,
        );

        let json =
            GraphSnapshot::from_resolve_result("comma", "test", &context, &result).to_json_pretty();

        assert!(json.contains("\"requirement\":\">=0.24.0,<1.0.0\""));
        assert!(!json.contains(">=0.24.0,\n"));
    }
}
