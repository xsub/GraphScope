use crate::evidence::stable_hash;
use crate::hypergraph::ResolvedGraphProjection;
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
            "{{\n  \"snapshot_id\": \"{}\",\n{}\n}}",
            escape_json(&self.id),
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

    let node_json = nodes
        .iter()
        .map(|node| {
            format!(
                "{{\"package\":\"{}\",\"depth\":{},\"selected_by\":[{}]}}",
                escape_json(&node.package.to_string()),
                node.depth,
                json_string_array(node.selected_by.iter().map(String::as_str))
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let occurrence_json = occurrences
        .iter()
        .map(|occurrence| {
            format!(
                "{{\"id\":\"{}\",\"package\":\"{}\",\"slot\":\"{}\",\"context_key\":\"{}\",\"artifact\":{},\"selected_by\":[{}]}}",
                escape_json(&occurrence.id),
                escape_json(&occurrence.package.to_string()),
                escape_json(&occurrence.slot),
                escape_json(&occurrence.context_key),
                optional_json_string(occurrence.artifact.as_deref()),
                json_string_array(occurrence.selected_by.iter().map(String::as_str))
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let occurrence_edge_json = occurrence_edges
        .iter()
        .map(|edge| {
            format!(
                "{{\"from\":{},\"to\":\"{}\",\"clause_id\":\"{}\",\"relation\":\"{}\",\"scope\":\"{}\",\"evidence\":\"{}\"}}",
                optional_json_string(edge.from.as_deref()),
                escape_json(&edge.to),
                escape_json(&edge.clause_id),
                edge.relation,
                edge.scope,
                escape_json(&edge.evidence)
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let edge_json = edges
        .iter()
        .map(|edge| {
            format!(
                "{{\"from\":{},\"to\":\"{}\",\"relation\":\"{}\",\"scope\":\"{}\",\"requirement\":\"{}\",\"evidence\":\"{}\"}}",
                edge.from
                    .as_ref()
                    .map(|from| format!("\"{}\"", escape_json(&from.to_string())))
                    .unwrap_or_else(|| "null".to_string()),
                escape_json(&edge.to.to_string()),
                edge.requirement.relation,
                edge.requirement.scope,
                escape_json(&edge.requirement.requirement.to_string()),
                escape_json(&edge.requirement.evidence)
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let skipped_json = skipped
        .iter()
        .map(|skipped| {
            format!(
                "{{\"requester\":{},\"target\":\"{}\",\"reason\":\"{}\",\"evidence\":\"{}\"}}",
                skipped
                    .requester
                    .as_ref()
                    .map(|requester| format!("\"{}\"", escape_json(&requester.to_string())))
                    .unwrap_or_else(|| "null".to_string()),
                escape_json(&skipped.target.to_string()),
                escape_json(&skipped.reason),
                escape_json(&skipped.requirement.evidence)
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let conflict_json = conflicts
        .iter()
        .map(|conflict| {
            format!(
                "{{\"package\":\"{}\",\"selection_slot\":\"{}\",\"reason\":\"{}\",\"constraints\":[{}]}}",
                escape_json(&conflict.package.to_string()),
                escape_json(&conflict.selection_slot),
                escape_json(&conflict.reason),
                json_string_array(conflict.constraints.iter().map(String::as_str))
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let trace_json = result
        .trace
        .iter()
        .map(|event| {
            format!(
                "{{\"id\":\"{}\",\"parent_id\":{},\"requester\":{},\"target\":\"{}\",\"selection_slot\":{},\"requirement\":\"{}\",\"outcome\":\"{}\",\"rule\":\"{}\",\"reason\":\"{}\",\"evidence\":\"{}\",\"active_constraints\":[{}],\"candidates_considered\":[{}],\"candidates_rejected\":[{}],\"selected\":{}}}",
                escape_json(&event.id),
                optional_json_string(event.parent_id.as_deref()),
                event
                    .requester
                    .as_ref()
                    .map(|requester| format!("\"{}\"", escape_json(&requester.to_string())))
                    .unwrap_or_else(|| "null".to_string()),
                escape_json(&event.target.to_string()),
                optional_json_string(event.selection_slot.as_deref()),
                escape_json(&event.requirement.requirement.to_string()),
                event.outcome,
                escape_json(&event.rule),
                escape_json(&event.reason),
                escape_json(&event.evidence),
                json_string_array(event.active_constraints.iter().map(String::as_str)),
                json_string_array(event.candidates_considered.iter().map(ToString::to_string)),
                json_string_array(event.candidates_rejected.iter().map(ToString::to_string)),
                event
                    .selected
                    .as_ref()
                    .map(|selected| format!("\"{}\"", escape_json(&selected.to_string())))
                    .unwrap_or_else(|| "null".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "\"name\":\"{}\",\"resolver_version\":\"{}\",\"context_hash\":\"{}\",\"context\":{},\"nodes\":[{}],\"edges\":[{}],\"occurrences\":[{}],\"occurrence_edges\":[{}],\"skipped\":[{}],\"conflicts\":[{}],\"trace\":[{}]",
        escape_json(name),
        escape_json(resolver_version),
        escape_json(context_hash),
        context_json,
        node_json,
        edge_json,
        occurrence_json,
        occurrence_edge_json,
        skipped_json,
        conflict_json,
        trace_json
    )
}

fn context_json(context: &ResolutionContext) -> String {
    let language_versions = context
        .language_versions
        .iter()
        .map(|(ecosystem, version)| (ecosystem.to_string(), version.clone()))
        .collect::<Vec<(String, Version)>>();

    format!(
        "{{\"os\":\"{:?}\",\"distro\":\"{:?}\",\"arch\":\"{:?}\",\"distro_major_version\":{},\"profiles\":[{}],\"enabled_features\":[{}],\"include_scopes\":[{}],\"include_optional\":{},\"language_versions\":[{}],\"repository_channels\":[{}]}}",
        context.os,
        context.distro,
        context.arch,
        context
            .distro_major_version
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_string()),
        json_string_array(context.profiles.iter().map(|value| format!("{value:?}"))),
        json_string_array(context.enabled_features.iter().map(String::as_str)),
        json_string_array(context.include_scopes.iter().map(ToString::to_string)),
        context.include_optional,
        language_versions
            .iter()
            .map(|(ecosystem, version)| format!(
                "{{\"ecosystem\":\"{}\",\"version\":\"{}\"}}",
                escape_json(ecosystem),
                escape_json(&version.to_string())
            ))
            .collect::<Vec<_>>()
            .join(","),
        json_string_array(context.repository_channels.iter().map(String::as_str))
    )
}

fn json_string_array<'a>(values: impl IntoIterator<Item = impl AsRef<str> + 'a>) -> String {
    values
        .into_iter()
        .map(|value| format!("\"{}\"", escape_json(value.as_ref())))
        .collect::<Vec<_>>()
        .join(",")
}

fn optional_json_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn indent_body(body: &str) -> String {
    format!("  {body}")
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
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
