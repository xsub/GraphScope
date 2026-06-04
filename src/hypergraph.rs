use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::model::{
    ContextPredicate, DependencyRelation, DependencyRequirement, DependencyScope, PackageId,
    PackageRef, ResolutionContext, VersionRequirement,
};
use crate::resolver::ResolveResult;

pub type ClauseId = String;
pub type OccurrenceId = String;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClauseSource {
    Root,
    Package(PackageRef),
    Project(String),
}

impl fmt::Display for ClauseSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseSource::Root => write!(f, "root"),
            ClauseSource::Package(package) => write!(f, "{package}"),
            ClauseSource::Project(project) => write!(f, "project:{project}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClauseSemantics {
    RequiresOne,
    RequiresAll,
    ConflictsWith,
    Provides,
    Replaces,
    Bundles,
    Links,
    LoadsDynamically,
}

impl ClauseSemantics {
    pub fn from_relation(relation: &DependencyRelation) -> Self {
        match relation {
            DependencyRelation::Conflicts => Self::ConflictsWith,
            DependencyRelation::Provides => Self::Provides,
            DependencyRelation::Replaces => Self::Replaces,
            DependencyRelation::Bundles => Self::Bundles,
            DependencyRelation::Links => Self::Links,
            DependencyRelation::LoadsDynamically => Self::LoadsDynamically,
            DependencyRelation::Requires
            | DependencyRelation::Recommends
            | DependencyRelation::Suggests => Self::RequiresOne,
        }
    }
}

impl fmt::Display for ClauseSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClauseSemantics::RequiresOne => write!(f, "requires-one"),
            ClauseSemantics::RequiresAll => write!(f, "requires-all"),
            ClauseSemantics::ConflictsWith => write!(f, "conflicts-with"),
            ClauseSemantics::Provides => write!(f, "provides"),
            ClauseSemantics::Replaces => write!(f, "replaces"),
            ClauseSemantics::Bundles => write!(f, "bundles"),
            ClauseSemantics::Links => write!(f, "links"),
            ClauseSemantics::LoadsDynamically => write!(f, "loads-dynamically"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyAlternative {
    pub target: PackageId,
    pub requirement: VersionRequirement,
    pub capability: Option<String>,
}

impl DependencyAlternative {
    pub fn new(target: PackageId, requirement: VersionRequirement) -> Self {
        Self {
            target,
            requirement,
            capability: None,
        }
    }

    pub fn capability(mut self, capability: impl Into<String>) -> Self {
        self.capability = Some(capability.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequirementClause {
    pub id: ClauseId,
    pub source: ClauseSource,
    pub semantics: ClauseSemantics,
    pub relation: DependencyRelation,
    pub scope: DependencyScope,
    pub optional: bool,
    pub conditions: Vec<ContextPredicate>,
    pub features: BTreeSet<String>,
    pub alternatives: Vec<DependencyAlternative>,
    pub evidence: String,
}

impl RequirementClause {
    pub fn from_requirement(
        id: impl Into<ClauseId>,
        source: ClauseSource,
        requirement: DependencyRequirement,
    ) -> Self {
        let relation = requirement.relation;
        let semantics = ClauseSemantics::from_relation(&relation);
        Self {
            id: id.into(),
            source,
            semantics,
            relation,
            scope: requirement.scope,
            optional: requirement.optional,
            conditions: requirement.conditions,
            features: requirement.features,
            alternatives: vec![DependencyAlternative::new(
                requirement.target,
                requirement.requirement,
            )],
            evidence: requirement.evidence,
        }
    }

    pub fn with_semantics(mut self, semantics: ClauseSemantics) -> Self {
        self.semantics = semantics;
        self
    }

    pub fn with_alternative(mut self, alternative: DependencyAlternative) -> Self {
        self.alternatives.push(alternative);
        self
    }

    pub fn activation(&self, context: &ResolutionContext) -> Result<(), String> {
        if !context.includes_scope(&self.scope) {
            return Err(format!("scope {} excluded by context", self.scope));
        }

        if self.optional && !context.include_optional && self.features.is_empty() {
            return Err("optional dependency not requested".to_string());
        }

        if self.optional
            && !self.features.is_empty()
            && !self
                .features
                .iter()
                .any(|feature| context.enabled_features.contains(feature))
        {
            return Err(format!(
                "optional feature not enabled: {}",
                self.features.iter().cloned().collect::<Vec<_>>().join(",")
            ));
        }

        for condition in &self.conditions {
            if !condition.matches(context) {
                return Err(format!(
                    "context predicate did not match: {}",
                    condition.describe()
                ));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DependencyHypergraph {
    pub clauses: BTreeMap<ClauseId, RequirementClause>,
    by_source: BTreeMap<ClauseSource, BTreeSet<ClauseId>>,
    by_target: BTreeMap<PackageId, BTreeSet<ClauseId>>,
}

impl DependencyHypergraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_requirements(
        source: ClauseSource,
        requirements: Vec<DependencyRequirement>,
    ) -> Self {
        let mut graph = Self::new();
        for (index, requirement) in requirements.into_iter().enumerate() {
            let id = format!(
                "clause:{}:{}:{}",
                source,
                index,
                requirement.target.purl_like()
            );
            graph.add_clause(RequirementClause::from_requirement(
                id,
                source.clone(),
                requirement,
            ));
        }
        graph
    }

    pub fn add_clause(&mut self, clause: RequirementClause) {
        let id = clause.id.clone();
        self.by_source
            .entry(clause.source.clone())
            .or_default()
            .insert(id.clone());
        for alternative in &clause.alternatives {
            self.by_target
                .entry(alternative.target.clone())
                .or_default()
                .insert(id.clone());
        }
        self.clauses.insert(id, clause);
    }

    pub fn clauses_from(&self, source: &ClauseSource) -> Vec<&RequirementClause> {
        self.by_source
            .get(source)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.clauses.get(id))
            .collect()
    }

    pub fn clauses_for_target(&self, target: &PackageId) -> Vec<&RequirementClause> {
        self.by_target
            .get(target)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.clauses.get(id))
            .collect()
    }

    pub fn active_clauses(&self, context: &ResolutionContext) -> Vec<&RequirementClause> {
        self.clauses
            .values()
            .filter(|clause| clause.activation(context).is_ok())
            .collect()
    }

    pub fn candidate_targets(
        &self,
        source: &ClauseSource,
        context: &ResolutionContext,
    ) -> Vec<PackageId> {
        self.clauses_from(source)
            .into_iter()
            .filter(|clause| clause.activation(context).is_ok())
            .flat_map(|clause| {
                clause
                    .alternatives
                    .iter()
                    .map(|alternative| &alternative.target)
            })
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedOccurrence {
    pub id: OccurrenceId,
    pub package: PackageRef,
    pub slot: String,
    pub context_key: String,
    pub artifact: Option<String>,
    pub selected_by: BTreeSet<String>,
}

impl ResolvedOccurrence {
    pub fn new(
        package: PackageRef,
        slot: impl Into<String>,
        context_key: impl Into<String>,
    ) -> Self {
        let slot = slot.into();
        let context_key = context_key.into();
        let id = occurrence_id(&context_key, &slot, &package);
        Self {
            id,
            package,
            slot,
            context_key,
            artifact: None,
            selected_by: BTreeSet::new(),
        }
    }

    pub fn artifact(mut self, artifact: impl Into<Option<String>>) -> Self {
        self.artifact = artifact.into();
        self
    }

    pub fn selected_by(mut self, selected_by: BTreeSet<String>) -> Self {
        self.selected_by = selected_by;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedOccurrenceEdge {
    pub from: Option<OccurrenceId>,
    pub to: OccurrenceId,
    pub clause_id: ClauseId,
    pub relation: DependencyRelation,
    pub scope: DependencyScope,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedGraphProjection {
    pub context_key: String,
    pub occurrences: BTreeMap<OccurrenceId, ResolvedOccurrence>,
    pub edges: Vec<ResolvedOccurrenceEdge>,
    roots: BTreeSet<OccurrenceId>,
    forward: BTreeMap<OccurrenceId, BTreeSet<OccurrenceId>>,
    reverse: BTreeMap<OccurrenceId, BTreeSet<OccurrenceId>>,
}

impl ResolvedGraphProjection {
    pub fn new(context_key: impl Into<String>) -> Self {
        Self {
            context_key: context_key.into(),
            occurrences: BTreeMap::new(),
            edges: Vec::new(),
            roots: BTreeSet::new(),
            forward: BTreeMap::new(),
            reverse: BTreeMap::new(),
        }
    }

    pub fn from_resolve_result(context_key: impl Into<String>, result: &ResolveResult) -> Self {
        let context_key = context_key.into();
        let mut projection = Self::new(context_key.clone());

        for node in result.nodes.values() {
            let slot = default_occurrence_slot(&node.package);
            let occurrence =
                ResolvedOccurrence::new(node.package.clone(), slot, context_key.clone())
                    .artifact(
                        node.metadata
                            .purl
                            .clone()
                            .or(node.metadata.checksum.clone()),
                    )
                    .selected_by(node.selected_by.clone());
            projection.add_occurrence(occurrence);
        }

        for (index, edge) in result.edges.iter().enumerate() {
            let to_slot = default_occurrence_slot(&edge.to);
            let to = occurrence_id(&context_key, &to_slot, &edge.to);
            let from = edge.from.as_ref().map(|package| {
                let slot = default_occurrence_slot(package);
                occurrence_id(&context_key, &slot, package)
            });
            projection.add_edge(ResolvedOccurrenceEdge {
                from,
                to,
                clause_id: format!("resolved-clause:{index}:{}", edge.requirement.target),
                relation: edge.requirement.relation.clone(),
                scope: edge.requirement.scope.clone(),
                evidence: edge.requirement.evidence.clone(),
            });
        }

        projection
    }

    pub fn add_occurrence(&mut self, occurrence: ResolvedOccurrence) {
        self.occurrences.insert(occurrence.id.clone(), occurrence);
    }

    pub fn add_edge(&mut self, edge: ResolvedOccurrenceEdge) {
        if let Some(from) = &edge.from {
            self.forward
                .entry(from.clone())
                .or_default()
                .insert(edge.to.clone());
            self.reverse
                .entry(edge.to.clone())
                .or_default()
                .insert(from.clone());
        } else {
            self.roots.insert(edge.to.clone());
        }

        if !self.edges.contains(&edge) {
            self.edges.push(edge);
        }
    }

    pub fn roots(&self) -> Vec<OccurrenceId> {
        self.roots.iter().cloned().collect()
    }

    pub fn direct_dependencies(&self, occurrence: &OccurrenceId) -> Vec<OccurrenceId> {
        self.forward
            .get(occurrence)
            .into_iter()
            .flat_map(|dependencies| dependencies.iter().cloned())
            .collect()
    }

    pub fn reverse_dependencies(&self, occurrence: &OccurrenceId) -> Vec<OccurrenceId> {
        self.reverse
            .get(occurrence)
            .into_iter()
            .flat_map(|dependents| dependents.iter().cloned())
            .collect()
    }

    pub fn dependency_closure_from(&self, occurrence: &OccurrenceId) -> Vec<OccurrenceId> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from([occurrence.clone()]);

        while let Some(current) = queue.pop_front() {
            if visited.insert(current.clone()) {
                for dependency in self.direct_dependencies(&current) {
                    queue.push_back(dependency);
                }
            }
        }

        visited.into_iter().collect()
    }

    pub fn reverse_closure_from(&self, occurrence: &OccurrenceId) -> Vec<OccurrenceId> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from(self.reverse_dependencies(occurrence));

        while let Some(current) = queue.pop_front() {
            if visited.insert(current.clone()) {
                for dependent in self.reverse_dependencies(&current) {
                    queue.push_back(dependent);
                }
            }
        }

        visited.into_iter().collect()
    }

    pub fn package_occurrences(&self, package: &PackageId) -> Vec<OccurrenceId> {
        self.occurrences
            .values()
            .filter(|occurrence| occurrence.package.id == *package)
            .map(|occurrence| occurrence.id.clone())
            .collect()
    }
}

pub fn occurrence_id(context_key: &str, slot: &str, package: &PackageRef) -> OccurrenceId {
    format!("occ:{context_key}:{slot}:{package}")
}

fn default_occurrence_slot(package: &PackageRef) -> String {
    package.id.to_string()
}

#[cfg(test)]
mod tests {
    use crate::model::{BuildProfile, ContextPredicate, PackageId, VersionRequirement};
    use crate::repository::InMemoryRepository;
    use crate::resolver::Resolver;
    use crate::{PackageVersion, ResolutionContext};

    use super::*;

    #[test]
    fn hypergraph_clause_preserves_alternative_targets() {
        let capability = "editor".to_string();
        let root = ClauseSource::Project("os-image".to_string());
        let vim = PackageId::rpm("vim-enhanced");
        let nano = PackageId::rpm("nano");
        let mut clause = RequirementClause::from_requirement(
            "rpm-provider-choice",
            root.clone(),
            DependencyRequirement::new(vim.clone(), VersionRequirement::any())
                .relation(DependencyRelation::Requires)
                .evidence("dnf requires editor"),
        )
        .with_semantics(ClauseSemantics::RequiresOne);
        clause.alternatives[0].capability = Some(capability.clone());
        clause = clause.with_alternative(
            DependencyAlternative::new(nano.clone(), VersionRequirement::any())
                .capability(capability),
        );

        let mut graph = DependencyHypergraph::new();
        graph.add_clause(clause);

        let targets =
            graph.candidate_targets(&root, &ResolutionContext::cloudlinux_production_x86_64());
        assert_eq!(targets, vec![nano.clone(), vim.clone()]);
        assert_eq!(graph.clauses_for_target(&vim).len(), 1);
        assert_eq!(graph.clauses_for_target(&nano).len(), 1);
    }

    #[test]
    fn hypergraph_filters_clauses_by_context_before_traversal() {
        let gpu = PackageId::python("nvidia-ml-py");
        let graph = DependencyHypergraph::from_requirements(
            ClauseSource::Root,
            vec![
                DependencyRequirement::new(gpu.clone(), VersionRequirement::any())
                    .optional()
                    .feature("gpu")
                    .when(ContextPredicate::ProfileEnabled(BuildProfile::Gpu)),
            ],
        );

        assert!(
            graph
                .active_clauses(&ResolutionContext::cloudlinux_production_x86_64())
                .is_empty()
        );
        assert_eq!(
            graph
                .active_clauses(
                    &ResolutionContext::cloudlinux_production_x86_64()
                        .with_feature("gpu")
                        .with_optional(),
                )
                .len(),
            0
        );

        let mut context = ResolutionContext::cloudlinux_production_x86_64()
            .with_feature("gpu")
            .with_optional();
        context.profiles.insert(BuildProfile::Gpu);
        assert_eq!(graph.active_clauses(&context).len(), 1);
    }

    #[test]
    fn resolved_projection_builds_forward_and_reverse_occurrence_indexes() {
        let app = PackageId::internal("app");
        let web = PackageId::python("web");
        let openssl = PackageId::rpm("openssl-libs");
        let mut repository = InMemoryRepository::new();
        repository.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(web.clone(), VersionRequirement::any()),
            ]),
        );
        repository.add(
            PackageVersion::new(web.clone(), "2.0").with_dependencies(vec![
                DependencyRequirement::new(openssl.clone(), VersionRequirement::any()),
            ]),
        );
        repository.add(PackageVersion::new(openssl.clone(), "3.0.0"));

        let context = ResolutionContext::cloudlinux_production_x86_64();
        let result = Resolver::new(repository).resolve(
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            &context,
        );
        let projection =
            ResolvedGraphProjection::from_resolve_result(context.stable_key(), &result);
        let root = projection.roots().pop().expect("root occurrence");
        let closure = projection.dependency_closure_from(&root);
        let openssl_occurrence = projection
            .package_occurrences(&openssl)
            .pop()
            .expect("openssl occurrence");

        assert!(closure.contains(&openssl_occurrence));
        assert!(
            projection
                .reverse_closure_from(&openssl_occurrence)
                .contains(&root)
        );
    }
}
