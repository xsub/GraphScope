use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::evidence::stable_hash;
use crate::model::{
    ActiveDecision, ArtifactMetadata, DependencyRequirement, Ecosystem, PackageId, PackageRef,
    PackageVersion, ResolutionContext,
};
use crate::repository::PackageRepository;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionPolicy {
    HighestCompatible,
    MinimalCompatible,
}

impl fmt::Display for SelectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectionPolicy::HighestCompatible => write!(f, "highest-compatible"),
            SelectionPolicy::MinimalCompatible => write!(f, "minimal-compatible"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionMultiplicity {
    OnePerPackage,
    ParallelPerParent,
}

impl fmt::Display for VersionMultiplicity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionMultiplicity::OnePerPackage => write!(f, "one-per-package"),
            VersionMultiplicity::ParallelPerParent => write!(f, "parallel-per-parent"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolverOptions {
    pub default_selection_policy: SelectionPolicy,
    pub ecosystem_selection_policy: BTreeMap<Ecosystem, SelectionPolicy>,
    pub ecosystem_multiplicity: BTreeMap<Ecosystem, VersionMultiplicity>,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            default_selection_policy: SelectionPolicy::HighestCompatible,
            ecosystem_selection_policy: BTreeMap::from([
                (Ecosystem::Go, SelectionPolicy::MinimalCompatible),
                (Ecosystem::Rpm, SelectionPolicy::HighestCompatible),
                (Ecosystem::Python, SelectionPolicy::HighestCompatible),
                (Ecosystem::Maven, SelectionPolicy::HighestCompatible),
                (Ecosystem::Gradle, SelectionPolicy::HighestCompatible),
                (Ecosystem::Npm, SelectionPolicy::HighestCompatible),
                (Ecosystem::Cargo, SelectionPolicy::HighestCompatible),
            ]),
            ecosystem_multiplicity: BTreeMap::from([
                (Ecosystem::Npm, VersionMultiplicity::ParallelPerParent),
                (Ecosystem::Cargo, VersionMultiplicity::ParallelPerParent),
            ]),
        }
    }
}

impl ResolverOptions {
    fn selection_policy(&self, ecosystem: &Ecosystem) -> SelectionPolicy {
        self.ecosystem_selection_policy
            .get(ecosystem)
            .cloned()
            .unwrap_or_else(|| self.default_selection_policy.clone())
    }

    fn multiplicity(&self, ecosystem: &Ecosystem) -> VersionMultiplicity {
        self.ecosystem_multiplicity
            .get(ecosystem)
            .cloned()
            .unwrap_or(VersionMultiplicity::OnePerPackage)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNode {
    pub package: PackageRef,
    pub depth: usize,
    pub selected_by: BTreeSet<String>,
    pub metadata: ArtifactMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedEdge {
    pub from: Option<PackageRef>,
    pub to: PackageRef,
    pub requirement: DependencyRequirement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictDiagnostic {
    pub package: PackageId,
    pub selection_slot: String,
    pub constraints: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedDependency {
    pub requester: Option<PackageRef>,
    pub target: PackageId,
    pub requirement: DependencyRequirement,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolverTraceOutcome {
    Selected,
    Skipped,
    Conflict,
}

impl fmt::Display for ResolverTraceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverTraceOutcome::Selected => write!(f, "selected"),
            ResolverTraceOutcome::Skipped => write!(f, "skipped"),
            ResolverTraceOutcome::Conflict => write!(f, "conflict"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverTraceEvent {
    pub id: String,
    pub parent_id: Option<String>,
    pub requester: Option<PackageRef>,
    pub target: PackageId,
    pub requirement: DependencyRequirement,
    pub selection_slot: Option<String>,
    pub active_constraints: Vec<String>,
    pub candidates_considered: Vec<PackageRef>,
    pub candidates_rejected: Vec<PackageRef>,
    pub selected: Option<PackageRef>,
    pub outcome: ResolverTraceOutcome,
    pub rule: String,
    pub reason: String,
    pub evidence: String,
}

impl ResolverTraceEvent {
    fn stable_key(&self, sequence: usize) -> String {
        format!(
            "{}|{:?}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            sequence,
            self.parent_id,
            self.requester
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "root".to_string()),
            self.target,
            self.requirement.requirement,
            self.selection_slot.as_deref().unwrap_or(""),
            self.active_constraints.join("\n"),
            self.candidates_considered
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            self.candidates_rejected
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            self.selected
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            self.outcome,
            self.rule,
            self.reason
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolveResult {
    pub nodes: BTreeMap<PackageRef, ResolvedNode>,
    pub edges: Vec<ResolvedEdge>,
    pub conflicts: Vec<ConflictDiagnostic>,
    pub skipped: Vec<SkippedDependency>,
    pub trace: Vec<ResolverTraceEvent>,
}

impl ResolveResult {
    pub fn contains_package(&self, package: &PackageId) -> bool {
        self.nodes.keys().any(|node| &node.id == package)
    }

    pub fn selected_version(&self, package: &PackageId) -> Option<&PackageRef> {
        self.nodes.keys().find(|node| &node.id == package)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SelectionKey {
    package: PackageId,
    slot: String,
}

#[derive(Clone, Debug)]
struct ConstraintOrigin {
    requirement: DependencyRequirement,
    requester: Option<PackageRef>,
    depth: usize,
}

#[derive(Clone, Debug)]
struct PendingRequirement {
    requirement: DependencyRequirement,
    requester: Option<PackageRef>,
    slot_parent: String,
    depth: usize,
    inherited_exclusions: BTreeSet<PackageId>,
    parent_trace_id: Option<String>,
}

#[derive(Clone, Debug)]
struct CandidateDecision {
    selected: Option<PackageVersion>,
    considered: Vec<PackageRef>,
    rejected: Vec<PackageRef>,
    rule: String,
}

pub struct Resolver<R> {
    repository: R,
    options: ResolverOptions,
}

impl<R> Resolver<R>
where
    R: PackageRepository,
{
    pub fn new(repository: R) -> Self {
        Self {
            repository,
            options: ResolverOptions::default(),
        }
    }

    pub fn with_options(repository: R, options: ResolverOptions) -> Self {
        Self {
            repository,
            options,
        }
    }

    pub fn resolve(
        &self,
        roots: Vec<DependencyRequirement>,
        context: &ResolutionContext,
    ) -> ResolveResult {
        let mut result = ResolveResult::default();
        let mut selected: BTreeMap<SelectionKey, PackageRef> = BTreeMap::new();
        let mut constraints: BTreeMap<SelectionKey, Vec<ConstraintOrigin>> = BTreeMap::new();
        let mut expanded: BTreeSet<(PackageRef, String)> = BTreeSet::new();
        let mut trace_sequence = 0;
        let mut queue = roots
            .into_iter()
            .map(|requirement| PendingRequirement {
                requirement,
                requester: None,
                slot_parent: "root".to_string(),
                depth: 0,
                inherited_exclusions: BTreeSet::new(),
                parent_trace_id: None,
            })
            .collect::<VecDeque<_>>();

        while let Some(pending) = queue.pop_front() {
            if pending
                .inherited_exclusions
                .contains(&pending.requirement.target)
            {
                let reason = "excluded by ancestor dependency edge".to_string();
                result.skipped.push(SkippedDependency {
                    requester: pending.requester.clone(),
                    target: pending.requirement.target.clone(),
                    requirement: pending.requirement.clone(),
                    reason: reason.clone(),
                });
                push_trace_event(
                    &mut result,
                    &mut trace_sequence,
                    ResolverTraceEvent {
                        id: String::new(),
                        parent_id: pending.parent_trace_id,
                        requester: pending.requester,
                        target: pending.requirement.target.clone(),
                        requirement: pending.requirement.clone(),
                        selection_slot: None,
                        active_constraints: Vec::new(),
                        candidates_considered: Vec::new(),
                        candidates_rejected: Vec::new(),
                        selected: None,
                        outcome: ResolverTraceOutcome::Skipped,
                        rule: "inherited-exclusion".to_string(),
                        reason,
                        evidence: pending.requirement.evidence.clone(),
                    },
                );
                continue;
            }

            match pending.requirement.is_active(context) {
                ActiveDecision::Active => {}
                ActiveDecision::Skipped(reason) => {
                    result.skipped.push(SkippedDependency {
                        requester: pending.requester.clone(),
                        target: pending.requirement.target.clone(),
                        requirement: pending.requirement.clone(),
                        reason: reason.clone(),
                    });
                    push_trace_event(
                        &mut result,
                        &mut trace_sequence,
                        ResolverTraceEvent {
                            id: String::new(),
                            parent_id: pending.parent_trace_id,
                            requester: pending.requester,
                            target: pending.requirement.target.clone(),
                            requirement: pending.requirement.clone(),
                            selection_slot: None,
                            active_constraints: Vec::new(),
                            candidates_considered: Vec::new(),
                            candidates_rejected: Vec::new(),
                            selected: None,
                            outcome: ResolverTraceOutcome::Skipped,
                            rule: "context-activation".to_string(),
                            reason,
                            evidence: pending.requirement.evidence.clone(),
                        },
                    );
                    continue;
                }
            }

            let selection_key =
                self.selection_key(&pending.requirement.target, &pending.slot_parent);
            constraints
                .entry(selection_key.clone())
                .or_default()
                .push(ConstraintOrigin {
                    requirement: pending.requirement.clone(),
                    requester: pending.requester.clone(),
                    depth: pending.depth,
                });

            let active_constraints = constraints
                .get(&selection_key)
                .expect("constraint was just inserted");
            let formatted_constraints = active_constraints
                .iter()
                .map(format_constraint)
                .collect::<Vec<_>>();

            let decision = self.select_candidate(&selection_key, active_constraints);
            let Some(candidate) = decision.selected else {
                let reason = "no package candidate satisfies all active constraints".to_string();
                result.conflicts.push(ConflictDiagnostic {
                    package: selection_key.package.clone(),
                    selection_slot: selection_key.slot.clone(),
                    constraints: formatted_constraints.clone(),
                    reason: reason.clone(),
                });
                push_trace_event(
                    &mut result,
                    &mut trace_sequence,
                    ResolverTraceEvent {
                        id: String::new(),
                        parent_id: pending.parent_trace_id,
                        requester: pending.requester,
                        target: pending.requirement.target.clone(),
                        requirement: pending.requirement.clone(),
                        selection_slot: Some(selection_key.slot),
                        active_constraints: formatted_constraints,
                        candidates_considered: decision.considered,
                        candidates_rejected: decision.rejected,
                        selected: None,
                        outcome: ResolverTraceOutcome::Conflict,
                        rule: decision.rule,
                        reason,
                        evidence: pending.requirement.evidence.clone(),
                    },
                );
                continue;
            };

            let package_ref = candidate.package_ref();
            let selection_reason = match selected.get(&selection_key) {
                None => "selected candidate for new slot",
                Some(previous) if previous != &package_ref => {
                    "selected candidate replaced previous slot candidate"
                }
                Some(_)
                    if expanded.contains(&(package_ref.clone(), selection_key.slot.clone())) =>
                {
                    "selected candidate; dependencies already expanded for slot"
                }
                Some(_) => "selected candidate; dependencies pending expansion",
            }
            .to_string();
            selected.insert(selection_key.clone(), package_ref.clone());
            self.upsert_node(
                &mut result,
                &package_ref,
                &candidate.metadata,
                active_constraints,
            );
            self.push_edge(
                &mut result,
                pending.requester.clone(),
                package_ref.clone(),
                pending.requirement,
            );

            let trace_id = push_trace_event(
                &mut result,
                &mut trace_sequence,
                ResolverTraceEvent {
                    id: String::new(),
                    parent_id: pending.parent_trace_id,
                    requester: pending.requester,
                    target: selection_key.package.clone(),
                    requirement: active_constraints
                        .last()
                        .expect("active constraint exists")
                        .requirement
                        .clone(),
                    selection_slot: Some(selection_key.slot.clone()),
                    active_constraints: formatted_constraints,
                    candidates_considered: decision.considered,
                    candidates_rejected: decision.rejected,
                    selected: Some(package_ref.clone()),
                    outcome: ResolverTraceOutcome::Selected,
                    rule: decision.rule,
                    reason: selection_reason,
                    evidence: active_constraints
                        .last()
                        .expect("active constraint exists")
                        .requirement
                        .evidence
                        .clone(),
                },
            );
            let expansion_key = (package_ref.clone(), selection_key.slot.clone());
            if expanded.insert(expansion_key) {
                for dependency in candidate.dependencies {
                    let mut inherited_exclusions = pending.inherited_exclusions.clone();
                    inherited_exclusions.extend(dependency.exclusions.iter().cloned());
                    queue.push_back(PendingRequirement {
                        requirement: dependency,
                        requester: Some(package_ref.clone()),
                        slot_parent: package_ref.to_string(),
                        depth: pending.depth + 1,
                        inherited_exclusions,
                        parent_trace_id: Some(trace_id.clone()),
                    });
                }
            }
        }

        self.prune_unselected(&selected, &mut result);
        result
    }

    fn selection_key(&self, package: &PackageId, parent_slot: &str) -> SelectionKey {
        let slot = match self.options.multiplicity(&package.ecosystem) {
            VersionMultiplicity::OnePerPackage => "global".to_string(),
            VersionMultiplicity::ParallelPerParent => parent_slot.to_string(),
        };

        SelectionKey {
            package: package.clone(),
            slot,
        }
    }

    fn select_candidate(
        &self,
        selection_key: &SelectionKey,
        constraints: &[ConstraintOrigin],
    ) -> CandidateDecision {
        let package = &selection_key.package;
        let policy = self.options.selection_policy(&package.ecosystem);
        let multiplicity = self.options.multiplicity(&package.ecosystem);
        let candidates = self
            .repository
            .candidates(package)
            .into_iter()
            .collect::<Vec<_>>();
        let considered = candidates
            .iter()
            .map(PackageVersion::package_ref)
            .collect::<Vec<_>>();
        let rejected = candidates
            .iter()
            .filter(|candidate| {
                !constraints
                    .iter()
                    .all(|origin| origin.requirement.requirement.matches(&candidate.version))
            })
            .map(PackageVersion::package_ref)
            .collect::<Vec<_>>();
        let mut compatible = candidates
            .into_iter()
            .filter(|candidate| {
                constraints
                    .iter()
                    .all(|origin| origin.requirement.requirement.matches(&candidate.version))
            })
            .collect::<Vec<_>>();

        match policy {
            SelectionPolicy::HighestCompatible => {
                compatible.sort_by(|left, right| right.version.cmp(&left.version));
            }
            SelectionPolicy::MinimalCompatible => {
                compatible.sort_by(|left, right| left.version.cmp(&right.version));
            }
        }

        CandidateDecision {
            selected: compatible.into_iter().next(),
            considered,
            rejected,
            rule: format!(
                "selection_policy={policy}; version_multiplicity={multiplicity}; slot={}",
                selection_key.slot
            ),
        }
    }

    fn upsert_node(
        &self,
        result: &mut ResolveResult,
        package: &PackageRef,
        metadata: &ArtifactMetadata,
        constraints: &[ConstraintOrigin],
    ) {
        let depth = constraints
            .iter()
            .map(|constraint| constraint.depth)
            .min()
            .unwrap_or(0);
        let selected_by = constraints
            .iter()
            .map(|constraint| match &constraint.requester {
                Some(requester) => requester.to_string(),
                None => "root".to_string(),
            })
            .collect::<BTreeSet<_>>();

        result
            .nodes
            .entry(package.clone())
            .and_modify(|node| {
                node.depth = node.depth.min(depth);
                node.selected_by.extend(selected_by.iter().cloned());
            })
            .or_insert_with(|| ResolvedNode {
                package: package.clone(),
                depth,
                selected_by,
                metadata: metadata.clone(),
            });
    }

    fn push_edge(
        &self,
        result: &mut ResolveResult,
        from: Option<PackageRef>,
        to: PackageRef,
        requirement: DependencyRequirement,
    ) {
        let edge = ResolvedEdge {
            from,
            to,
            requirement,
        };

        if !result.edges.contains(&edge) {
            result.edges.push(edge);
        }
    }

    fn prune_unselected(
        &self,
        selected: &BTreeMap<SelectionKey, PackageRef>,
        result: &mut ResolveResult,
    ) {
        let selected_refs = selected.values().cloned().collect::<BTreeSet<_>>();
        result.edges.retain(|edge| {
            selected_refs.contains(&edge.to)
                && edge
                    .from
                    .as_ref()
                    .is_none_or(|from| selected_refs.contains(from))
        });

        let mut reachable = BTreeSet::new();
        let mut queue = result
            .edges
            .iter()
            .filter(|edge| edge.from.is_none())
            .map(|edge| edge.to.clone())
            .collect::<VecDeque<_>>();

        while let Some(package) = queue.pop_front() {
            if reachable.insert(package.clone()) {
                for edge in result
                    .edges
                    .iter()
                    .filter(|edge| edge.from.as_ref() == Some(&package))
                {
                    queue.push_back(edge.to.clone());
                }
            }
        }

        result.nodes.retain(|package_ref, _node| {
            selected_refs.contains(package_ref) && reachable.contains(package_ref)
        });
        result.edges.retain(|edge| {
            reachable.contains(&edge.to)
                && edge
                    .from
                    .as_ref()
                    .is_none_or(|from| reachable.contains(from))
        });
    }
}

fn format_constraint(origin: &ConstraintOrigin) -> String {
    let requester = origin
        .requester
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "root".to_string());
    format!(
        "{} requested {} {} via {}",
        requester,
        origin.requirement.target,
        origin.requirement.requirement,
        origin.requirement.evidence
    )
}

fn push_trace_event(
    result: &mut ResolveResult,
    sequence: &mut usize,
    mut event: ResolverTraceEvent,
) -> String {
    *sequence += 1;
    event.id = format!(
        "trace-{:06}-{:016x}",
        *sequence,
        stable_hash(&event.stable_key(*sequence))
    );
    let id = event.id.clone();
    result.trace.push(event);
    id
}

#[cfg(test)]
mod tests {
    use crate::model::{
        Architecture, ContextPredicate, DependencyRelation, DependencyScope, DistroFlavor,
        Ecosystem, OperatingSystem, PackageId, PackageVersion, ResolutionContext,
        VersionRequirement,
    };
    use crate::repository::InMemoryRepository;

    use super::*;

    #[test]
    fn context_specific_optional_gpu_dependency_is_activated_by_feature() {
        let root = PackageId::internal("app");
        let gpu = PackageId::python("nvidia-ml-py");
        let scanner = PackageId::python("scanner");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(scanner.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(scanner, "1.0").with_dependencies(vec![
            DependencyRequirement::new(gpu.clone(), VersionRequirement::parse("^12.0"))
                .optional()
                .feature("gpu")
                .when(ContextPredicate::ArchIs(Architecture::X86_64)),
        ]));
        repo.add(PackageVersion::new(gpu.clone(), "12.1.0"));

        let resolver = Resolver::new(repo);
        let without_gpu = resolver.resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        assert!(!without_gpu.contains_package(&gpu));
        assert_eq!(without_gpu.skipped.len(), 1);

        let root = PackageId::internal("app");
        let with_gpu = resolver.resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64()
                .with_optional()
                .with_feature("gpu"),
        );
        assert!(with_gpu.contains_package(&gpu));
    }

    #[test]
    fn platform_dependency_is_skipped_when_context_does_not_match() {
        let root = PackageId::npm(None::<String>, "portal");
        let fsevents = PackageId::npm(None::<String>, "fsevents");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(fsevents.clone(), VersionRequirement::parse("^2.3"))
                    .optional()
                    .when(ContextPredicate::OsIs(OperatingSystem::Macos)),
            ]),
        );
        repo.add(PackageVersion::new(fsevents.clone(), "2.3.3"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64().with_optional(),
        );

        assert!(!result.contains_package(&fsevents));
        assert!(
            result
                .skipped
                .iter()
                .any(|skipped| { skipped.reason.contains("context predicate did not match") })
        );
    }

    #[test]
    fn conflicting_constraints_are_reported() {
        let root = PackageId::internal("app");
        let left = PackageId::internal("left");
        let right = PackageId::internal("right");
        let shared = PackageId::python("shared");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(left, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::exact("1.0")),
        ]));
        repo.add(PackageVersion::new(right, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::exact("2.0")),
        ]));
        repo.add(PackageVersion::new(shared.clone(), "1.0"));
        repo.add(PackageVersion::new(shared.clone(), "2.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].package, shared);
    }

    #[test]
    fn go_uses_minimal_compatible_version_selection() {
        let root = PackageId::internal("go-app");
        let net = PackageId::go("golang.org/x/net");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(net.clone(), VersionRequirement::parse(">=0.24.0")),
            ]),
        );
        repo.add(PackageVersion::new(net.clone(), "0.24.0"));
        repo.add(PackageVersion::new(net.clone(), "0.26.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(
            result
                .selected_version(&net)
                .map(|selected| selected.version.raw.as_str()),
            Some("0.24.0")
        );
    }

    #[test]
    fn maven_style_exclusion_skips_transitive_dependency() {
        let root = PackageId::internal("java-app");
        let logging = PackageId::maven("ch.qos.logback", "logback-classic");
        let commons = PackageId::maven("commons-logging", "commons-logging");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(logging.clone(), VersionRequirement::any())
                    .exclude(commons.clone()),
            ]),
        );
        repo.add(
            PackageVersion::new(logging, "1.4.14").with_dependencies(vec![
                DependencyRequirement::new(commons.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(commons.clone(), "1.2"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(!result.contains_package(&commons));
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn cycles_do_not_expand_forever() {
        let a = PackageId::internal("a");
        let b = PackageId::internal("b");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(a.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(b.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(
            PackageVersion::new(b.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(a.clone(), VersionRequirement::any()),
            ]),
        );

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(a, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(result.nodes.len(), 2);
        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn distro_specific_dependency_is_active_for_cloudlinux() {
        let root = PackageId::rpm("kernelcare");
        let els = PackageId::rpm("tuxcare-els-release");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "3.1").with_dependencies(vec![
                DependencyRequirement::new(els.clone(), VersionRequirement::any())
                    .scope(DependencyScope::System)
                    .when(ContextPredicate::DistroIs(DistroFlavor::CloudLinux)),
            ]),
        );
        repo.add(PackageVersion::new(els.clone(), "9.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(result.contains_package(&els));
    }

    #[test]
    fn language_version_predicate_filters_dependencies() {
        let root = PackageId::python("scanner");
        let backport = PackageId::python("typing-extensions");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(backport.clone(), VersionRequirement::any()).when(
                    ContextPredicate::LanguageVersionMatches {
                        ecosystem: Ecosystem::Python,
                        requirement: VersionRequirement::parse("<3.11"),
                    },
                ),
            ]),
        );
        repo.add(PackageVersion::new(backport.clone(), "4.12.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(!result.contains_package(&backport));
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn highest_compatible_policy_selects_highest_matching_python_version() {
        let root = PackageId::internal("app");
        let requests = PackageId::python("requests");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(
                    requests.clone(),
                    VersionRequirement::parse(">=2.31,<3.0"),
                ),
            ]),
        );
        repo.add(PackageVersion::new(requests.clone(), "2.31.0"));
        repo.add(PackageVersion::new(requests.clone(), "2.32.3"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(
            result
                .selected_version(&requests)
                .map(|selected| selected.version.raw.as_str()),
            Some("2.32.3")
        );
    }

    #[test]
    fn custom_options_can_force_minimal_python_selection() {
        let root = PackageId::internal("app");
        let requests = PackageId::python("requests");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(
                    requests.clone(),
                    VersionRequirement::parse(">=2.31,<3.0"),
                ),
            ]),
        );
        repo.add(PackageVersion::new(requests.clone(), "2.31.0"));
        repo.add(PackageVersion::new(requests.clone(), "2.32.3"));

        let mut options = ResolverOptions::default();
        options
            .ecosystem_selection_policy
            .insert(Ecosystem::Python, SelectionPolicy::MinimalCompatible);
        let result = Resolver::with_options(repo, options).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(
            result
                .selected_version(&requests)
                .map(|selected| selected.version.raw.as_str()),
            Some("2.31.0")
        );
    }

    #[test]
    fn missing_package_candidate_records_conflict() {
        let missing = PackageId::rpm("does-not-exist");

        let result = Resolver::new(InMemoryRepository::new()).resolve(
            vec![
                DependencyRequirement::new(missing.clone(), VersionRequirement::parse(">=1.0"))
                    .evidence("root manifest"),
            ],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].package, missing);
        assert!(result.nodes.is_empty());
    }

    #[test]
    fn root_dependency_skipped_by_context_creates_no_nodes() {
        let mac_only = PackageId::npm(None::<String>, "fsevents");
        let mut repo = InMemoryRepository::new();
        repo.add(PackageVersion::new(mac_only.clone(), "2.3.3"));

        let result = Resolver::new(repo).resolve(
            vec![
                DependencyRequirement::new(mac_only, VersionRequirement::any())
                    .when(ContextPredicate::OsIs(OperatingSystem::Macos)),
            ],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(result.nodes.is_empty());
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn conflict_diagnostic_includes_all_constraint_evidence() {
        let root = PackageId::internal("app");
        let left = PackageId::internal("left");
        let right = PackageId::internal("right");
        let shared = PackageId::python("shared");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(left, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::exact("1.0"))
                .evidence("left.txt"),
        ]));
        repo.add(PackageVersion::new(right, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::exact("2.0"))
                .evidence("right.txt"),
        ]));
        repo.add(PackageVersion::new(shared, "1.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        let constraints = result.conflicts[0].constraints.join("\n");
        assert!(constraints.contains("left.txt"));
        assert!(constraints.contains("right.txt"));
    }

    #[test]
    fn combined_constraints_can_narrow_selected_version_without_conflict() {
        let root = PackageId::internal("app");
        let left = PackageId::internal("left");
        let right = PackageId::internal("right");
        let shared = PackageId::python("shared");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(left, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse(">=1.0,<3.0")),
        ]));
        repo.add(PackageVersion::new(right, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse("<2.0")),
        ]));
        repo.add(PackageVersion::new(shared.clone(), "1.5.0"));
        repo.add(PackageVersion::new(shared.clone(), "2.5.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(result.conflicts.is_empty());
        assert_eq!(
            result
                .selected_version(&shared)
                .map(|selected| selected.version.raw.as_str()),
            Some("1.5.0")
        );
    }

    #[test]
    fn changed_selection_prunes_orphaned_transitive_nodes() {
        let root = PackageId::internal("app");
        let left = PackageId::internal("left");
        let right = PackageId::internal("right");
        let shared = PackageId::python("shared");
        let old_only = PackageId::python("old-only");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(left, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse(">=1.0")),
        ]));
        repo.add(PackageVersion::new(right, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse("<2.0")),
        ]));
        repo.add(
            PackageVersion::new(shared.clone(), "3.0.0").with_dependencies(vec![
                DependencyRequirement::new(old_only.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(shared.clone(), "1.5.0"));
        repo.add(PackageVersion::new(old_only.clone(), "1.0.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(
            result
                .selected_version(&shared)
                .map(|selected| selected.version.raw.as_str()),
            Some("1.5.0")
        );
        assert!(!result.contains_package(&old_only));
        assert!(
            result
                .edges
                .iter()
                .all(|edge| edge.from.as_ref().is_none_or(|from| from.id != old_only))
        );
    }

    #[test]
    fn npm_parallel_slots_allow_different_versions_per_parent() {
        let root = PackageId::internal("app");
        let left = PackageId::npm(None::<String>, "left");
        let right = PackageId::npm(None::<String>, "right");
        let shared = PackageId::npm(None::<String>, "shared");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(left, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse("^1.0.0")),
        ]));
        repo.add(PackageVersion::new(right, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse("^2.0.0")),
        ]));
        repo.add(PackageVersion::new(shared.clone(), "1.9.0"));
        repo.add(PackageVersion::new(shared.clone(), "2.1.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let selected_shared_versions = result
            .nodes
            .keys()
            .filter(|package_ref| package_ref.id == shared)
            .map(|package_ref| package_ref.version.raw.as_str())
            .collect::<Vec<_>>();

        assert!(result.conflicts.is_empty());
        assert_eq!(selected_shared_versions, vec!["1.9.0", "2.1.0"]);
    }

    #[test]
    fn python_global_slot_conflicts_on_incompatible_versions() {
        let root = PackageId::internal("app");
        let left = PackageId::internal("left");
        let right = PackageId::internal("right");
        let shared = PackageId::python("shared");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(left, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse("^1.0.0")),
        ]));
        repo.add(PackageVersion::new(right, "1.0").with_dependencies(vec![
            DependencyRequirement::new(shared.clone(), VersionRequirement::parse("^2.0.0")),
        ]));
        repo.add(PackageVersion::new(shared.clone(), "1.9.0"));
        repo.add(PackageVersion::new(shared.clone(), "2.1.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].package, shared);
    }

    #[test]
    fn duplicate_root_requirements_do_not_duplicate_edges() {
        let package = PackageId::rpm("openssl-libs");
        let requirement =
            DependencyRequirement::new(package.clone(), VersionRequirement::parse(">=3.0"));
        let mut repo = InMemoryRepository::new();
        repo.add(PackageVersion::new(package, "3.2.2"));

        let result = Resolver::new(repo).resolve(
            vec![requirement.clone(), requirement],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(result.edges.len(), 1);
    }

    #[test]
    fn selected_by_records_multiple_requesters_for_shared_dependency() {
        let root = PackageId::internal("app");
        let left = PackageId::internal("left");
        let right = PackageId::internal("right");
        let shared = PackageId::maven("org.slf4j", "slf4j-api");

        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(left.clone(), VersionRequirement::any()),
                DependencyRequirement::new(right.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(
            PackageVersion::new(left.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(shared.clone(), VersionRequirement::parse(">=2.0,<3.0")),
            ]),
        );
        repo.add(
            PackageVersion::new(right.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(shared.clone(), VersionRequirement::parse(">=2.0,<3.0")),
            ]),
        );
        repo.add(PackageVersion::new(shared.clone(), "2.0.13"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let shared_ref = result.selected_version(&shared).unwrap();
        let node = result.nodes.get(shared_ref).unwrap();

        assert_eq!(node.selected_by.len(), 2);
    }

    #[test]
    fn relation_metadata_is_preserved_on_resolved_edge() {
        let root = PackageId::rpm("kernelcare");
        let headers = PackageId::rpm("kernel-headers");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "3.1").with_dependencies(vec![
                DependencyRequirement::new(headers.clone(), VersionRequirement::parse(">=5.14"))
                    .scope(DependencyScope::Weak)
                    .relation(DependencyRelation::Recommends),
            ]),
        );
        repo.add(PackageVersion::new(headers, "5.14.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(result.edges.iter().any(|edge| edge.requirement.relation
            == DependencyRelation::Recommends
            && edge.requirement.scope == DependencyScope::Weak));
    }

    #[test]
    fn unresolved_transitive_dependency_keeps_resolved_parent_and_reports_conflict() {
        let root = PackageId::internal("app");
        let parent = PackageId::python("parent");
        let missing = PackageId::python("missing");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(parent.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(
            PackageVersion::new(parent.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(missing.clone(), VersionRequirement::any()),
            ]),
        );

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(result.contains_package(&parent));
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].package, missing);
    }

    #[test]
    fn trace_records_selected_parent_child_decisions() {
        let root = PackageId::internal("app");
        let dependency = PackageId::python("requests");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dependency.clone(), VersionRequirement::parse("^2.31"))
                    .evidence("manifest:requests"),
            ]),
        );
        repo.add(PackageVersion::new(dependency.clone(), "2.32.3"));

        let result = Resolver::new(repo).resolve(
            vec![
                DependencyRequirement::new(root.clone(), VersionRequirement::any())
                    .evidence("manifest:root"),
            ],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert_eq!(result.trace.len(), 2);
        assert_eq!(result.trace[0].outcome, ResolverTraceOutcome::Selected);
        assert_eq!(result.trace[0].parent_id, None);
        assert_eq!(result.trace[0].target, root);
        assert_eq!(result.trace[1].outcome, ResolverTraceOutcome::Selected);
        assert_eq!(result.trace[1].parent_id, Some(result.trace[0].id.clone()));
        assert_eq!(result.trace[1].target, dependency);
        assert!(result.trace[1].selected.is_some());
        assert!(
            result.trace[1]
                .active_constraints
                .iter()
                .any(|constraint| constraint.contains("manifest:requests"))
        );
    }

    #[test]
    fn trace_records_context_skip_with_parent_path() {
        let root = PackageId::internal("app");
        let mac_only = PackageId::npm(None::<String>, "fsevents");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(mac_only.clone(), VersionRequirement::any())
                    .when(ContextPredicate::OsIs(OperatingSystem::Macos))
                    .evidence("package.json:optionalDependencies.fsevents"),
            ]),
        );
        repo.add(PackageVersion::new(mac_only.clone(), "2.3.3"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let skipped = result
            .trace
            .iter()
            .find(|event| event.target == mac_only)
            .expect("skip trace event should exist");

        assert_eq!(skipped.outcome, ResolverTraceOutcome::Skipped);
        assert_eq!(skipped.parent_id, Some(result.trace[0].id.clone()));
        assert!(skipped.reason.contains("context predicate did not match"));
        assert_eq!(skipped.candidates_considered.len(), 0);
    }

    #[test]
    fn trace_records_conflict_constraints_and_rejected_candidates() {
        let root = PackageId::internal("app");
        let dependency = PackageId::python("shared");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dependency.clone(), VersionRequirement::parse(">=2.0"))
                    .evidence("manifest:shared>=2"),
            ]),
        );
        repo.add(PackageVersion::new(dependency.clone(), "1.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );
        let conflict = result
            .trace
            .iter()
            .find(|event| event.outcome == ResolverTraceOutcome::Conflict)
            .expect("conflict trace event should exist");

        assert_eq!(conflict.target, dependency);
        assert_eq!(conflict.candidates_considered.len(), 1);
        assert_eq!(conflict.candidates_rejected.len(), 1);
        assert_eq!(
            conflict.candidates_considered[0],
            conflict.candidates_rejected[0]
        );
        assert!(
            conflict
                .active_constraints
                .iter()
                .any(|constraint| constraint.contains("manifest:shared>=2"))
        );
    }

    #[test]
    fn selected_version_returns_none_for_unresolved_package() {
        let result = ResolveResult::default();

        assert!(
            result
                .selected_version(&PackageId::rpm("openssl-libs"))
                .is_none()
        );
    }

    #[test]
    fn test_scope_dependency_is_skipped_in_production_context() {
        let root = PackageId::internal("app");
        let pytest = PackageId::python("pytest");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(root.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(pytest.clone(), VersionRequirement::any())
                    .scope(DependencyScope::Test),
            ]),
        );
        repo.add(PackageVersion::new(pytest.clone(), "8.2.0"));

        let result = Resolver::new(repo).resolve(
            vec![DependencyRequirement::new(root, VersionRequirement::any())],
            &ResolutionContext::cloudlinux_production_x86_64(),
        );

        assert!(!result.contains_package(&pytest));
        assert_eq!(result.skipped.len(), 1);
    }
}
