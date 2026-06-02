use crate::event::{EventKind, RuntimeEvent};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityKey {
    pub kind: EntityKind,
    pub id: String,
}

impl EntityKey {
    pub fn new(kind: EntityKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    pub fn process(pid: u32) -> Self {
        Self::new(EntityKind::Process, format!("pid:{pid}"))
    }

    pub fn file(path: impl Into<String>) -> Self {
        Self::new(EntityKind::File, path)
    }

    pub fn socket(remote_addr: impl Into<String>) -> Self {
        Self::new(EntityKind::Socket, remote_addr)
    }

    pub fn user(uid: u32) -> Self {
        Self::new(EntityKind::User, format!("uid:{uid}"))
    }

    pub fn source_repository(repository: impl Into<String>) -> Self {
        Self::new(EntityKind::SourceRepository, repository)
    }

    pub fn dependency(
        ecosystem: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self::new(
            EntityKind::Dependency,
            format!("{}:{}@{}", ecosystem.into(), name.into(), version.into()),
        )
    }

    pub fn build_artifact(artifact: impl Into<String>) -> Self {
        Self::new(EntityKind::BuildArtifact, artifact)
    }

    pub fn sbom_component(component: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            EntityKind::SbomComponent,
            format!("{}@{}", component.into(), version.into()),
        )
    }

    pub fn security_event(event_id: impl Into<String>) -> Self {
        Self::new(EntityKind::SecurityEvent, event_id)
    }
}

impl fmt::Display for EntityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntityKind {
    Process,
    File,
    Socket,
    User,
    Group,
    SelinuxContext,
    Namespace,
    Container,
    Image,
    Service,
    RpmPackage,
    BuildArtifact,
    SourceRepository,
    Dependency,
    SbomComponent,
    BpfProgram,
    KernelModule,
    SecurityEvent,
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Process => "process",
            Self::File => "file",
            Self::Socket => "socket",
            Self::User => "user",
            Self::Group => "group",
            Self::SelinuxContext => "selinux-context",
            Self::Namespace => "namespace",
            Self::Container => "container",
            Self::Image => "image",
            Self::Service => "service",
            Self::RpmPackage => "rpm-package",
            Self::BuildArtifact => "build-artifact",
            Self::SourceRepository => "source-repository",
            Self::Dependency => "dependency",
            Self::SbomComponent => "sbom-component",
            Self::BpfProgram => "bpf-program",
            Self::KernelModule => "kernel-module",
            Self::SecurityEvent => "security-event",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub key: EntityKey,
    pub labels: BTreeSet<String>,
    pub attributes: BTreeMap<String, String>,
}

impl Node {
    pub fn new(key: EntityKey) -> Self {
        Self {
            key,
            labels: BTreeSet::new(),
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    pub source: EntityKey,
    pub target: EntityKey,
    pub relationship: Relationship,
    pub event_sequence: u64,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Relationship {
    Spawned,
    Opened,
    Modified,
    Deleted,
    Connected,
    Inherited,
    Authenticated,
    Transitioned,
    Loaded,
    Executed,
    Installed,
    DependsOn,
    BuiltFrom,
    InstalledFrom,
    Owns,
    Caused,
    TrustedBy,
    DeniedBy,
}

impl fmt::Display for Relationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Spawned => "spawned",
            Self::Opened => "opened",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::Connected => "connected",
            Self::Inherited => "inherited",
            Self::Authenticated => "authenticated",
            Self::Transitioned => "transitioned",
            Self::Loaded => "loaded",
            Self::Executed => "executed",
            Self::Installed => "installed",
            Self::DependsOn => "depends_on",
            Self::BuiltFrom => "built_from",
            Self::InstalledFrom => "installed_from",
            Self::Owns => "owns",
            Self::Caused => "caused",
            Self::TrustedBy => "trusted_by",
            Self::DeniedBy => "denied_by",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CausalityGraph {
    nodes: HashMap<EntityKey, Node>,
    edges: Vec<Edge>,
    outgoing: HashMap<EntityKey, Vec<usize>>,
    incoming: HashMap<EntityKey, Vec<usize>>,
    process_executables: HashMap<u32, String>,
}

impl CausalityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&mut self, event: &RuntimeEvent) {
        match &event.kind {
            EventKind::ProcessExec {
                pid,
                ppid,
                executable,
                argv,
                uid,
                euid,
                selinux_context,
            } => {
                let process = EntityKey::process(*pid);
                let executable_file = EntityKey::file(executable.clone());
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.upsert_node(
                    executable_file.clone(),
                    &[
                        ("path", executable.clone()),
                        ("type", "executable".to_string()),
                    ],
                );
                self.set_attr(&process, "executable", executable);
                self.set_attr(&process, "argv", &argv.join(" "));
                self.set_attr(&process, "uid", &uid.to_string());
                self.set_attr(&process, "euid", &euid.to_string());
                self.process_executables.insert(*pid, executable.clone());

                if *ppid > 0 {
                    let parent = EntityKey::process(*ppid);
                    self.upsert_node(parent.clone(), &[("pid", ppid.to_string())]);
                    self.add_edge(
                        parent,
                        process.clone(),
                        Relationship::Spawned,
                        event.sequence,
                    );
                }

                self.add_edge(
                    executable_file,
                    process.clone(),
                    Relationship::Executed,
                    event.sequence,
                );
                self.add_edge(
                    EntityKey::user(*uid),
                    process.clone(),
                    Relationship::Inherited,
                    event.sequence,
                );

                if let Some(context) = selinux_context {
                    let context_node = EntityKey::new(EntityKind::SelinuxContext, context);
                    self.upsert_node(context_node.clone(), &[("context", context.clone())]);
                    self.add_edge(
                        context_node,
                        process,
                        Relationship::Transitioned,
                        event.sequence,
                    );
                }
            }
            EventKind::ProcessExit { pid, exit_code } => {
                let process = EntityKey::process(*pid);
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.set_attr(&process, "exit_code", &exit_code.to_string());
            }
            EventKind::FileOpen { pid, path, mode } => {
                let process = EntityKey::process(*pid);
                let file = EntityKey::file(path.clone());
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.upsert_node(file.clone(), &[("path", path.clone())]);
                let mut attributes = BTreeMap::new();
                attributes.insert("mode".to_string(), mode.to_string());
                self.add_edge_with_attrs(
                    process,
                    file,
                    Relationship::Opened,
                    event.sequence,
                    attributes,
                );
            }
            EventKind::FileModify { pid, path } => {
                let process = EntityKey::process(*pid);
                let file = EntityKey::file(path.clone());
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.upsert_node(file.clone(), &[("path", path.clone())]);
                self.add_edge(process, file, Relationship::Modified, event.sequence);
            }
            EventKind::NetworkConnect {
                pid,
                protocol,
                remote_addr,
            } => {
                let process = EntityKey::process(*pid);
                let socket = EntityKey::socket(remote_addr.clone());
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.upsert_node(
                    socket.clone(),
                    &[
                        ("remote_addr", remote_addr.clone()),
                        ("protocol", protocol.to_string()),
                    ],
                );
                self.add_edge(process, socket, Relationship::Connected, event.sequence);
            }
            EventKind::CredentialChange {
                pid,
                old_uid,
                new_uid,
                reason,
            } => {
                let process = EntityKey::process(*pid);
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.set_attr(&process, "uid", &new_uid.to_string());
                let mut attributes = BTreeMap::new();
                attributes.insert("old_uid".to_string(), old_uid.to_string());
                attributes.insert("new_uid".to_string(), new_uid.to_string());
                attributes.insert("reason".to_string(), reason.to_string());
                self.add_edge_with_attrs(
                    EntityKey::user(*old_uid),
                    EntityKey::user(*new_uid),
                    Relationship::Authenticated,
                    event.sequence,
                    attributes.clone(),
                );
                self.add_edge_with_attrs(
                    EntityKey::user(*new_uid),
                    process,
                    Relationship::Inherited,
                    event.sequence,
                    attributes,
                );
            }
            EventKind::PackageFile {
                package,
                path,
                digest,
                signed,
            } => {
                let package_node = EntityKey::new(EntityKind::RpmPackage, package);
                let file = EntityKey::file(path.clone());
                self.upsert_node(
                    package_node.clone(),
                    &[
                        ("package", package.clone()),
                        ("signed", signed.to_string()),
                        ("digest", digest.clone()),
                    ],
                );
                self.upsert_node(
                    file.clone(),
                    &[("path", path.clone()), ("digest", digest.clone())],
                );
                self.add_edge(package_node, file, Relationship::Owns, event.sequence);
            }
            EventKind::SourceRepository { repository, commit } => {
                let source = EntityKey::source_repository(repository.clone());
                self.upsert_node(
                    source,
                    &[
                        ("repository", repository.clone()),
                        ("commit", commit.clone()),
                    ],
                );
            }
            EventKind::SourceDependency {
                repository,
                dependency,
                version,
                ecosystem,
            } => {
                let source = EntityKey::source_repository(repository.clone());
                let dependency_node =
                    EntityKey::dependency(ecosystem.clone(), dependency.clone(), version.clone());
                self.upsert_node(source.clone(), &[("repository", repository.clone())]);
                self.upsert_node(
                    dependency_node.clone(),
                    &[
                        ("name", dependency.clone()),
                        ("version", version.clone()),
                        ("ecosystem", ecosystem.clone()),
                    ],
                );
                self.add_edge(
                    source,
                    dependency_node,
                    Relationship::DependsOn,
                    event.sequence,
                );
            }
            EventKind::BuildArtifact {
                artifact,
                digest,
                source_repository,
                commit,
            } => {
                let source = EntityKey::source_repository(source_repository.clone());
                let artifact_node = EntityKey::build_artifact(artifact.clone());
                self.upsert_node(
                    source.clone(),
                    &[
                        ("repository", source_repository.clone()),
                        ("commit", commit.clone()),
                    ],
                );
                self.upsert_node(
                    artifact_node.clone(),
                    &[("artifact", artifact.clone()), ("digest", digest.clone())],
                );
                self.add_edge(
                    source,
                    artifact_node,
                    Relationship::BuiltFrom,
                    event.sequence,
                );
            }
            EventKind::ArtifactDependency {
                artifact,
                dependency,
                version,
                ecosystem,
            } => {
                let dependency_node =
                    EntityKey::dependency(ecosystem.clone(), dependency.clone(), version.clone());
                let artifact_node = EntityKey::build_artifact(artifact.clone());
                self.upsert_node(
                    dependency_node.clone(),
                    &[
                        ("name", dependency.clone()),
                        ("version", version.clone()),
                        ("ecosystem", ecosystem.clone()),
                    ],
                );
                self.upsert_node(artifact_node.clone(), &[("artifact", artifact.clone())]);
                self.add_edge(
                    dependency_node,
                    artifact_node,
                    Relationship::BuiltFrom,
                    event.sequence,
                );
            }
            EventKind::ArtifactPackage { artifact, package } => {
                let artifact_node = EntityKey::build_artifact(artifact.clone());
                let package_node = EntityKey::new(EntityKind::RpmPackage, package.clone());
                self.upsert_node(artifact_node.clone(), &[("artifact", artifact.clone())]);
                self.upsert_node(package_node.clone(), &[("package", package.clone())]);
                self.add_edge(
                    artifact_node,
                    package_node,
                    Relationship::InstalledFrom,
                    event.sequence,
                );
            }
            EventKind::SbomComponent {
                artifact,
                component,
                version,
            } => {
                let artifact_node = EntityKey::build_artifact(artifact.clone());
                let component_node = EntityKey::sbom_component(component.clone(), version.clone());
                self.upsert_node(artifact_node.clone(), &[("artifact", artifact.clone())]);
                self.upsert_node(
                    component_node.clone(),
                    &[
                        ("component", component.clone()),
                        ("version", version.clone()),
                    ],
                );
                self.add_edge(
                    artifact_node,
                    component_node,
                    Relationship::DependsOn,
                    event.sequence,
                );
            }
            EventKind::KernelModuleLoad { pid, module } => {
                let process = EntityKey::process(*pid);
                let module_node = EntityKey::new(EntityKind::KernelModule, module);
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.upsert_node(module_node.clone(), &[("module", module.clone())]);
                self.add_edge(process, module_node, Relationship::Loaded, event.sequence);
            }
            EventKind::BpfProgramLoad { pid, program } => {
                let process = EntityKey::process(*pid);
                let program_node = EntityKey::new(EntityKind::BpfProgram, program);
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.upsert_node(program_node.clone(), &[("program", program.clone())]);
                self.add_edge(process, program_node, Relationship::Loaded, event.sequence);
            }
            EventKind::SelinuxAvc {
                pid,
                source_context,
                target_context,
                class_name,
                permission,
                allowed,
            } => {
                let process = EntityKey::process(*pid);
                let source = EntityKey::new(EntityKind::SelinuxContext, source_context);
                let target = EntityKey::new(EntityKind::SelinuxContext, target_context);
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.upsert_node(source.clone(), &[("context", source_context.clone())]);
                self.upsert_node(target.clone(), &[("context", target_context.clone())]);
                let mut attributes = BTreeMap::new();
                attributes.insert("class".to_string(), class_name.clone());
                attributes.insert("permission".to_string(), permission.clone());
                let relationship = if *allowed {
                    Relationship::Transitioned
                } else {
                    Relationship::DeniedBy
                };
                self.add_edge_with_attrs(
                    source,
                    process.clone(),
                    relationship,
                    event.sequence,
                    attributes,
                );
                self.add_edge(target, process, Relationship::Transitioned, event.sequence);
            }
            EventKind::ServiceStart { service, pid } => {
                let service_node = EntityKey::new(EntityKind::Service, service);
                let process = EntityKey::process(*pid);
                self.upsert_node(service_node.clone(), &[("service", service.clone())]);
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.add_edge(service_node, process, Relationship::Spawned, event.sequence);
            }
            EventKind::ContainerStart {
                container_id,
                image,
                pid,
            } => {
                let image_node = EntityKey::new(EntityKind::Image, image);
                let container = EntityKey::new(EntityKind::Container, container_id);
                let process = EntityKey::process(*pid);
                self.upsert_node(image_node.clone(), &[("image", image.clone())]);
                self.upsert_node(container.clone(), &[("container_id", container_id.clone())]);
                self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                self.add_edge(
                    image_node,
                    container.clone(),
                    Relationship::Installed,
                    event.sequence,
                );
                self.add_edge(container, process, Relationship::Spawned, event.sequence);
            }
            EventKind::SecurityEvent {
                event_id,
                pid,
                summary,
                severity,
            } => {
                let security_event = EntityKey::security_event(event_id.clone());
                self.upsert_node(
                    security_event.clone(),
                    &[
                        ("event_id", event_id.clone()),
                        ("summary", summary.clone()),
                        ("severity", severity.clone()),
                    ],
                );
                if let Some(pid) = pid {
                    let process = EntityKey::process(*pid);
                    self.upsert_node(process.clone(), &[("pid", pid.to_string())]);
                    self.add_edge(
                        process,
                        security_event,
                        Relationship::Caused,
                        event.sequence,
                    );
                }
            }
        }
    }

    pub fn node(&self, key: &EntityKey) -> Option<&Node> {
        self.nodes.get(key)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    pub fn process_executable(&self, pid: u32) -> Option<&str> {
        self.process_executables.get(&pid).map(String::as_str)
    }

    pub fn causal_path(&self, source: &EntityKey, target: &EntityKey) -> Option<Vec<EntityKey>> {
        if source == target {
            return Some(vec![source.clone()]);
        }

        let mut queue = VecDeque::from([source.clone()]);
        let mut visited = BTreeSet::from([source.clone()]);
        let mut previous: HashMap<EntityKey, EntityKey> = HashMap::new();

        while let Some(current) = queue.pop_front() {
            for edge_index in self.outgoing.get(&current).into_iter().flatten() {
                let next = self.edges[*edge_index].target.clone();
                if !visited.insert(next.clone()) {
                    continue;
                }
                previous.insert(next.clone(), current.clone());
                if &next == target {
                    return Some(reconstruct_path(source, target, previous));
                }
                queue.push_back(next);
            }
        }

        None
    }

    pub fn provenance_path(
        &self,
        source: &EntityKey,
        target: &EntityKey,
    ) -> Option<Vec<EntityKey>> {
        let mut visited = BTreeSet::from([source.clone()]);
        let mut path = vec![source.clone()];
        if self.provenance_path_inner(source, target, &mut visited, &mut path) {
            Some(path)
        } else {
            None
        }
    }

    pub fn causal_chain_to(&self, target: &EntityKey, max_depth: usize) -> Vec<EntityKey> {
        let mut chain = vec![target.clone()];
        let mut current = target.clone();

        for _ in 0..max_depth {
            let Some(edge_indexes) = self.incoming.get(&current) else {
                break;
            };
            let incoming_edges = edge_indexes
                .iter()
                .map(|index| &self.edges[*index])
                .collect::<Vec<_>>();
            let Some(next_edge) = preferred_incoming_edge(&current, &incoming_edges) else {
                break;
            };
            current = next_edge.source.clone();
            chain.push(current.clone());
        }

        chain.reverse();
        chain
    }

    fn provenance_path_inner(
        &self,
        current: &EntityKey,
        target: &EntityKey,
        visited: &mut BTreeSet<EntityKey>,
        path: &mut Vec<EntityKey>,
    ) -> bool {
        if current == target {
            return true;
        }

        let Some(edge_indexes) = self.outgoing.get(current) else {
            return false;
        };
        let mut edges = edge_indexes
            .iter()
            .map(|index| &self.edges[*index])
            .filter(|edge| is_provenance_relationship(&edge.relationship))
            .collect::<Vec<_>>();
        edges.sort_by_key(|edge| provenance_relationship_preference(&edge.relationship));

        for edge in edges {
            if !visited.insert(edge.target.clone()) {
                continue;
            }
            path.push(edge.target.clone());
            if self.provenance_path_inner(&edge.target, target, visited, path) {
                return true;
            }
            path.pop();
        }

        false
    }

    fn upsert_node(&mut self, key: EntityKey, attrs: &[(&str, String)]) {
        let node = self
            .nodes
            .entry(key.clone())
            .or_insert_with(|| Node::new(key));
        node.labels.insert(node.key.kind.to_string());
        for (name, value) in attrs {
            node.attributes.insert((*name).to_string(), value.clone());
        }
    }

    fn set_attr(&mut self, key: &EntityKey, name: &str, value: &str) {
        let node = self
            .nodes
            .entry(key.clone())
            .or_insert_with(|| Node::new(key.clone()));
        node.attributes.insert(name.to_string(), value.to_string());
    }

    fn add_edge(
        &mut self,
        source: EntityKey,
        target: EntityKey,
        relationship: Relationship,
        event_sequence: u64,
    ) {
        self.add_edge_with_attrs(
            source,
            target,
            relationship,
            event_sequence,
            BTreeMap::new(),
        );
    }

    fn add_edge_with_attrs(
        &mut self,
        source: EntityKey,
        target: EntityKey,
        relationship: Relationship,
        event_sequence: u64,
        attributes: BTreeMap<String, String>,
    ) {
        self.upsert_node(source.clone(), &[]);
        self.upsert_node(target.clone(), &[]);
        let index = self.edges.len();
        self.edges.push(Edge {
            source: source.clone(),
            target: target.clone(),
            relationship,
            event_sequence,
            attributes,
        });
        self.outgoing.entry(source).or_default().push(index);
        self.incoming.entry(target).or_default().push(index);
    }
}

fn preferred_incoming_edge<'a>(
    current: &EntityKey,
    incoming_edges: &[&'a Edge],
) -> Option<&'a Edge> {
    if current.kind == EntityKind::Process {
        return incoming_edges
            .iter()
            .copied()
            .filter(|edge| edge.relationship == Relationship::Spawned)
            .min_by_key(|edge| edge.event_sequence);
    }

    incoming_edges.iter().copied().min_by_key(|edge| {
        (
            relationship_preference(&edge.relationship),
            edge.event_sequence,
        )
    })
}

fn relationship_preference(relationship: &Relationship) -> u8 {
    match relationship {
        Relationship::Spawned => 0,
        Relationship::Connected => 1,
        Relationship::Modified => 2,
        Relationship::Executed => 3,
        Relationship::Authenticated => 4,
        Relationship::Inherited => 5,
        Relationship::Transitioned => 6,
        Relationship::Opened => 7,
        Relationship::Loaded => 8,
        Relationship::Installed => 9,
        Relationship::DependsOn => 10,
        Relationship::BuiltFrom => 11,
        Relationship::InstalledFrom => 12,
        Relationship::Owns => 13,
        Relationship::Caused => 14,
        Relationship::TrustedBy => 15,
        Relationship::DeniedBy => 16,
        Relationship::Deleted => 17,
    }
}

fn is_provenance_relationship(relationship: &Relationship) -> bool {
    matches!(
        relationship,
        Relationship::DependsOn
            | Relationship::BuiltFrom
            | Relationship::InstalledFrom
            | Relationship::Owns
            | Relationship::Installed
            | Relationship::TrustedBy
    )
}

fn provenance_relationship_preference(relationship: &Relationship) -> u8 {
    match relationship {
        Relationship::DependsOn => 0,
        Relationship::BuiltFrom => 1,
        Relationship::InstalledFrom => 2,
        Relationship::Owns => 3,
        Relationship::Installed => 4,
        Relationship::TrustedBy => 5,
        _ => 99,
    }
}

fn reconstruct_path(
    source: &EntityKey,
    target: &EntityKey,
    previous: HashMap<EntityKey, EntityKey>,
) -> Vec<EntityKey> {
    let mut path = vec![target.clone()];
    let mut current = target.clone();
    while &current != source {
        let Some(parent) = previous.get(&current) else {
            break;
        };
        current = parent.clone();
        path.push(current.clone());
    }
    path.reverse();
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, RuntimeEvent};

    #[test]
    fn process_exec_creates_spawn_path() {
        let mut graph = CausalityGraph::new();
        graph.ingest(&RuntimeEvent::new(
            1,
            0,
            EventKind::ProcessExec {
                pid: 1,
                ppid: 0,
                executable: "/usr/lib/systemd/systemd".to_string(),
                argv: vec!["systemd".to_string()],
                uid: 0,
                euid: 0,
                selinux_context: None,
            },
        ));
        graph.ingest(&RuntimeEvent::new(
            2,
            0,
            EventKind::ProcessExec {
                pid: 100,
                ppid: 1,
                executable: "/usr/sbin/nginx".to_string(),
                argv: vec!["nginx".to_string()],
                uid: 0,
                euid: 0,
                selinux_context: None,
            },
        ));

        let path = graph
            .causal_path(&EntityKey::process(1), &EntityKey::process(100))
            .expect("spawn path");
        assert_eq!(path, vec![EntityKey::process(1), EntityKey::process(100)]);
    }

    #[test]
    fn supply_chain_events_create_trust_path_to_runtime_file() {
        let mut graph = CausalityGraph::new();
        let repository = "https://example.test/nginx.git".to_string();
        let artifact = "nginx-1.26.0-2.el10.x86_64.rpm".to_string();
        let package = "nginx-1.26.0-2.el10".to_string();
        let file = "/usr/sbin/nginx".to_string();

        for event in [
            RuntimeEvent::new(
                1,
                0,
                EventKind::SourceRepository {
                    repository: repository.clone(),
                    commit: "abc123".to_string(),
                },
            ),
            RuntimeEvent::new(
                2,
                0,
                EventKind::SourceDependency {
                    repository: repository.clone(),
                    dependency: "openssl".to_string(),
                    version: "3.2.0".to_string(),
                    ecosystem: "rpm".to_string(),
                },
            ),
            RuntimeEvent::new(
                3,
                0,
                EventKind::ArtifactDependency {
                    artifact: artifact.clone(),
                    dependency: "openssl".to_string(),
                    version: "3.2.0".to_string(),
                    ecosystem: "rpm".to_string(),
                },
            ),
            RuntimeEvent::new(
                4,
                0,
                EventKind::ArtifactPackage {
                    artifact: artifact.clone(),
                    package: package.clone(),
                },
            ),
            RuntimeEvent::new(
                5,
                0,
                EventKind::PackageFile {
                    package,
                    path: file.clone(),
                    digest: "sha256:nginx".to_string(),
                    signed: true,
                },
            ),
        ] {
            graph.ingest(&event);
        }

        let path = graph
            .provenance_path(
                &EntityKey::source_repository(repository),
                &EntityKey::file(file),
            )
            .expect("source to installed file path");

        assert_eq!(path.len(), 5);
        assert_eq!(path[0].kind, EntityKind::SourceRepository);
        assert_eq!(path[1].kind, EntityKind::Dependency);
        assert_eq!(path[2].kind, EntityKind::BuildArtifact);
        assert_eq!(path[3].kind, EntityKind::RpmPackage);
        assert_eq!(path[4].kind, EntityKind::File);
    }
}
