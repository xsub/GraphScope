use crate::graph::{CausalityGraph, EntityKey, EntityKind};
use crate::rules::is_tmp_path;
use std::collections::{BTreeSet, HashMap};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedArtifact {
    pub path: String,
    pub package: String,
    pub digest: String,
    pub signed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustFinding {
    pub entity: EntityKey,
    pub verdict: TrustVerdict,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPath {
    pub target: EntityKey,
    pub verdict: TrustVerdict,
    pub path: Vec<EntityKey>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustVerdict {
    Trusted,
    Unknown,
    Suspicious,
    Untrusted,
}

impl fmt::Display for TrustVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Trusted => "trusted",
            Self::Unknown => "unknown",
            Self::Suspicious => "suspicious",
            Self::Untrusted => "untrusted",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, Default)]
pub struct TrustEngine {
    artifacts_by_path: HashMap<String, TrustedArtifact>,
}

impl TrustEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust_artifact(&mut self, artifact: TrustedArtifact) {
        self.artifacts_by_path
            .insert(artifact.path.clone(), artifact);
    }

    pub fn evaluate_executable(&self, path: &str, euid: Option<u32>) -> TrustFinding {
        let entity = EntityKey::file(path.to_string());
        if let Some(artifact) = self.artifacts_by_path.get(path) {
            if artifact.signed {
                return TrustFinding {
                    entity,
                    verdict: TrustVerdict::Trusted,
                    reason: format!(
                        "owned by signed package '{}' with digest {}",
                        artifact.package, artifact.digest
                    ),
                };
            }

            return TrustFinding {
                entity,
                verdict: TrustVerdict::Suspicious,
                reason: format!("owned by unsigned package '{}'", artifact.package),
            };
        }

        if euid == Some(0) && is_tmp_path(path) {
            return TrustFinding {
                entity,
                verdict: TrustVerdict::Untrusted,
                reason: "root execution from a temporary path has no trusted provenance"
                    .to_string(),
            };
        }

        TrustFinding {
            entity,
            verdict: TrustVerdict::Unknown,
            reason: "no package ownership or build provenance recorded".to_string(),
        }
    }

    pub fn evaluate_graph(&self, graph: &CausalityGraph) -> Vec<TrustFinding> {
        let mut seen = BTreeSet::new();
        let mut findings = graph
            .nodes()
            .filter(|node| node.key.kind == EntityKind::Process)
            .filter_map(|node| {
                let executable = node.attributes.get("executable")?;
                if !seen.insert(executable.clone()) {
                    return None;
                }
                let euid = node
                    .attributes
                    .get("euid")
                    .and_then(|value| value.parse::<u32>().ok());
                Some(self.evaluate_executable(executable, euid))
            })
            .collect::<Vec<_>>();
        findings.sort_by(|left, right| left.entity.to_string().cmp(&right.entity.to_string()));
        findings
    }

    pub fn reconstruct_trust_path(
        &self,
        graph: &CausalityGraph,
        executable_path: &str,
        euid: Option<u32>,
    ) -> TrustPath {
        let finding = self.evaluate_executable(executable_path, euid);
        let target = EntityKey::file(executable_path.to_string());
        let path = graph
            .nodes()
            .filter(|node| node.key.kind == EntityKind::SourceRepository)
            .filter_map(|node| graph.provenance_path(&node.key, &target))
            .min_by_key(path_rank)
            .or_else(|| {
                graph
                    .nodes()
                    .filter(|node| node.key.kind == EntityKind::RpmPackage)
                    .filter_map(|node| graph.provenance_path(&node.key, &target))
                    .min_by_key(path_rank)
            })
            .unwrap_or_else(|| vec![target.clone()]);

        TrustPath {
            target,
            verdict: finding.verdict,
            path,
            reason: finding.reason,
        }
    }
}

fn path_rank(path: &Vec<EntityKey>) -> (bool, usize) {
    (
        !path
            .iter()
            .any(|entity| entity.kind == EntityKind::Dependency),
        path.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, RuntimeEvent};

    #[test]
    fn root_tmp_execution_is_untrusted() {
        let engine = TrustEngine::new();
        let finding = engine.evaluate_executable("/tmp/payload", Some(0));

        assert_eq!(finding.verdict, TrustVerdict::Untrusted);
    }

    #[test]
    fn reconstructs_source_to_file_trust_path() {
        let mut graph = CausalityGraph::new();
        let mut engine = TrustEngine::new();
        let repository = "https://example.test/nginx.git".to_string();
        let artifact = "nginx.rpm".to_string();
        let package = "nginx-1.26.0-2.el10".to_string();
        let file = "/usr/sbin/nginx".to_string();

        engine.trust_artifact(TrustedArtifact {
            path: file.clone(),
            package: package.clone(),
            digest: "sha256:nginx".to_string(),
            signed: true,
        });

        for event in [
            RuntimeEvent::new(
                1,
                0,
                EventKind::SourceDependency {
                    repository: repository.clone(),
                    dependency: "openssl".to_string(),
                    version: "3.2.0".to_string(),
                    ecosystem: "rpm".to_string(),
                },
            ),
            RuntimeEvent::new(
                2,
                0,
                EventKind::ArtifactDependency {
                    artifact: artifact.clone(),
                    dependency: "openssl".to_string(),
                    version: "3.2.0".to_string(),
                    ecosystem: "rpm".to_string(),
                },
            ),
            RuntimeEvent::new(
                3,
                0,
                EventKind::ArtifactPackage {
                    artifact,
                    package: package.clone(),
                },
            ),
            RuntimeEvent::new(
                4,
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

        let trust_path = engine.reconstruct_trust_path(&graph, &file, Some(0));

        assert_eq!(trust_path.verdict, TrustVerdict::Trusted);
        assert_eq!(
            trust_path.path.first().unwrap().kind,
            EntityKind::SourceRepository
        );
        assert_eq!(trust_path.path.last().unwrap(), &EntityKey::file(file));
        assert!(
            trust_path
                .path
                .iter()
                .any(|entity| entity.kind == EntityKind::Dependency)
        );
    }
}
