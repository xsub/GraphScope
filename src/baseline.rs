use crate::event::{EventKind, RuntimeEvent};
use crate::graph::CausalityGraph;
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaselineFinding {
    pub executable: String,
    pub behavior: String,
    pub observed: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct BaselineEngine {
    parents_by_child: HashMap<String, BTreeSet<String>>,
    children_by_parent: HashMap<String, BTreeSet<String>>,
    destinations_by_executable: HashMap<String, BTreeSet<String>>,
    modified_files_by_executable: HashMap<String, BTreeSet<String>>,
    selinux_contexts_by_executable: HashMap<String, BTreeSet<String>>,
}

impl BaselineEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn learn(&mut self, graph: &CausalityGraph, event: &RuntimeEvent) {
        match &event.kind {
            EventKind::ProcessExec {
                pid,
                ppid,
                executable,
                selinux_context,
                ..
            } => {
                if *ppid > 0 {
                    if let Some(parent_executable) = graph.process_executable(*ppid) {
                        self.parents_by_child
                            .entry(executable.clone())
                            .or_default()
                            .insert(parent_executable.to_string());
                        self.children_by_parent
                            .entry(parent_executable.to_string())
                            .or_default()
                            .insert(executable.clone());
                    }
                }
                if let Some(context) = selinux_context {
                    self.selinux_contexts_by_executable
                        .entry(executable.clone())
                        .or_default()
                        .insert(context.clone());
                }
                if let Some(process_executable) = graph.process_executable(*pid) {
                    self.parents_by_child
                        .entry(process_executable.to_string())
                        .or_default();
                }
            }
            EventKind::NetworkConnect {
                pid, remote_addr, ..
            } => {
                if let Some(executable) = graph.process_executable(*pid) {
                    self.destinations_by_executable
                        .entry(executable.to_string())
                        .or_default()
                        .insert(remote_addr.clone());
                }
            }
            EventKind::FileModify { pid, path } => {
                if let Some(executable) = graph.process_executable(*pid) {
                    self.modified_files_by_executable
                        .entry(executable.to_string())
                        .or_default()
                        .insert(path.clone());
                }
            }
            _ => {}
        }
    }

    pub fn assess(&self, graph: &CausalityGraph, event: &RuntimeEvent) -> Vec<BaselineFinding> {
        match &event.kind {
            EventKind::ProcessExec {
                ppid, executable, ..
            } => {
                let mut findings = self.assess_parent(graph, *ppid, executable);
                findings.extend(self.assess_child(graph, *ppid, executable));
                findings
            }
            EventKind::NetworkConnect {
                pid, remote_addr, ..
            } => self.assess_destination(graph, *pid, remote_addr),
            EventKind::FileModify { pid, path } => self.assess_modified_file(graph, *pid, path),
            _ => Vec::new(),
        }
    }

    fn assess_parent(
        &self,
        graph: &CausalityGraph,
        ppid: u32,
        executable: &str,
    ) -> Vec<BaselineFinding> {
        let Some(expected_parents) = self.parents_by_child.get(executable) else {
            return Vec::new();
        };
        let Some(parent_executable) = graph.process_executable(ppid) else {
            return Vec::new();
        };
        if parent_executable == executable {
            return Vec::new();
        }
        if expected_parents.contains(parent_executable) {
            return Vec::new();
        }
        vec![BaselineFinding {
            executable: executable.to_string(),
            behavior: "parent".to_string(),
            observed: parent_executable.to_string(),
            reason: format!(
                "expected one of [{}]",
                expected_parents
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }]
    }

    fn assess_child(
        &self,
        graph: &CausalityGraph,
        ppid: u32,
        executable: &str,
    ) -> Vec<BaselineFinding> {
        let Some(parent_executable) = graph.process_executable(ppid) else {
            return Vec::new();
        };
        let Some(expected_children) = self.children_by_parent.get(parent_executable) else {
            return Vec::new();
        };
        if expected_children.contains(executable) {
            return Vec::new();
        }
        vec![BaselineFinding {
            executable: parent_executable.to_string(),
            behavior: "child-process".to_string(),
            observed: executable.to_string(),
            reason: format!(
                "expected one of [{}]",
                expected_children
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }]
    }

    fn assess_destination(
        &self,
        graph: &CausalityGraph,
        pid: u32,
        remote_addr: &str,
    ) -> Vec<BaselineFinding> {
        let Some(executable) = graph.process_executable(pid) else {
            return Vec::new();
        };
        let Some(expected_destinations) = self.destinations_by_executable.get(executable) else {
            return Vec::new();
        };
        if expected_destinations.contains(remote_addr) {
            return Vec::new();
        }
        vec![BaselineFinding {
            executable: executable.to_string(),
            behavior: "network-destination".to_string(),
            observed: remote_addr.to_string(),
            reason: format!(
                "expected one of [{}]",
                expected_destinations
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }]
    }

    fn assess_modified_file(
        &self,
        graph: &CausalityGraph,
        pid: u32,
        path: &str,
    ) -> Vec<BaselineFinding> {
        let Some(executable) = graph.process_executable(pid) else {
            return Vec::new();
        };
        let Some(expected_files) = self.modified_files_by_executable.get(executable) else {
            return Vec::new();
        };
        if expected_files.contains(path) {
            return Vec::new();
        }
        vec![BaselineFinding {
            executable: executable.to_string(),
            behavior: "modified-file".to_string(),
            observed: path.to_string(),
            reason: format!(
                "expected one of [{}]",
                expected_files
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    #[test]
    fn flags_unexpected_parent_when_baseline_exists() {
        let mut graph = CausalityGraph::new();
        let mut baseline = BaselineEngine::new();

        let systemd = RuntimeEvent::new(
            1,
            0,
            EventKind::ProcessExec {
                pid: 1,
                ppid: 0,
                executable: "/usr/lib/systemd/systemd".to_string(),
                argv: vec![],
                uid: 0,
                euid: 0,
                selinux_context: None,
            },
        );
        graph.ingest(&systemd);
        baseline.learn(&graph, &systemd);

        let expected = RuntimeEvent::new(
            2,
            0,
            EventKind::ProcessExec {
                pid: 10,
                ppid: 1,
                executable: "/usr/sbin/nginx".to_string(),
                argv: vec![],
                uid: 0,
                euid: 0,
                selinux_context: None,
            },
        );
        graph.ingest(&expected);
        baseline.learn(&graph, &expected);

        let unexpected_parent = RuntimeEvent::new(
            3,
            0,
            EventKind::ProcessExec {
                pid: 20,
                ppid: 1,
                executable: "/usr/bin/bash".to_string(),
                argv: vec![],
                uid: 0,
                euid: 0,
                selinux_context: None,
            },
        );
        graph.ingest(&unexpected_parent);
        baseline.learn(&graph, &unexpected_parent);

        let shell = RuntimeEvent::new(
            4,
            0,
            EventKind::ProcessExec {
                pid: 11,
                ppid: 20,
                executable: "/usr/sbin/nginx".to_string(),
                argv: vec![],
                uid: 0,
                euid: 0,
                selinux_context: None,
            },
        );
        let findings = baseline.assess(&graph, &shell);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].behavior, "parent");
    }

    #[test]
    fn flags_unexpected_child_when_parent_baseline_exists() {
        let mut graph = CausalityGraph::new();
        let mut baseline = BaselineEngine::new();

        let nginx = RuntimeEvent::new(
            1,
            0,
            EventKind::ProcessExec {
                pid: 10,
                ppid: 0,
                executable: "/usr/sbin/nginx".to_string(),
                argv: vec![],
                uid: 0,
                euid: 0,
                selinux_context: None,
            },
        );
        graph.ingest(&nginx);
        baseline.learn(&graph, &nginx);

        let worker = RuntimeEvent::new(
            2,
            0,
            EventKind::ProcessExec {
                pid: 11,
                ppid: 10,
                executable: "/usr/sbin/nginx".to_string(),
                argv: vec![],
                uid: 997,
                euid: 997,
                selinux_context: None,
            },
        );
        graph.ingest(&worker);
        baseline.learn(&graph, &worker);

        let shell = RuntimeEvent::new(
            3,
            0,
            EventKind::ProcessExec {
                pid: 12,
                ppid: 10,
                executable: "/usr/bin/bash".to_string(),
                argv: vec![],
                uid: 997,
                euid: 997,
                selinux_context: None,
            },
        );
        let findings = baseline.assess(&graph, &shell);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].behavior, "child-process");
        assert_eq!(findings[0].observed, "/usr/bin/bash");
    }
}
