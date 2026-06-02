use crate::graph::{CausalityGraph, EntityKey};
use crate::trust::{TrustEngine, TrustFinding, TrustPath};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Investigation {
    pub question: String,
    pub target: EntityKey,
    pub causal_chain: Vec<EntityKey>,
    pub trust_findings: Vec<TrustFinding>,
    pub trust_paths: Vec<TrustPath>,
}

pub struct InvestigationEngine<'a> {
    graph: &'a CausalityGraph,
    trust: &'a TrustEngine,
}

impl<'a> InvestigationEngine<'a> {
    pub fn new(graph: &'a CausalityGraph, trust: &'a TrustEngine) -> Self {
        Self { graph, trust }
    }

    pub fn why_process_started(&self, pid: u32) -> Investigation {
        let target = EntityKey::process(pid);
        let causal_chain = self.graph.causal_chain_to(&target, 16);
        Investigation {
            question: format!("Why did process {pid} start?"),
            target: target.clone(),
            trust_paths: self.trust_paths_for_chain(&causal_chain),
            causal_chain,
            trust_findings: self.trust.evaluate_graph(self.graph),
        }
    }

    pub fn why_connection(&self, remote_addr: &str) -> Investigation {
        let target = EntityKey::socket(remote_addr.to_string());
        let causal_chain = self.graph.causal_chain_to(&target, 16);
        Investigation {
            question: format!("Why did connection to {remote_addr} occur?"),
            target: target.clone(),
            trust_paths: self.trust_paths_for_chain(&causal_chain),
            causal_chain,
            trust_findings: self.trust.evaluate_graph(self.graph),
        }
    }

    pub fn why_security_event(&self, event_id: &str) -> Investigation {
        let target = EntityKey::security_event(event_id.to_string());
        let causal_chain = self.graph.causal_chain_to(&target, 16);
        Investigation {
            question: format!("Why did security event {event_id} occur?"),
            target,
            trust_paths: self.trust_paths_for_chain(&causal_chain),
            causal_chain,
            trust_findings: self.trust.evaluate_graph(self.graph),
        }
    }

    fn trust_paths_for_chain(&self, chain: &[EntityKey]) -> Vec<TrustPath> {
        let mut paths = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for entity in chain {
            let Some(node) = self.graph.node(entity) else {
                continue;
            };
            let Some(executable) = node.attributes.get("executable") else {
                continue;
            };
            if !seen.insert(executable.clone()) {
                continue;
            }
            let euid = node
                .attributes
                .get("euid")
                .and_then(|value| value.parse::<u32>().ok());
            paths.push(
                self.trust
                    .reconstruct_trust_path(self.graph, executable, euid),
            );
        }
        paths
    }
}
