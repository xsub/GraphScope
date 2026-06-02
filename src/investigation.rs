use crate::graph::{CausalityGraph, EntityKey};
use crate::trust::{TrustEngine, TrustFinding};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Investigation {
    pub question: String,
    pub target: EntityKey,
    pub causal_chain: Vec<EntityKey>,
    pub trust_findings: Vec<TrustFinding>,
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
        Investigation {
            question: format!("Why did process {pid} start?"),
            target: target.clone(),
            causal_chain: self.graph.causal_chain_to(&target, 16),
            trust_findings: self.trust.evaluate_graph(self.graph),
        }
    }

    pub fn why_connection(&self, remote_addr: &str) -> Investigation {
        let target = EntityKey::socket(remote_addr.to_string());
        Investigation {
            question: format!("Why did connection to {remote_addr} occur?"),
            target: target.clone(),
            causal_chain: self.graph.causal_chain_to(&target, 16),
            trust_findings: self.trust.evaluate_graph(self.graph),
        }
    }
}
