//! GraphScope core library.
//!
//! This crate is the userspace prototype for the GraphScope runtime causality
//! platform. It models kernel facts as events, projects them into a causality
//! graph, and layers trust, rule, baseline, and investigation engines on top.

pub mod baseline;
pub mod event;
pub mod graph;
pub mod investigation;
pub mod rules;
pub mod storage;
pub mod trust;

pub use baseline::{BaselineEngine, BaselineFinding};
pub use event::{EventKind, RuntimeEvent};
pub use graph::{CausalityGraph, Edge, EntityKey, EntityKind, Relationship};
pub use investigation::{Investigation, InvestigationEngine};
pub use rules::{GuardRule, RuleEngine, RuleExecutionLayer, RuleFinding, Severity};
pub use storage::{
    EventJournal, InMemoryEventJournal, InMemoryKernelPolicyStore, InMemoryMetadataStore,
    KernelPolicyStore, MetadataStore,
};
pub use trust::{TrustEngine, TrustFinding, TrustPath, TrustVerdict, TrustedArtifact};
