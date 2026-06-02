use crate::event::RuntimeEvent;
use std::collections::{BTreeMap, BTreeSet};

pub trait EventJournal {
    fn append(&mut self, event: RuntimeEvent);
    fn replay(&self) -> Vec<RuntimeEvent>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryEventJournal {
    events: Vec<RuntimeEvent>,
}

impl InMemoryEventJournal {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EventJournal for InMemoryEventJournal {
    fn append(&mut self, event: RuntimeEvent) {
        self.events.push(event);
        self.events.sort_by_key(|event| event.sequence);
    }

    fn replay(&self) -> Vec<RuntimeEvent> {
        self.events.clone()
    }
}

pub trait KernelPolicyStore {
    fn trust_executable(&mut self, path: impl Into<String>);
    fn deny_action(&mut self, action: impl Into<String>);
    fn is_trusted_executable(&self, path: &str) -> bool;
    fn is_denied_action(&self, action: &str) -> bool;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryKernelPolicyStore {
    trusted_executables: BTreeSet<String>,
    denied_actions: BTreeSet<String>,
    counters: BTreeMap<String, u64>,
}

impl InMemoryKernelPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_counter(&mut self, name: impl Into<String>) {
        *self.counters.entry(name.into()).or_default() += 1;
    }

    pub fn counter(&self, name: &str) -> u64 {
        self.counters.get(name).copied().unwrap_or_default()
    }
}

impl KernelPolicyStore for InMemoryKernelPolicyStore {
    fn trust_executable(&mut self, path: impl Into<String>) {
        self.trusted_executables.insert(path.into());
    }

    fn deny_action(&mut self, action: impl Into<String>) {
        self.denied_actions.insert(action.into());
    }

    fn is_trusted_executable(&self, path: &str) -> bool {
        self.trusted_executables.contains(path)
    }

    fn is_denied_action(&self, action: &str) -> bool {
        self.denied_actions.contains(action)
    }
}
