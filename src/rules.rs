use crate::event::{CredentialReason, EventKind, RuntimeEvent};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleFinding {
    pub rule: GuardRule,
    pub layer: RuleExecutionLayer,
    pub severity: Severity,
    pub subject: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardRule {
    UnexpectedUid0Transition,
    UnexpectedCapabilityGain,
    ExecutionFromTmpAsRoot,
    UnknownSetuidExecution,
    UnexpectedBpfProgramLoad,
    UnexpectedKernelModuleLoad,
    ContainerEscapeIndicator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleExecutionLayer {
    KernelHardGuard,
    UserspaceSoftRule,
}

impl fmt::Display for RuleExecutionLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::KernelHardGuard => "kernel_hard_guard",
            Self::UserspaceSoftRule => "userspace_soft_rule",
        };
        f.write_str(value)
    }
}

impl fmt::Display for GuardRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::UnexpectedUid0Transition => "unexpected_uid0_transition",
            Self::UnexpectedCapabilityGain => "unexpected_capability_gain",
            Self::ExecutionFromTmpAsRoot => "execution_from_tmp_as_root",
            Self::UnknownSetuidExecution => "unknown_setuid_execution",
            Self::UnexpectedBpfProgramLoad => "unexpected_bpf_program_load",
            Self::UnexpectedKernelModuleLoad => "unexpected_kernel_module_load",
            Self::ContainerEscapeIndicator => "container_escape_indicator",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug)]
pub struct RuleEngine {
    enabled: Vec<GuardRule>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self {
            enabled: vec![
                GuardRule::UnexpectedUid0Transition,
                GuardRule::ExecutionFromTmpAsRoot,
                GuardRule::UnexpectedBpfProgramLoad,
                GuardRule::UnexpectedKernelModuleLoad,
            ],
        }
    }
}

impl RuleEngine {
    pub fn new(enabled: Vec<GuardRule>) -> Self {
        Self { enabled }
    }

    pub fn evaluate(&self, event: &RuntimeEvent) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for rule in &self.enabled {
            if let Some(finding) = evaluate_rule(rule, event) {
                findings.push(finding);
            }
        }
        findings
    }
}

fn evaluate_rule(rule: &GuardRule, event: &RuntimeEvent) -> Option<RuleFinding> {
    match (rule, &event.kind) {
        (
            GuardRule::UnexpectedUid0Transition,
            EventKind::CredentialChange {
                pid,
                old_uid,
                new_uid,
                reason,
            },
        ) if *new_uid == 0 && *old_uid != 0 && !is_expected_root_reason(reason) => {
            Some(RuleFinding {
                rule: rule.clone(),
                layer: RuleExecutionLayer::KernelHardGuard,
                severity: Severity::High,
                subject: format!("pid:{pid}"),
                reason: format!(
                    "uid changed from {old_uid} to 0 through untrusted reason '{reason}'"
                ),
            })
        }
        (
            GuardRule::ExecutionFromTmpAsRoot,
            EventKind::ProcessExec {
                pid,
                executable,
                euid,
                ..
            },
        ) if *euid == 0 && is_tmp_path(executable) => Some(RuleFinding {
            rule: rule.clone(),
            layer: RuleExecutionLayer::KernelHardGuard,
            severity: Severity::Critical,
            subject: format!("pid:{pid}"),
            reason: format!("root process executed from temporary path '{executable}'"),
        }),
        (GuardRule::UnexpectedBpfProgramLoad, EventKind::BpfProgramLoad { pid, program }) => {
            Some(RuleFinding {
                rule: rule.clone(),
                layer: RuleExecutionLayer::KernelHardGuard,
                severity: Severity::Medium,
                subject: format!("pid:{pid}"),
                reason: format!("loaded BPF program '{program}'"),
            })
        }
        (GuardRule::UnexpectedKernelModuleLoad, EventKind::KernelModuleLoad { pid, module }) => {
            Some(RuleFinding {
                rule: rule.clone(),
                layer: RuleExecutionLayer::KernelHardGuard,
                severity: Severity::High,
                subject: format!("pid:{pid}"),
                reason: format!("loaded kernel module '{module}'"),
            })
        }
        _ => None,
    }
}

fn is_expected_root_reason(reason: &CredentialReason) -> bool {
    matches!(
        reason,
        CredentialReason::Sudo
            | CredentialReason::Pam
            | CredentialReason::Polkit
            | CredentialReason::SetUid
    )
}

pub fn is_tmp_path(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path == "/tmp"
        || path == "/var/tmp"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unexpected_uid_zero_transition() {
        let engine = RuleEngine::default();
        let findings = engine.evaluate(&RuntimeEvent::new(
            1,
            0,
            EventKind::CredentialChange {
                pid: 42,
                old_uid: 1000,
                new_uid: 0,
                reason: CredentialReason::Unknown,
            },
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, GuardRule::UnexpectedUid0Transition);
    }
}
