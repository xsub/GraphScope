use std::fmt;

/// Kernel and userspace facts normalized into a single append-only event model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub sequence: u64,
    pub timestamp_millis: u64,
    pub kind: EventKind,
}

impl RuntimeEvent {
    pub fn new(sequence: u64, timestamp_millis: u64, kind: EventKind) -> Self {
        Self {
            sequence,
            timestamp_millis,
            kind,
        }
    }

    pub fn subject_pid(&self) -> Option<u32> {
        match &self.kind {
            EventKind::ProcessExec { pid, .. }
            | EventKind::ProcessExit { pid, .. }
            | EventKind::FileOpen { pid, .. }
            | EventKind::FileModify { pid, .. }
            | EventKind::NetworkConnect { pid, .. }
            | EventKind::CredentialChange { pid, .. }
            | EventKind::KernelModuleLoad { pid, .. }
            | EventKind::BpfProgramLoad { pid, .. }
            | EventKind::SelinuxAvc { pid, .. } => Some(*pid),
            EventKind::PackageFile { .. }
            | EventKind::ServiceStart { .. }
            | EventKind::ContainerStart { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    ProcessExec {
        pid: u32,
        ppid: u32,
        executable: String,
        argv: Vec<String>,
        uid: u32,
        euid: u32,
        selinux_context: Option<String>,
    },
    ProcessExit {
        pid: u32,
        exit_code: i32,
    },
    FileOpen {
        pid: u32,
        path: String,
        mode: FileAccess,
    },
    FileModify {
        pid: u32,
        path: String,
    },
    NetworkConnect {
        pid: u32,
        protocol: NetworkProtocol,
        remote_addr: String,
    },
    CredentialChange {
        pid: u32,
        old_uid: u32,
        new_uid: u32,
        reason: CredentialReason,
    },
    PackageFile {
        package: String,
        path: String,
        digest: String,
        signed: bool,
    },
    KernelModuleLoad {
        pid: u32,
        module: String,
    },
    BpfProgramLoad {
        pid: u32,
        program: String,
    },
    SelinuxAvc {
        pid: u32,
        source_context: String,
        target_context: String,
        class_name: String,
        permission: String,
        allowed: bool,
    },
    ServiceStart {
        service: String,
        pid: u32,
    },
    ContainerStart {
        container_id: String,
        image: String,
        pid: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    Write,
    ReadWrite,
    Execute,
}

impl fmt::Display for FileAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::ReadWrite => f.write_str("read-write"),
            Self::Execute => f.write_str("execute"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Unix,
}

impl fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Unix => f.write_str("unix"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialReason {
    SetUid,
    SetGid,
    Sudo,
    Pam,
    Polkit,
    FileCapability,
    Unknown,
}

impl fmt::Display for CredentialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetUid => f.write_str("setuid"),
            Self::SetGid => f.write_str("setgid"),
            Self::Sudo => f.write_str("sudo"),
            Self::Pam => f.write_str("pam"),
            Self::Polkit => f.write_str("polkit"),
            Self::FileCapability => f.write_str("file-capability"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}
