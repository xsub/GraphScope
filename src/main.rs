use graphscope::event::{CredentialReason, EventKind, NetworkProtocol, RuntimeEvent};
use graphscope::{
    BaselineEngine, CausalityGraph, EntityKey, EventJournal, InMemoryEventJournal,
    InvestigationEngine, RuleEngine, TrustEngine, TrustedArtifact,
};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        None | Some("demo") => run_demo(),
        Some("help") | Some("--help") | Some("-h") => print_help(),
        Some(command) => {
            eprintln!("unknown command: {command}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("GraphScope");
    println!();
    println!("Usage:");
    println!("  graphscope demo     replay a sample causality investigation");
    println!("  graphscope help     show this help");
}

fn run_demo() {
    let events = demo_events();
    let mut journal = InMemoryEventJournal::new();
    let mut graph = CausalityGraph::new();
    let mut baseline = BaselineEngine::new();
    let rules = RuleEngine::default();
    let mut trust = TrustEngine::new();

    trust.trust_artifact(TrustedArtifact {
        path: "/usr/lib/systemd/systemd".to_string(),
        package: "systemd-256.1-1.el10".to_string(),
        digest: "sha256:systemd-demo".to_string(),
        signed: true,
    });
    trust.trust_artifact(TrustedArtifact {
        path: "/usr/sbin/nginx".to_string(),
        package: "nginx-1.26.0-2.el10".to_string(),
        digest: "sha256:nginx-demo".to_string(),
        signed: true,
    });

    println!("GraphScope demo: universal relationship graph reconstruction");
    println!();

    for event in events {
        for finding in baseline.assess(&graph, &event) {
            println!(
                "[baseline] {} {} observed={} ({})",
                finding.executable, finding.behavior, finding.observed, finding.reason
            );
        }
        for finding in rules.evaluate(&event) {
            println!(
                "[{}:{}] {} subject={} ({})",
                finding.layer, finding.severity, finding.rule, finding.subject, finding.reason
            );
        }
        graph.ingest(&event);
        baseline.learn(&graph, &event);
        journal.append(event);
    }

    let investigator = InvestigationEngine::new(&graph, &trust);
    let investigation = investigator.why_security_event("evt-0001");

    println!();
    println!("{}", investigation.question);
    println!("{}", format_chain(&investigation.causal_chain));

    println!();
    println!("Trust findings");
    for finding in investigation.trust_findings {
        println!(
            "- {}: {} ({})",
            finding.entity, finding.verdict, finding.reason
        );
    }

    println!();
    println!("Trust paths");
    for path in investigation.trust_paths {
        println!(
            "- {}: {} ({})",
            path.target,
            format_chain(&path.path),
            path.reason
        );
    }

    println!();
    println!(
        "Replay journal contains {} ordered events",
        journal.replay().len()
    );

    if let Some(path) = graph.causal_path(
        &EntityKey::process(1),
        &EntityKey::security_event("evt-0001"),
    ) {
        println!("Root-to-alert path: {}", format_chain(&path));
    }
}

fn format_chain(chain: &[EntityKey]) -> String {
    chain
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn demo_events() -> Vec<RuntimeEvent> {
    let repository = "https://git.example.test/platform/nginx".to_string();
    let artifact = "nginx-1.26.0-2.el10.x86_64.rpm".to_string();
    let package = "nginx-1.26.0-2.el10".to_string();

    vec![
        RuntimeEvent::new(
            1,
            0,
            EventKind::SourceRepository {
                repository: repository.clone(),
                commit: "8f4f2a1".to_string(),
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
            EventKind::BuildArtifact {
                artifact: artifact.clone(),
                digest: "sha256:nginx-artifact-demo".to_string(),
                source_repository: repository,
                commit: "8f4f2a1".to_string(),
            },
        ),
        RuntimeEvent::new(
            4,
            0,
            EventKind::ArtifactDependency {
                artifact: artifact.clone(),
                dependency: "openssl".to_string(),
                version: "3.2.0".to_string(),
                ecosystem: "rpm".to_string(),
            },
        ),
        RuntimeEvent::new(
            5,
            0,
            EventKind::SbomComponent {
                artifact: artifact.clone(),
                component: "openssl".to_string(),
                version: "3.2.0".to_string(),
            },
        ),
        RuntimeEvent::new(
            6,
            0,
            EventKind::ArtifactPackage {
                artifact,
                package: package.clone(),
            },
        ),
        RuntimeEvent::new(
            7,
            0,
            EventKind::PackageFile {
                package,
                path: "/usr/sbin/nginx".to_string(),
                digest: "sha256:nginx-demo".to_string(),
                signed: true,
            },
        ),
        RuntimeEvent::new(
            8,
            0,
            EventKind::PackageFile {
                package: "systemd-256.1-1.el10".to_string(),
                path: "/usr/lib/systemd/systemd".to_string(),
                digest: "sha256:systemd-demo".to_string(),
                signed: true,
            },
        ),
        RuntimeEvent::new(
            100,
            0,
            EventKind::ProcessExec {
                pid: 1,
                ppid: 0,
                executable: "/usr/lib/systemd/systemd".to_string(),
                argv: vec!["systemd".to_string()],
                uid: 0,
                euid: 0,
                selinux_context: Some("system_u:system_r:init_t:s0".to_string()),
            },
        ),
        RuntimeEvent::new(
            101,
            1,
            EventKind::ProcessExec {
                pid: 100,
                ppid: 1,
                executable: "/usr/sbin/nginx".to_string(),
                argv: vec![
                    "nginx".to_string(),
                    "-g".to_string(),
                    "daemon off;".to_string(),
                ],
                uid: 0,
                euid: 0,
                selinux_context: Some("system_u:system_r:httpd_t:s0".to_string()),
            },
        ),
        RuntimeEvent::new(
            102,
            2,
            EventKind::ProcessExec {
                pid: 101,
                ppid: 100,
                executable: "/usr/sbin/nginx".to_string(),
                argv: vec!["nginx: worker process".to_string()],
                uid: 997,
                euid: 997,
                selinux_context: Some("system_u:system_r:httpd_t:s0".to_string()),
            },
        ),
        RuntimeEvent::new(
            103,
            3,
            EventKind::ProcessExec {
                pid: 120,
                ppid: 100,
                executable: "/usr/bin/bash".to_string(),
                argv: vec!["bash".to_string(), "-c".to_string(), "curl ...".to_string()],
                uid: 997,
                euid: 997,
                selinux_context: Some("system_u:system_r:httpd_t:s0".to_string()),
            },
        ),
        RuntimeEvent::new(
            104,
            4,
            EventKind::ProcessExec {
                pid: 121,
                ppid: 120,
                executable: "/usr/bin/curl".to_string(),
                argv: vec![
                    "curl".to_string(),
                    "-o".to_string(),
                    "/tmp/payload".to_string(),
                ],
                uid: 997,
                euid: 997,
                selinux_context: Some("system_u:system_r:httpd_t:s0".to_string()),
            },
        ),
        RuntimeEvent::new(
            105,
            5,
            EventKind::FileModify {
                pid: 121,
                path: "/tmp/payload".to_string(),
            },
        ),
        RuntimeEvent::new(
            106,
            6,
            EventKind::CredentialChange {
                pid: 122,
                old_uid: 997,
                new_uid: 0,
                reason: CredentialReason::Unknown,
            },
        ),
        RuntimeEvent::new(
            107,
            7,
            EventKind::ProcessExec {
                pid: 122,
                ppid: 121,
                executable: "/tmp/payload".to_string(),
                argv: vec!["/tmp/payload".to_string()],
                uid: 0,
                euid: 0,
                selinux_context: Some("system_u:system_r:httpd_t:s0".to_string()),
            },
        ),
        RuntimeEvent::new(
            108,
            8,
            EventKind::NetworkConnect {
                pid: 122,
                protocol: NetworkProtocol::Tcp,
                remote_addr: "1.2.3.4:443".to_string(),
            },
        ),
        RuntimeEvent::new(
            109,
            9,
            EventKind::SecurityEvent {
                event_id: "evt-0001".to_string(),
                pid: Some(122),
                summary: "root temporary payload opened outbound connection".to_string(),
                severity: "critical".to_string(),
            },
        ),
    ]
}
