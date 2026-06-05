//! Command-line workflows that exercise the GraphScope MVP APIs.

use graphscope::{
    AlgorithmBenchmarkConfig, ChangeEvent, CycloneDxView, EvidenceRepositoryBuilder,
    EvidenceSubject, FileChangeEventLog, FileGraphStore, GraphDiff, GraphQuery, GraphSnapshot,
    ImpactReport, InMemoryGraphStore, ProjectEvidence, RemediationReport, Resolver, ResolverJob,
    ResolverService, RiskDashboard, SlaSummary, SpdxView, TenantAccessPolicy, TenantRole, VexView,
    adapter_profiles, adapter_resolution_contract, demo_advisories, demo_policy_set,
    demo_repository, parse_evidence, run_algorithm_benchmark,
};

const REAL_WORLD_RPM_INVENTORY: &str = include_str!("../examples/real-world/almalinux-10-rpm.list");
const REAL_WORLD_OS_RELEASE: &str = include_str!("../examples/real-world/os-release.txt");
const REAL_WORLD_DNF_REPOLIST: &str = include_str!("../examples/real-world/dnf-repolist.txt");

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let command = args.get(1).map(String::as_str).unwrap_or("demo");

    match command {
        "demo" => run_demo(),
        "snapshot" => print_snapshot(),
        "impact" => print_impact(),
        "report" => print_report(),
        "sbom" => print_sbom(),
        "spdx" => print_spdx(),
        "vex" => print_vex(),
        "policy" => print_policy(),
        "sla" => print_sla(),
        "dashboard" => print_dashboard(),
        "invalidate" => print_invalidation(),
        "evidence" => print_evidence(args.get(2).map(String::as_str)),
        "resolve-evidence" => print_resolve_evidence(
            args.iter()
                .skip(2)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        ),
        "adapters" => print_adapters(),
        "real-world" => print_real_world(),
        "access" => print_access(),
        "persist" => persist_demo(args.get(2).map(String::as_str)),
        "events" => persist_demo_events(args.get(2).map(String::as_str)),
        "explain" => print_explain(),
        "diff" => print_diff(),
        "benchmark" => print_benchmark(
            args.iter()
                .skip(2)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        ),
        "help" | "--help" | "-h" => print_help(),
        unknown => {
            eprintln!("unknown command: {unknown}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("GraphScope");
    println!();
    println!("Usage:");
    println!("  graphscope demo   resolve the demo CloudLinux/TuxCare dependency graph");
    println!("  graphscope snapshot   print the demo graph as stable JSON");
    println!("  graphscope impact   print advisory impact for the demo graph");
    println!("  graphscope report   print a remediation report for the demo graph");
    println!("  graphscope sbom   print a CycloneDX-style SBOM view");
    println!("  graphscope spdx   print an SPDX-style SBOM view");
    println!("  graphscope vex   print a VEX-style advisory view");
    println!("  graphscope policy   evaluate demo customer policy");
    println!("  graphscope sla   print an SLA-style risk summary");
    println!("  graphscope dashboard   print a product risk dashboard summary");
    println!("  graphscope invalidate   plan graph invalidation from metadata changes");
    println!("  graphscope evidence <path>   normalize a manifest, lockfile, or inventory");
    println!("  graphscope resolve-evidence <path...>   resolve evidence files into a snapshot");
    println!("  graphscope adapters   show ecosystem adapter coverage");
    println!("  graphscope real-world   summarize checked-in AlmaLinux runtime evidence");
    println!("  graphscope access   demonstrate tenant access isolation");
    println!("  graphscope persist <dir>   persist the demo graph snapshot to a file store");
    println!("  graphscope events <dir>   append demo invalidation events to a file log");
    println!("  graphscope explain   explain why urllib3 is present in the demo graph");
    println!("  graphscope diff   compare demo graph with and without optional GPU context");
    println!(
        "  graphscope benchmark [layers width fanout max_paths]   benchmark graph creation and traversal"
    );
    println!("  graphscope help   show this help");
}

fn print_snapshot() {
    let (repository, roots, context) = demo_repository();
    let result = Resolver::new(repository).resolve(roots, &context);
    let snapshot = GraphSnapshot::from_resolve_result(
        "tuxcare-demo",
        env!("CARGO_PKG_VERSION"),
        &context,
        &result,
    );

    println!("{}", snapshot.to_json_pretty());
}

fn run_demo() {
    let (repository, roots, context) = demo_repository();
    let package_count = repository.package_count();
    let result = Resolver::new(repository).resolve(roots, &context);

    println!("GraphScope unified dependency graph demo");
    println!("Context: CloudLinux 9 x86_64 production, ELS + KernelCare, GPU extra enabled");
    println!("Candidate catalog: {package_count} package versions");
    println!();

    println!("Selected packages");
    for node in result.nodes.values() {
        println!(
            "- depth={} {} selected_by={}",
            node.depth,
            node.package,
            node.selected_by
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    println!();
    println!("Activated edges");
    for edge in &result.edges {
        let from = edge
            .from
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "root".to_string());
        println!(
            "- {} -> {} [{} {} {}] ({})",
            from,
            edge.to,
            edge.requirement.relation,
            edge.requirement.scope,
            edge.requirement.requirement,
            edge.requirement.evidence
        );
    }

    println!();
    println!("Skipped dependencies");
    if result.skipped.is_empty() {
        println!("- none");
    } else {
        for skipped in &result.skipped {
            let requester = skipped
                .requester
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "root".to_string());
            println!(
                "- {} -> {} skipped: {} ({})",
                requester, skipped.target, skipped.reason, skipped.requirement.evidence
            );
        }
    }

    println!();
    println!("Conflicts");
    if result.conflicts.is_empty() {
        println!("- none");
    } else {
        for conflict in &result.conflicts {
            println!(
                "- {} in slot {}: {}",
                conflict.package, conflict.selection_slot, conflict.reason
            );
            for constraint in &conflict.constraints {
                println!("  - {constraint}");
            }
        }
    }

    println!();
    println!("Resolver trace");
    for event in &result.trace {
        let requester = event
            .requester
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "root".to_string());
        let slot = event.selection_slot.as_deref().unwrap_or("none");
        let selected = event
            .selected
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "none".to_string());
        println!(
            "- {} {} {} -> {} slot={} selected={} reason={}",
            event.id, event.outcome, requester, event.target, slot, selected, event.reason
        );
    }
}

fn demo_result() -> graphscope::ResolveResult {
    let (repository, roots, context) = demo_repository();
    Resolver::new(repository).resolve(roots, &context)
}

fn print_impact() {
    let result = demo_result();
    let advisories = demo_advisories();
    let report = ImpactReport::from_result("tuxcare-demo", &result, &advisories);

    println!("Advisory impact");
    if report.findings.is_empty() {
        println!("- none");
    }
    for finding in report.findings {
        println!(
            "- {} {} affects {}: {}",
            finding.advisory.id, finding.advisory.severity, finding.package, finding.remediation
        );
        for path in finding.dependency_paths {
            println!("  path: {}", path.display());
        }
    }
}

fn print_report() {
    let result = demo_result();
    let advisories = demo_advisories();
    let impact = ImpactReport::from_result("tuxcare-demo", &result, &advisories);
    let report = RemediationReport::from_impact_report(&impact);

    print!("{}", report.to_markdown());
}

fn print_sbom() {
    let result = demo_result();
    let bom = CycloneDxView::from_result("tuxcare-demo", &result);

    println!("{}", bom.to_json());
}

fn print_spdx() {
    let result = demo_result();
    let spdx = SpdxView::from_result("tuxcare-demo", &result);

    println!("{}", spdx.to_json());
}

fn print_vex() {
    let result = demo_result();
    let advisories = demo_advisories();
    let impact = ImpactReport::from_result("tuxcare-demo", &result, &advisories);
    let vex = VexView::from_impact_report(&impact);

    println!("{}", vex.to_json());
}

fn print_policy() {
    let result = demo_result();
    let evaluation = demo_policy_set().evaluate(&result);

    println!("Policy evaluation");
    println!("Compliant: {}", evaluation.is_compliant());
    if evaluation.violations.is_empty() {
        println!("- none");
    }
    for violation in evaluation.violations {
        let package = violation
            .package
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "graph".to_string());
        println!(
            "- {} {} {}: {}",
            violation.severity, violation.rule, package, violation.message
        );
    }
}

fn print_sla() {
    let result = demo_result();
    let advisories = demo_advisories();
    let impact = ImpactReport::from_result("tuxcare-demo", &result, &advisories);
    let policy = demo_policy_set().evaluate(&result);
    let summary = SlaSummary::from_impact_and_policy("tuxcare-demo", &impact, &policy);

    println!("{}", summary.to_json());
}

fn print_dashboard() {
    let result = demo_result();
    let advisories = demo_advisories();
    let impact = ImpactReport::from_result("tuxcare-demo", &result, &advisories);
    let policy = demo_policy_set().evaluate(&result);
    let summary = SlaSummary::from_impact_and_policy("customer-a/tuxcare-demo", &impact, &policy);
    let dashboard = RiskDashboard::from_summaries(&[summary]);

    println!("{}", dashboard.to_json());
}

fn print_invalidation() {
    let (repository, roots, context) = demo_repository();
    let service = ResolverService::new(repository);
    let record = service.process(ResolverJob::new(
        "customer-a",
        "tuxcare-demo",
        roots,
        context,
        env!("CARGO_PKG_VERSION"),
    ));
    let mut store = InMemoryGraphStore::new();
    store.upsert(record);
    let plan = store.plan_invalidation(&[
        ChangeEvent::PackageChanged(graphscope::PackageId::python("urllib3")),
        ChangeEvent::RepositoryChanged("cloudlinux-baseos".to_string()),
        ChangeEvent::PolicyChanged("default-policy".to_string()),
    ]);

    println!("Invalidation plan");
    if plan.is_empty() {
        println!("- none");
    }
    for record in &plan.impacted_records {
        println!("- rerun {record}");
        if let Some(reasons) = plan.reasons.get(record) {
            for reason in reasons {
                println!("  reason: {reason}");
            }
        }
    }
}

fn print_evidence(path: Option<&str>) {
    let Some(path) = path else {
        eprintln!("missing evidence path");
        print_help();
        std::process::exit(2);
    };
    let input = std::fs::read_to_string(path).unwrap_or_else(|error| {
        eprintln!("failed to read {path}: {error}");
        std::process::exit(2);
    });
    let catalog = parse_evidence(&input, path).unwrap_or_else(|error| {
        eprintln!("failed to parse evidence: {error}");
        std::process::exit(2);
    });
    let summary = catalog.summary();

    println!("Evidence summary");
    println!("Locator: {path}");
    println!("Records: {}", summary.total_records);
    println!("Packages: {}", summary.package_records);
    println!("Dependencies: {}", summary.dependency_records);
    print_counts("Kinds", &summary.by_kind);
    print_counts("Ecosystems", &summary.by_ecosystem);
    print_counts("Confidence", &summary.by_confidence);
    println!("Records");
    for record in catalog.records() {
        println!(
            "- {} {} {}",
            record.id,
            subject_summary(&record.subject),
            record.summary
        );
    }
}

fn print_resolve_evidence(paths: &[&str]) {
    if paths.is_empty() {
        eprintln!("missing evidence path");
        print_help();
        std::process::exit(2);
    }

    let mut catalogs = Vec::new();
    for path in paths {
        let input = std::fs::read_to_string(path).unwrap_or_else(|error| {
            eprintln!("failed to read {path}: {error}");
            std::process::exit(2);
        });
        let catalog = parse_evidence(&input, *path).unwrap_or_else(|error| {
            eprintln!("failed to parse evidence: {error}");
            std::process::exit(2);
        });
        catalogs.push(catalog);
    }

    let evidence = ProjectEvidence::from_catalogs(catalogs);
    let input = EvidenceRepositoryBuilder::new().build(&evidence);
    let context = graphscope::ResolutionContext::cloudlinux_production_x86_64();
    let result = Resolver::new(input.repository).resolve(input.roots, &context);
    let snapshot = GraphSnapshot::from_resolve_result(
        "evidence",
        env!("CARGO_PKG_VERSION"),
        &context,
        &result,
    );

    println!("{}", snapshot.to_json_pretty());
}

fn print_real_world() {
    let locator = "examples/real-world/almalinux-10-rpm.list";
    let catalog = parse_evidence(REAL_WORLD_RPM_INVENTORY, locator).unwrap_or_else(|error| {
        eprintln!("failed to parse checked-in real-world evidence: {error}");
        std::process::exit(2);
    });
    let summary = catalog.summary();
    let evidence = ProjectEvidence::from_catalog(catalog);
    let input = EvidenceRepositoryBuilder::new().build(&evidence);
    let context = graphscope::ResolutionContext::cloudlinux_production_x86_64();
    let result = Resolver::new(input.repository).resolve(input.roots, &context);
    let snapshot = GraphSnapshot::from_resolve_result(
        "almalinux-10-observed-rpm-inventory",
        env!("CARGO_PKG_VERSION"),
        &context,
        &result,
    );
    let source_os = REAL_WORLD_OS_RELEASE
        .lines()
        .find(|line| line.starts_with("PRETTY_NAME="))
        .unwrap_or("PRETTY_NAME=\"AlmaLinux 10\"");
    let enabled_repositories = REAL_WORLD_DNF_REPOLIST
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with("repo id")
        })
        .count();
    let observed = summary.by_confidence.get("Observed").copied().unwrap_or(0);

    println!("GraphScope real-world AlmaLinux evidence");
    println!("Source OS: {source_os}");
    println!("Inventory: {locator}");
    println!("Enabled repositories: {enabled_repositories}");
    println!("Records: {}", summary.total_records);
    println!("Observed RPM packages: {observed}");
    println!("Resolved snapshot: {}", snapshot.id);
    println!("Resolved nodes: {}", result.nodes.len());
    println!("Resolved root edges: {}", result.edges.len());
    println!("Conflicts: {}", result.conflicts.len());
    println!("Skipped dependencies: {}", result.skipped.len());
    if !result.conflicts.is_empty() {
        println!(
            "Resolver note: conflicts indicate observed multi-version RPM inventory that still needs installonly/package-manager semantics from the DNF/libsolv oracle."
        );
    }
    println!(
        "Note: this is real observed runtime inventory; transitive RPM solving still requires the DNF/libsolv oracle adapter."
    );
}

fn print_counts(label: &str, counts: &std::collections::BTreeMap<String, usize>) {
    if counts.is_empty() {
        return;
    }
    println!("{label}:");
    for (name, count) in counts {
        println!("- {name}: {count}");
    }
}

fn print_adapters() {
    println!("Adapter coverage");
    for profile in adapter_profiles() {
        let formats = profile
            .evidence_formats
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let capabilities = profile
            .capabilities
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "- {} via {}: status={} formats=[{}] capabilities=[{}]",
            profile.ecosystem, profile.package_manager, profile.status, formats, capabilities
        );
        if let Some(contract) = adapter_resolution_contract(&profile.ecosystem) {
            println!(
                "  resolution: mode={} selection={} multiplicity={}",
                contract.mode, contract.selection_policy, contract.multiplicity
            );
            if let Some(command) = contract.native_oracle_commands.first() {
                println!("  oracle command: {command}");
            }
        }
        if !profile.production_gaps.is_empty() {
            println!("  production gaps: {}", profile.production_gaps.join("; "));
        }
    }
}

fn print_access() {
    let (repository, roots, context) = demo_repository();
    let record = ResolverService::new(repository).process(ResolverJob::new(
        "customer-a",
        "tuxcare-demo",
        roots,
        context,
        env!("CARGO_PKG_VERSION"),
    ));
    let context_hash = record.snapshot.context_hash.clone();
    let mut store = InMemoryGraphStore::new();
    store.upsert(record);

    let mut policy = TenantAccessPolicy::new();
    policy.grant("analyst@cloudlinux", "customer-a", TenantRole::Analyst);

    let allowed = policy.authorize("analyst@cloudlinux", "customer-a", TenantRole::Reader);
    let denied = policy.authorize("analyst@cloudlinux", "customer-b", TenantRole::Reader);

    println!("Tenant access demo");
    println!("- allowed: {}", allowed.reason);
    println!("- denied: {}", denied.reason);
    match store.authorized_get(
        &policy,
        "analyst@cloudlinux",
        "customer-a",
        "tuxcare-demo",
        &context_hash,
        TenantRole::Reader,
    ) {
        Ok(Some(record)) => println!("- authorized snapshot: {}", record.snapshot.id),
        Ok(None) => println!("- authorized snapshot: not found"),
        Err(decision) => println!("- authorized snapshot denied: {}", decision.reason),
    }
}

fn subject_summary(subject: &EvidenceSubject) -> String {
    match subject {
        EvidenceSubject::Package(package) => format!("package {package}"),
        EvidenceSubject::Dependency { requirement, .. } => {
            format!(
                "dependency {} {}",
                requirement.target, requirement.requirement
            )
        }
        EvidenceSubject::Advisory {
            advisory_id,
            package,
        } => {
            format!("advisory {advisory_id} {package}")
        }
        EvidenceSubject::Context(context) => format!("context {context}"),
    }
}

fn persist_demo(root: Option<&str>) {
    let Some(root) = root else {
        eprintln!("missing storage directory");
        print_help();
        std::process::exit(2);
    };
    let (repository, roots, context) = demo_repository();
    let record = ResolverService::new(repository).process(ResolverJob::new(
        "customer-a",
        "tuxcare-demo",
        roots,
        context,
        env!("CARGO_PKG_VERSION"),
    ));
    let store = FileGraphStore::new(root).unwrap_or_else(|error| {
        eprintln!("failed to initialize store {root}: {error}");
        std::process::exit(2);
    });
    let stored = store.persist_record(&record).unwrap_or_else(|error| {
        eprintln!("failed to persist snapshot: {error}");
        std::process::exit(2);
    });

    println!("Persisted snapshot");
    println!("Store: {}", store.root().display());
    println!("Tenant: {}", stored.tenant);
    println!("Product: {}", stored.product);
    println!("Context: {}", stored.context_hash);
    println!("Snapshot: {}", stored.snapshot_id);
    println!("Path: {}", stored.snapshot_path.display());
}

fn persist_demo_events(root: Option<&str>) {
    let Some(root) = root else {
        eprintln!("missing event log directory");
        print_help();
        std::process::exit(2);
    };
    let log_path = std::path::Path::new(root).join("events.tsv");
    let log = FileChangeEventLog::new(&log_path).unwrap_or_else(|error| {
        eprintln!(
            "failed to initialize event log {}: {error}",
            log_path.display()
        );
        std::process::exit(2);
    });
    let stored = log
        .append_all(&[
            ChangeEvent::PackageChanged(graphscope::PackageId::python("urllib3")),
            ChangeEvent::RepositoryChanged("cloudlinux-baseos".to_string()),
            ChangeEvent::PolicyChanged("default-policy".to_string()),
        ])
        .unwrap_or_else(|error| {
            eprintln!("failed to append change events: {error}");
            std::process::exit(2);
        });

    println!("Persisted change events");
    println!("Log: {}", log.path().display());
    println!("Events: {}", stored.len());
    for event in stored {
        println!(
            "- #{} {}",
            event.sequence,
            change_event_summary(&event.event)
        );
    }
}

fn change_event_summary(event: &ChangeEvent) -> String {
    match event {
        ChangeEvent::PackageChanged(package) => format!("package changed: {package}"),
        ChangeEvent::AdvisoryChanged {
            advisory_id,
            package,
        } => {
            format!("advisory changed: {advisory_id} for {package}")
        }
        ChangeEvent::RepositoryChanged(channel) => {
            format!("repository channel changed: {channel}")
        }
        ChangeEvent::PolicyChanged(policy_id) => format!("policy changed: {policy_id}"),
    }
}

fn print_explain() {
    let result = demo_result();
    let target = graphscope::PackageId::python("urllib3");
    let query = GraphQuery::new(&result);

    match query.explain_package(&target) {
        Some(explanation) => {
            println!("Package explanation");
            println!("Package: {}", explanation.package);
            println!(
                "Selected by: {}",
                explanation
                    .selected_by
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            );
            for path in explanation.paths {
                println!("Path: {}", path.display());
            }
            for event in explanation.trace_events {
                println!("Trace: {} {} {}", event.id, event.outcome, event.reason);
            }
        }
        None => {
            for reason in query.skipped_reasons(&target) {
                println!("Skipped: {reason}");
            }
        }
    }
}

fn print_diff() {
    let (repo_with_gpu, roots_with_gpu, context_with_gpu) = demo_repository();
    let with_gpu = Resolver::new(repo_with_gpu).resolve(roots_with_gpu, &context_with_gpu);
    let (repo_without_gpu, roots_without_gpu, _context) = demo_repository();
    let without_gpu = Resolver::new(repo_without_gpu).resolve(
        roots_without_gpu,
        &graphscope::ResolutionContext::cloudlinux_production_x86_64(),
    );
    let diff = GraphDiff::between(&without_gpu, &with_gpu);

    println!("Graph diff: base production vs production+gpu");
    for package in diff.added_packages {
        println!("- added package {package}");
    }
    for package in diff.removed_packages {
        println!("- removed package {package}");
    }
    for change in diff.changed_packages {
        println!(
            "- changed package {}: {:?} -> {:?}",
            change.package, change.left_versions, change.right_versions
        );
    }
}

fn print_benchmark(args: &[&str]) {
    let config = match parse_benchmark_config(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("benchmark configuration error: {error}");
            std::process::exit(2);
        }
    };

    match run_algorithm_benchmark(config) {
        Ok(report) => println!("{}", report.to_text()),
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            std::process::exit(2);
        }
    }
}

fn parse_benchmark_config(args: &[&str]) -> Result<AlgorithmBenchmarkConfig, String> {
    if args.is_empty() {
        return Ok(AlgorithmBenchmarkConfig::default());
    }
    if args.len() != 4 {
        return Err("expected either no arguments or: layers width fanout max_paths".to_string());
    }

    AlgorithmBenchmarkConfig {
        layers: parse_usize_arg("layers", args[0])?,
        width: parse_usize_arg("width", args[1])?,
        fanout: parse_usize_arg("fanout", args[2])?,
        max_paths: parse_usize_arg("max_paths", args[3])?,
    }
    .validate()
}

fn parse_usize_arg(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|error| format!("{name} must be a positive integer: {error}"))
}
