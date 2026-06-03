use graphscope::{
    CycloneDxView, GraphDiff, GraphQuery, GraphSnapshot, ImpactReport, RemediationReport, Resolver,
    VexView, demo_advisories, demo_repository,
};

fn main() {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "demo".to_string());

    match command.as_str() {
        "demo" => run_demo(),
        "snapshot" => print_snapshot(),
        "impact" => print_impact(),
        "report" => print_report(),
        "sbom" => print_sbom(),
        "vex" => print_vex(),
        "explain" => print_explain(),
        "diff" => print_diff(),
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
    println!("  graphscope vex   print a VEX-style advisory view");
    println!("  graphscope explain   explain why urllib3 is present in the demo graph");
    println!("  graphscope diff   compare demo graph with and without optional GPU context");
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

fn print_vex() {
    let result = demo_result();
    let advisories = demo_advisories();
    let impact = ImpactReport::from_result("tuxcare-demo", &result, &advisories);
    let vex = VexView::from_impact_report(&impact);

    println!("{}", vex.to_json());
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
