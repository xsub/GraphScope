use graphscope::{Resolver, demo_repository};

fn main() {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "demo".to_string());

    match command.as_str() {
        "demo" => run_demo(),
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
    println!("  graphscope help   show this help");
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
}
