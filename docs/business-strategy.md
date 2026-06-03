# Business Strategy

GraphScope is the dependency intelligence layer for CloudLinux, AlmaLinux, and
TuxCare. It should become the system that explains which software components are
present, why they are present, which environments activate them, and what
maintenance or security obligation they create.

## Business Outcomes

The platform should deliver five measurable outcomes:

1. Reduce vulnerability triage time.
   Security teams should move from "package X is mentioned somewhere" to "these
   customers run a vulnerable resolved component under these exact conditions."

2. Improve TuxCare patch targeting.
   Patch engineering should identify affected dependency paths, package rebuild
   order, reverse dependencies, and runtime exposure before a maintenance window.

3. Strengthen CloudLinux OS and AlmaLinux ecosystem planning.
   Product and release teams should understand package reachability, weak
   dependencies, module streams, ELS demand, and architecture-specific deltas.

4. Produce customer-grade supply-chain evidence.
   Customers should receive explainable SBOM/VEX-style answers backed by
   resolver evidence, not static inventory guesswork.

5. Create a reusable dependency graph asset.
   The same graph should support CVE impact, package lifecycle, compliance,
   malware investigation, rebuild planning, and end-of-life prioritization.

## Primary Users

- TuxCare security engineers investigating CVEs and live patch applicability.
- CloudLinux OS engineers planning repository, module, and package changes.
- AlmaLinux ecosystem maintainers analyzing rebuild and compatibility impact.
- Customer success and support teams answering exposure and remediation
  questions.
- Product leadership tracking risk, coverage, and maintenance economics.

## Product Capabilities

GraphScope should support the following workflows:

- ingest a project, image, host, repository, or SBOM and produce a resolved graph;
- explain why a dependency exists, including the parent path and activation
  conditions;
- compare graphs across CloudLinux, AlmaLinux, RHEL-compatible baselines,
  architectures, and package channels;
- find all applications impacted by an advisory, package removal, ABI change, or
  end-of-life event;
- plan resolver re-runs after package, repository, advisory, or customer-policy
  changes;
- distinguish runtime exposure from build, test, development, optional, weak,
  peer, and provided dependencies;
- evaluate customer policy such as allowed sources, required signatures, denied
  components, and CloudLinux/TuxCare coverage;
- preserve package-manager-specific evidence for audit and customer trust;
- export CycloneDX/SPDX/VEX-compatible views without losing GraphScope-native
  context;
- summarize advisory and policy findings into SLA-style risk and remediation
  metrics.

## Success Metrics

- Median CVE impact-analysis time.
- Percentage of dependency edges with resolver evidence and source provenance.
- False-positive rate for customer exposure findings.
- Number of ecosystems and package-manager modes covered with conformance tests.
- Graph freshness by repository, customer fleet, and advisory source.
- Resolver cost per project and cache hit ratio.
- Time to produce a customer-ready remediation report.
- Number of graph snapshots invalidated per metadata change versus full
  re-resolution.

## Operating Model

GraphScope should be run as a control-plane service with stateless resolver
workers and durable graph storage. The resolver workers should be horizontally
scaled by ecosystem and workload type:

- RPM/native OS resolution for AlmaLinux, CloudLinux, ELS, and TuxCare channels.
- Language package resolution for source projects and build manifests.
- Lockfile and SBOM normalization for already-resolved application artifacts.
- Runtime inventory enrichment from hosts, containers, and images.

Business-critical graph snapshots should be immutable. New metadata, advisories,
or resolver versions create new graph revisions so findings can be audited and
reproduced.

## Non-Goals

- Replacing package managers.
- Treating SBOMs as the source of truth when resolver evidence is available.
- Flattening all ecosystems into a single semver-only model.
- Making AI-generated explanations authoritative. AI can summarize evidence; the
  graph and resolver traces remain authoritative.

## Build-Versus-Buy Rationale

Existing SBOM scanners are valuable ingestion sources but are not enough for the
CloudLinux/TuxCare problem. They often lose environment markers, weak RPM
dependencies, package-manager conflict rules, repository channels, distro
context, and lifecycle state. GraphScope should ingest external SBOMs, but the
business differentiator is resolver-grade evidence across customer-specific OS
and application contexts.
