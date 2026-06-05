//! Tenant-scoped resolver jobs, graph records, stores, and invalidation planning.

use std::collections::{BTreeMap, VecDeque};

use crate::advisory::{Advisory, ImpactReport};
use crate::evidence::stable_hash;
use crate::model::{DependencyRequirement, PackageId, ResolutionContext};
use crate::query::GraphQuery;
use crate::repository::PackageRepository;
use crate::resolver::{ResolveResult, Resolver};
use crate::snapshot::GraphSnapshot;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverJob {
    pub id: String,
    pub tenant: String,
    pub product: String,
    pub roots: Vec<DependencyRequirement>,
    pub context: ResolutionContext,
    pub resolver_version: String,
}

impl ResolverJob {
    pub fn new(
        tenant: impl Into<String>,
        product: impl Into<String>,
        roots: Vec<DependencyRequirement>,
        context: ResolutionContext,
        resolver_version: impl Into<String>,
    ) -> Self {
        let tenant = tenant.into();
        let product = product.into();
        let resolver_version = resolver_version.into();
        let context_key = context.stable_key();
        let stable = format!(
            "{tenant}|{product}|{}|{context_key}|{}",
            roots
                .iter()
                .map(|root| format!("{}:{}", root.target, root.requirement))
                .collect::<Vec<_>>()
                .join(","),
            resolver_version
        );

        Self {
            id: format!("job-{:016x}", stable_hash(&stable)),
            tenant,
            product,
            roots,
            context,
            resolver_version,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ResolverWorkQueue {
    pending: VecDeque<ResolverJob>,
}

impl ResolverWorkQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, job: ResolverJob) {
        self.pending.push_back(job);
    }

    pub fn pop_next(&mut self) -> Option<ResolverJob> {
        self.pending.pop_front()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphRecord {
    pub tenant: String,
    pub product: String,
    pub context: ResolutionContext,
    pub snapshot: GraphSnapshot,
    pub result: ResolveResult,
}

impl GraphRecord {
    pub fn contains_package(&self, package: &PackageId) -> bool {
        self.result.contains_package(package)
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryGraphStore {
    records: BTreeMap<(String, String, String), GraphRecord>,
}

impl InMemoryGraphStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, record: GraphRecord) {
        let key = (
            record.tenant.clone(),
            record.product.clone(),
            record.snapshot.context_hash.clone(),
        );
        self.records.insert(key, record);
    }

    pub fn get(&self, tenant: &str, product: &str, context_hash: &str) -> Option<&GraphRecord> {
        self.records.get(&(
            tenant.to_string(),
            product.to_string(),
            context_hash.to_string(),
        ))
    }

    pub fn authorized_get(
        &self,
        policy: &TenantAccessPolicy,
        principal: &str,
        tenant: &str,
        product: &str,
        context_hash: &str,
        required_role: TenantRole,
    ) -> Result<Option<&GraphRecord>, AccessDecision> {
        let decision = policy.authorize(principal, tenant, required_role);
        if !decision.allowed {
            return Err(decision);
        }
        Ok(self.get(tenant, product, context_hash))
    }

    pub fn records_for_package(&self, package: &PackageId) -> Vec<&GraphRecord> {
        self.records
            .values()
            .filter(|record| record.contains_package(package))
            .collect()
    }

    pub fn impact_reports(&self, advisories: &[Advisory]) -> Vec<ImpactReport> {
        self.records
            .values()
            .map(|record| {
                ImpactReport::from_result(
                    format!("{}/{}", record.tenant, record.product),
                    &record.result,
                    advisories,
                )
            })
            .filter(ImpactReport::is_affected)
            .collect()
    }

    pub fn plan_invalidation(&self, changes: &[ChangeEvent]) -> InvalidationPlan {
        let mut impacted_records = Vec::new();
        let mut reasons = BTreeMap::<String, Vec<String>>::new();

        for record in self.records.values() {
            for change in changes {
                if let Some(reason) = change.impacts(record) {
                    let key = record_key(record);
                    if !impacted_records.contains(&key) {
                        impacted_records.push(key.clone());
                    }
                    reasons.entry(key).or_default().push(reason);
                }
            }
        }

        impacted_records.sort();
        for record_reasons in reasons.values_mut() {
            record_reasons.sort();
            record_reasons.dedup();
        }

        InvalidationPlan {
            impacted_records,
            reasons,
        }
    }

    pub fn explain(
        &self,
        tenant: &str,
        product: &str,
        context_hash: &str,
        package: &PackageId,
    ) -> Option<crate::query::PackageExplanation> {
        self.get(tenant, product, context_hash)
            .and_then(|record| GraphQuery::new(&record.result).explain_package(package))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TenantRole {
    Reader,
    Analyst,
    Admin,
}

impl TenantRole {
    fn allows(self, required: Self) -> bool {
        self >= required
    }
}

impl std::fmt::Display for TenantRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reader => write!(f, "reader"),
            Self::Analyst => write!(f, "analyst"),
            Self::Admin => write!(f, "admin"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantAccessPolicy {
    grants: BTreeMap<String, BTreeMap<String, TenantRole>>,
}

impl TenantAccessPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(
        &mut self,
        principal: impl Into<String>,
        tenant: impl Into<String>,
        role: TenantRole,
    ) {
        self.grants
            .entry(principal.into())
            .or_default()
            .insert(tenant.into(), role);
    }

    pub fn authorize(
        &self,
        principal: &str,
        tenant: &str,
        required_role: TenantRole,
    ) -> AccessDecision {
        let granted_role = self
            .grants
            .get(principal)
            .and_then(|tenants| tenants.get(tenant))
            .copied();

        match granted_role {
            Some(role) if role.allows(required_role) => AccessDecision::allow(format!(
                "principal {principal} has {role} access to tenant {tenant}"
            )),
            Some(role) => AccessDecision::deny(format!(
                "principal {principal} has {role} access to tenant {tenant}, but {required_role} is required"
            )),
            None => AccessDecision::deny(format!(
                "principal {principal} has no access to tenant {tenant}"
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessDecision {
    pub allowed: bool,
    pub reason: String,
}

impl AccessDecision {
    fn allow(reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolverService<R> {
    repository: R,
}

impl<R> ResolverService<R>
where
    R: Clone + PackageRepository,
{
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn process(&self, job: ResolverJob) -> GraphRecord {
        let context = job.context;
        let result = Resolver::new(self.repository.clone()).resolve(job.roots, &context);
        let snapshot = GraphSnapshot::from_resolve_result(
            format!("{}/{}", job.tenant, job.product),
            job.resolver_version,
            &context,
            &result,
        );

        GraphRecord {
            tenant: job.tenant,
            product: job.product,
            context,
            snapshot,
            result,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeEvent {
    PackageChanged(PackageId),
    AdvisoryChanged {
        advisory_id: String,
        package: PackageId,
    },
    RepositoryChanged(String),
    PolicyChanged(String),
}

impl ChangeEvent {
    fn impacts(&self, record: &GraphRecord) -> Option<String> {
        match self {
            ChangeEvent::PackageChanged(package) => record
                .contains_package(package)
                .then(|| format!("package changed: {package}")),
            ChangeEvent::AdvisoryChanged {
                advisory_id,
                package,
            } => record
                .contains_package(package)
                .then(|| format!("advisory changed: {advisory_id} for {package}")),
            ChangeEvent::RepositoryChanged(channel) => record
                .context
                .repository_channels
                .contains(channel)
                .then(|| format!("repository channel changed: {channel}")),
            ChangeEvent::PolicyChanged(policy_id) => Some(format!("policy changed: {policy_id}")),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidationPlan {
    pub impacted_records: Vec<String>,
    pub reasons: BTreeMap<String, Vec<String>>,
}

impl InvalidationPlan {
    pub fn is_empty(&self) -> bool {
        self.impacted_records.is_empty()
    }
}

fn record_key(record: &GraphRecord) -> String {
    format!(
        "{}/{}/{}",
        record.tenant, record.product, record.snapshot.context_hash
    )
}

#[cfg(test)]
mod tests {
    use crate::advisory::{Advisory, AdvisorySeverity};
    use crate::model::{PackageVersion, VersionRequirement};
    use crate::repository::InMemoryRepository;

    use super::*;

    #[test]
    fn work_queue_processes_jobs_fifo() {
        let app = PackageId::internal("app");
        let context = ResolutionContext::cloudlinux_production_x86_64();
        let first = ResolverJob::new(
            "tenant",
            "first",
            vec![DependencyRequirement::new(
                app.clone(),
                VersionRequirement::any(),
            )],
            context.clone(),
            "test",
        );
        let second = ResolverJob::new(
            "tenant",
            "second",
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            context,
            "test",
        );
        let mut queue = ResolverWorkQueue::new();
        queue.enqueue(first.clone());
        queue.enqueue(second);

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop_next().unwrap(), first);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn resolver_jobs_include_context_in_stable_id() {
        let app = PackageId::internal("app");
        let roots = vec![DependencyRequirement::new(app, VersionRequirement::any())];
        let base = ResolverJob::new(
            "tenant",
            "product",
            roots.clone(),
            ResolutionContext::cloudlinux_production_x86_64(),
            "test",
        );
        let with_gpu = ResolverJob::new(
            "tenant",
            "product",
            roots,
            ResolutionContext::cloudlinux_production_x86_64().with_feature("gpu"),
            "test",
        );

        assert_ne!(base.id, with_gpu.id);
    }

    #[test]
    fn resolver_service_creates_graph_record_for_store() {
        let app = PackageId::internal("app");
        let dep = PackageId::rpm("openssl-libs");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "3.2.2"));
        let job = ResolverJob::new(
            "customer-a",
            "portal",
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            ResolutionContext::cloudlinux_production_x86_64(),
            "test",
        );
        let service = ResolverService::new(repo);
        let record = service.process(job);
        let context_hash = record.snapshot.context_hash.clone();
        let mut store = InMemoryGraphStore::new();
        store.upsert(record);

        assert!(store.get("customer-a", "portal", &context_hash).is_some());
        assert_eq!(store.records_for_package(&dep).len(), 1);
    }

    #[test]
    fn store_runs_impact_reports_across_records() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("urllib3");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "2.2.2"));
        let job = ResolverJob::new(
            "customer-a",
            "scanner",
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            ResolutionContext::cloudlinux_production_x86_64(),
            "test",
        );
        let record = ResolverService::new(repo).process(job);
        let mut store = InMemoryGraphStore::new();
        store.upsert(record);
        let advisory = Advisory::new(
            "CVE-1",
            "urllib3",
            dep,
            VersionRequirement::parse("<2.2.3"),
            AdvisorySeverity::High,
        );

        let reports = store.impact_reports(&[advisory]);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].product, "customer-a/scanner");
    }

    #[test]
    fn store_plans_invalidation_for_package_repository_advisory_and_policy_changes() {
        let app = PackageId::internal("app");
        let dep = PackageId::python("urllib3");
        let mut repo = InMemoryRepository::new();
        repo.add(
            PackageVersion::new(app.clone(), "1.0").with_dependencies(vec![
                DependencyRequirement::new(dep.clone(), VersionRequirement::any()),
            ]),
        );
        repo.add(PackageVersion::new(dep.clone(), "2.2.2"));
        let job = ResolverJob::new(
            "customer-a",
            "scanner",
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            ResolutionContext::cloudlinux_production_x86_64(),
            "test",
        );
        let record = ResolverService::new(repo).process(job);
        let mut store = InMemoryGraphStore::new();
        store.upsert(record);

        let plan = store.plan_invalidation(&[
            ChangeEvent::PackageChanged(dep.clone()),
            ChangeEvent::AdvisoryChanged {
                advisory_id: "CVE-1".to_string(),
                package: dep,
            },
            ChangeEvent::RepositoryChanged("cloudlinux-baseos".to_string()),
            ChangeEvent::PolicyChanged("default".to_string()),
        ]);

        assert!(!plan.is_empty());
        assert_eq!(plan.impacted_records.len(), 1);
        assert_eq!(plan.reasons[&plan.impacted_records[0]].len(), 4);
    }

    #[test]
    fn tenant_access_policy_allows_reader_for_granted_tenant() {
        let mut policy = TenantAccessPolicy::new();
        policy.grant("analyst@cloudlinux", "customer-a", TenantRole::Analyst);

        let decision = policy.authorize("analyst@cloudlinux", "customer-a", TenantRole::Reader);

        assert!(decision.allowed);
        assert!(decision.reason.contains("analyst access"));
    }

    #[test]
    fn tenant_access_policy_blocks_cross_tenant_access() {
        let mut policy = TenantAccessPolicy::new();
        policy.grant("analyst@cloudlinux", "customer-a", TenantRole::Analyst);

        let decision = policy.authorize("analyst@cloudlinux", "customer-b", TenantRole::Reader);

        assert!(!decision.allowed);
        assert!(decision.reason.contains("no access"));
    }

    #[test]
    fn store_authorized_get_enforces_tenant_policy() {
        let app = PackageId::internal("app");
        let mut repo = InMemoryRepository::new();
        repo.add(PackageVersion::new(app.clone(), "1.0"));
        let job = ResolverJob::new(
            "customer-a",
            "portal",
            vec![DependencyRequirement::new(app, VersionRequirement::any())],
            ResolutionContext::cloudlinux_production_x86_64(),
            "test",
        );
        let record = ResolverService::new(repo).process(job);
        let context_hash = record.snapshot.context_hash.clone();
        let mut store = InMemoryGraphStore::new();
        store.upsert(record);
        let mut policy = TenantAccessPolicy::new();
        policy.grant("analyst@cloudlinux", "customer-a", TenantRole::Reader);

        let allowed = store
            .authorized_get(
                &policy,
                "analyst@cloudlinux",
                "customer-a",
                "portal",
                &context_hash,
                TenantRole::Reader,
            )
            .unwrap();
        let denied = store.authorized_get(
            &policy,
            "analyst@cloudlinux",
            "customer-b",
            "portal",
            &context_hash,
            TenantRole::Reader,
        );

        assert!(allowed.is_some());
        assert!(denied.unwrap_err().reason.contains("customer-b"));
    }
}
