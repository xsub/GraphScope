use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(feature = "sqlite")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::{Ecosystem, PackageId};
use crate::platform::ChangeEvent;
use crate::platform::GraphRecord;
#[cfg(feature = "sqlite")]
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSnapshotRecord {
    pub tenant: String,
    pub product: String,
    pub context_hash: String,
    pub snapshot_id: String,
    pub resolver_version: String,
    pub snapshot_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileGraphStore {
    root: PathBuf,
}

impl FileGraphStore {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("snapshots"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn persist_record(&self, record: &GraphRecord) -> io::Result<StoredSnapshotRecord> {
        let snapshot_json = record.snapshot.to_json_pretty();
        let snapshot_path = self.snapshot_path(
            &record.tenant,
            &record.product,
            &record.snapshot.context_hash,
            &record.snapshot.id,
        );
        if let Some(parent) = snapshot_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if snapshot_path.exists() {
            let existing = fs::read_to_string(&snapshot_path)?;
            if existing != snapshot_json {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "snapshot id already exists with different content",
                ));
            }
        } else {
            fs::write(&snapshot_path, snapshot_json)?;
        }

        let stored = StoredSnapshotRecord {
            tenant: record.tenant.clone(),
            product: record.product.clone(),
            context_hash: record.snapshot.context_hash.clone(),
            snapshot_id: record.snapshot.id.clone(),
            resolver_version: record.snapshot.resolver_version.clone(),
            snapshot_path,
        };
        self.upsert_index(&stored)?;
        Ok(stored)
    }

    pub fn list(&self) -> io::Result<Vec<StoredSnapshotRecord>> {
        let mut records = self.read_index()?;
        records.sort_by(|left, right| {
            (
                left.tenant.as_str(),
                left.product.as_str(),
                left.context_hash.as_str(),
                left.snapshot_id.as_str(),
            )
                .cmp(&(
                    right.tenant.as_str(),
                    right.product.as_str(),
                    right.context_hash.as_str(),
                    right.snapshot_id.as_str(),
                ))
        });
        Ok(records)
    }

    pub fn find(
        &self,
        tenant: &str,
        product: &str,
        context_hash: &str,
    ) -> io::Result<Vec<StoredSnapshotRecord>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|record| {
                record.tenant == tenant
                    && record.product == product
                    && record.context_hash == context_hash
            })
            .collect())
    }

    pub fn snapshot_json(&self, snapshot_id: &str) -> io::Result<Option<String>> {
        let Some(record) = self
            .list()?
            .into_iter()
            .find(|record| record.snapshot_id == snapshot_id)
        else {
            return Ok(None);
        };
        fs::read_to_string(record.snapshot_path).map(Some)
    }

    fn upsert_index(&self, record: &StoredSnapshotRecord) -> io::Result<()> {
        let mut records = self.read_index()?;
        records.retain(|existing| existing.snapshot_id != record.snapshot_id);
        records.push(record.clone());
        records.sort_by(|left, right| left.snapshot_id.cmp(&right.snapshot_id));

        let body = records
            .iter()
            .map(format_index_line)
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(self.index_path(), format!("{body}\n"))
    }

    fn read_index(&self) -> io::Result<Vec<StoredSnapshotRecord>> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        fs::read_to_string(path)?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_index_line(&self.root, line))
            .collect()
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.tsv")
    }

    fn snapshot_path(
        &self,
        tenant: &str,
        product: &str,
        context_hash: &str,
        snapshot_id: &str,
    ) -> PathBuf {
        self.root.join("snapshots").join(format!(
            "{}__{}__{}__{}.json",
            encode_field(tenant),
            encode_field(product),
            encode_field(context_hash),
            encode_field(snapshot_id)
        ))
    }
}

#[cfg(feature = "sqlite")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqliteGraphStore {
    path: PathBuf,
}

#[cfg(feature = "sqlite")]
impl SqliteGraphStore {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let store = Self { path };
        store.initialize()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn persist_record(&self, record: &GraphRecord) -> io::Result<StoredSnapshotRecord> {
        let snapshot_json = record.snapshot.to_json_pretty();
        let stored = StoredSnapshotRecord {
            tenant: record.tenant.clone(),
            product: record.product.clone(),
            context_hash: record.snapshot.context_hash.clone(),
            snapshot_id: record.snapshot.id.clone(),
            resolver_version: record.snapshot.resolver_version.clone(),
            snapshot_path: self.path.clone(),
        };
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        let existing = transaction
            .query_row(
                "SELECT snapshot_json FROM graph_snapshots WHERE snapshot_id = ?1",
                params![stored.snapshot_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;

        if let Some(existing) = existing {
            if existing != snapshot_json {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "snapshot id already exists with different content",
                ));
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }

        transaction
            .execute(
                "INSERT INTO graph_snapshots (
                    snapshot_id,
                    tenant,
                    product,
                    context_hash,
                    resolver_version,
                    snapshot_json,
                    created_at_epoch
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    stored.snapshot_id,
                    stored.tenant,
                    stored.product,
                    stored.context_hash,
                    stored.resolver_version,
                    snapshot_json,
                    current_epoch_seconds()?
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    pub fn list(&self) -> io::Result<Vec<StoredSnapshotRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT tenant, product, context_hash, snapshot_id, resolver_version
                 FROM graph_snapshots
                 ORDER BY tenant, product, context_hash, snapshot_id",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok(StoredSnapshotRecord {
                    tenant: row.get(0)?,
                    product: row.get(1)?,
                    context_hash: row.get(2)?,
                    snapshot_id: row.get(3)?,
                    resolver_version: row.get(4)?,
                    snapshot_path: self.path.clone(),
                })
            })
            .map_err(sqlite_error)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    pub fn find(
        &self,
        tenant: &str,
        product: &str,
        context_hash: &str,
    ) -> io::Result<Vec<StoredSnapshotRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT tenant, product, context_hash, snapshot_id, resolver_version
                 FROM graph_snapshots
                 WHERE tenant = ?1 AND product = ?2 AND context_hash = ?3
                 ORDER BY snapshot_id",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![tenant, product, context_hash], |row| {
                Ok(StoredSnapshotRecord {
                    tenant: row.get(0)?,
                    product: row.get(1)?,
                    context_hash: row.get(2)?,
                    snapshot_id: row.get(3)?,
                    resolver_version: row.get(4)?,
                    snapshot_path: self.path.clone(),
                })
            })
            .map_err(sqlite_error)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    pub fn snapshot_json(&self, snapshot_id: &str) -> io::Result<Option<String>> {
        self.connection()?
            .query_row(
                "SELECT snapshot_json FROM graph_snapshots WHERE snapshot_id = ?1",
                params![snapshot_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)
    }

    pub fn append_event(&self, event: &ChangeEvent) -> io::Result<StoredChangeEvent> {
        let (kind, payload_a, payload_b) = sqlite_event_fields(event);
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO change_events (kind, payload_a, payload_b)
                 VALUES (?1, ?2, ?3)",
                params![kind, payload_a, payload_b],
            )
            .map_err(sqlite_error)?;
        Ok(StoredChangeEvent {
            sequence: connection.last_insert_rowid() as u64,
            event: event.clone(),
        })
    }

    pub fn append_events(&self, events: &[ChangeEvent]) -> io::Result<Vec<StoredChangeEvent>> {
        events
            .iter()
            .map(|event| self.append_event(event))
            .collect()
    }

    pub fn list_events(&self) -> io::Result<Vec<StoredChangeEvent>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT sequence, kind, payload_a, payload_b
                 FROM change_events
                 ORDER BY sequence",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                let sequence = row.get::<_, i64>(0)? as u64;
                let kind = row.get::<_, String>(1)?;
                let payload_a = row.get::<_, String>(2)?;
                let payload_b = row.get::<_, Option<String>>(3)?;
                let event = sqlite_event_from_fields(&kind, payload_a, payload_b)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
                Ok(StoredChangeEvent { sequence, event })
            })
            .map_err(sqlite_error)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    pub fn events(&self) -> io::Result<Vec<ChangeEvent>> {
        Ok(self
            .list_events()?
            .into_iter()
            .map(|stored| stored.event)
            .collect())
    }

    fn initialize(&self) -> io::Result<()> {
        self.connection()?
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS graph_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    product TEXT NOT NULL,
                    context_hash TEXT NOT NULL,
                    resolver_version TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    created_at_epoch INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS graph_snapshots_lookup
                    ON graph_snapshots (tenant, product, context_hash);
                CREATE TABLE IF NOT EXISTS change_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    payload_a TEXT NOT NULL,
                    payload_b TEXT
                );
                ",
            )
            .map(|_| ())
            .map_err(sqlite_error)
    }

    fn connection(&self) -> io::Result<Connection> {
        Connection::open(&self.path).map_err(sqlite_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredChangeEvent {
    pub sequence: u64,
    pub event: ChangeEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileChangeEventLog {
    path: PathBuf,
}

impl FileChangeEventLog {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            fs::File::create(&path)?;
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: &ChangeEvent) -> io::Result<StoredChangeEvent> {
        let sequence = self.next_sequence()?;
        let stored = StoredChangeEvent {
            sequence,
            event: event.clone(),
        };
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", format_event_line(&stored))?;
        Ok(stored)
    }

    pub fn append_all(&self, events: &[ChangeEvent]) -> io::Result<Vec<StoredChangeEvent>> {
        events.iter().map(|event| self.append(event)).collect()
    }

    pub fn list(&self) -> io::Result<Vec<StoredChangeEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        fs::read_to_string(&self.path)?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(parse_event_line)
            .collect()
    }

    pub fn events(&self) -> io::Result<Vec<ChangeEvent>> {
        Ok(self
            .list()?
            .into_iter()
            .map(|stored| stored.event)
            .collect())
    }

    fn next_sequence(&self) -> io::Result<u64> {
        Ok(self
            .list()?
            .into_iter()
            .map(|stored| stored.sequence)
            .max()
            .unwrap_or(0)
            + 1)
    }
}

fn format_index_line(record: &StoredSnapshotRecord) -> String {
    [
        encode_field(&record.tenant),
        encode_field(&record.product),
        encode_field(&record.context_hash),
        encode_field(&record.snapshot_id),
        encode_field(&record.resolver_version),
        encode_field(&record.snapshot_path.to_string_lossy()),
    ]
    .join("\t")
}

fn parse_index_line(root: &Path, line: &str) -> io::Result<StoredSnapshotRecord> {
    let fields = line.split('\t').collect::<Vec<_>>();
    if fields.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot index line must contain six fields",
        ));
    }

    Ok(StoredSnapshotRecord {
        tenant: decode_field(fields[0])?,
        product: decode_field(fields[1])?,
        context_hash: decode_field(fields[2])?,
        snapshot_id: decode_field(fields[3])?,
        resolver_version: decode_field(fields[4])?,
        snapshot_path: absolute_path(root, decode_field(fields[5])?),
    })
}

fn format_event_line(stored: &StoredChangeEvent) -> String {
    let mut fields = vec![stored.sequence.to_string()];
    match &stored.event {
        ChangeEvent::PackageChanged(package) => {
            fields.push("package".to_string());
            fields.push(encode_field(&package.to_string()));
        }
        ChangeEvent::AdvisoryChanged {
            advisory_id,
            package,
        } => {
            fields.push("advisory".to_string());
            fields.push(encode_field(advisory_id));
            fields.push(encode_field(&package.to_string()));
        }
        ChangeEvent::RepositoryChanged(channel) => {
            fields.push("repository".to_string());
            fields.push(encode_field(channel));
        }
        ChangeEvent::PolicyChanged(policy_id) => {
            fields.push("policy".to_string());
            fields.push(encode_field(policy_id));
        }
    }
    fields.join("\t")
}

fn parse_event_line(line: &str) -> io::Result<StoredChangeEvent> {
    let fields = line.split('\t').collect::<Vec<_>>();
    if fields.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "change event line must contain sequence, kind, and payload",
        ));
    }
    let sequence = fields[0].parse::<u64>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid change event sequence: {error}"),
        )
    })?;
    let event = match fields[1] {
        "package" if fields.len() == 3 => {
            ChangeEvent::PackageChanged(parse_package_id(&decode_field(fields[2])?)?)
        }
        "advisory" if fields.len() == 4 => ChangeEvent::AdvisoryChanged {
            advisory_id: decode_field(fields[2])?,
            package: parse_package_id(&decode_field(fields[3])?)?,
        },
        "repository" if fields.len() == 3 => {
            ChangeEvent::RepositoryChanged(decode_field(fields[2])?)
        }
        "policy" if fields.len() == 3 => ChangeEvent::PolicyChanged(decode_field(fields[2])?),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported change event line",
            ));
        }
    };
    Ok(StoredChangeEvent { sequence, event })
}

fn parse_package_id(value: &str) -> io::Result<PackageId> {
    let Some((ecosystem, rest)) = value.split_once(':') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package id is missing ecosystem prefix",
        ));
    };
    let ecosystem = parse_ecosystem(ecosystem);
    let (namespace, name) = match &ecosystem {
        Ecosystem::Maven | Ecosystem::Gradle | Ecosystem::Npm => rest
            .split_once('/')
            .map_or((None, rest.to_string()), |(namespace, name)| {
                (Some(namespace.to_string()), name.to_string())
            }),
        _ => (None, rest.to_string()),
    };
    Ok(PackageId::new(ecosystem, namespace, name))
}

fn parse_ecosystem(value: &str) -> Ecosystem {
    match value {
        "internal" => Ecosystem::Internal,
        "rpm" => Ecosystem::Rpm,
        "python" => Ecosystem::Python,
        "maven" => Ecosystem::Maven,
        "gradle" => Ecosystem::Gradle,
        "npm" => Ecosystem::Npm,
        "go" => Ecosystem::Go,
        "cargo" => Ecosystem::Cargo,
        "nuget" => Ecosystem::NuGet,
        "rubygems" => Ecosystem::RubyGems,
        other => Ecosystem::Other(other.to_string()),
    }
}

#[cfg(feature = "sqlite")]
fn sqlite_event_fields(event: &ChangeEvent) -> (&'static str, String, Option<String>) {
    match event {
        ChangeEvent::PackageChanged(package) => ("package", package.to_string(), None),
        ChangeEvent::AdvisoryChanged {
            advisory_id,
            package,
        } => ("advisory", advisory_id.clone(), Some(package.to_string())),
        ChangeEvent::RepositoryChanged(channel) => ("repository", channel.clone(), None),
        ChangeEvent::PolicyChanged(policy_id) => ("policy", policy_id.clone(), None),
    }
}

#[cfg(feature = "sqlite")]
fn sqlite_event_from_fields(
    kind: &str,
    payload_a: String,
    payload_b: Option<String>,
) -> io::Result<ChangeEvent> {
    match kind {
        "package" => Ok(ChangeEvent::PackageChanged(parse_package_id(&payload_a)?)),
        "advisory" => {
            let Some(package) = payload_b else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "advisory event is missing package payload",
                ));
            };
            Ok(ChangeEvent::AdvisoryChanged {
                advisory_id: payload_a,
                package: parse_package_id(&package)?,
            })
        }
        "repository" => Ok(ChangeEvent::RepositoryChanged(payload_a)),
        "policy" => Ok(ChangeEvent::PolicyChanged(payload_a)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SQLite change event kind",
        )),
    }
}

#[cfg(feature = "sqlite")]
fn current_epoch_seconds() -> io::Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|error| io::Error::other(format!("system time before UNIX epoch: {error}")))
}

#[cfg(feature = "sqlite")]
fn sqlite_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(format!("SQLite storage error: {error}"))
}

fn absolute_path(root: &Path, path: String) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn encode_field(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn decode_field(value: &str) -> io::Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated percent escape in snapshot index",
                ));
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid percent escape: {error}"),
                )
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid percent escape: {error}"),
                )
            })?;
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snapshot index field is not UTF-8: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::demo::demo_repository;
    use crate::platform::{InMemoryGraphStore, ResolverJob, ResolverService};

    use super::*;

    #[test]
    fn file_graph_store_persists_and_reads_snapshot_json() {
        let store = FileGraphStore::new(test_store_dir("persist")).unwrap();
        let record = demo_record("customer-a", "portal");

        let stored = store.persist_record(&record).unwrap();
        let json = store.snapshot_json(&stored.snapshot_id).unwrap().unwrap();

        assert!(stored.snapshot_path.exists());
        assert!(json.contains(&record.snapshot.id));
        assert!(json.contains("tuxcare-supply-chain-platform"));
    }

    #[test]
    fn file_graph_store_lists_and_finds_context_records() {
        let store = FileGraphStore::new(test_store_dir("find")).unwrap();
        let record = demo_record("customer-a", "portal");
        let context_hash = record.snapshot.context_hash.clone();
        store.persist_record(&record).unwrap();

        let records = store.find("customer-a", "portal", &context_hash).unwrap();

        assert_eq!(store.list().unwrap().len(), 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].snapshot_id, record.snapshot.id);
    }

    #[test]
    fn file_graph_store_repeated_persist_is_idempotent() {
        let store = FileGraphStore::new(test_store_dir("idempotent")).unwrap();
        let record = demo_record("tenant with spaces", "portal/main");

        let first = store.persist_record(&record).unwrap();
        let second = store.persist_record(&record).unwrap();

        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(first.snapshot_path.exists());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_graph_store_persists_and_reads_snapshot_json() {
        let path = test_store_dir("sqlite-persist").join("graphscope.db");
        let store = SqliteGraphStore::new(path.clone()).unwrap();
        let record = demo_record("customer-a", "portal");

        let stored = store.persist_record(&record).unwrap();
        let json = store.snapshot_json(&stored.snapshot_id).unwrap().unwrap();

        assert_eq!(stored.snapshot_path, path);
        assert!(store.path().exists());
        assert!(json.contains(&record.snapshot.id));
        assert!(json.contains("\"occurrences\""));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_graph_store_finds_context_records_after_reopen() {
        let path = test_store_dir("sqlite-reopen").join("graphscope.db");
        let store = SqliteGraphStore::new(path.clone()).unwrap();
        let record = demo_record("customer-a", "portal");
        let context_hash = record.snapshot.context_hash.clone();
        let first = store.persist_record(&record).unwrap();
        let second = store.persist_record(&record).unwrap();
        drop(store);

        let reopened = SqliteGraphStore::new(path).unwrap();
        let records = reopened
            .find("customer-a", "portal", &context_hash)
            .unwrap();

        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_eq!(reopened.list().unwrap().len(), 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].snapshot_id, record.snapshot.id);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_graph_store_appends_and_replays_events() {
        let store =
            SqliteGraphStore::new(test_store_dir("sqlite-events").join("graphscope.db")).unwrap();
        store
            .append_events(&[
                ChangeEvent::PackageChanged(PackageId::python("urllib3")),
                ChangeEvent::AdvisoryChanged {
                    advisory_id: "CVE-2026-demo".to_string(),
                    package: PackageId::rpm("openssl-libs"),
                },
                ChangeEvent::PolicyChanged("default-policy".to_string()),
            ])
            .unwrap();

        let stored = store.list_events().unwrap();
        let events = store.events().unwrap();

        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0].sequence, 1);
        assert_eq!(
            events[1],
            ChangeEvent::AdvisoryChanged {
                advisory_id: "CVE-2026-demo".to_string(),
                package: PackageId::rpm("openssl-libs"),
            }
        );
    }

    #[test]
    fn file_change_event_log_appends_and_replays_events() {
        let log = FileChangeEventLog::new(test_store_dir("events").join("events.tsv")).unwrap();
        log.append_all(&[
            ChangeEvent::PackageChanged(PackageId::python("urllib3")),
            ChangeEvent::RepositoryChanged("cloudlinux-baseos".to_string()),
            ChangeEvent::PolicyChanged("default-policy".to_string()),
        ])
        .unwrap();

        let stored = log.list().unwrap();
        let events = log.events().unwrap();

        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0].sequence, 1);
        assert_eq!(
            events[0],
            ChangeEvent::PackageChanged(PackageId::python("urllib3"))
        );
        assert_eq!(
            events[2],
            ChangeEvent::PolicyChanged("default-policy".to_string())
        );
    }

    #[test]
    fn file_change_event_log_feeds_invalidation_planning() {
        let log =
            FileChangeEventLog::new(test_store_dir("plan-events").join("events.tsv")).unwrap();
        log.append_all(&[
            ChangeEvent::PackageChanged(PackageId::python("urllib3")),
            ChangeEvent::RepositoryChanged("cloudlinux-baseos".to_string()),
        ])
        .unwrap();
        let mut graph_store = InMemoryGraphStore::new();
        graph_store.upsert(demo_record("customer-a", "portal"));

        let events = log.events().unwrap();
        let plan = graph_store.plan_invalidation(&events);

        assert_eq!(plan.impacted_records.len(), 1);
        assert_eq!(plan.reasons[&plan.impacted_records[0]].len(), 2);
    }

    fn demo_record(tenant: &str, product: &str) -> GraphRecord {
        let (repository, roots, context) = demo_repository();
        ResolverService::new(repository)
            .process(ResolverJob::new(tenant, product, roots, context, "test"))
    }

    fn test_store_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("graphscope-{name}-{nanos}"))
    }
}
