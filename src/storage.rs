use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::platform::GraphRecord;

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
    use crate::platform::{ResolverJob, ResolverService};

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
