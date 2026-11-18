//! Small shared state the door guard and the front desk keep between calls.
//!
//! Six kinds of entry, all short and non-secret:
//!
//! - **Approvals**: `sandbox + action fingerprint → activity id`, written when
//!   Core requires approval, so the identical retry (on any replica) asks Core
//!   about that activity instead of opening a new one. Lives for the approval
//!   TTL.
//! - **Requests**: `request id → activity id, type, start time`, written when a
//!   request is allowed, read once when its response comes back, so the
//!   `ActivityCompleted` names the same activity and carries a duration.
//! - **Prompts**: `sandbox + user turn`, once that turn's prompt is signalled,
//!   so a conversation resent on every model call is signalled once.
//! - **Sessions**: `sandbox id → start time`, for the session's duration.
//! - **Pending**: `sandbox id → request ids`, each allowed request whose
//!   completion (its span and the end of its activity) the door guard has not
//!   sent yet, so the front desk ends a deleted sandbox's session only after
//!   them.
//! - **Session ends owed**: `sandbox id → duration, last attempt`, plus the
//!   set of those ids, from a sandbox's delete until Core accepts its session
//!   end, so a failed end is retried by this or any later front desk.
//!
//! Every reader treats a store failure as "nothing remembered": an approval
//! retry is then scored as a new activity (fail closed, never auto-approved),
//! and a completion falls back to the request-derived activity id with no
//! duration.
//!
//! [`RedisStore`] shares this across replicas; [`MemoryStore`] is for a single
//! replica and tests.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tonic::async_trait]
pub trait SharedStore: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// `ttl: None` keeps the entry until it is taken or deleted.
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), String>;
    /// Reads and removes.
    async fn take(&self, key: &str) -> Result<Option<String>, String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
    /// Adds a member to the set at `key`, which lives `ttl` from now.
    async fn add_member(&self, key: &str, member: &str, ttl: Duration) -> Result<(), String>;
    async fn remove_member(&self, key: &str, member: &str) -> Result<(), String>;
    /// How many members the set at `key` has; 0 when there is none.
    async fn count_members(&self, key: &str) -> Result<u64, String>;
    /// The members of the set at `key`, in no order; empty when there is none.
    async fn members(&self, key: &str) -> Result<Vec<String>, String> {
        let _ = key;
        Err("this store cannot list set members".to_owned())
    }
}

pub fn approval_key(sandbox_id: &str, fingerprint: &str) -> String {
    format!("openbox:approval:{sandbox_id}:{fingerprint}")
}

pub fn request_key(request_id: &str) -> String {
    format!("openbox:request:{request_id}")
}

pub fn prompt_key(sandbox_id: &str, turn: &str) -> String {
    format!("openbox:prompt:{sandbox_id}:{turn}")
}

/// A tool the model asked for in a sandbox: its activity and whether it is
/// open, started in Core, or closed.
pub fn tool_key(sandbox_id: &str, call_id: &str) -> String {
    format!("openbox:tool:{sandbox_id}:{call_id}")
}

/// The call ids of a sandbox's open tools, oldest first.
pub fn open_tools_key(sandbox_id: &str) -> String {
    format!("openbox:tools:{sandbox_id}")
}

pub fn session_key(sandbox_id: &str) -> String {
    format!("openbox:session:{sandbox_id}")
}

/// The request ids of a sandbox whose completion is still to be sent.
pub fn pending_key(sandbox_id: &str) -> String {
    format!("openbox:pending:{sandbox_id}")
}

/// The sandbox ids whose session end Core has not accepted yet.
pub fn ends_owed_key() -> String {
    "openbox:sessions:end-owed".to_owned()
}

/// A sandbox's owed session end: its duration and when it was last tried.
pub fn end_owed_key(sandbox_id: &str) -> String {
    format!("openbox:session-end:{sandbox_id}")
}

/// In-process store. Expired entries are dropped when read.
#[derive(Default)]
pub struct MemoryStore {
    entries: Mutex<HashMap<String, (String, Option<Instant>)>>,
    sets: Mutex<HashMap<String, (HashSet<String>, Instant)>>,
}

impl MemoryStore {
    fn live(&self, key: &str, remove: bool) -> Option<String> {
        let mut entries = self.entries.lock().expect("store lock");
        let expired = entries
            .get(key)
            .is_some_and(|(_, until)| until.is_some_and(|until| until <= Instant::now()));
        if expired {
            entries.remove(key);
            return None;
        }
        if remove {
            entries.remove(key).map(|(value, _)| value)
        } else {
            entries.get(key).map(|(value, _)| value.clone())
        }
    }
}

#[tonic::async_trait]
impl SharedStore for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        Ok(self.live(key, false))
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), String> {
        self.entries.lock().expect("store lock").insert(
            key.to_owned(),
            (value.to_owned(), ttl.map(|ttl| Instant::now() + ttl)),
        );
        Ok(())
    }

    async fn take(&self, key: &str) -> Result<Option<String>, String> {
        Ok(self.live(key, true))
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.entries.lock().expect("store lock").remove(key);
        Ok(())
    }

    async fn add_member(&self, key: &str, member: &str, ttl: Duration) -> Result<(), String> {
        let mut sets = self.sets.lock().expect("store lock");
        let until = Instant::now() + ttl;
        let (members, expires) = sets
            .entry(key.to_owned())
            .or_insert_with(|| (HashSet::new(), until));
        if *expires <= Instant::now() {
            members.clear();
        }
        members.insert(member.to_owned());
        *expires = until;
        Ok(())
    }

    async fn remove_member(&self, key: &str, member: &str) -> Result<(), String> {
        let mut sets = self.sets.lock().expect("store lock");
        if let Some((members, _)) = sets.get_mut(key) {
            members.remove(member);
            if members.is_empty() {
                sets.remove(key);
            }
        }
        Ok(())
    }

    async fn count_members(&self, key: &str) -> Result<u64, String> {
        let sets = self.sets.lock().expect("store lock");
        Ok(sets
            .get(key)
            .filter(|(_, expires)| *expires > Instant::now())
            .map_or(0, |(members, _)| members.len() as u64))
    }

    async fn members(&self, key: &str) -> Result<Vec<String>, String> {
        let sets = self.sets.lock().expect("store lock");
        Ok(sets
            .get(key)
            .filter(|(_, expires)| *expires > Instant::now())
            .map(|(members, _)| members.iter().cloned().collect())
            .unwrap_or_default())
    }
}

/// Connections a [`RedisStore`] opens by default.
pub const DEFAULT_REDIS_POOL: usize = 16;

/// Redis over RESP, through a small pool of connections.
///
/// At most `pool` commands are in flight at once, each on a connection of its
/// own; a connection is reused after a clean exchange and dropped after any
/// error. Every command, including its wait for a free connection, is bounded
/// by `timeout` so a slow Redis cannot hold up a verdict.
///
/// One connection for every request made each command wait for all the
/// others: under load (SPEC-001 A9) the wait alone ran past the timeout, and
/// a timed-out read counts as "nothing remembered".
pub struct RedisStore {
    address: String,
    password: Option<String>,
    db: u32,
    timeout: Duration,
    idle: Mutex<Vec<BufReader<TcpStream>>>,
    slots: tokio::sync::Semaphore,
}

enum Reply {
    Ok,
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    /// An array of bulk strings (`SMEMBERS`); nil elements are dropped.
    Array(Vec<Vec<u8>>),
}

impl RedisStore {
    /// `redis://[:password@]host[:port][/db]`.
    pub fn from_url(url: &str, timeout: Duration) -> Result<Self, String> {
        let rest = url
            .strip_prefix("redis://")
            .ok_or("OPENBOX_REDIS_URL must start with redis://")?;
        let (auth, rest) = match rest.rsplit_once('@') {
            Some((auth, rest)) => (Some(auth), rest),
            None => (None, rest),
        };
        let password = auth
            .map(|auth| auth.split_once(':').map_or(auth, |(_, password)| password))
            .filter(|password| !password.is_empty())
            .map(str::to_owned);
        let (host, db) = match rest.split_once('/') {
            Some((host, db)) if !db.is_empty() => (
                host,
                db.parse()
                    .map_err(|_| "OPENBOX_REDIS_URL database must be a number")?,
            ),
            Some((host, _)) => (host, 0),
            None => (rest, 0),
        };
        if host.is_empty() {
            return Err("OPENBOX_REDIS_URL has no host".to_owned());
        }
        let address = if host.contains(':') {
            host.to_owned()
        } else {
            format!("{host}:6379")
        };
        Ok(Self {
            address,
            password,
            db,
            timeout,
            idle: Mutex::new(Vec::new()),
            slots: tokio::sync::Semaphore::new(DEFAULT_REDIS_POOL),
        })
    }

    /// At most `size` connections (and commands in flight), 1 to 256.
    pub fn with_pool(mut self, size: usize) -> Result<Self, String> {
        if !(1..=256).contains(&size) {
            return Err("OPENBOX_REDIS_POOL must be between 1 and 256".to_owned());
        }
        self.slots = tokio::sync::Semaphore::new(size);
        Ok(self)
    }

    async fn open(&self) -> Result<BufReader<TcpStream>, String> {
        let stream = TcpStream::connect(&self.address)
            .await
            .map_err(|error| format!("redis connect {}: {error}", self.address))?;
        let mut connection = BufReader::new(stream);
        if let Some(password) = &self.password {
            exchange(&mut connection, &[b"AUTH", password.as_bytes()]).await?;
        }
        if self.db != 0 {
            exchange(
                &mut connection,
                &[b"SELECT", self.db.to_string().as_bytes()],
            )
            .await?;
        }
        Ok(connection)
    }

    async fn command(&self, args: &[&[u8]]) -> Result<Reply, String> {
        let attempt = async {
            let _slot = self
                .slots
                .acquire()
                .await
                .map_err(|_| "redis pool closed".to_owned())?;
            // Out of the pool while in use: if this future is dropped mid
            // exchange (a timeout, or OpenShell cancelling the request), the
            // half-used connection goes with it instead of desynchronising
            // the next caller.
            let idle = self.idle.lock().expect("redis pool lock").pop();
            let mut connection = match idle {
                Some(connection) => connection,
                None => self.open().await?,
            };
            let outcome = exchange(&mut connection, args).await;
            if outcome.is_ok() {
                self.idle.lock().expect("redis pool lock").push(connection);
            }
            outcome
        };
        tokio::time::timeout(self.timeout, attempt)
            .await
            .unwrap_or_else(|_| Err("redis timed out".to_owned()))
    }
}

async fn exchange(connection: &mut BufReader<TcpStream>, args: &[&[u8]]) -> Result<Reply, String> {
    let mut frame = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        frame.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        frame.extend_from_slice(arg);
        frame.extend_from_slice(b"\r\n");
    }
    connection
        .get_mut()
        .write_all(&frame)
        .await
        .map_err(|error| format!("redis write: {error}"))?;
    let mut line = String::new();
    connection
        .read_line(&mut line)
        .await
        .map_err(|error| format!("redis read: {error}"))?;
    let line = line.trim_end_matches("\r\n");
    match line.as_bytes().first() {
        Some(b'+') => Ok(Reply::Ok),
        Some(b':') => line[1..]
            .parse()
            .map(Reply::Integer)
            .map_err(|_| "redis: bad integer".to_owned()),
        Some(b'-') => Err(format!("redis error: {}", &line[1..])),
        Some(b'$') => read_bulk(connection, line).await.map(Reply::Bulk),
        Some(b'*') => {
            let count: i64 = line[1..]
                .parse()
                .map_err(|_| "redis: bad array length".to_owned())?;
            let mut items = Vec::new();
            for _ in 0..count.max(0) {
                let mut item = String::new();
                connection
                    .read_line(&mut item)
                    .await
                    .map_err(|error| format!("redis read: {error}"))?;
                let item = item.trim_end_matches("\r\n");
                if !item.starts_with('$') {
                    return Err(format!("redis: unexpected array element {item:?}"));
                }
                items.extend(read_bulk(connection, item).await?);
            }
            Ok(Reply::Array(items))
        }
        _ => Err(format!("redis: unexpected reply {line:?}")),
    }
}

/// Reads the body of a bulk string whose `$<length>` header is `header`.
async fn read_bulk(
    connection: &mut BufReader<TcpStream>,
    header: &str,
) -> Result<Option<Vec<u8>>, String> {
    let length: i64 = header[1..]
        .parse()
        .map_err(|_| "redis: bad bulk length".to_owned())?;
    if length < 0 {
        return Ok(None);
    }
    let mut data = vec![0; usize::try_from(length).unwrap_or(0) + 2];
    connection
        .read_exact(&mut data)
        .await
        .map_err(|error| format!("redis read: {error}"))?;
    data.truncate(data.len() - 2);
    Ok(Some(data))
}

fn text(reply: Reply) -> Result<Option<String>, String> {
    match reply {
        Reply::Bulk(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "redis: value is not UTF-8".to_owned()),
        Reply::Bulk(None) => Ok(None),
        Reply::Ok | Reply::Integer(_) | Reply::Array(_) => {
            Err("redis: expected a value".to_owned())
        }
    }
}

#[tonic::async_trait]
impl SharedStore for RedisStore {
    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        text(self.command(&[b"GET", key.as_bytes()]).await?)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), String> {
        let reply = match ttl {
            Some(ttl) => {
                let millis = ttl.as_millis().max(1).to_string();
                self.command(&[
                    b"SET",
                    key.as_bytes(),
                    value.as_bytes(),
                    b"PX",
                    millis.as_bytes(),
                ])
                .await?
            }
            None => {
                self.command(&[b"SET", key.as_bytes(), value.as_bytes()])
                    .await?
            }
        };
        match reply {
            Reply::Ok => Ok(()),
            _ => Err("redis: SET was not acknowledged".to_owned()),
        }
    }

    async fn take(&self, key: &str) -> Result<Option<String>, String> {
        text(self.command(&[b"GETDEL", key.as_bytes()]).await?)
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.command(&[b"DEL", key.as_bytes()]).await.map(|_| ())
    }

    async fn add_member(&self, key: &str, member: &str, ttl: Duration) -> Result<(), String> {
        self.command(&[b"SADD", key.as_bytes(), member.as_bytes()])
            .await?;
        let millis = ttl.as_millis().max(1).to_string();
        self.command(&[b"PEXPIRE", key.as_bytes(), millis.as_bytes()])
            .await
            .map(|_| ())
    }

    async fn remove_member(&self, key: &str, member: &str) -> Result<(), String> {
        self.command(&[b"SREM", key.as_bytes(), member.as_bytes()])
            .await
            .map(|_| ())
    }

    async fn count_members(&self, key: &str) -> Result<u64, String> {
        match self.command(&[b"SCARD", key.as_bytes()]).await? {
            Reply::Integer(count) => Ok(u64::try_from(count).unwrap_or(0)),
            _ => Err("redis: SCARD did not return a count".to_owned()),
        }
    }

    async fn members(&self, key: &str) -> Result<Vec<String>, String> {
        match self.command(&[b"SMEMBERS", key.as_bytes()]).await? {
            Reply::Array(items) => items
                .into_iter()
                .map(|item| {
                    String::from_utf8(item).map_err(|_| "redis: member is not UTF-8".to_owned())
                })
                .collect(),
            _ => Err("redis: SMEMBERS did not return an array".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_expires_and_takes() {
        let store = MemoryStore::default();
        store.set("a", "1", None).await.unwrap();
        store
            .set("b", "2", Some(Duration::from_millis(1)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(store.get("a").await.unwrap().as_deref(), Some("1"));
        assert_eq!(store.get("b").await.unwrap(), None);
        assert_eq!(store.take("a").await.unwrap().as_deref(), Some("1"));
        assert_eq!(store.get("a").await.unwrap(), None);
    }

    #[tokio::test]
    async fn memory_store_counts_members() {
        let store = MemoryStore::default();
        store
            .add_member("p", "a", Duration::from_secs(5))
            .await
            .unwrap();
        store
            .add_member("p", "b", Duration::from_secs(5))
            .await
            .unwrap();
        store
            .add_member("p", "a", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(store.count_members("p").await.unwrap(), 2);
        store.remove_member("p", "a").await.unwrap();
        store.remove_member("p", "missing").await.unwrap();
        assert_eq!(store.count_members("p").await.unwrap(), 1);
        assert_eq!(store.members("p").await.unwrap(), ["b"]);
        store.remove_member("p", "b").await.unwrap();
        assert!(store.members("p").await.unwrap().is_empty());
        assert_eq!(store.count_members("p").await.unwrap(), 0);
        store
            .add_member("q", "a", Duration::from_millis(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(store.count_members("q").await.unwrap(), 0);
    }

    #[test]
    fn redis_urls() {
        let plain = RedisStore::from_url("redis://localhost", Duration::from_secs(1)).unwrap();
        assert_eq!((plain.address.as_str(), plain.db), ("localhost:6379", 0));
        assert!(plain.password.is_none());
        let full = RedisStore::from_url(
            "redis://:s3cret@redis.internal:6380/2",
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            (full.address.as_str(), full.db, full.password.as_deref()),
            ("redis.internal:6380", 2, Some("s3cret"))
        );
        assert!(RedisStore::from_url("http://localhost", Duration::from_secs(1)).is_err());
        assert!(RedisStore::from_url("redis:///1", Duration::from_secs(1)).is_err());
    }

    /// Against a real Redis when `OBX_TEST_REDIS_URL` is set (the verify
    /// script does), otherwise skipped.
    #[tokio::test]
    async fn redis_store_round_trip() {
        let Ok(url) = std::env::var("OBX_TEST_REDIS_URL") else {
            return;
        };
        let store = RedisStore::from_url(&url, Duration::from_secs(1)).unwrap();
        let key = format!("openbox:test:{}", std::process::id());
        store
            .set(&key, "v", Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(store.get(&key).await.unwrap().as_deref(), Some("v"));
        assert_eq!(store.take(&key).await.unwrap().as_deref(), Some("v"));
        assert_eq!(store.get(&key).await.unwrap(), None);
        let set = format!("openbox:test:set:{}", std::process::id());
        store
            .add_member(&set, "a", Duration::from_secs(5))
            .await
            .unwrap();
        store
            .add_member(&set, "b", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(store.count_members(&set).await.unwrap(), 2);
        let mut members = store.members(&set).await.unwrap();
        members.sort();
        assert_eq!(members, ["a", "b"]);
        store.remove_member(&set, "a").await.unwrap();
        store.remove_member(&set, "b").await.unwrap();
        assert_eq!(store.count_members(&set).await.unwrap(), 0);
        assert!(store.members(&set).await.unwrap().is_empty());
    }

    /// Many commands at once share a small pool without mixing up replies.
    #[tokio::test]
    async fn redis_store_pool_under_concurrency() {
        let Ok(url) = std::env::var("OBX_TEST_REDIS_URL") else {
            return;
        };
        let store = std::sync::Arc::new(
            RedisStore::from_url(&url, Duration::from_secs(2))
                .unwrap()
                .with_pool(4)
                .unwrap(),
        );
        let base = format!("openbox:test:pool:{}", std::process::id());
        let tasks: Vec<_> = (0..200)
            .map(|i| {
                let store = std::sync::Arc::clone(&store);
                let key = format!("{base}:{i}");
                tokio::spawn(async move {
                    let value = format!("v{i}");
                    store
                        .set(&key, &value, Some(Duration::from_secs(5)))
                        .await
                        .unwrap();
                    assert_eq!(store.take(&key).await.unwrap(), Some(value));
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        assert!(store.idle.lock().unwrap().len() <= 4);
    }

    #[test]
    fn redis_pool_size_is_bounded() {
        let store = || RedisStore::from_url("redis://localhost", Duration::from_secs(1)).unwrap();
        assert!(store().with_pool(0).is_err());
        assert!(store().with_pool(257).is_err());
        assert!(store().with_pool(64).is_ok());
    }
}
