//! Small shared state the door guard and the front desk keep between calls.
//!
//! Three kinds of entry, all short and non-secret:
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
//!
//! Every reader treats a store failure as "nothing remembered": an approval
//! retry is then scored as a new activity (fail closed, never auto-approved),
//! and a completion falls back to the request-derived activity id with no
//! duration.
//!
//! [`RedisStore`] shares this across replicas; [`MemoryStore`] is for a single
//! replica and tests.

use std::collections::HashMap;
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

pub fn session_key(sandbox_id: &str) -> String {
    format!("openbox:session:{sandbox_id}")
}

/// In-process store. Expired entries are dropped when read.
#[derive(Default)]
pub struct MemoryStore {
    entries: Mutex<HashMap<String, (String, Option<Instant>)>>,
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
}

/// Redis over RESP, one connection reused and reopened after any error.
/// Every command is bounded by `timeout` so a slow Redis cannot hold up a
/// verdict.
pub struct RedisStore {
    address: String,
    password: Option<String>,
    db: u32,
    timeout: Duration,
    connection: tokio::sync::Mutex<Option<BufReader<TcpStream>>>,
}

enum Reply {
    Ok,
    Integer,
    Bulk(Option<Vec<u8>>),
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
            connection: tokio::sync::Mutex::new(None),
        })
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
            let mut slot = self.connection.lock().await;
            // Out of the slot while in use: if this future is dropped mid
            // exchange (a timeout, or OpenShell cancelling the request), the
            // half-used connection goes with it instead of desynchronising
            // the next caller.
            let mut connection = match slot.take() {
                Some(connection) => connection,
                None => self.open().await?,
            };
            let outcome = exchange(&mut connection, args).await;
            if outcome.is_ok() {
                *slot = Some(connection);
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
        Some(b':') => Ok(Reply::Integer),
        Some(b'-') => Err(format!("redis error: {}", &line[1..])),
        Some(b'$') => {
            let length: i64 = line[1..]
                .parse()
                .map_err(|_| "redis: bad bulk length".to_owned())?;
            if length < 0 {
                return Ok(Reply::Bulk(None));
            }
            let mut data = vec![0; usize::try_from(length).unwrap_or(0) + 2];
            connection
                .read_exact(&mut data)
                .await
                .map_err(|error| format!("redis read: {error}"))?;
            data.truncate(data.len() - 2);
            Ok(Reply::Bulk(Some(data)))
        }
        _ => Err(format!("redis: unexpected reply {line:?}")),
    }
}

fn text(reply: Reply) -> Result<Option<String>, String> {
    match reply {
        Reply::Bulk(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "redis: value is not UTF-8".to_owned()),
        Reply::Bulk(None) => Ok(None),
        Reply::Ok | Reply::Integer => Err("redis: expected a value".to_owned()),
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
    }
}
