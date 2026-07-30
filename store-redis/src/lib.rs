// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Redis** backend for busbar's durable governance store - the shared, multi-node `db` plugin
//! over a KEY-VALUE data model. Implements `busbar_api::Store` on a mutex-guarded SYNCHRONOUS redis
//! connection, depending only on the `busbar-api` contract (plus the `redis` driver), never on the
//! engine.
//!
//! Redis has no tables, so the relational schema the SQLite/Postgres backends use is modeled in KV:
//!
//! - **virtual keys** - `busbar:key:<id>` holds the JSON [`VirtualKey`]; the set `busbar:keys` indexes
//!   every id so `list_keys` is a SMEMBERS + per-id GET.
//! - **AWS credentials** - `busbar:awscred:<access_key_id>` holds the JSON credential; `busbar:awscreds`
//!   indexes them; `busbar:awscred_ids:<key_id>` maps a virtual key to its AccessKeyIds so a key delete
//!   removes them (a revoked key's SigV4 credential must never outlive it - the same guarantee the SQL
//!   backends enforce with a `DELETE … WHERE key_id`).
//! - **token ledger** - `busbar:usage:<bucket_id>:<window_start>` is a HASH holding `requests`
//!   (admission count) + `billable_requests` (v4: admitted minus non-2xx refunds, the fee base)
//!   plus per-(model, tier) token fields `m:<model>:input|output|cache_read|cache_write`. `put_usage`
//!   replaces the hash with absolute values; `add_usage` HINCRBYs the signed deltas (the
//!   fleet-additive flush, so concurrent nodes accumulate instead of overwriting each other);
//!   `get_usage` HGETALLs and parses the model fields. NO spend field: dollars are derived at read
//!   time from `ledger x rate_card` in the engine. (Floor-at-zero parity note: the SQL backends
//!   floor each counter at 0 IN THE WRITE; HINCRBY has no atomic floor, so a transient negative is
//!   possible in the stored hash and is clamped to 0 ON READ - same observable floor.)
//! - **metering** - `busbar:metering:<bucket>` is a SET of row keys; each row is a HASH accumulated
//!   with HINCRBY (add), so concurrent responses accumulate without a read-modify-write race.
//! - **audit** - `busbar:audit` is a SORTED SET scored by `seq`, each member the JSON [`AuditRecord`].
//!
//! ## Atomicity
//!
//! Every MULTI-KEY write cascade runs as ONE atomic `MULTI`/`EXEC` pipeline
//! ([`redis::Pipeline::atomic`]): `put_key_with_aws_credential` (key + credential + all three
//! indexes) and the `delete_key` cascade (key row, key index, usage windows, credentials, credential
//! indexes). A mid-cascade failure therefore can NEVER orphan a SigV4 credential behind a deleted
//! key or publish a credential for a key that was not stored - the transactional parity of the SQL
//! backends' `BEGIN`/`COMMIT`.
//!
//! ## Connections, TLS, reconnect
//!
//! A single mutex-guarded synchronous connection used off the request hot path (key CRUD + the
//! write-behind usage flush). A DROPPED connection (server restart, idle timeout, network blip) is
//! transparently re-established: a READ / idempotent op retries exactly ONCE on a connection-level
//! error by reopening from the client before failing. A NON-IDEMPOTENT write cascade
//! (`add_usage`/`add_metering`: HINCRBY `MULTI`/`EXEC`) does NOT auto-retry - a lost-reply timeout
//! may have already committed the EXEC server-side, so a retry would double-apply the delta; instead
//! the error surfaces and the write-behind flusher re-derives the correct total from the baseline on
//! the next tick (exactly-once on error). `rediss://` URLs use TLS (rustls, ring provider, OS-native
//! roots). Error strings are SCRUBBED of the URL password before they leave this crate, so a
//! connection failure can never leak the secret into logs.
//!
//! ## Data growth (documented, deliberate)
//!
//! Rows are written WITHOUT a TTL: usage windows, metering buckets, and audit entries accumulate
//! unboundedly by design - the store is the durable system of record and busbar never silently
//! expires governance data. Operators who want bounded growth should reap old
//! `busbar:usage:*`/`busbar:metering:*` keys (or apply `EXPIRE` out-of-band) on their own retention
//! schedule; the audit zset should be archived, not expired.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, ModelTokens, Store, StoreError,
    StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};
use redis::{Commands, Connection};
use std::sync::Mutex;
use std::time::Duration;

/// Default connect timeout (`Client::open` + the initial `get_connection`): with no DSN-level
/// escape hatch (unlike postgres's libpq `connect_timeout`), a blackholed/firewalled host would
/// otherwise wedge engine boot indefinitely. `connect_with_timeout` lets a caller override this.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Key-space helpers (one namespace prefix so a Redis shared with other apps never collides) ──────
const KEY_PREFIX: &str = "busbar:key:";
const KEYS_INDEX: &str = "busbar:keys";
const AWSCRED_PREFIX: &str = "busbar:awscred:";
const AWSCRED_INDEX: &str = "busbar:awscreds";
const AWSCRED_IDS_PREFIX: &str = "busbar:awscred_ids:";
const AUDIT_ZSET: &str = "busbar:audit";
/// The signed-token REVOCATION denylist (1.5.0). `busbar:denylist:<sub>` holds the operator reason
/// (a plain string), and `busbar:denylist` is a SET indexing every denied sub so `list_denylist` is
/// a SMEMBERS. Both live under the `busbar:*` namespace, so the legacy migration SCAN wipe already
/// accounts for them.
const DENYLIST_PREFIX: &str = "busbar:denylist:";
const DENYLIST_INDEX: &str = "busbar:denylist";
/// The schema-version marker key (mirrors the SQLite `PRAGMA user_version`). v2 (1.5.0 dev) = the
/// token-ledger cost model; v3 = the 1.5.0 PURE-AUTH key shape (the key JSON dropped its inline
/// limit fields, renamed `budget_group` to `group`, and re-encoded `allowed_pools` as an Option:
/// `null` = all pools, `[]` = no pools - C6). v4 = the usage ledger's REQUEST-COUNT SPLIT: the
/// `busbar:usage:*` HASH gains a `billable_requests` field (admitted minus non-2xx refunds - the
/// fee base) alongside `requests` (the admission count), HINCRBY-accumulated on its own axis. A
/// pre-v4 namespace is WIPED on connect (1.5.0 unreleased: bump, not migrate).
const SCHEMA_KEY: &str = "busbar:schema";
const SCHEMA_VERSION: i64 = 4;

fn usage_key(bucket_id: &str, window_start: u64) -> String {
    format!("busbar:usage:{bucket_id}:{window_start}")
}

/// Hash field for one (model, tier) token counter: `m:<model>:<tier>`. Parsed with a RIGHT split on
/// the tier so a model name containing `:` still round-trips.
fn model_field(model: &str, tier: &str) -> String {
    format!("m:{model}:{tier}")
}

/// Parse a `m:<model>:<tier>` hash field back into `(model, tier)`.
fn parse_model_field(field: &str) -> Option<(&str, &str)> {
    field.strip_prefix("m:")?.rsplit_once(':')
}
fn metering_set(bucket: u64) -> String {
    format!("busbar:metering:{bucket}")
}
fn metering_row(bucket: u64, key_id: &str, model: &str, provider: &str) -> String {
    // `|` joins the composite row identity; it is not a legal character in a model/provider name in
    // practice, and even if present it only affects the row's own key (never cross-row correctness).
    format!("busbar:metering:{bucket}:{key_id}|{model}|{provider}")
}

/// Clamp a `u64` into `i64` for Redis integer ops (HINCRBY is signed) - a value above `i64::MAX` pins
/// to `i64::MAX`, never wraps. Mirrors the SQL backends.
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed counter back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as` - mirrors the SQL backends' DI-3 posture.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// Extract the PASSWORD component from a redis URL (`redis://user:pass@host/...` or
/// `redis://:pass@host/...`), if any - the secret that must never appear in an error string.
fn url_password(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let userinfo = rest.rsplit_once('@').map(|(u, _)| u)?;
    let pass = match userinfo.split_once(':') {
        Some((_, p)) => p,
        None => return None, // user only, no password
    };
    (!pass.is_empty()).then(|| pass.to_string())
}

/// Percent-DECODE a URL component (`%40` -> `@`, `%25` -> `%`). A malformed escape is left verbatim.
/// Used so the scrub redacts BOTH the raw (as-written-in-URL) and decoded forms of the password -
/// the redis driver may surface either in an error string (L1).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Replace every occurrence of `secret` (in BOTH its raw and percent-decoded forms) in `msg` with
/// `<redacted>` - the password-in-error scrub. Scrubbing both forms means a secret that appears
/// percent-encoded in the URL but DECODED in a driver error string (or vice-versa) is still caught.
fn scrub(msg: String, secret: Option<&str>) -> String {
    let Some(s) = secret.filter(|s| !s.is_empty()) else {
        return msg;
    };
    let mut out = msg;
    if out.contains(s) {
        out = out.replace(s, "<redacted>");
    }
    let decoded = percent_decode(s);
    if decoded != s && !decoded.is_empty() && out.contains(&decoded) {
        out = out.replace(&decoded, "<redacted>");
    }
    out
}

/// Is this a CONNECTION-LEVEL error worth one reconnect-and-retry (dropped socket, IO failure,
/// server going away) as opposed to a command/data error that would fail identically on a fresh
/// connection?
fn is_connection_error(e: &redis::RedisError) -> bool {
    e.is_io_error() || e.is_connection_dropped() || e.is_connection_refusal() || e.is_timeout()
}

/// Redis `Store` backend (durable, shared across a cluster). A single mutex-guarded synchronous
/// connection with one-shot reconnect - governance is off the request hot path, so serializing
/// access is fine.
pub struct RedisStore {
    client: redis::Client,
    /// The live connection, lazily (re)established. `None` after a detected drop.
    conn: Mutex<Option<Connection>>,
    /// The URL password (if any), scrubbed out of every error string this crate emits.
    secret: Option<String>,
}

impl RedisStore {
    /// Connect to Redis with the given URL (e.g. `redis://:pass@host:6379/0`, or
    /// `rediss://:pass@host:6380/0` for TLS via rustls + OS-native roots), using the
    /// [`DEFAULT_CONNECT_TIMEOUT`]. See [`Self::connect_with_timeout`] for a caller-supplied
    /// timeout.
    pub fn connect(url: &str) -> StoreResult<Self> {
        Self::connect_with_timeout(url, DEFAULT_CONNECT_TIMEOUT)
    }

    /// Like [`Self::connect`], but with an explicit connect timeout. Unlike postgres's libpq, the
    /// `redis` crate gives no DSN-level timeout escape hatch, so a blackholed/firewalled host would
    /// otherwise hang `get_connection()` indefinitely and wedge engine boot; bounding the initial
    /// TCP connect here fails fast instead.
    pub fn connect_with_timeout(url: &str, timeout: Duration) -> StoreResult<Self> {
        let secret = url_password(url);
        // TLS (`rediss://`): the redis driver builds its rustls config against the PROCESS default
        // crypto provider. This crate can live inside a plugin cdylib with its own rustls state, so
        // install the ring provider here explicitly (idempotent; an already-installed provider wins).
        if url.starts_with("rediss://") {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let client = redis::Client::open(url)
            .map_err(|e| StoreError(scrub(format!("redis connect: {e}"), secret.as_deref())))?;
        let conn = client
            .get_connection_with_timeout(timeout)
            .map_err(|e| StoreError(scrub(format!("redis connect: {e}"), secret.as_deref())))?;
        let store = Self {
            client,
            conn: Mutex::new(Some(conn)),
            secret,
        };
        store.migrate()?;
        Ok(store)
    }

    /// SCHEMA-VERSION BUMP (v4, the 1.5.0 billable-requests ledger split; see SCHEMA_VERSION): a
    /// `busbar:*` namespace written by a pre-v4 build (no/older `busbar:schema` marker but
    /// governance keys present) is WIPED and re-marked - 1.5.0 is unreleased, so this is a bump,
    /// never a migration. A fresh namespace is simply marked; a v4 namespace passes through
    /// untouched.
    fn migrate(&self) -> StoreResult<()> {
        let marker: Option<i64> = self.with_conn(|c| c.get::<_, Option<i64>>(SCHEMA_KEY))?;
        let version = marker.unwrap_or(0);
        if version >= SCHEMA_VERSION {
            return Ok(());
        }
        let existing: Vec<String> = self.with_conn(|c| {
            c.scan_match::<_, String>("busbar:*")?
                .collect::<Result<Vec<String>, _>>()
        })?;
        if existing.is_empty() {
            // A fresh namespace: just mark it v4.
            return self.with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION));
        }
        // A PRESENT-but-older marker PROVES this is a busbar namespace of an earlier dev schema:
        // wipe it (1.5.0 unreleased: bump, not migrate) without the legacy-shape heuristic, which
        // only exists for the marker-ABSENT ambiguity below.
        if marker.is_some() {
            self.with_conn(|c| {
                let mut pipe = redis::pipe();
                pipe.atomic();
                for k in &existing {
                    pipe.del(k).ignore();
                }
                pipe.query::<()>(c)
            })?;
            return self.with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION));
        }
        // M2 (data-loss): the marker is absent (or pre-v3) but `busbar:*` DATA exists. The old code
        // WIPED the whole namespace unconditionally - so a marker EVICTED under `maxmemory
        // allkeys-*` (while the current-version data survived) destroyed a healthy database on the
        // next boot. Only wipe when LEGACY-SHAPED keys are actually present (a pre-v2 build's
        // `busbar:usage:*` HASH carried a `spend_cents` field that the token-ledger shape never
        // has). If data exists but is NOT legacy-shaped and the marker is absent, we CANNOT prove
        // it is safe to wipe - REFUSE to boot loudly rather than silently destroy it.
        if !self.namespace_is_legacy_shaped(&existing)? {
            return Err(StoreError(format!(
                "redis: found {} busbar:* keys but no '{SCHEMA_KEY}' marker, and the data is NOT \
                 legacy (pre-1.5.0) shaped. Refusing to wipe a namespace that may be a healthy \
                 current-version database whose schema marker was evicted (e.g. under `maxmemory \
                 allkeys-*`). Restore the marker with `SET {SCHEMA_KEY} {SCHEMA_VERSION}` if this \
                 IS a current-version database, or clear the busbar:* namespace deliberately if \
                 it is not.",
                existing.len()
            )));
        }
        // Confirmed legacy: a bump-not-migrate wipe (1.5.0 is unreleased).
        self.with_conn(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            for k in &existing {
                pipe.del(k).ignore();
            }
            pipe.query::<()>(c)
        })?;
        self.with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION))
    }

    /// M2: is the `busbar:*` namespace shaped like a PRE-v2 (legacy 1.4.x) store? The distinguishing
    /// marker is a `busbar:usage:*` HASH carrying the legacy `spend_cents` field, which the v2
    /// token-ledger usage shape (`requests` + `m:<model>:<tier>`) never has. Returns true only when
    /// such a key is actually observed - so an ambiguous/unknown namespace is treated as NOT legacy
    /// (fail-closed: refuse to wipe rather than guess).
    fn namespace_is_legacy_shaped(&self, existing: &[String]) -> StoreResult<bool> {
        for k in existing {
            // Only usage hashes carried the legacy field; skip everything else quickly.
            if !k.starts_with("busbar:usage:") {
                continue;
            }
            let has_legacy: bool = self
                .with_conn(|c| c.hexists(k, "spend_cents"))
                .unwrap_or(false);
            if has_legacy {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Run `f` against the live connection, transparently reconnecting ONCE on a connection-level
    /// error (dropped socket / IO / timeout). The single retry re-runs `f` on the fresh connection;
    /// a second failure (or any command-level error) surfaces, password-scrubbed.
    ///
    /// M3 (over-bill): the one-shot retry is SAFE ONLY for READ / idempotent ops. It is UNSAFE for a
    /// non-idempotent write cascade (`add_usage`/`add_metering` are HINCRBY MULTI/EXEC): a LOST-REPLY
    /// TIMEOUT means the EXEC may already have committed on the server, so re-running `f` would
    /// DOUBLE-APPLY the delta permanently (over-bill). Mutating cascades therefore use
    /// `with_conn_no_retry`, which returns the error so the write-behind flusher re-derives the
    /// correct total from the baseline on the next tick (exactly-once on error).
    fn with_conn<T>(
        &self,
        f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
    ) -> StoreResult<T> {
        self.run(f, true)
    }

    /// Like `with_conn` but with NO reconnect-retry - for non-idempotent write cascades where a
    /// lost-reply timeout must NOT be retried (see the M3 note on `with_conn`). A connection-level
    /// error surfaces so the caller (the flusher) re-derives from baseline instead of double-applying.
    fn with_conn_no_retry<T>(
        &self,
        f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
    ) -> StoreResult<T> {
        self.run(f, false)
    }

    /// Shared connection driver. `retry` gates the one-shot reconnect-and-retry (safe only for
    /// idempotent ops - see `with_conn`). Every operation in this crate funnels through here, so
    /// reconnect + scrub are uniform.
    fn run<T>(
        &self,
        mut f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
        retry: bool,
    ) -> StoreResult<T> {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        // (Re)establish if the previous operation dropped the connection.
        if guard.is_none() {
            *guard = Some(
                self.client
                    .get_connection()
                    .map_err(|e| self.err(e, "reconnect"))?,
            );
        }
        let conn = guard.as_mut().expect("connection just ensured");
        match f(conn) {
            Ok(v) => Ok(v),
            Err(e) if retry && is_connection_error(&e) => {
                // Drop the dead connection and retry exactly once on a fresh one.
                *guard = None;
                let mut fresh = self
                    .client
                    .get_connection()
                    .map_err(|e2| self.err(e2, "reconnect after drop"))?;
                match f(&mut fresh) {
                    Ok(v) => {
                        *guard = Some(fresh);
                        Ok(v)
                    }
                    Err(e2) => Err(self.err(e2, "retry after reconnect")),
                }
            }
            Err(e) => {
                // A connection-level failure (retried or not) leaves the guard's connection suspect;
                // drop it so the NEXT op reconnects cleanly rather than reusing a dead socket.
                if is_connection_error(&e) {
                    *guard = None;
                }
                Err(self.err(e, "command"))
            }
        }
    }

    /// Map a redis error into the api error, scrubbing the URL password.
    fn err(&self, e: redis::RedisError, ctx: &str) -> StoreError {
        StoreError(scrub(format!("redis {ctx}: {e}"), self.secret.as_deref()))
    }
}

// `allowed_pools` encoding - identical to the SQL backends: the whole key rides as JSON, so pool
// names with commas are delimiter-safe.
fn key_to_json(key: &VirtualKey) -> StoreResult<String> {
    serde_json::to_string(key).map_err(|e| StoreError(format!("key encode failed: {e}")))
}
fn key_from_json(raw: &str) -> StoreResult<VirtualKey> {
    serde_json::from_str(raw).map_err(|e| StoreError(format!("key decode failed: {e}")))
}

impl Store for RedisStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let json = key_to_json(key)?;
        // Row + index as ONE atomic MULTI/EXEC - a re-put is idempotent (SET overwrites, SADD is a
        // set member).
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .set(format!("{KEY_PREFIX}{}", key.id), &json)
                .ignore()
                .sadd(KEYS_INDEX, &key.id)
                .ignore()
                .query(c)
        })
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let raw: Option<String> = self.with_conn(|c| c.get(format!("{KEY_PREFIX}{id}")))?;
        raw.map(|r| key_from_json(&r)).transpose()
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let ids: Vec<String> = self.with_conn(|c| c.smembers(KEYS_INDEX))?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            // A dangling index member (row removed out-of-band) is skipped, not an error.
            if let Some(raw) =
                self.with_conn(|c| c.get::<_, Option<String>>(format!("{KEY_PREFIX}{id}")))?
            {
                out.push(key_from_json(&raw)?);
            }
        }
        // Deterministic order (mirrors the SQL backends' ORDER BY created_at, then id as a tiebreak).
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // READ phase: collect everything the cascade must remove (usage windows via a non-blocking
        // SCAN; the key's AccessKeyIds via SMEMBERS). Reads are outside the transaction - the
        // in-memory engine is the sole writer for a key's lifecycle, and a concurrent write after
        // the read would at worst leave a benign dangling index member that list paths skip.
        let pattern = format!("busbar:usage:{id}:*");
        let usage_keys: Vec<String> = self.with_conn(|c| {
            c.scan_match::<_, String>(&pattern)?
                .collect::<Result<Vec<String>, _>>()
        })?;
        let cred_ids: Vec<String> =
            self.with_conn(|c| c.smembers(format!("{AWSCRED_IDS_PREFIX}{id}")))?;

        // WRITE phase: the ENTIRE delete cascade as ONE atomic MULTI/EXEC. Either everything goes
        // (key row, key index, usage windows, every credential + its index memberships, the id map)
        // or nothing does - a mid-cascade failure can never orphan a SigV4 credential behind a
        // deleted key (the bug this replaces: N independent commands).
        self.with_conn(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.del(format!("{KEY_PREFIX}{id}")).ignore();
            pipe.srem(KEYS_INDEX, id).ignore();
            for k in &usage_keys {
                pipe.del(k).ignore();
            }
            for akid in &cred_ids {
                pipe.del(format!("{AWSCRED_PREFIX}{akid}")).ignore();
                pipe.srem(AWSCRED_INDEX, akid).ignore();
            }
            pipe.del(format!("{AWSCRED_IDS_PREFIX}{id}")).ignore();
            pipe.query(c)
        })
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        let k = usage_key(bucket_id, window_start);
        let fields: Vec<(String, i64)> = self.with_conn(|c| c.hgetall(&k))?;
        if fields.is_empty() {
            return Ok(UsageLedger::default());
        }
        let mut ledger = UsageLedger::default();
        for (name, v) in fields {
            if name == "requests" {
                ledger.requests = read_u64(v);
                continue;
            }
            if name == "billable_requests" {
                // v4: the 2xx-only fee base, on its own hash field (a transient negative from an
                // over-refunding HINCRBY clamps to 0 on read, same posture as `requests`).
                ledger.billable_requests = read_u64(v);
                continue;
            }
            let Some((model, tier)) = parse_model_field(&name) else {
                continue;
            };
            let entry = match ledger.models.iter_mut().find(|m| m.model == model) {
                Some(m) => m,
                None => {
                    ledger.models.push(ModelTokens {
                        model: model.to_string(),
                        tokens: TierTokens::default(),
                    });
                    ledger.models.last_mut().expect("just pushed")
                }
            };
            match tier {
                "input" => entry.tokens.input = read_u64(v),
                "output" => entry.tokens.output = read_u64(v),
                "cache_read" => entry.tokens.cache_read = read_u64(v),
                "cache_write" => entry.tokens.cache_write = read_u64(v),
                _ => {}
            }
        }
        // Deterministic order (mirrors the SQL backends' ORDER BY model).
        ledger.models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(ledger)
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // ABSOLUTE set: DEL + HSET the whole ledger in ONE atomic MULTI/EXEC so a re-put is
        // idempotent, a stale model field never lingers, and a reader never sees half a ledger.
        // The fleet-additive flush path uses `add_usage` instead.
        let k = usage_key(bucket_id, window_start);
        self.with_conn(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.del(&k).ignore();
            pipe.hset(&k, "requests", clamp(ledger.requests)).ignore();
            pipe.hset(&k, "billable_requests", clamp(ledger.billable_requests))
                .ignore();
            for m in &ledger.models {
                pipe.hset(&k, model_field(&m.model, "input"), clamp(m.tokens.input))
                    .ignore();
                pipe.hset(&k, model_field(&m.model, "output"), clamp(m.tokens.output))
                    .ignore();
                pipe.hset(
                    &k,
                    model_field(&m.model, "cache_read"),
                    clamp(m.tokens.cache_read),
                )
                .ignore();
                pipe.hset(
                    &k,
                    model_field(&m.model, "cache_write"),
                    clamp(m.tokens.cache_write),
                )
                .ignore();
            }
            pipe.query(c)
        })
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ADDITIVE accumulate: HINCRBY the requests delta plus every per-(model, tier) token delta,
        // atomically as one MULTI/EXEC - the fleet-honest write: N nodes flushing deltas sum to the
        // true fleet total instead of last-writer-wins overwriting each other. No dollar delta
        // crosses this wire. (A transient negative is clamped to 0 on read - see the crate doc.)
        let k = usage_key(bucket_id, window_start);
        // NON-IDEMPOTENT HINCRBY cascade - no auto-retry (a lost-reply timeout must not
        // double-apply; the flusher re-derives from baseline on error).
        self.with_conn_no_retry(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.cmd("HINCRBY")
                .arg(&k)
                .arg("requests")
                .arg(delta.requests)
                .ignore();
            // v4: accumulate the fee base on its own hash field, exactly like `requests`. Kept
            // unconditional (matching the `requests` HINCRBY) so the field materializes even on a
            // zero delta, and a transient negative from an over-refund clamps to 0 on read.
            pipe.cmd("HINCRBY")
                .arg(&k)
                .arg("billable_requests")
                .arg(delta.billable_requests)
                .ignore();
            for m in &delta.models {
                for (tier, v) in [
                    ("input", m.tokens.input),
                    ("output", m.tokens.output),
                    ("cache_read", m.tokens.cache_read),
                    ("cache_write", m.tokens.cache_write),
                ] {
                    if v != 0 {
                        pipe.cmd("HINCRBY")
                            .arg(&k)
                            .arg(model_field(&m.model, tier))
                            .arg(v)
                            .ignore();
                    }
                }
            }
            pipe.query(c)
        })
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let row = metering_row(d.bucket, &d.key_id, &d.model, &d.provider);
        let set = metering_set(d.bucket);
        // One atomic MULTI/EXEC: index the row + HINCRBY the four token fields and the request
        // count + persist the identity fields (idempotent HSET). Accumulation without a
        // read-modify-write race, and no partially-written row on failure.
        // NON-IDEMPOTENT HINCRBY cascade - no auto-retry (a lost-reply timeout must not
        // double-apply; the flusher re-derives from baseline on error).
        self.with_conn_no_retry(|c| {
            redis::pipe()
                .atomic()
                .sadd(&set, &row)
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_input")
                .arg(clamp(d.tokens_input))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_output")
                .arg(clamp(d.tokens_output))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_cache_read")
                .arg(clamp(d.tokens_cache_read))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_cache_creation")
                .arg(clamp(d.tokens_cache_creation))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("requests")
                .arg(clamp(d.requests))
                .ignore()
                .hset_multiple(
                    &row,
                    &[
                        ("key_id", d.key_id.as_str()),
                        ("model", d.model.as_str()),
                        ("provider", d.provider.as_str()),
                    ],
                )
                .ignore()
                .query(c)
        })
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let set = metering_set(bucket);
        let rows: Vec<String> = self.with_conn(|c| c.smembers(&set))?;
        let mut out = Vec::with_capacity(rows.len());
        for row_key in rows {
            let fields: Vec<(String, String)> = self.with_conn(|c| c.hgetall(&row_key))?;
            if fields.is_empty() {
                continue; // a stale index member with no hash - skip
            }
            let mut m = MeteringRow {
                key_id: String::new(),
                model: String::new(),
                provider: String::new(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_creation: 0,
                requests: 0,
            };
            for (name, val) in fields {
                let num = || val.parse::<i64>().unwrap_or(0);
                match name.as_str() {
                    "key_id" => m.key_id = val.clone(),
                    "model" => m.model = val.clone(),
                    "provider" => m.provider = val.clone(),
                    "tokens_input" => m.tokens_input = read_u64(num()),
                    "tokens_output" => m.tokens_output = read_u64(num()),
                    "tokens_cache_read" => m.tokens_cache_read = read_u64(num()),
                    "tokens_cache_creation" => m.tokens_cache_creation = read_u64(num()),
                    "requests" => m.requests = read_u64(num()),
                    _ => {}
                }
            }
            out.push(m);
        }
        Ok(out)
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        let json = serde_json::to_string(cred)
            .map_err(|e| StoreError(format!("aws credential encode failed: {e}")))?;
        // Credential row + both indexes as ONE atomic MULTI/EXEC (no partially-indexed credential).
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .set(format!("{AWSCRED_PREFIX}{}", cred.access_key_id), &json)
                .ignore()
                .sadd(AWSCRED_INDEX, &cred.access_key_id)
                .ignore()
                .sadd(
                    format!("{AWSCRED_IDS_PREFIX}{}", cred.key_id),
                    &cred.access_key_id,
                )
                .ignore()
                .query(c)
        })
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        // The WHOLE key+credential publish as ONE atomic MULTI/EXEC - either both the key and its
        // SigV4 credential (with every index) exist, or neither does. This replaces the old
        // sequential put_key-then-put_aws_credential, whose mid-sequence failure could mint a key
        // with no credential (or, reversed, a credential for a key that failed to store).
        let key_json = key_to_json(key)?;
        let cred_json = serde_json::to_string(cred)
            .map_err(|e| StoreError(format!("aws credential encode failed: {e}")))?;
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .set(format!("{KEY_PREFIX}{}", key.id), &key_json)
                .ignore()
                .sadd(KEYS_INDEX, &key.id)
                .ignore()
                .set(
                    format!("{AWSCRED_PREFIX}{}", cred.access_key_id),
                    &cred_json,
                )
                .ignore()
                .sadd(AWSCRED_INDEX, &cred.access_key_id)
                .ignore()
                .sadd(
                    format!("{AWSCRED_IDS_PREFIX}{}", cred.key_id),
                    &cred.access_key_id,
                )
                .ignore()
                .query(c)
        })
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let ids: Vec<String> = self.with_conn(|c| c.smembers(AWSCRED_INDEX))?;
        let mut out = Vec::with_capacity(ids.len());
        for akid in ids {
            if let Some(raw) =
                self.with_conn(|c| c.get::<_, Option<String>>(format!("{AWSCRED_PREFIX}{akid}")))?
            {
                let cred: AwsCredential = serde_json::from_str(&raw)
                    .map_err(|e| StoreError(format!("aws credential decode failed: {e}")))?;
                out.push(cred);
            }
        }
        Ok(out)
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // The audit log's durable home: a SORTED SET scored by `seq` (the engine's monotonic
        // sequence), each member the JSON record. `seq` is the record's IDENTITY (the SQL backends'
        // PRIMARY KEY), so a re-append of an existing seq must UPSERT ON seq - overwriting whatever
        // record currently sits at that score. A bare ZADD upserts on the MEMBER (the JSON bytes),
        // so re-appending the same seq with a DIFFERENT payload (e.g. a corrected hash) would leave
        // TWO members at one score - a duplicate audit entry and a divergence from the SQL backends
        // (whose test asserts the replay overwrites the digest). Do it as ONE atomic MULTI/EXEC:
        // drop any member already at this exact score, then add the new one.
        let json = serde_json::to_string(entry)
            .map_err(|e| StoreError(format!("audit encode failed: {e}")))?;
        let score = clamp(entry.seq);
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .cmd("ZREMRANGEBYSCORE")
                .arg(AUDIT_ZSET)
                .arg(score)
                .arg(score)
                .ignore()
                .zadd(AUDIT_ZSET, &json, score)
                .ignore()
                .query(c)
        })
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        // ZRANGE 0..-1 returns members ordered by score (seq) ascending = oldest-first, the boot
        // restore order the engine expects.
        let members: Vec<String> = self.with_conn(|c| c.zrange(AUDIT_ZSET, 0, -1))?;
        let mut out = Vec::with_capacity(members.len());
        for m in members {
            let rec: AuditRecord = serde_json::from_str(&m)
                .map_err(|e| StoreError(format!("audit decode failed: {e}")))?;
            out.push(rec);
        }
        Ok(out)
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        // BOUNDED restore read: fetch only the most-recent `limit` members at the SOURCE. `ZRANGE key
        // -limit -1` returns the highest-scored (newest) `limit` members in ASCENDING score order =
        // oldest-first WITHIN the tail, exactly the restore contract — no in-memory reverse needed.
        // Without this override the trait default ZRANGEs the WHOLE (never-pruned) audit zset and
        // truncates in memory, which over the plugin ABI can exceed the response cap or OOM on a large
        // log. Mirrors the SQLite/Postgres `LIMIT`ed tail queries. `limit == 0` degenerates to
        // `ZRANGE 0 -1` (start 0 wins), which the engine never requests (the ring is always positive).
        let start: isize = isize::try_from(limit).map(|n| -n).unwrap_or(isize::MIN);
        let members: Vec<String> = self.with_conn(|c| c.zrange(AUDIT_ZSET, start, -1))?;
        let mut out = Vec::with_capacity(members.len());
        for m in members {
            let rec: AuditRecord = serde_json::from_str(&m)
                .map_err(|e| StoreError(format!("audit decode failed: {e}")))?;
            out.push(rec);
        }
        Ok(out)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
        // Revoke a signed-token key by subject id: SET the reason string + SADD the sub to the index,
        // as ONE atomic MULTI/EXEC. Idempotent (SET overwrites the reason, SADD is a set member), so
        // the one-shot reconnect-retry of `with_conn` is safe here.
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .set(format!("{DENYLIST_PREFIX}{sub}"), reason)
                .ignore()
                .sadd(DENYLIST_INDEX, sub)
                .ignore()
                .query(c)
        })
    }

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        self.with_conn(|c| c.smembers(DENYLIST_INDEX))
    }
}

#[cfg(test)]
mod tests;
