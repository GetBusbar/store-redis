// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Valkey** backend for busbar's durable governance store — the
//! shared, multi-node `db` plugin over a KEY-VALUE data model. Implements `busbar_api::Store` on a
//! mutex-guarded SYNCHRONOUS connection, depending only on the `busbar-api` contract (plus the
//! upstream RESP driver crate, which is still published on crates.io under its pre-fork name and is
//! therefore the ONE spelling in this repo that is not ours to rename), never on the engine.
//!
//! Valkey is what busbar ships and documents: the Linux-Foundation-governed, BSD-licensed store the
//! ecosystem standardized on. The only remnants of the pre-fork name anywhere in this crate are the
//! upstream driver crate's own name/paths and the `url://` scheme strings that driver parses
//! (`redis://` / `rediss://`) — both fixed by upstream, neither a busbar-owned identifier.
//!
//! ## Schema v5 — the generic-credentials redesign
//!
//! `AwsCredential`/`aws_credentials` (a type/table that only ever held SigV4 credentials, discovered
//! mid-audit to be vendor-shaped rather than designed) is replaced by a kind-polymorphic
//! `CredentialMeta`/`CredentialSecret` — see `busbar_api::store` for the full rationale. `VirtualKey`
//! gains `deleted_at` (tombstone, not hard-delete — see [`Store::delete_key`]'s doc) and `revision`
//! (a store-global monotonic counter for incremental hydration).
//!
//! - **virtual keys** — `busbar:key:<id>` holds the JSON [`VirtualKey`] (now carrying `deleted_at`/
//!   `revision`); `busbar:keys` indexes every id (`list_keys` is unfiltered — including tombstones,
//!   per the trait's own contract, since a hydrator must observe a tombstone to evict cached
//!   credentials); `busbar:keys:byrev` is a ZSET scored by revision, serving both "all keys" and
//!   "keys since N" (`list_keys_since`).
//! - **credentials** — `busbar:cred:<key_id>:<kind>:<slot>` holds the JSON [`CredentialSecret`]
//!   (meta + secret together; the METADATA-only view the admin/listing surface gets is produced by
//!   discarding `.secret` after decode, never by a separate on-disk shape — so there is no
//!   `SELECT *`-shaped bug possible here, only a decode-then-drop-field bug, which is far easier to
//!   audit). `slot` is `0` or `1`, baked into the key name, so `(key_id, kind, slot)` uniqueness is
//!   a structural property of the keyspace, not an application-level check to get wrong.
//!   `busbar:cred:pub:<kind>:<public_id>` enforces `UNIQUE(kind, public_id)` via `SETNX`.
//!   `busbar:cred:id:<cred_id>` resolves a credential by its own id (`revoke_credential`'s lookup).
//!   `busbar:cred:ids:<key_id>` is a SET of `"<kind>:<slot>"` members, bounding `delete_key`'s fan-out
//!   to a small `SMEMBERS` regardless of how many kinds exist. `busbar:creds:byrev` is the credential
//!   equivalent of `keys:byrev`.
//! - **token ledger** / **metering** / **audit** / **denylist** — unchanged in shape from the prior
//!   schema (see the write-behind/HINCRBY/ZSET reasoning below); metering gains `billable_requests`
//!   (HINCRBY, same as `requests`), `key_group_at_use`/`pricing_version` (`HSETNX` — first-write-wins,
//!   the attribution snapshot at first use of the bucket), and the `tokens_cache_creation` field is
//!   renamed `tokens_cache_write` (a naming-drift fix: identical concept, same as `TierTokens`).
//!
//! ## Atomicity
//!
//! Every multi-key write cascade runs as ONE atomic `MULTI`/`EXEC` pipeline
//! ([`redis::Pipeline::atomic`]), or — where a write's correctness depends on a value read
//! immediately beforehand (credential slot occupancy, `delete_key`'s credential fan-out) — as an
//! optimistic `WATCH`/`MULTI`/`EXEC` transaction ([`redis::transaction`]), so a concurrent mutation of
//! the watched key aborts and retries the whole read+build+EXEC cycle against fresh state rather than
//! racing. `delete_key`'s cascade (tombstone the key row, destroy every credential row + its
//! reverse-lookup pointers, drop the credential-id index) is the highest-stakes of these: a mid-
//! cascade failure must never leave a credential outliving the key it was destroyed for, mirroring
//! the crate's long-standing invariant, now generalized past SigV4 to every credential kind.
//!
//! ## Connections, TLS, reconnect
//!
//! Unchanged from the prior schema: a single mutex-guarded synchronous connection, one-shot
//! reconnect-and-retry for connection-level errors on READ/idempotent ops only (a non-idempotent
//! HINCRBY write cascade never auto-retries — see `with_conn_no_retry`'s doc). `rediss://` URLs use
//! TLS (rustls, ring provider, OS-native roots). Error strings are scrubbed of the URL password.
//!
//! ## Data growth (documented, deliberate)
//!
//! Rows are written WITHOUT a TTL: usage windows, metering buckets, and audit entries accumulate
//! unboundedly by design — the store is the durable system of record. `purge_windows_before`/
//! `purge_metering_before` are left at the trait's `Ok(0)` default (no obligation to self-bound);
//! operators wanting bounded growth reap old `busbar:usage:*` keys on their own retention schedule.

use busbar_api::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens, Store,
    StoreError, StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};
use redis::{Commands, Connection};
use std::sync::Mutex;
use std::time::Duration;
/// Default connect timeout (`Client::open` + the initial `get_connection`): with no DSN-level
/// escape hatch (unlike postgres's libpq `connect_timeout`), a blackholed/firewalled host would
/// otherwise wedge engine boot indefinitely. `connect_with_timeout` lets a caller override this.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Key-space helpers (one namespace prefix so a Valkey shared with other apps never collides) ──
const KEY_PREFIX: &str = "busbar:key:";
const KEYS_INDEX: &str = "busbar:keys";
const KEYS_BYREV: &str = "busbar:keys:byrev";
const CRED_IDS_PREFIX: &str = "busbar:cred:ids:";
const CRED_PUB_PREFIX: &str = "busbar:cred:pub:";
const CRED_ID_PREFIX: &str = "busbar:cred:id:";
const CREDS_BYREV: &str = "busbar:creds:byrev";
const AUDIT_ZSET: &str = "busbar:audit";
/// The signed-token REVOCATION denylist (1.5.0). `busbar:denylist:<sub>` holds the operator reason
/// (a plain string), and `busbar:denylist` is a SET indexing every denied sub so `list_denylist` is
/// a SMEMBERS.
const DENYLIST_PREFIX: &str = "busbar:denylist:";
const DENYLIST_INDEX: &str = "busbar:denylist";
/// The store-global monotonic revision counter (INCR only). Stamped onto `VirtualKey`/`CredentialMeta`
/// rows at write time, driving `list_keys_since`/`list_credentials_since`'s incremental hydration.
const REVISION_KEY: &str = "busbar:revision";
/// The schema-version marker key (mirrors the SQLite `PRAGMA user_version`). v5 (1.5.0 dev) = the
/// generic-credentials redesign: `AwsCredential` -> kind-polymorphic `CredentialMeta`/`CredentialSecret`,
/// `VirtualKey` gains `deleted_at`/`revision`, `delete_key` becomes a tombstone, metering gains
/// `billable_requests`/`key_group_at_use`/`pricing_version` and renames `tokens_cache_creation` to
/// `tokens_cache_write`. A pre-v5 namespace is WIPED on connect (1.5.0 unreleased: bump, not migrate).
///
/// v6 closes a real billing bug in busbarAI core's `GovState::hydrate_budgets`: that function used
/// to infer "legacy pre-split row, needs `billable_requests` seeded from `requests`" from the value
/// shape `billable_requests == 0 && requests > 0` alone — but that exact shape is ALSO what a bucket
/// looks like after a legitimate full refund (`refund_bucket` decrements `billable_requests` but
/// never `requests`, by design), so a restart could silently re-bill correctly-refunded fees. Fixed
/// by removing the value-based guess from `hydrate_budgets` entirely and doing the one-time cutover
/// HERE instead, at a real schema-version boundary, which by construction happens exactly once ever
/// per store. v6 wipes any pre-v6 namespace the SAME way the v5 bump did (1.5.0 is STILL unreleased
/// as of this bump — no real customer has run any pre-v6 build in production, so there is no
/// genuinely-ambiguous refunded-vs-legacy data anywhere to lose). This is a ONE-TIME safe window: the
/// NEXT schema bump after 1.5.0 actually ships must NOT reuse this wipe-on-bump shortcut, since real
/// customer usage/billing history would exist by then and wiping it would itself be a real bug.
const SCHEMA_KEY: &str = "busbar:schema";
const SCHEMA_VERSION: i64 = 6;

/// Internal sentinel: `delete_key`'s outer retry loop uses this to distinguish "credential
/// membership changed since our watch-set pre-read, restart with a fresh watch set" from a real
/// terminal error. `redis::ErrorKind` has no built-in "retry me" variant, so this is carried in
/// the error message rather than the kind.
const DELETE_KEY_RETRY_SENTINEL: &str = "__internal_delete_key_retry__";

fn usage_key(bucket_id: &str, window_start: u64) -> String {
    format!("busbar:usage:{bucket_id}:{window_start}")
}

fn cred_row_key(key_id: &str, kind: &str, slot: u8) -> String {
    format!("busbar:cred:{key_id}:{kind}:{slot}")
}

fn cred_ids_key(key_id: &str) -> String {
    format!("{CRED_IDS_PREFIX}{key_id}")
}

fn cred_pub_key(kind: &str, public_id: &str) -> String {
    format!("{CRED_PUB_PREFIX}{kind}:{public_id}")
}

fn cred_id_key(cred_id: &str) -> String {
    format!("{CRED_ID_PREFIX}{cred_id}")
}

/// Escape Valkey glob metacharacters (`*`, `?`, `[`, `]`, and the escape character `\` itself)
/// in a value that must match LITERALLY inside a `SCAN MATCH` pattern. Without this, a virtual key id
/// containing one of these characters lets `delete_key`'s cleanup SCAN match keys belonging to OTHER
/// buckets/ids that merely share a glob-matching prefix.
fn escape_glob(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
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
/// Escape `\` and the `|` join delimiter (in that order, so the escape character itself round-trips
/// unambiguously) in one `metering_row` component. Without this, two DISTINCT `(key_id, model,
/// provider)` triples can collide onto the identical joined string whenever a component contains a
/// literal `|` — e.g. `("k", "a|b", "p")` and `("k", "a", "b|p")` both join to `"k|a|b|p"` — merging
/// two logically separate metering rows' HINCRBY'd counters into one. Neither `key_id` (busbar-
/// generated) nor `model`/`provider` (operator-configured lane names, never restricted to a fixed
/// charset anywhere upstream) is guaranteed `|`-free, so this is not a theoretical concern.
fn escape_metering_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '|') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn metering_row(bucket: u64, key_id: &str, model: &str, provider: &str) -> String {
    // Each component is escaped before joining (see `escape_metering_component`), so the join is
    // injective: two different `(key_id, model, provider)` triples can never produce the same row
    // key, even when a component itself contains `|` or `\`.
    format!(
        "busbar:metering:{bucket}:{}|{}|{}",
        escape_metering_component(key_id),
        escape_metering_component(model),
        escape_metering_component(provider)
    )
}

/// Clamp a `u64` into `i64` for Valkey integer ops (HINCRBY is signed) - a value above `i64::MAX` pins
/// to `i64::MAX`, never wraps. Mirrors the SQL backends.
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed counter back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as` - mirrors the SQL backends' DI-3 posture.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// Extract the PASSWORD component from a valkey URL (`redis://user:pass@host/...` or
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
/// the valkey driver may surface either in an error string.
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
/// `<redacted>` - the password-in-error scrub.
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

/// Valkey `Store` backend (durable, shared across a cluster). A single
/// mutex-guarded synchronous connection with one-shot reconnect - governance is off the request hot
/// path, so serializing access is fine.
pub struct ValkeyStore {
    client: redis::Client,
    /// The live connection, lazily (re)established. `None` after a detected drop.
    conn: Mutex<Option<Connection>>,
    /// The URL password (if any), scrubbed out of every error string this crate emits.
    secret: Option<String>,
}

impl ValkeyStore {
    /// Connect to Valkey with the given URL (e.g. `redis://:pass@host:6379/0`, or
    /// `rediss://:pass@host:6380/0` for TLS via rustls + OS-native roots), using the
    /// [`DEFAULT_CONNECT_TIMEOUT`]. See [`Self::connect_with_timeout`] for a caller-supplied
    /// timeout.
    pub fn connect(url: &str) -> StoreResult<Self> {
        Self::connect_with_timeout(url, DEFAULT_CONNECT_TIMEOUT)
    }

    /// Like [`Self::connect`], but with an explicit connect timeout. Unlike postgres's libpq, the
    /// upstream driver crate gives no DSN-level timeout escape hatch, so a blackholed/firewalled
    /// host would otherwise hang `get_connection()` indefinitely and wedge engine boot; bounding
    /// the initial TCP connect here fails fast instead.
    pub fn connect_with_timeout(url: &str, timeout: Duration) -> StoreResult<Self> {
        let secret = url_password(url);
        if url.starts_with("rediss://") {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let client = redis::Client::open(url)
            .map_err(|e| StoreError(scrub(format!("valkey connect: {e}"), secret.as_deref())))?;
        let conn = client
            .get_connection_with_timeout(timeout)
            .map_err(|e| StoreError(scrub(format!("valkey connect: {e}"), secret.as_deref())))?;
        let store = Self {
            client,
            conn: Mutex::new(Some(conn)),
            secret,
        };
        store.migrate()?;
        store.assert_noeviction()?;
        Ok(store)
    }

    /// STARTUP ASSERTION, non-negotiable: `maxmemory-policy` must be `noeviction`. Under any eviction
    /// policy, Valkey can silently evict a denylist entry (un-revoking a compromised key) or a
    /// metering row (destroying billing evidence) under memory pressure, with zero error anywhere in
    /// the request path — the loss is invisible until someone goes looking for data that should be
    /// there. Refuse to start rather than risk it. If `CONFIG GET` itself is disabled by an ACL
    /// (a legitimate hardened deployment), we cannot verify the policy either way — fail loud with a
    /// distinct message rather than silently assuming it's safe.
    fn assert_noeviction(&self) -> StoreResult<()> {
        let pairs: Vec<(String, String)> = self.with_conn(|c| {
            redis::cmd("CONFIG")
                .arg("GET")
                .arg("maxmemory-policy")
                .query(c)
        })?;
        let policy = pairs
            .iter()
            .find(|(k, _)| k == "maxmemory-policy")
            .map(|(_, v)| v.as_str());
        match policy {
            Some("noeviction") => Ok(()),
            Some(other) => Err(StoreError(format!(
                "valkey maxmemory-policy is '{other}', not 'noeviction': an eviction policy \
                 can silently drop a denylist entry (un-revoking a key) or a metering row \
                 (destroying billing evidence) under memory pressure with no error anywhere. \
                 Refusing to start. Run `CONFIG SET maxmemory-policy noeviction` (and persist it in \
                 the server's own config, since CONFIG SET does not survive a restart) before \
                 pointing busbar at this instance."
            ))),
            None => Err(StoreError(
                "valkey CONFIG GET maxmemory-policy returned no value — either this server \
                 restricts CONFIG GET via ACL, or something unexpected happened. Refusing to start: \
                 cannot verify the noeviction invariant governance data durability depends on."
                    .to_string(),
            )),
        }
    }

    /// SCHEMA-VERSION BUMP (currently v6; see `SCHEMA_VERSION`'s own doc for what each bump did): a
    /// `busbar:*` namespace written by an older build is WIPED and re-marked - 1.5.0 is unreleased,
    /// so this is a bump, never a migration. A fresh namespace is simply marked; a namespace already
    /// at the current version passes through untouched.
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
            return self.with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION));
        }
        // Any presence of a busbar:* namespace pre-v5 (marker present-but-older, or a pre-marker
        // legacy namespace) is wiped: 1.5.0 is unreleased, so there is no live data to preserve
        // across this specific bump, unlike the v2/v3/v4 bumps this crate's history navigated
        // around a possibly-populated dev database more carefully.
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

    /// Run `f` against the live connection, transparently reconnecting ONCE on a connection-level
    /// error. Safe only for READ / idempotent ops.
    fn with_conn<T>(
        &self,
        f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
    ) -> StoreResult<T> {
        self.run(f, true)
    }

    /// Like `with_conn` but with NO reconnect-retry - for non-idempotent write cascades where a
    /// lost-reply timeout must NOT be retried.
    fn with_conn_no_retry<T>(
        &self,
        f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
    ) -> StoreResult<T> {
        self.run(f, false)
    }

    fn run<T>(
        &self,
        mut f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
        retry: bool,
    ) -> StoreResult<T> {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
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
                if is_connection_error(&e) {
                    *guard = None;
                }
                Err(self.err(e, "command"))
            }
        }
    }

    fn err(&self, e: redis::RedisError, ctx: &str) -> StoreError {
        StoreError(scrub(format!("valkey {ctx}: {e}"), self.secret.as_deref()))
    }

    /// Allocate the next revision — a plain `INCR`. Called once per key/credential mutation, inside
    /// whatever pipe/transaction performs the write, so the stamped value and the write are never
    /// observed apart.
    fn next_revision(&self, c: &mut Connection) -> redis::RedisResult<u64> {
        let v: i64 = c.incr(REVISION_KEY, 1)?;
        Ok(v.max(0) as u64)
    }
}

fn key_from_json(raw: &str) -> StoreResult<VirtualKey> {
    serde_json::from_str(raw).map_err(|e| StoreError(format!("key decode failed: {e}")))
}
fn cred_to_json(cred: &CredentialSecret) -> StoreResult<String> {
    serde_json::to_string(cred).map_err(|e| StoreError(format!("credential encode failed: {e}")))
}
fn cred_from_json(raw: &str) -> StoreResult<CredentialSecret> {
    serde_json::from_str(raw).map_err(|e| StoreError(format!("credential decode failed: {e}")))
}

/// Parse a `"<key_id>:<kind>:<slot>"` pointer value back into its parts. `kind` cannot itself contain
/// `:` (enforced by the fixed kind allowlist upstream), so a right-split on `:` twice is unambiguous
/// even if a future `key_id` contained a colon.
fn parse_slot_pointer(s: &str) -> Option<(String, String, u8)> {
    let (rest, slot) = s.rsplit_once(':')?;
    let (key_id, kind) = rest.rsplit_once(':')?;
    Some((key_id.to_string(), kind.to_string(), slot.parse().ok()?))
}

/// Test-only cleanup surface. The conformance suite runs against a SHARED live Valkey that is not
/// flushed between tests, so it has to be able to remove exactly the rows it is about to write —
/// and it cannot do that through the `Store` trait, since `delete_key` deliberately TOMBSTONES
/// rather than removing. These delete the underlying entries outright. `#[cfg(test)]` so none of it
/// exists in a shipped artifact.
#[cfg(test)]
impl ValkeyStore {
    /// Remove a key row and every index entry pointing at it, tombstone included.
    pub(crate) fn purge_key_for_test(&self, id: &str) -> StoreResult<()> {
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .del(format!("{KEY_PREFIX}{id}"))
                .ignore()
                .srem(KEYS_INDEX, id)
                .ignore()
                .zrem(KEYS_BYREV, id)
                .ignore()
                .del(cred_ids_key(id))
                .ignore()
                .query(c)
        })
    }

    /// Remove a credential's id pointer. The slot row itself goes with its owning key.
    pub(crate) fn purge_credential_for_test(&self, id: &str) -> StoreResult<()> {
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .del(cred_id_key(id))
                .ignore()
                .query(c)
        })
    }

    /// Remove whatever occupies one audit `seq`.
    pub(crate) fn purge_audit_seq_for_test(&self, seq: u64) -> StoreResult<()> {
        let score = clamp(seq);
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .cmd("ZREMRANGEBYSCORE")
                .arg(AUDIT_ZSET)
                .arg(score)
                .arg(score)
                .ignore()
                .query(c)
        })
    }
}

impl Store for ValkeyStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let key = key.clone();
        let row_key = format!("{KEY_PREFIX}{}", key.id);
        self.with_conn(|c| {
            // TOMBSTONE PRECONDITION (see `Store::put_key`): a live-shaped write must not overwrite
            // a tombstoned row, which would reissue an id the contract says is never reissued and
            // revive every token minted before the delete. WATCHed rather than read-then-written, so
            // a `delete_key` committing between the read and the SET aborts and retries instead of
            // slipping through — the same TOCTOU the caller-side checks in core cannot close.
            redis::transaction(c, &[row_key.as_str()], |c, pipe| {
                if key.deleted_at.is_none() {
                    let existing: Option<String> = c.get(&row_key)?;
                    // A row that does not parse is left to the normal write path rather than being
                    // treated as a tombstone: refusing here would make a corrupt row permanently
                    // unwritable, and this method is not the one that should be adjudicating that.
                    if let Some(prior) = existing.as_deref().and_then(|r| key_from_json(r).ok()) {
                        if prior.deleted_at.is_some() {
                            return Err(redis::RedisError::from((
                                redis::ErrorKind::Client,
                                "put_key refused",
                                format!(
                                    "put_key: '{}' is tombstoned and its id is never reissued; \
                                     refusing to clear the tombstone",
                                    key.id
                                ),
                            )));
                        }
                    }
                }
                let mut key = key.clone();
                let rev = self.next_revision(c)?;
                key.revision = rev;
                let json = serde_json::to_string(&key)
                    .map_err(|_e| redis::RedisError::from((redis::ErrorKind::Client, "encode")))?;
                pipe.atomic()
                    .set(&row_key, &json)
                    .ignore()
                    .sadd(KEYS_INDEX, &key.id)
                    .ignore()
                    .zadd(KEYS_BYREV, &key.id, rev)
                    .ignore()
                    .query(c)
            })
        })
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let raw: Option<String> = self.with_conn(|c| c.get(format!("{KEY_PREFIX}{id}")))?;
        raw.map(|r| key_from_json(&r)).transpose()
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED — including tombstones. See the trait's own doc: this serves both
        // the admin-listing caller (which filters `is_live()` itself) and `list_keys_since`'s default
        // hydration fallback, which needs to SEE a tombstone to evict cached credentials.
        let ids: Vec<String> = self.with_conn(|c| c.smembers(KEYS_INDEX))?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let raws: Vec<Option<String>> = self.with_conn(|c| {
            let mut pipe = redis::pipe();
            for id in &ids {
                pipe.get(format!("{KEY_PREFIX}{id}"));
            }
            pipe.query(c)
        })?;
        let mut out = Vec::with_capacity(ids.len());
        for raw in raws.into_iter().flatten() {
            out.push(key_from_json(&raw)?);
        }
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    fn list_keys_since(&self, since: u64) -> StoreResult<Vec<VirtualKey>> {
        // Real delta-fetch: ZRANGEBYSCORE the byrev index, not a full scan-and-filter — the whole
        // point of maintaining `keys:byrev`.
        let ids: Vec<String> =
            self.with_conn(|c| c.zrangebyscore(KEYS_BYREV, format!("({since}"), "+inf"))?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let raws: Vec<Option<String>> = self.with_conn(|c| {
            let mut pipe = redis::pipe();
            for id in &ids {
                pipe.get(format!("{KEY_PREFIX}{id}"));
            }
            pipe.query(c)
        })?;
        let mut out = Vec::with_capacity(ids.len());
        for raw in raws.into_iter().flatten() {
            out.push(key_from_json(&raw)?);
        }
        Ok(out)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        let ids_key = cred_ids_key(id);
        let key_row = format!("{KEY_PREFIX}{id}");
        // Usage windows: a non-blocking SCAN outside the transaction (mirrors the crate's prior
        // behavior). A deleted key's rate-limit windows are meaningless — best-effort cleanup, not a
        // correctness-critical invariant like the credential cascade below, so a concurrent
        // add_usage/put_usage racing a new window into existence between this SCAN and the EXEC is an
        // acceptable, already-documented gap (stale data, not an identity/auth issue).
        let pattern = format!("busbar:usage:{}:*", escape_glob(id));
        let usage_keys: Vec<String> = self.with_conn(|c| {
            c.scan_match::<_, String>(&pattern)?
                .collect::<Result<Vec<String>, _>>()
        })?;
        // WATCH the key row, its credential-id index, AND every current member's own credential
        // row: a concurrent put_credential can rewrite a slot's row in place (reusing an existing
        // member of `ids_key`, so SADD never fires and `ids_key` itself doesn't change) — if only
        // `key_row`/`ids_key` were watched, that in-place rewrite would slip past WATCH entirely,
        // and this cascade would then destroy the row (and fail to clean up the NEW public_id's
        // reverse pointer) without ever having observed the change. Because the row-key set itself
        // depends on `ids_key`'s membership, and membership can also change between our pre-read
        // and the transaction's WATCH, this loops: any membership change aborts (ids_key is
        // watched) and we recompute the watch set from scratch against fresh state.
        self.with_conn(|c| loop {
            let members: Vec<String> = c.smembers(&ids_key)?;
            let row_keys: Vec<String> = members
                .iter()
                .filter_map(|m| parse_slot_pointer(&format!("{id}:{m}")))
                .map(|(_, kind, slot)| cred_row_key(id, &kind, slot))
                .collect();
            let mut watch_keys: Vec<&str> = vec![key_row.as_str(), ids_key.as_str()];
            watch_keys.extend(row_keys.iter().map(String::as_str));

            let outcome = redis::transaction(c, &watch_keys, |c, pipe| {
                let raw: Option<String> = c.get(&key_row)?;
                let Some(raw) = raw else {
                    // Unknown id (never existed): a real error, matching the SQL backends'
                    // `delete_key`-on-unknown-id contract — distinct from "already tombstoned",
                    // which IS an idempotent no-op (see below).
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Client,
                        "delete_key: unknown id",
                    )));
                };
                let mut key: VirtualKey = serde_json::from_str(&raw).map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::Client, "key decode"))
                })?;
                if key.deleted_at.is_some() {
                    // Already tombstoned: idempotent no-op (do not re-bump revision or re-destroy
                    // credentials that are already gone).
                    pipe.atomic();
                    return pipe.query(c);
                }
                // `redis::transaction`'s own internal WATCH-abort retry reruns this closure with
                // the SAME fixed `watch_keys` computed above -- it can't recompute which row keys
                // to watch. So re-read membership fresh here and compare against the outer
                // pre-read: if it changed, `ids_key` (which IS watched) will already have aborted
                // this EXEC, but we still need to bail out to the OUTER loop to rebuild `watch_keys`
                // against the new members' rows, rather than silently proceeding against the stale
                // set.
                let fresh_members: Vec<String> = c.smembers(&ids_key)?;
                if fresh_members.len() != members.len()
                    || !fresh_members.iter().all(|m| members.contains(m))
                {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Client,
                        DELETE_KEY_RETRY_SENTINEL,
                    )));
                }
                let rev = self.next_revision(c)?;
                key.enabled = false;
                key.deleted_at = Some(crate::now());
                key.revision = rev;
                let key_json = serde_json::to_string(&key).map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::Client, "key encode"))
                })?;

                pipe.atomic();
                pipe.set(&key_row, &key_json).ignore();
                pipe.zadd(KEYS_BYREV, id, rev).ignore();
                for uk in &usage_keys {
                    pipe.del(uk).ignore();
                }
                // Destroy every credential row + its reverse-lookup pointers. Per the trait's own
                // hydration contract, a hard-deleted credential row is fine here (not a hazard) —
                // the CONSUMER evicts cached credentials off this key's OWN `deleted_at` delta, never
                // waiting for a credential-row delta that (by construction) will never come.
                for member in &members {
                    let Some((_, kind, slot)) = parse_slot_pointer(&format!("{id}:{member}"))
                    else {
                        continue;
                    };
                    let row_key = cred_row_key(id, &kind, slot);
                    // Need the row's public_id to clean up its reverse pointer — read it (still
                    // inside the WATCHed transaction closure, so this is consistent with the EXEC).
                    // A missing row is a legitimate no-op (already gone). A row that IS present but
                    // fails to decode must abort the whole cascade rather than be silently skipped
                    // — an `if let Ok(...) = ...` swallow here would still delete the row while
                    // leaving its `cred:pub:*`/`cred:id:*` reverse pointers permanently dangling,
                    // reporting `delete_key` as a success despite violating its own "destroy every
                    // credential row + pointers" contract. Every other decode path in this file
                    // (key_from_json, cred_from_json, list_metering) propagates a corrupt value as
                    // an error rather than silently under-delivering; this matches that.
                    if let Some(raw) = c.get::<_, Option<String>>(&row_key)? {
                        let cred: CredentialSecret = serde_json::from_str(&raw).map_err(|_| {
                            redis::RedisError::from((
                                redis::ErrorKind::Client,
                                "delete_key: corrupt credential row",
                            ))
                        })?;
                        pipe.del(cred_pub_key(&kind, &cred.meta.public_id)).ignore();
                        pipe.del(cred_id_key(&cred.meta.id)).ignore();
                    }
                    pipe.del(&row_key).ignore();
                }
                pipe.del(&ids_key).ignore();
                pipe.query(c)
            });

            match outcome {
                Err(e) if e.to_string().contains(DELETE_KEY_RETRY_SENTINEL) => continue,
                other => break other,
            }
        })
    }

    fn scrub_key(&self, id: &str) -> StoreResult<()> {
        let key_row = format!("{KEY_PREFIX}{id}");
        self.with_conn(|c| {
            redis::transaction(c, &[key_row.as_str()], |c, pipe| {
                let raw: Option<String> = c.get(&key_row)?;
                let Some(raw) = raw else {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Client,
                        "scrub_key: unknown id",
                    )));
                };
                let mut key: VirtualKey = serde_json::from_str(&raw).map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::Client, "key decode"))
                })?;
                if key.deleted_at.is_none() {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Client,
                        "scrub_key: key is not tombstoned — delete_key it first",
                    )));
                }
                let rev = self.next_revision(c)?;
                key.name = String::new();
                key.labels.clear();
                key.revision = rev;
                let json = serde_json::to_string(&key).map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::Client, "key encode"))
                })?;
                pipe.atomic();
                pipe.set(&key_row, &json).ignore();
                pipe.zadd(KEYS_BYREV, id, rev).ignore();
                pipe.query(c)
            })
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
        ledger.models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(ledger)
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
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
        let k = usage_key(bucket_id, window_start);
        self.with_conn_no_retry(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.cmd("HINCRBY")
                .arg(&k)
                .arg("requests")
                .arg(delta.requests)
                .ignore();
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
                .arg("tokens_cache_write")
                .arg(clamp(d.tokens_cache_write))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("requests")
                .arg(clamp(d.requests))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("billable_requests")
                .arg(clamp(d.billable_requests))
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
                // First-write-wins attribution snapshot: HSETNX only sets if the field is absent.
                .cmd("HSETNX")
                .arg(&row)
                .arg("key_group_at_use")
                .arg(&d.key_group_at_use)
                .ignore()
                .cmd("HSETNX")
                .arg(&row)
                .arg("pricing_version")
                .arg(&d.pricing_version)
                .ignore()
                .query(c)
        })
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let set = metering_set(bucket);
        let row_keys: Vec<String> = self.with_conn(|c| c.smembers(&set))?;
        if row_keys.is_empty() {
            return Ok(Vec::new());
        }
        let all_fields: Vec<Vec<(String, String)>> = self.with_conn(|c| {
            let mut pipe = redis::pipe();
            for row_key in &row_keys {
                pipe.hgetall(row_key);
            }
            pipe.query(c)
        })?;
        let mut out = Vec::with_capacity(row_keys.len());
        for fields in all_fields {
            if fields.is_empty() {
                continue;
            }
            let mut m = MeteringRow {
                key_id: String::new(),
                model: String::new(),
                provider: String::new(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 0,
                billable_requests: 0,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
            };
            for (name, val) in fields {
                // Every other decode path in this file (key_from_json, cred_from_json, audit
                // records) propagates a StoreError on a corrupt value rather than silently
                // substituting a default -- a malformed numeric field here must not silently
                // read back as 0 and under-report billing/usage data.
                let num = |field: &str, val: &str| {
                    val.parse::<i64>().map_err(|e| {
                        StoreError(format!("list_metering: bad {field} value {val:?}: {e}"))
                    })
                };
                match name.as_str() {
                    "key_id" => m.key_id = val.clone(),
                    "model" => m.model = val.clone(),
                    "provider" => m.provider = val.clone(),
                    "tokens_input" => m.tokens_input = read_u64(num("tokens_input", &val)?),
                    "tokens_output" => m.tokens_output = read_u64(num("tokens_output", &val)?),
                    "tokens_cache_read" => {
                        m.tokens_cache_read = read_u64(num("tokens_cache_read", &val)?)
                    }
                    "tokens_cache_write" => {
                        m.tokens_cache_write = read_u64(num("tokens_cache_write", &val)?)
                    }
                    "requests" => m.requests = read_u64(num("requests", &val)?),
                    "billable_requests" => {
                        m.billable_requests = read_u64(num("billable_requests", &val)?)
                    }
                    "key_group_at_use" => m.key_group_at_use = val.clone(),
                    "pricing_version" => m.pricing_version = val.clone(),
                    _ => {}
                }
            }
            out.push(m);
        }
        Ok(out)
    }

    fn put_credential(&self, secret: &CredentialSecret) -> StoreResult<()> {
        let row_key = cred_row_key(&secret.meta.key_id, &secret.meta.kind, secret.meta.slot);
        let ids_key = cred_ids_key(&secret.meta.key_id);
        let pub_key = cred_pub_key(&secret.meta.kind, &secret.meta.public_id);
        let id_key = cred_id_key(&secret.meta.id);
        let mut secret = secret.clone();
        let slot_ptr = format!(
            "{}:{}:{}",
            secret.meta.key_id, secret.meta.kind, secret.meta.slot
        );
        self.with_conn(|c| {
            // WATCH both the slot's own row AND the public_id pointer: the uniqueness check reads
            // `pub_key` here, immediately (not through the pipe, so its result is actually
            // inspected — a `SETNX` queued inside an `.ignore()`d pipe command would silently
            // discard the "already claimed" signal, which is exactly the bug this shape avoids). A
            // concurrent writer claiming this public_id between the read and EXEC touches the
            // watched `pub_key`, aborting and retrying this whole closure against fresh state.
            redis::transaction(c, &[row_key.as_str(), pub_key.as_str()], |c, pipe| {
                let existing: Option<String> = c.get(&row_key)?;
                let mut old_pub: Option<String> = None;
                let mut old_id: Option<String> = None;
                if let Some(raw) = &existing {
                    let cur: CredentialSecret = serde_json::from_str(raw).map_err(|_| {
                        redis::RedisError::from((redis::ErrorKind::Client, "cred decode"))
                    })?;
                    if cur.meta.revoked_at.is_none() {
                        if cur.meta.id == secret.meta.id {
                            // Retry-safe no-op: the slot already holds THIS SAME credential
                            // (matched by its own id, never reused across mints). This is not a
                            // genuine second mint attempt — it is `with_conn`'s automatic
                            // reconnect-and-retry replaying this whole closure after a connection
                            // blip dropped the reply for an EXEC that had already committed
                            // server-side. Erroring here would report failure for a write that, in
                            // fact, already fully succeeded.
                            pipe.atomic();
                            return pipe.query(c);
                        }
                        // Slot occupied by a DIFFERENT live credential — an explicit mint into it
                        // would silently destroy a working credential mid-overlap-window. Fail
                        // loud.
                        return Err(redis::RedisError::from((
                            redis::ErrorKind::Client,
                            "put_credential: slot holds a live credential; revoke it first",
                        )));
                    }
                    old_pub = Some(cur.meta.public_id);
                    old_id = Some(cur.meta.id);
                }
                // UNIQUE(kind, public_id), enforced by an actual read-and-check (not a discarded
                // SETNX): if some OTHER slot already holds this public_id, reject before writing
                // anything. Reclaiming the SAME slot's own previous public_id is fine (that case is
                // `old_pub == Some(secret.meta.public_id)` and is not a collision).
                let pub_holder: Option<String> = c.get(&pub_key)?;
                if let Some(holder) = &pub_holder {
                    if *holder != slot_ptr {
                        return Err(redis::RedisError::from((
                            redis::ErrorKind::Client,
                            "put_credential: public_id already claimed by a different credential",
                        )));
                    }
                }
                let rev = self.next_revision(c)?;
                secret.meta.revision = rev;
                let json = cred_to_json(&secret).map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::Client, "cred encode"))
                })?;

                pipe.atomic();
                if let Some(old_pub) = &old_pub {
                    if *old_pub != secret.meta.public_id {
                        pipe.del(cred_pub_key(&secret.meta.kind, old_pub)).ignore();
                    }
                }
                if let Some(old_id) = &old_id {
                    // Reclaiming this slot with a DIFFERENT credential id: the previous occupant's
                    // `cred:id:<old_id>` pointer would otherwise keep resolving to this slot
                    // forever, now holding someone else's row. Left alive, a later call to
                    // `revoke_credential(old_id)` (an idempotent-retry, or simply a caller that
                    // still has the old id) would revoke and secret-wipe the NEW, unrelated
                    // occupant instead of being the no-op the trait's contract promises for a dead
                    // id. Delete it in the same atomic pipe as the reclaim so the two writes are
                    // never observed apart.
                    if *old_id != secret.meta.id {
                        pipe.del(cred_id_key(old_id)).ignore();
                    }
                }
                pipe.set(&pub_key, &slot_ptr).ignore();
                pipe.set(&id_key, &slot_ptr).ignore();
                pipe.set(&row_key, &json).ignore();
                pipe.sadd(
                    &ids_key,
                    format!("{}:{}", secret.meta.kind, secret.meta.slot),
                )
                .ignore();
                pipe.zadd(CREDS_BYREV, &slot_ptr, rev).ignore();
                pipe.query(c)
            })
        })
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> StoreResult<()> {
        // Atomic key+credential mint: WATCH both rows so neither write is observed without the
        // other. The credential row cannot pre-exist for a brand-new mint (a fresh id/slot), so this
        // is simpler than `put_credential`'s slot-reuse path — no old-pointer cleanup needed.
        let key_row = format!("{KEY_PREFIX}{}", key.id);
        let row_key = cred_row_key(&secret.meta.key_id, &secret.meta.kind, secret.meta.slot);
        let ids_key = cred_ids_key(&secret.meta.key_id);
        let pub_key = cred_pub_key(&secret.meta.kind, &secret.meta.public_id);
        let id_key = cred_id_key(&secret.meta.id);
        let mut key = key.clone();
        let mut secret = secret.clone();
        let slot_ptr = format!(
            "{}:{}:{}",
            secret.meta.key_id, secret.meta.kind, secret.meta.slot
        );
        self.with_conn(|c| {
            // WATCH the key row, the credential's own row, AND the public_id pointer — a fresh
            // mint's public_id must not already be claimed (real check, not a discarded SETNX; see
            // `put_credential`'s identical reasoning).
            redis::transaction(
                c,
                &[key_row.as_str(), row_key.as_str(), pub_key.as_str()],
                |c, pipe| {
                    let pub_holder: Option<String> = c.get(&pub_key)?;
                    if let Some(holder) = &pub_holder {
                        if *holder == slot_ptr {
                            // Possibly retry-safe: the public_id already points at THIS slot. This
                            // only happens for a genuinely fresh mint if `with_conn`'s automatic
                            // reconnect-and-retry is replaying this whole closure after a
                            // connection blip dropped the reply for an EXEC that had already
                            // committed server-side — so confirm by id before treating it as a
                            // no-op rather than a real collision.
                            let existing_row: Option<String> = c.get(&row_key)?;
                            let same = existing_row
                                .as_deref()
                                .and_then(|r| serde_json::from_str::<CredentialSecret>(r).ok())
                                .is_some_and(|cur| cur.meta.id == secret.meta.id);
                            if same {
                                pipe.atomic();
                                return pipe.query(c);
                            }
                        }
                        return Err(redis::RedisError::from((
                            redis::ErrorKind::Client,
                            "put_key_with_credential: public_id already claimed",
                        )));
                    }
                    let key_rev = self.next_revision(c)?;
                    let cred_rev = self.next_revision(c)?;
                    key.revision = key_rev;
                    secret.meta.revision = cred_rev;
                    let key_json = serde_json::to_string(&key).map_err(|_| {
                        redis::RedisError::from((redis::ErrorKind::Client, "key encode"))
                    })?;
                    let cred_json = cred_to_json(&secret).map_err(|_| {
                        redis::RedisError::from((redis::ErrorKind::Client, "cred encode"))
                    })?;
                    pipe.atomic();
                    pipe.set(&key_row, &key_json).ignore();
                    pipe.sadd(KEYS_INDEX, &key.id).ignore();
                    pipe.zadd(KEYS_BYREV, &key.id, key_rev).ignore();
                    pipe.set(&pub_key, &slot_ptr).ignore();
                    pipe.set(&id_key, &slot_ptr).ignore();
                    pipe.set(&row_key, &cred_json).ignore();
                    pipe.sadd(
                        &ids_key,
                        format!("{}:{}", secret.meta.kind, secret.meta.slot),
                    )
                    .ignore();
                    pipe.zadd(CREDS_BYREV, &slot_ptr, cred_rev).ignore();
                    pipe.query(c)
                },
            )
        })
    }

    fn list_credentials(&self, key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
        let members: Vec<String> = self.with_conn(|c| c.smembers(cred_ids_key(key_id)))?;
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let row_keys: Vec<String> = members
            .iter()
            .filter_map(|m| {
                let (kind, slot) = m.split_once(':')?;
                Some(cred_row_key(key_id, kind, slot.parse().ok()?))
            })
            .collect();
        let raws: Vec<Option<String>> = self.with_conn(|c| {
            let mut pipe = redis::pipe();
            for k in &row_keys {
                pipe.get(k);
            }
            pipe.query(c)
        })?;
        let mut out = Vec::with_capacity(raws.len());
        for raw in raws.into_iter().flatten() {
            // Decode the full CredentialSecret, then keep ONLY `.meta` — the secret never leaves
            // this function's stack. There is no separate on-disk "meta view" to drift from the
            // real row; this is the one and only decode path for a credential row.
            out.push(cred_from_json(&raw)?.meta);
        }
        Ok(out)
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> StoreResult<Option<CredentialSecret>> {
        let ptr: Option<String> = self.with_conn(|c| c.get(cred_pub_key(kind, public_id)))?;
        let Some(ptr) = ptr else {
            return Ok(None);
        };
        let Some((key_id, kind, slot)) = parse_slot_pointer(&ptr) else {
            return Ok(None);
        };
        let raw: Option<String> = self.with_conn(|c| c.get(cred_row_key(&key_id, &kind, slot)))?;
        raw.map(|r| cred_from_json(&r)).transpose()
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> StoreResult<()> {
        let id_key = cred_id_key(id);
        self.with_conn(|c| {
            redis::transaction(c, &[id_key.as_str()], |c, pipe| {
                let ptr: Option<String> = c.get(&id_key)?;
                let Some(ptr) = ptr else {
                    // Unknown credential id: an ERROR. The trait's "idempotent" covers revoking an
                    // ALREADY-REVOKED id, not an id that names nothing — a silent no-op here lets
                    // an operator responding to a leak believe the credential is dead while it is
                    // still live and still authenticating.
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Client,
                        "revoke_credential refused",
                        format!("revoke_credential: unknown id '{id}'"),
                    )));
                };
                // A pointer that exists but does not parse is CORRUPTION, not an unknown id.
                // Returning Ok here would report a revocation that never happened: the row keeps
                // its secret, `revoked_at` stays unset, and the credential goes on authenticating
                // while the audit trail says it was revoked. `delete_key` already fails loud on
                // the sibling case (see `delete_key_fails_loud_on_a_corrupt_credential_row`).
                let Some((key_id, kind, slot)) = parse_slot_pointer(&ptr) else {
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Client,
                        "corrupt credential pointer",
                        format!("busbar:cred:id:{id} does not parse as <key_id>:<kind>:<slot>"),
                    )));
                };
                let row_key = cred_row_key(&key_id, &kind, slot);
                let raw: Option<String> = c.get(&row_key)?;
                let Some(raw) = raw else {
                    pipe.atomic();
                    return pipe.query(c);
                };
                let mut cred: CredentialSecret = serde_json::from_str(&raw).map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::Client, "cred decode"))
                })?;
                if cred.meta.revoked_at.is_some() {
                    // Already revoked: idempotent no-op.
                    pipe.atomic();
                    return pipe.query(c);
                }
                let rev = self.next_revision(c)?;
                cred.meta.revoked_at = Some(crate::now());
                cred.meta.revoke_reason = Some(reason.to_string());
                cred.meta.revision = rev;
                // Destroy the secret material on revoke — defense in depth: a revoked credential's
                // plaintext has no further legitimate reader, so there is no reason to retain it.
                cred.secret = String::new();
                let json = cred_to_json(&cred).map_err(|_| {
                    redis::RedisError::from((redis::ErrorKind::Client, "cred encode"))
                })?;
                pipe.atomic();
                pipe.set(&row_key, &json).ignore();
                pipe.zadd(CREDS_BYREV, format!("{key_id}:{kind}:{slot}"), rev)
                    .ignore();
                pipe.query(c)
            })
        })
    }

    fn list_credentials_since(&self, since: u64) -> StoreResult<Vec<CredentialSecret>> {
        let members: Vec<String> =
            self.with_conn(|c| c.zrangebyscore(CREDS_BYREV, format!("({since}"), "+inf"))?;
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let row_keys: Vec<String> = members
            .iter()
            .filter_map(|m| {
                let (key_id, kind, slot) = parse_slot_pointer(m)?;
                Some(cred_row_key(&key_id, &kind, slot))
            })
            .collect();
        let raws: Vec<Option<String>> = self.with_conn(|c| {
            let mut pipe = redis::pipe();
            for k in &row_keys {
                pipe.get(k);
            }
            pipe.query(c)
        })?;
        // A row that will not decode is SKIPPED, not propagated as an error for the whole call.
        //
        // This is the hydration delta, and it is a GLOBAL scan of every credential in the store, so
        // failing the call on one bad row turns a single corrupt row into a total credential
        // hydration failure for every key at once — the engine hydrates nothing and no credential
        // authenticates anywhere. Skipping degrades that to exactly one credential missing.
        //
        // Skipping is also the fail-CLOSED direction here, which is why it is safe: a credential
        // that cannot be decoded cannot be used to authenticate anyone, so omitting it from the
        // delta denies access rather than granting it. Core's own `load_by_credential` already
        // takes the same view, skipping credentials it cannot use rather than refusing to load.
        //
        // Deliberately NOT the same call as `delete_key`, which fails loud on a corrupt row: there,
        // continuing would orphan that row's reverse-lookup pointers, so silence would leave the
        // store inconsistent. Here nothing is written and nothing is left inconsistent.
        //
        // Reported on stderr because a plugin's `tracing` output does not reach the host (a cdylib
        // links its own dispatcher and nothing bridges them) — the same local workaround auth-oidc
        // and webrequest-hook already use. The row key names `key_id:kind:slot` and carries no
        // secret.
        let mut out = Vec::with_capacity(raws.len());
        for (i, raw) in raws.into_iter().enumerate() {
            let Some(raw) = raw else { continue };
            match cred_from_json(&raw) {
                Ok(cred) => out.push(cred),
                Err(e) => {
                    eprintln!(
                        "busbar-store-valkey: skipping undecodable credential row {} in the \
                         hydration delta ({e}); that credential cannot authenticate until the row \
                         is repaired, and the rest of the delta is unaffected",
                        row_keys.get(i).map(String::as_str).unwrap_or("<unknown>")
                    );
                }
            }
        }
        Ok(out)
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        let json = serde_json::to_string(entry)
            .map_err(|e| StoreError(format!("audit encode failed: {e}")))?;
        let score = clamp(entry.seq);
        self.with_conn(|c| {
            // This used to ZREMRANGEBYSCORE the score then ZADD, i.e. OVERWRITE, last writer wins.
            // That is the one outcome the trait rules out outright ("a store never rewrites or
            // recomputes the digest"): it destroys the evidence in exactly the case that matters
            // most, a second record claiming an occupied chain position.
            //
            // Compare instead, under WATCH so a concurrent append cannot land between the read and
            // the write:
            //   nothing there -> append.
            //   identical     -> the write-through retrying after a lost ACK. Benign, Ok, no write.
            //   different     -> a forked or tampered chain. Error, and the stored record stands.
            redis::transaction(c, &[AUDIT_ZSET], |c, pipe| {
                let existing: Vec<String> = c.zrangebyscore(AUDIT_ZSET, score, score)?;
                if let Some(raw) = existing.first() {
                    let stored: AuditRecord = serde_json::from_str(raw).map_err(|e| {
                        redis::RedisError::from((
                            redis::ErrorKind::Client,
                            "audit decode failed",
                            e.to_string(),
                        ))
                    })?;
                    if stored == *entry {
                        // No write at all: re-adding the identical member would be a no-op anyway,
                        // and skipping it keeps this path free of any rewrite.
                        pipe.atomic();
                        return pipe.query(c);
                    }
                    return Err(redis::RedisError::from((
                        redis::ErrorKind::Client,
                        "append_audit refused",
                        format!(
                            "append_audit: seq {} already holds a DIFFERENT record; the audit \
                             chain has forked (stored action '{}', incoming '{}')",
                            entry.seq, stored.action, entry.action
                        ),
                    )));
                }
                pipe.atomic().zadd(AUDIT_ZSET, &json, score).ignore();
                pipe.query(c)
            })
        })
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
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

/// Current unix time in seconds. A thin wrapper so tests can be deterministic about "now" only via
/// real elapsed time (no injected clock in this crate — governance timestamps are advisory metadata
/// here, never used for admission math inside the store itself).
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
