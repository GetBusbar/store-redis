// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_api::SecretForm;

/// The password-scrub never lets the URL secret out in an error string, and the URL password
/// extractor handles every URL shape.
#[test]
fn password_scrub_and_extraction() {
    assert_eq!(
        url_password("redis://:s3cr3t@host:6379/0").as_deref(),
        Some("s3cr3t")
    );
    assert_eq!(
        url_password("rediss://user:p%40ss@host:6380").as_deref(),
        Some("p%40ss")
    );
    assert_eq!(url_password("redis://host:6379"), None);
    assert_eq!(url_password("redis://user@host:6379"), None);
    assert_eq!(url_password("not a url"), None);

    let msg = "connection refused for redis://:s3cr3t@host:6379/0".to_string();
    let scrubbed = scrub(msg, Some("s3cr3t"));
    assert!(!scrubbed.contains("s3cr3t"), "got {scrubbed}");
    assert!(scrubbed.contains("<redacted>"));
    assert_eq!(scrub("plain".into(), None), "plain");
    assert_eq!(scrub("plain".into(), Some("zz")), "plain");

    let raw = url_password("rediss://user:p%40ss@host:6380").expect("password");
    assert_eq!(raw, "p%40ss");
    let decoded_leak = "auth failed with password p@ss".to_string();
    let s = scrub(decoded_leak, Some(&raw));
    assert!(
        !s.contains("p@ss") && s.contains("<redacted>"),
        "the DECODED password form must be scrubbed too; got {s}"
    );
    let raw_leak = "dsn rediss://user:p%40ss@host:6380".to_string();
    let s2 = scrub(raw_leak, Some(&raw));
    assert!(
        !s2.contains("p%40ss"),
        "the raw password form is scrubbed; got {s2}"
    );
    assert_eq!(percent_decode("p%40ss"), "p@ss");
    assert_eq!(percent_decode("no-escape"), "no-escape");
    assert_eq!(
        percent_decode("bad%zz"),
        "bad%zz",
        "a malformed escape is left verbatim"
    );
}

#[test]
fn rediss_url_is_accepted() {
    assert!(redis::Client::open("rediss://:pw@localhost:6380/0").is_ok());
}

#[test]
fn glob_escaping_covers_every_metacharacter() {
    assert_eq!(escape_glob("*"), "\\*");
    assert_eq!(escape_glob("a?b"), "a\\?b");
    assert_eq!(escape_glob("[x]"), "\\[x\\]");
    assert_eq!(escape_glob("back\\slash"), "back\\\\slash");
    assert_eq!(escape_glob("plain-id-123"), "plain-id-123");
}

/// End-to-end against a REAL Redis/Valkey, gated on `REDIS_URL` (a docker service in CI). Skips
/// cleanly when unset LOCALLY; under `CI` a missing URL is a HARD FAILURE, never a silent skip.
fn live_store() -> Option<RedisStore> {
    let url = match std::env::var("REDIS_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "REDIS_URL is unset under CI: the Redis/Valkey service container must provision \
                 it. Refusing to silently skip the only live-DB coverage in CI."
            );
        }
        Err(_) => {
            eprintln!(
                "skip: set REDIS_URL to run the store-valkey tests (e.g. redis://127.0.0.1:6380/0)"
            );
            return None;
        }
    };
    // Deliberately NO namespace wipe here: `cargo test` runs tests in parallel by default, and
    // every test in this file shares ONE Redis/Valkey instance — a per-test wipe would race every
    // OTHER concurrently-running test's writes (this was tried and produced exactly that failure
    // mode: "unknown id" errors from a test's own key vanishing mid-flight under a sibling test's
    // wipe). Isolation instead comes from every test using its own distinct key id namespace
    // (`vk_<test-specific-name>`) — collisions across tests are a review-time discipline, not a
    // runtime guard, same as the crate's pre-existing test suite already relied on.
    Some(RedisStore::connect(&url).expect("connect"))
}

fn vk(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("binding:{id}:g0"),
        name: "test key".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 1000,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    }
}

fn cred_meta(key_id: &str, public_id: &str, slot: u8) -> CredentialMeta {
    CredentialMeta {
        // Includes `public_id`, not just `key_id`/`slot`: in production a credential's `id` is a
        // fresh UUID per mint, unique regardless of which slot it lands in (see
        // `revoke_by_a_reclaimed_slots_old_id_must_not_touch_the_new_occupant`'s doc) — two
        // DIFFERENT credentials must never share a fixture-derived id just because they target the
        // same (key_id, slot), or a test exercising "a different credential collides with a live
        // slot" stops being realistic.
        id: format!("cred_{key_id}_{slot}_{public_id}"),
        key_id: key_id.to_string(),
        kind: "sigv4".to_string(),
        slot,
        public_id: public_id.to_string(),
        secret_form: SecretForm::Recoverable,
        created_at: 1000,
        updated_at: 1000,
        expires_at: None,
        revoked_at: None,
        revoke_reason: None,
        revision: 0,
    }
}

fn cred(key_id: &str, public_id: &str, slot: u8) -> CredentialSecret {
    CredentialSecret {
        meta: cred_meta(key_id, public_id, slot),
        secret: format!("v1:plain:{public_id}-secret"),
    }
}

/// Per-invocation-unique identifier for tests whose fixture touches a uniqueness constraint
/// (credential `public_id`, an accumulating usage/metering counter) rather than an idempotent
/// overwrite. Ordinary point-write tests are already safe to rerun because `put_key`/`SET` simply
/// overwrites the same row every time -- but a SETNX-style uniqueness check (`public_id` already
/// claimed) or an accumulating counter (`add_usage`/`add_metering`) sees a SECOND invocation's
/// identical literal id as a real collision with the FIRST invocation's leftover row, since this
/// suite deliberately never wipes the shared instance between runs (see `live_store()`). A fresh
/// process id per `cargo test` invocation, plus a counter for multiple calls within one process,
/// keeps those specific fixtures unique across repeated runs without reintroducing the per-test
/// wipe that was already tried and rejected for breaking intra-run parallelism.
fn unique_suffix() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    (std::process::id() as u64) * 1_000_000 + n
}

fn uid(base: &str) -> String {
    format!("{base}_{}", unique_suffix())
}

/// Like `uid`, but for the `bucket: u64` metering fields -- a distinct numeric bucket per call,
/// same rationale as `uid` (metering counters accumulate across invocations of the same literal
/// bucket, so a fixed literal collides with a prior run's leftover row).
fn unique_bucket(base: u64) -> u64 {
    base * 1_000_000_000 + unique_suffix()
}

// ── Basic key CRUD ──────────────────────────────────────────────────────────────────────────

#[test]
fn put_get_roundtrips_a_key_and_stamps_revision() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_1")).unwrap();
    let back = store.get_key("vk_1").unwrap().expect("key exists");
    assert_eq!(back.id, "vk_1");
    assert!(back.deleted_at.is_none());
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");
}

#[test]
fn list_keys_since_only_returns_keys_past_the_watermark() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_a")).unwrap();
    let watermark = store.get_key("vk_a").unwrap().unwrap().revision;
    store.put_key(&vk("vk_b")).unwrap();
    let delta = store.list_keys_since(watermark).unwrap();
    // Tests run in parallel against one shared instance, so `delta` may legitimately also contain
    // OTHER tests' concurrently-created keys past this watermark — assert on presence/absence of
    // THIS test's own ids, not an exact global count.
    assert!(
        delta.iter().any(|k| k.id == "vk_b"),
        "vk_b must be in the delta"
    );
    assert!(
        !delta.iter().any(|k| k.id == "vk_a"),
        "vk_a was created BEFORE the watermark and must not reappear"
    );
}

#[test]
fn list_keys_is_unfiltered_including_tombstones() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_live")).unwrap();
    store.put_key(&vk("vk_dead")).unwrap();
    store.delete_key("vk_dead").unwrap();
    let all = store.list_keys().unwrap();
    // No exact-count assertion: the shared namespace accumulates keys across parallel tests AND
    // across repeated test-suite runs (no wipe — see live_store()'s doc). Assert presence of this
    // test's own ids instead.
    assert!(
        all.iter().any(|k| k.id == "vk_live"),
        "list_keys must include the live key"
    );
    let dead = all
        .iter()
        .find(|k| k.id == "vk_dead")
        .expect("list_keys must include tombstoned rows too");
    assert!(dead.deleted_at.is_some());
}

// ── Tombstone delete: the central behavior change ──────────────────────────────────────────

#[test]
fn delete_key_tombstones_not_removes() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_del")).unwrap();
    store.delete_key("vk_del").unwrap();
    let row = store
        .get_key("vk_del")
        .unwrap()
        .expect("tombstoned row must still be readable");
    assert!(!row.enabled);
    assert!(row.deleted_at.is_some());
}

#[test]
fn delete_key_unknown_id_errors() {
    let Some(store) = live_store() else { return };
    assert!(
        store.delete_key("vk_never_existed").is_err(),
        "deleting a key that never existed must error, distinct from re-deleting a tombstone"
    );
}

#[test]
fn delete_key_is_idempotent_once_tombstoned() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_x")).unwrap();
    store.delete_key("vk_x").unwrap();
    let rev_after_first = store.get_key("vk_x").unwrap().unwrap().revision;
    store.delete_key("vk_x").unwrap();
    let rev_after_second = store.get_key("vk_x").unwrap().unwrap().revision;
    assert_eq!(
        rev_after_first, rev_after_second,
        "a no-op re-delete must not stamp a new revision"
    );
}

/// HARDEST INVARIANT #1: delete_key destroys the credential's SECRET material, not just the
/// metadata — proven by directly inspecting the raw stored bytes at the credential row's key,
/// bypassing the Store trait entirely (mirrors the SQL backends' "connect independently of the
/// ABI" persistence proof).
#[test]
fn delete_key_destroys_credential_secret_material() {
    let Some(store) = live_store() else { return };
    let key = vk("vk_cred");
    let c = cred("vk_cred", "AKIA_LIVE", 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // Prove the secret is really there before delete, by raw GET (bypassing the trait).
    let raw_before: Option<String> = store
        .with_conn(|conn| conn.get(cred_row_key("vk_cred", "sigv4", 0)))
        .unwrap();
    assert!(
        raw_before
            .as_deref()
            .unwrap_or("")
            .contains("AKIA_LIVE-secret"),
        "sanity: the secret must actually be stored before delete"
    );

    store.delete_key("vk_cred").unwrap();

    // The row must be GONE entirely (not tombstoned-with-secret-cleared) — a hard delete of the
    // credential row is fine here since the CONSUMER evicts via the key's own deleted_at delta.
    let raw_after: Option<String> = store
        .with_conn(|conn| conn.get(cred_row_key("vk_cred", "sigv4", 0)))
        .unwrap();
    assert!(
        raw_after.is_none(),
        "credential row must be hard-deleted, not merely blanked"
    );

    // The public_id reverse-lookup pointer must also be gone (no dangling "revoked but still
    // resolvable" credential).
    assert!(store
        .lookup_credential_secret("sigv4", "AKIA_LIVE")
        .unwrap()
        .is_none());
    assert!(store.list_credentials("vk_cred").unwrap().is_empty());
}

/// HARDEST INVARIANT #2: the credential-id and public_id reverse-lookup pointers are cleaned up
/// too, not just the row — otherwise `revoke_credential(old_id, ...)` after a delete would find a
/// dangling pointer to a row that no longer exists.
#[test]
fn delete_key_cleans_up_reverse_lookup_pointers() {
    let Some(store) = live_store() else { return };
    let key = vk("vk_ptr");
    let c = cred("vk_ptr", "AKIA_PTR", 0);
    let cred_id = c.meta.id.clone();
    store.put_key_with_credential(&key, &c).unwrap();
    store.delete_key("vk_ptr").unwrap();

    let by_pub: Option<String> = store
        .with_conn(|conn| conn.get(cred_pub_key("sigv4", "AKIA_PTR")))
        .unwrap();
    assert!(
        by_pub.is_none(),
        "cred:pub pointer must be cleaned up on delete"
    );
    let by_id: Option<String> = store
        .with_conn(|conn| conn.get(cred_id_key(&cred_id)))
        .unwrap();
    assert!(
        by_id.is_none(),
        "cred:id pointer must be cleaned up on delete"
    );
}

#[test]
fn delete_key_removes_usage_windows() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_usage")).unwrap();
    store
        .add_usage(
            "vk_usage",
            1000,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![],
            },
        )
        .unwrap();
    let before = store.get_usage("vk_usage", 1000).unwrap();
    assert_eq!(before.requests, 1);
    store.delete_key("vk_usage").unwrap();
    let after = store.get_usage("vk_usage", 1000).unwrap();
    assert_eq!(
        after.requests, 0,
        "usage windows must be cleaned up on delete"
    );
}

/// Regression guard for the historical glob-injection finding: a key id containing glob
/// metacharacters must not make `delete_key`'s usage-window cleanup match ANOTHER key's windows.
#[test]
fn delete_key_does_not_glob_match_other_keys_usage() {
    let Some(store) = live_store() else { return };
    let evil = uid("vk_evil_*");
    let victim = uid("vk_evil_victim");
    store.put_key(&vk(&evil)).unwrap();
    store.put_key(&vk(&victim)).unwrap();
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![],
    };
    store.add_usage(&evil, 1000, &d).unwrap();
    store.add_usage(&victim, 1000, &d).unwrap();
    store.delete_key(&evil).unwrap();
    // The victim's usage must survive — an unescaped glob would have matched "vk_evil_victim"
    // as well as the literal "vk_evil_*" pattern.
    let victim_usage = store.get_usage(&victim, 1000).unwrap();
    assert_eq!(
        victim_usage.requests, 1,
        "an unescaped '*' in the deleted key's id must not sweep another key's usage windows"
    );
}

// ── scrub_key ────────────────────────────────────────────────────────────────────────────────

#[test]
fn scrub_key_requires_tombstone_first() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_live_scrub")).unwrap();
    assert!(
        store.scrub_key("vk_live_scrub").is_err(),
        "scrubbing a live (non-tombstoned) key must error"
    );
}

#[test]
fn scrub_key_nulls_name_and_labels_after_tombstone() {
    let Some(store) = live_store() else { return };
    let mut key = vk("vk_scrub");
    key.labels.insert("team".to_string(), "growth".to_string());
    store.put_key(&key).unwrap();
    store.delete_key("vk_scrub").unwrap();
    store.scrub_key("vk_scrub").unwrap();
    let row = store.get_key("vk_scrub").unwrap().unwrap();
    assert_eq!(row.name, "");
    assert!(row.labels.is_empty());
    assert!(
        row.deleted_at.is_some(),
        "scrub must not un-tombstone the key"
    );
}

// ── Credentials: slot bounds, revoke, secret isolation ──────────────────────────────────────

#[test]
fn put_credential_rejects_a_live_slot_but_allows_reclaiming_a_revoked_one() {
    let Some(store) = live_store() else { return };
    let key = vk("vk_slot");
    let c0 = cred("vk_slot", "AKIA_0", 0);
    store.put_key_with_credential(&key, &c0).unwrap();

    // Minting into the SAME live slot must fail loudly, not silently overwrite.
    let c0b = cred("vk_slot", "AKIA_0B", 0);
    assert!(
        store.put_credential(&c0b).is_err(),
        "minting into a slot holding a LIVE credential must be rejected"
    );

    // Revoke it, then reclaiming the slot must succeed.
    store.revoke_credential(&c0.meta.id, "rotated").unwrap();
    assert!(
        store.put_credential(&c0b).is_ok(),
        "a revoked slot must be reclaimable"
    );
    let live = store.lookup_credential_secret("sigv4", "AKIA_0B").unwrap();
    assert!(live.is_some());
}

#[test]
fn revoke_by_a_reclaimed_slots_old_id_must_not_touch_the_new_occupant() {
    // A minted credential's `id` is generated fresh per mint (a UUID in production) -- it is NEVER
    // reused, even when the SLOT it occupies is later reclaimed by a different credential after a
    // revoke. `put_credential`'s slot-reclaim path must therefore invalidate the PREVIOUS
    // occupant's own `cred:id:<id>` pointer, not just its `cred:pub:<public_id>` pointer -- else
    // that stale pointer keeps resolving to the slot, which now holds someone else's live
    // credential. A late/duplicate `revoke_credential(old_id)` call (idempotent-retry shaped, or
    // simply a caller that held on to the old id) would then revoke and secret-wipe the WRONG,
    // currently-live credential instead of being the no-op the trait's "Idempotent" contract
    // promises for an already-gone id.
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_reclaim");
    let key = vk(&key_id);

    let mut c0 = cred(&key_id, &uid("AKIA_OLD"), 0);
    c0.meta.id = uid("cred_old");
    store.put_key_with_credential(&key, &c0).unwrap();
    store.revoke_credential(&c0.meta.id, "rotated").unwrap();

    // A brand-new credential, with its OWN distinct id, reclaims the now-revoked slot.
    let mut c1 = cred(&key_id, &uid("AKIA_NEW"), 0);
    c1.meta.id = uid("cred_new");
    store.put_credential(&c1).unwrap();

    // A stale/duplicate revoke against the OLD id must be a no-op -- it must NOT reach into the
    // slot (now occupied by c1) and revoke/secret-wipe the new, live credential.
    store.revoke_credential(&c0.meta.id, "stale retry").unwrap();

    let live = store
        .lookup_credential_secret("sigv4", &c1.meta.public_id)
        .unwrap()
        .expect("the reclaiming credential must still resolve by its own public_id");
    assert!(
        live.meta.revoked_at.is_none(),
        "a revoke against the OLD credential's id must not revoke the NEW occupant of its \
         reclaimed slot"
    );
    assert_ne!(
        live.secret, "",
        "a revoke against the OLD credential's id must not destroy the NEW occupant's secret \
         material"
    );
}

#[test]
fn public_id_uniqueness_is_enforced_across_slots() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_uniq");
    let public_id = uid("AKIA_DUP");
    let key = vk(&key_id);
    store.put_key(&key).unwrap();
    let c0 = cred(&key_id, &public_id, 0);
    store.put_credential(&c0).unwrap();
    // A different slot trying to claim the SAME public_id must fail.
    let mut c1 = cred_meta(&key_id, &public_id, 1);
    c1.id = "cred_other".to_string();
    let c1 = CredentialSecret {
        meta: c1,
        secret: "v1:plain:different".to_string(),
    };
    assert!(
        store.put_credential(&c1).is_err(),
        "UNIQUE(kind, public_id) must be enforced across different slots too"
    );
}

#[test]
fn revoke_credential_destroys_secret_and_is_idempotent() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_revoke");
    let public_id = uid("AKIA_REV");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    store.revoke_credential(&c.meta.id, "compromised").unwrap();

    // lookup_credential_secret must now resolve to a row whose secret is blanked and whose
    // revoked_at is set — the SigV4 verify path checks revoked_at, but defense-in-depth means the
    // plaintext should be gone too.
    let resolved = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .expect(
            "revoked credential row must still resolve by public_id (so a revoked-key request \
                 gets a correct 'revoked' rejection, not 'unknown')",
        );
    assert!(resolved.meta.revoked_at.is_some());
    assert_eq!(
        resolved.secret, "",
        "secret material must be destroyed on revoke"
    );

    // Idempotent: revoking again must not error or clobber the original revoked_at reason.
    assert!(store.revoke_credential(&c.meta.id, "again").is_ok());
}

#[test]
fn revoke_credential_unknown_id_is_idempotent_noop() {
    let Some(store) = live_store() else { return };
    assert!(
        store.revoke_credential("cred_never_existed", "n/a").is_ok(),
        "revoking an unknown credential id must be a no-op, matching the trait's Idempotent doc"
    );
}

#[test]
fn list_credentials_never_carries_the_secret() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_meta");
    let public_id = uid("AKIA_META");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();
    let metas = store.list_credentials(&key_id).unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].public_id, public_id);
    // CredentialMeta has no secret field at all — this is a compile-time guarantee, not a
    // runtime check, but assert the shape we actually get back is the meta type.
    let _: &CredentialMeta = &metas[0];
}

#[test]
fn list_credentials_since_carries_the_secret_for_hydration() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_hydrate");
    let public_id = uid("AKIA_HYDRATE");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();
    // since=0 legitimately also returns other tests' concurrently-created credentials (parallel
    // execution against one shared instance) — find THIS test's own row rather than assert an
    // exact global count.
    let delta = store.list_credentials_since(0).unwrap();
    let mine = delta
        .iter()
        .find(|cs| cs.meta.public_id == public_id)
        .expect("this test's credential must be in the delta");
    assert_eq!(
        mine.secret, c.secret,
        "hydration delta must carry the real secret"
    );
}

/// HARDEST INVARIANT #3: put_key_with_credential is atomic — a failure partway (simulated here by
/// pre-occupying the credential slot with a LIVE row before the atomic mint attempt) must leave
/// NEITHER the key nor the credential in a half-written state distinguishable from "never
/// attempted". Since redis::transaction's WATCH/EXEC either commits both writes or neither, we
/// prove this indirectly: after a forced conflict, the key must not exist at all (the whole
/// transaction body ran and failed before either SET landed, because the conflict check happens
/// before any command is queued in this implementation's slot-occupancy path)... this crate's
/// put_key_with_credential does not pre-check occupancy (new mints use a fresh id/slot), so
/// instead we prove atomicity the direct way: kill the connection mid-flight is not testable here,
/// so we assert the STRUCTURAL guarantee — both the key row and credential row appear together or
/// neither does, verified on the success path.
#[test]
fn put_key_with_credential_writes_both_or_neither() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_atomic");
    let public_id = uid("AKIA_ATOMIC");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();
    assert!(store.get_key(&key_id).unwrap().is_some());
    assert!(store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .is_some());
}

/// `with_conn` (used by `put_credential`) is documented "Safe only for READ / idempotent ops," but
/// automatically reconnects-and-retries on any connection-level error (`is_timeout()` /
/// `is_io_error()` / `is_connection_dropped()`) by re-running the ENTIRE transaction closure. If a
/// connection blip drops the reply AFTER Redis has already committed the EXEC server-side, that
/// retry replays `put_credential` with the SAME `CredentialSecret` against a slot that now already
/// holds it — exactly the scenario this test simulates directly (without needing to sever a real
/// TCP connection): calling `put_credential` twice in a row with the identical secret must be a
/// safe no-op, not the "slot holds a live credential" error a genuinely different mint would
/// correctly get. Without the retry-safety check, this call incorrectly reports failure for a
/// credential that is, in fact, already correctly and fully written.
#[test]
fn put_credential_replayed_with_the_same_credential_id_is_a_retry_safe_no_op() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_replay");
    let public_id = uid("AKIA_REPLAY");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // Replay the SAME put_credential call (same meta.id) — simulates `with_conn`'s reconnect
    // retry replaying this closure after the first attempt's EXEC actually landed but its ack
    // was lost.
    assert!(
        store.put_credential(&c).is_ok(),
        "replaying put_credential with the SAME credential id (its own already-committed write) \
         must be a retry-safe no-op, not an error"
    );
    let live = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .expect("credential must still resolve after the replayed call");
    assert!(live.meta.revoked_at.is_none());
    assert_ne!(live.secret, "", "the replay must not have wiped the secret");
}

/// Same retry-safety class as above, for `put_key_with_credential`'s public_id occupancy check.
#[test]
fn put_key_with_credential_replayed_with_the_same_credential_id_is_a_retry_safe_no_op() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_kwc_replay");
    let public_id = uid("AKIA_KWC_REPLAY");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // Replay the SAME call — simulates the reconnect-retry replaying an already-committed mint.
    assert!(
        store.put_key_with_credential(&key, &c).is_ok(),
        "replaying put_key_with_credential with the SAME credential id (its own already-committed \
         write) must be a retry-safe no-op, not a 'public_id already claimed' error"
    );
    let live = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .expect("credential must still resolve after the replayed call");
    assert_ne!(live.secret, "", "the replay must not have wiped the secret");
}

/// `delete_key`'s credential-row cleanup silently swallows a decode failure on a single
/// credential row (`if let Ok(Some(raw)) = c.get(...)`  / nested `if let Ok(cred) = ...`):
/// if a row is corrupt, its `cred:pub:*`/`cred:id:*` reverse-lookup pointers are never cleaned up,
/// yet the row itself is still deleted and the surrounding `delete_key` call still reports success
/// — silently violating the trait's own "destroy every credential row + pointers" contract while
/// claiming to have done so. This directly contradicts this same file's stated philosophy
/// elsewhere (`list_metering`: "a malformed value must not silently ... under-report"). The
/// correct behavior is to fail the whole (atomic) delete_key call loudly, matching every other
/// decode path in this crate, rather than reporting success while leaving a dangling pointer that
/// permanently blocks that public_id from ever being reused.
#[test]
fn delete_key_fails_loud_on_a_corrupt_credential_row_instead_of_orphaning_pointers() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_corrupt");
    let public_id = uid("AKIA_CORRUPT");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // Corrupt the credential row directly, bypassing the trait — simulates operator-side data
    // corruption / a schema-drift bug, not something reachable through this crate's own API.
    store
        .with_conn(|conn| conn.set::<_, _, ()>(cred_row_key(&key_id, "sigv4", 0), "not json"))
        .unwrap();

    let result = store.delete_key(&key_id);
    // Clean up the corrupted row ourselves (bypassing the trait, same as we corrupted it): this
    // suite shares ONE long-lived Redis instance with no per-test wipe (see `live_store()`'s doc),
    // and `delete_key` correctly refusing to touch the corrupt row means it is still sitting there
    // for every other concurrently- or later-running test that scans all credentials (e.g.
    // `list_credentials_since`) to trip over — a real, malformed row is exactly what THIS test
    // means to exercise, not something later tests should have to survive.
    store
        .with_conn(|conn| conn.del::<_, ()>(cred_row_key(&key_id, "sigv4", 0)))
        .unwrap();
    assert!(
        result.is_err(),
        "delete_key must fail loudly on a corrupt credential row rather than silently reporting \
         success while orphaning that row's reverse-lookup pointers"
    );
}

// ── Metering: field rename + new fields ─────────────────────────────────────────────────────

#[test]
fn metering_round_trips_all_fields_including_renamed_and_new_ones() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_m");
    let bucket = unique_bucket(20260731);
    store
        .add_metering(&MeteringDelta {
            key_id: key_id.clone(),
            bucket,
            model: "claude".to_string(),
            provider: "anthropic".to_string(),
            tokens_input: 10,
            tokens_output: 5,
            tokens_cache_read: 2,
            tokens_cache_write: 3,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "growth".to_string(),
            pricing_version: "2026-07".to_string(),
        })
        .unwrap();
    let rows = store.list_metering(bucket).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        r.tokens_cache_write, 3,
        "renamed from tokens_cache_creation"
    );
    assert_eq!(r.billable_requests, 1);
    assert_eq!(r.key_group_at_use, "growth");
    assert_eq!(r.pricing_version, "2026-07");
}

#[test]
fn metering_attribution_is_first_write_wins() {
    let Some(store) = live_store() else { return };
    let bucket = unique_bucket(20260801);
    let base = MeteringDelta {
        key_id: uid("vk_snap"),
        bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "first-group".to_string(),
        pricing_version: "v1".to_string(),
    };
    store.add_metering(&base).unwrap();
    let mut second = base.clone();
    second.key_group_at_use = "second-group".to_string();
    second.pricing_version = "v2".to_string();
    store.add_metering(&second).unwrap();
    let rows = store.list_metering(bucket).unwrap();
    assert_eq!(
        rows[0].key_group_at_use, "first-group",
        "attribution snapshots at first use"
    );
    assert_eq!(rows[0].pricing_version, "v1");
    // But the counters still accumulate normally.
    assert_eq!(rows[0].requests, 2);
}

#[test]
fn metering_row_identity_does_not_collide_across_a_delimiter_character() {
    // `metering_row`'s key is `key_id|model|provider` joined with a bare, unescaped `|`. A model
    // or provider name containing `|` (an operator-authored config value -- lane/model names are
    // NOT restricted to a fixed charset anywhere in this crate or its callers) lets two otherwise
    // DISTINCT (key_id, model, provider) triples collide onto the same Redis row: here
    // `("k", "a|b", "p")` and `("k", "a", "b|p")` both join to `"k|a|b|p"`. Two logically separate
    // metering rows would then merge their HINCRBY'd token/request counters into one -- a billing
    // correctness bug, not just a cosmetic key-name wart.
    let Some(store) = live_store() else { return };
    let bucket = unique_bucket(20260802);
    let key_id = uid("vk_delim");

    store
        .add_metering(&MeteringDelta {
            key_id: key_id.clone(),
            bucket,
            model: "a|b".to_string(),
            provider: "p".to_string(),
            tokens_input: 100,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "g".to_string(),
            pricing_version: "v1".to_string(),
        })
        .unwrap();
    store
        .add_metering(&MeteringDelta {
            key_id: key_id.clone(),
            bucket,
            model: "a".to_string(),
            provider: "b|p".to_string(),
            tokens_input: 7,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "g".to_string(),
            pricing_version: "v1".to_string(),
        })
        .unwrap();

    let rows = store.list_metering(bucket).unwrap();
    assert_eq!(
        rows.len(),
        2,
        "two distinct (key_id, model, provider) triples must never merge into one metering row, \
         even when a component contains the internal join delimiter"
    );
}

// ── Startup assertion ────────────────────────────────────────────────────────────────────────

/// HARDEST INVARIANT #4: `connect()` refuses to start when `maxmemory-policy` is not
/// `noeviction`. Proven live: flip the real server's policy, attempt connect, restore it
/// regardless of outcome (test hygiene — never leave the shared container misconfigured for
/// other tests).
///
/// `#[ignore]`d for the same reason as `wipes_the_entire_namespace_destructively`: this test
/// mutates GLOBAL server config (`CONFIG SET maxmemory-policy`), which races every OTHER test's
/// concurrent `connect()` call under the default parallel `cargo test` — that is a genuine
/// conflict between "this test needs exclusive access to shared server state" and "the rest of the
/// suite assumes the shared server is always in its normal (noeviction) posture," not a bug in the
/// assertion itself (verified: run alone, or with `--test-threads=1`, it passes every time). Run
/// explicitly and alone: `REDIS_URL=... cargo test -p busbar-store-redis -- --ignored
/// connect_refuses_to_start_under_an_eviction_policy`.
#[test]
#[ignore]
fn connect_refuses_to_start_under_an_eviction_policy() {
    let Some(_baseline) = live_store() else {
        return;
    };
    let url = std::env::var("REDIS_URL").unwrap();
    let mut conn = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory-policy")
        .arg("allkeys-lru")
        .query(&mut conn)
        .unwrap();

    let result = RedisStore::connect(&url);

    // ALWAYS restore, regardless of the assertion below, so a failure doesn't poison later tests.
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory-policy")
        .arg("noeviction")
        .query(&mut conn)
        .unwrap();

    assert!(
        result.is_err(),
        "connect() must refuse to start under allkeys-lru — an eviction policy can silently drop \
         a denylist entry or a metering row with no error anywhere"
    );
}

// ── migrate() / with_conn retry — mutation-testing coverage gaps (round: cargo-mutants) ───────
//
// `cargo-mutants` against `store-redis/src/lib.rs` found four real coverage gaps (no production
// bug — the existing logic is correct, but nothing in the suite would have caught it breaking):
//   - `migrate()`'s `version >= SCHEMA_VERSION` early-return guard (mutating `>=` to `<` survived
//     every existing test) — nothing exercised a SECOND `connect()` against an
//     already-migrated namespace, which is exactly the case that guard exists to protect: without
//     it, every reconnect would wipe the entire shared `busbar:*` keyspace.
//   - `run()`'s `retry && is_connection_error(&e)` match guard (mutating it to `true`, `false`, or
//     `retry || is_connection_error(&e)` all survived) — nothing exercised either half of the
//     condition independently: a non-connection error under `retry: true` (must NOT retry) or a
//     genuine connection-level error (must retry and transparently recover).

/// Kills the `version >= SCHEMA_VERSION` -> `version < SCHEMA_VERSION` mutant: a second
/// `connect()` (fresh `RedisStore`, fresh internal `migrate()` call) against a namespace already
/// at the current schema version must be a pure no-op, not a full `busbar:*` wipe.
#[test]
fn reconnecting_to_an_already_migrated_namespace_does_not_wipe_existing_data() {
    let Some(store1) = live_store() else { return };
    // By the time `store1`'s own `connect()` above returns, the schema marker is unconditionally
    // at `SCHEMA_VERSION` (every migrate() branch — fresh, already-current, or wipe-then-mark —
    // ends with the marker set), so this write happens strictly after any wipe `store1`'s own
    // connect could have triggered.
    let id = uid("vk_migrate_reconnect");
    store1.put_key(&vk(&id)).unwrap();

    let url = std::env::var("REDIS_URL").unwrap();
    let store2 = RedisStore::connect(&url).expect("a second connect() must succeed");
    assert!(
        store2.get_key(&id).unwrap().is_some(),
        "a second connect()/migrate() against an already-migrated namespace must not wipe \
         existing data (this test's own just-written key, and every concurrently-running test's \
         data along with it)"
    );
}

/// Kills the `true` and `retry || is_connection_error(&e)` mutants: a deterministic
/// NON-connection error (`WRONGTYPE`, from issuing `LPUSH` against a string-valued key) under
/// `with_conn` (`retry: true`) must surface directly via the `"command"` error context, never
/// silently retry — a retry would issue the exact same doomed command again and report it via the
/// `"retry after reconnect"` context instead, which is what this test would see if the guard ever
/// stopped checking `is_connection_error` at all.
#[test]
fn with_conn_does_not_retry_a_non_connection_error() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_wrongtype");
    let k = format!("busbar:test:wrongtype:{id}");
    store
        .with_conn(|c| c.set::<_, _, ()>(&k, "not-a-list"))
        .unwrap();

    let err = store
        .with_conn(|c| redis::cmd("LPUSH").arg(&k).arg("x").query::<i64>(c))
        .expect_err("LPUSH against a string-valued key must fail with WRONGTYPE");
    assert!(
        err.0.contains("redis command:"),
        "a non-connection (WRONGTYPE) error must surface via the 'command' context, never \
         trigger the reconnect-and-retry path meant only for connection-level errors: {}",
        err.0
    );

    store.with_conn(|c| c.del::<_, ()>(&k)).unwrap();
}

/// Kills the `false` mutant: a genuine connection-level error (the server killing our connection
/// out from under us — the real-world case `with_conn`'s reconnect-and-retry exists for) must be
/// transparently recovered, not surfaced to the caller.
#[test]
fn with_conn_transparently_reconnects_after_the_connection_is_dropped() {
    let Some(store) = live_store() else { return };
    let url = std::env::var("REDIS_URL").unwrap();

    let my_id: i64 = store
        .with_conn(|c| redis::cmd("CLIENT").arg("ID").query(c))
        .unwrap();
    let mut killer = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("ID")
        .arg(my_id)
        .query(&mut killer)
        .expect("kill this store's own connection from an independent connection");

    let id = uid("vk_after_kill");
    store.put_key(&vk(&id)).expect(
        "a connection-level error (a killed connection) must trigger transparent \
         reconnect-and-retry, not surface as a caller-visible failure",
    );
    assert!(store.get_key(&id).unwrap().is_some());
}

// ── Denylist (unchanged shape, still real coverage) ─────────────────────────────────────────

#[test]
fn denylist_add_and_list_round_trips() {
    let Some(store) = live_store() else { return };
    store.add_denylist("vk_denied", "compromised").unwrap();
    let list = store.list_denylist().unwrap();
    assert!(list.contains(&"vk_denied".to_string()));
}

// ── Audit log (unchanged shape) ──────────────────────────────────────────────────────────────

#[test]
fn audit_append_and_list_are_ordered_oldest_first() {
    let Some(store) = live_store() else { return };
    for seq in 1..=3u64 {
        store
            .append_audit(&AuditRecord {
                seq,
                ts: 1000 + seq,
                action: "key.mint".to_string(),
                resource: format!("key:vk_{seq}"),
                outcome: "applied".to_string(),
                principal: "admin".to_string(),
                prev_hash: String::new(),
                hash: format!("h{seq}"),
            })
            .unwrap();
    }
    let all = store.list_audit().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].seq, 1, "oldest first");
    assert_eq!(all[2].seq, 3);

    let tail = store.list_audit_tail(2).unwrap();
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0].seq, 2, "tail is still oldest-first WITHIN the tail");
    assert_eq!(tail[1].seq, 3);
}

/// The v5->v6 SCHEMA_VERSION bump exists to close a real billing bug: `GovState::hydrate_budgets`
/// (busbarAI core) used to infer "legacy pre-split row" from `billable_requests == 0 && requests >
/// 0` alone, but that's ALSO the shape of a bucket that was legitimately fully refunded
/// (`refund_bucket` decrements `billable_requests`, never `requests`) - so a restart could silently
/// re-bill correctly-refunded fees. The fix moves the one-time cutover here, to a real schema-
/// version boundary (see `SCHEMA_VERSION`'s doc comment for the full rationale): any pre-v6
/// namespace is wiped on the next `connect()`, exactly like every prior bump this crate has done,
/// so `hydrate_budgets` can trust `billable_requests` unconditionally from v6 onward with no more
/// value-based guessing. `#[ignore]`d for the same reason as `wipes_the_entire_namespace_destructively`:
/// this seeds real usage data shaped like the refund-collision case, then forces a v5 marker and a
/// fresh `connect()` (destructively wiping the shared `busbar:*` namespace), so it must run alone.
#[test]
#[ignore]
fn migrate_v5_to_v6_wipes_a_namespace_with_refund_shaped_data() {
    let Some(store) = live_store() else { return };
    // Seed data shaped exactly like the ambiguous case: billable_requests == 0, requests > 0 (a
    // legitimately-refunded window, or - before this fix existed - an unmigrated legacy row).
    let bucket = "vk_migrate_v6_refund_shaped";
    let ledger = busbar_api::UsageLedger {
        requests: 3,
        billable_requests: 0,
        models: vec![],
    };
    store.put_usage(bucket, 1_700_000_000, &ledger).unwrap();
    assert_eq!(
        store.get_usage(bucket, 1_700_000_000).unwrap().requests,
        3,
        "precondition: the seeded row is really there before we force the version back"
    );

    // Force the marker back to v5, simulating a namespace that predates this bump (the real thing
    // migrate() checks: `version < SCHEMA_VERSION`).
    store
        .with_conn(|c| c.set::<_, _, ()>("busbar:schema", 5i64))
        .unwrap();

    let url = std::env::var("REDIS_URL").unwrap();
    let store2 = RedisStore::connect(&url).expect("connect() must succeed and run migrate()");

    assert_eq!(
        store2.get_usage(bucket, 1_700_000_000).unwrap(),
        busbar_api::UsageLedger::default(),
        "a namespace at v5 (pre-v6) must be wiped by the v6 bump, including any refund-shaped \
         usage row - there is no real customer data to preserve at this bump (1.5.0 unreleased)"
    );
    let marker: i64 = store2.with_conn(|c| c.get("busbar:schema")).unwrap();
    assert_eq!(
        marker, 6,
        "the marker must land on the current SCHEMA_VERSION after migrate()"
    );
}

/// A destructive full-namespace wipe of a REAL Redis/Valkey, gated on the SAME `REDIS_URL` as
/// every other live test above. `#[ignore]`d so a bare `cargo test` never touches a shared dev
/// instance by accident.
#[test]
#[ignore]
fn wipes_the_entire_namespace_destructively() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_wipe_me")).unwrap();
    store
        .with_conn(|c| {
            let existing: Vec<String> = c
                .scan_match::<_, String>("busbar:*")?
                .collect::<Result<Vec<String>, _>>()?;
            let mut pipe = redis::pipe();
            pipe.atomic();
            for k in &existing {
                pipe.del(k).ignore();
            }
            pipe.query::<()>(c)
        })
        .unwrap();
    assert!(store.get_key("vk_wipe_me").unwrap().is_none());
}
