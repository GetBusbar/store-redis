// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

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
    // No secret / secret absent: untouched.
    assert_eq!(scrub("plain".into(), None), "plain");
    assert_eq!(scrub("plain".into(), Some("zz")), "plain");

    // The scrub redacts BOTH the raw (percent-encoded) and DECODED forms of the password.
    // `url_password` returns the raw `p%40ss`; a driver error may print either the raw form or
    // the decoded `p@ss`. Both must be redacted.
    let raw = url_password("rediss://user:p%40ss@host:6380").expect("password");
    assert_eq!(raw, "p%40ss");
    // Decoded form leaking in an error string is scrubbed.
    let decoded_leak = "auth failed with password p@ss".to_string();
    let s = scrub(decoded_leak, Some(&raw));
    assert!(
        !s.contains("p@ss") && s.contains("<redacted>"),
        "the DECODED password form must be scrubbed too; got {s}"
    );
    // Raw form leaking is also scrubbed.
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

/// A `rediss://` (TLS) URL parses into a client without connecting - the TLS feature is
/// compiled in and the scheme is accepted (a live TLS round-trip needs a TLS redis, which the
/// live test covers when REDIS_URL is rediss).
#[test]
fn rediss_url_is_accepted() {
    assert!(redis::Client::open("rediss://:pw@localhost:6380/0").is_ok());
}

/// End-to-end against a REAL Redis, gated on `REDIS_URL` (a docker `redis:7` service in CI).
/// Skips cleanly when unset LOCALLY so the default `cargo test` needs no server - but MUST NOT
/// silently skip in CI: CI provisions the service and sets `REDIS_URL` (see
/// .github/workflows/ci.yml), so when `CI` is set the missing URL is a HARD FAILURE rather than
/// a silent skip (same discipline as the Postgres backend's `BUSBAR_TEST_POSTGRES_URL`).
fn live_store() -> Option<RedisStore> {
    let url = match std::env::var("REDIS_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "REDIS_URL is unset under CI: the Redis service container must provision it \
                 (see .github/workflows/ci.yml). Refusing to silently skip the only live-DB \
                 coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set REDIS_URL to run the Redis store tests");
            return None;
        }
    };
    Some(RedisStore::connect(&url).expect("connect"))
}

fn vk(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        key_hash: "h".into(),
        name: id.into(),
        allowed_pools: Some(vec!["prod,special".into()]),
        enabled: true,
        created_at: 99,
        group: Some("growth".into()),
        labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
    }
}

#[test]
fn roundtrip_against_live_redis() {
    let Some(store) = live_store() else { return };
    // Isolate from any prior run.
    let _ = store.delete_key("vk_redis");

    let key = vk("vk_redis");
    store.put_key(&key).unwrap();
    let got = store.get_key("vk_redis").unwrap().unwrap();
    // The comma-bearing pool name survives (whole-key JSON, not a bare comma split).
    assert_eq!(got.allowed_pools, Some(vec!["prod,special".to_string()]));
    assert_eq!(
        got.group.as_deref(),
        Some("growth"),
        "the group binding survives the redis JSON round-trip"
    );
    assert_eq!(got.labels.get("team").map(String::as_str), Some("growth"));
    // C6 grant intent round-trips through the whole-key JSON: null (all) vs [] (none).
    let mut all = vk("vk_redis_all");
    all.allowed_pools = None;
    let mut none = vk("vk_redis_none");
    none.allowed_pools = Some(vec![]);
    store.put_key(&all).unwrap();
    store.put_key(&none).unwrap();
    assert_eq!(
        store
            .get_key("vk_redis_all")
            .unwrap()
            .unwrap()
            .allowed_pools,
        None
    );
    assert_eq!(
        store
            .get_key("vk_redis_none")
            .unwrap()
            .unwrap()
            .allowed_pools,
        Some(vec![])
    );
    store.delete_key("vk_redis_all").unwrap();
    store.delete_key("vk_redis_none").unwrap();
    assert!(store
        .list_keys()
        .unwrap()
        .iter()
        .any(|k| k.id == "vk_redis"));

    // Token ledger: absolute put (DEL + HSET) round-trips; additive HINCRBY accumulates on top.
    let base = UsageLedger {
        requests: 3,
        // v4: 2 of the 3 admitted requests are billable (one non-2xx refunded off the fee
        // base); the two axes must round-trip INDEPENDENTLY through the hash.
        billable_requests: 2,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            tokens: TierTokens {
                input: 9,
                output: 4,
                cache_read: 2,
                cache_write: 1,
            },
        }],
    };
    store.put_usage("vk_redis", 100, &base).unwrap();
    let u = store.get_usage("vk_redis", 100).unwrap();
    assert_eq!(u.requests, 3);
    assert_eq!(
        u.billable_requests, 2,
        "billable_requests round-trips independently of requests"
    );
    let t = u.tokens_for("gpt-5").unwrap();
    assert_eq!(
        (t.input, t.output, t.cache_read, t.cache_write),
        (9, 4, 2, 1)
    );
    store
        .add_usage(
            "vk_redis",
            100,
            &busbar_api::UsageDelta {
                requests: 2,
                billable_requests: 2,
                models: vec![busbar_api::ModelTokensDelta {
                    model: "gpt-5".into(),
                    tokens: busbar_api::TierTokensDelta {
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                    },
                }],
            },
        )
        .unwrap();
    let u = store.get_usage("vk_redis", 100).unwrap();
    assert_eq!(u.requests, 5, "add_usage accumulates the requests delta");
    assert_eq!(
        u.billable_requests, 4,
        "add_usage accumulates the billable_requests delta on its own axis (2 + 2)"
    );
    let t = u.tokens_for("gpt-5").unwrap();
    assert_eq!(
        (t.input, t.output),
        (10, 5),
        "add_usage accumulates per-model tier deltas onto the durable record"
    );
    // A second model materializes its own fields; a model name CONTAINING ':' round-trips.
    store
        .add_usage(
            "vk_redis",
            100,
            &busbar_api::UsageDelta {
                requests: 0,
                billable_requests: 0,
                models: vec![busbar_api::ModelTokensDelta {
                    model: "org:custom:model".into(),
                    tokens: busbar_api::TierTokensDelta {
                        input: 7,
                        output: 0,
                        cache_read: 0,
                        cache_write: 0,
                    },
                }],
            },
        )
        .unwrap();
    let u = store.get_usage("vk_redis", 100).unwrap();
    assert_eq!(u.models.len(), 2);
    assert_eq!(
        u.tokens_for("org:custom:model").unwrap().input,
        7,
        "a colon-bearing model name survives the hash-field encoding"
    );

    // Metering: HINCRBY accumulation across two responses on the same row.
    let delta = |ti: u64| MeteringDelta {
        key_id: "vk_redis".into(),
        bucket: 7,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: ti,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_creation: 0,
        requests: 1,
    };
    // Clear the bucket rows from a prior run.
    let _ = store.with_conn(|c| {
        let row = metering_row(7, "vk_redis", "m", "p");
        redis::pipe()
            .atomic()
            .del(&row)
            .ignore()
            .srem(metering_set(7), &row)
            .ignore()
            .query::<()>(c)
    });
    store.add_metering(&delta(10)).unwrap();
    store.add_metering(&delta(5)).unwrap();
    let rows = store.list_metering(7).unwrap();
    let row = rows.iter().find(|r| r.key_id == "vk_redis").unwrap();
    assert_eq!(row.tokens_input, 15, "HINCRBY accumulated across responses");
    assert_eq!(row.requests, 2);

    // Audit: ZADD by seq, ZRANGE oldest-first.
    let rec = |seq: u64, prev: &str, hash: &str| AuditRecord {
        seq,
        ts: 1000 + seq,
        action: "hook.register".into(),
        resource: format!("hook:{seq}"),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: prev.into(),
        hash: hash.into(),
    };
    store.with_conn(|c| c.del::<_, ()>(AUDIT_ZSET)).unwrap();
    store.append_audit(&rec(1, "", "h1")).unwrap();
    store.append_audit(&rec(2, "h1", "h2")).unwrap();
    let audit = store.list_audit().unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!((audit[0].seq, audit[1].seq), (1, 2), "oldest-first by seq");
    assert_eq!(audit[1].prev_hash, "h1");

    // A re-append of an EXISTING seq with a
    // DIFFERENT payload (a corrected hash) must OVERWRITE the record at that seq, never leave two
    // members at one score. A bare ZADD (upsert-on-member) would produce a duplicate seq-2 row and
    // diverge from the SQL backends (whose replay overwrites the digest). ZREMRANGEBYSCORE+ZADD.
    store.append_audit(&rec(2, "h1", "h2b")).unwrap();
    let replayed = store.list_audit().unwrap();
    assert_eq!(
        replayed.len(),
        2,
        "re-appending an existing seq must upsert on seq, never add a duplicate"
    );
    assert_eq!(
        replayed[1].hash, "h2b",
        "the replayed record overwrites the prior digest (SQL-backend parity)"
    );

    // DENYLIST (P3, signed-token revocation): add a subject, list it back, and prove idempotency
    // (a repeat add leaves exactly one member). Isolate on a unique sub and clean up afterward.
    let dsub = "sub_redis_test";
    let _ = store.with_conn(|c| {
        redis::pipe()
            .atomic()
            .del(format!("{DENYLIST_PREFIX}{dsub}"))
            .ignore()
            .srem(DENYLIST_INDEX, dsub)
            .ignore()
            .query::<()>(c)
    });
    store.add_denylist(dsub, "compromised").unwrap();
    store.add_denylist(dsub, "still compromised").unwrap();
    let denied = store.list_denylist().unwrap();
    assert_eq!(
        denied.iter().filter(|s| *s == dsub).count(),
        1,
        "add_denylist is idempotent: the sub is denied exactly once"
    );
    // Confirm the denylist survives the with_conn path: the reason string is durably readable.
    let reason: Option<String> = store
        .with_conn(|c| c.get(format!("{DENYLIST_PREFIX}{dsub}")))
        .unwrap();
    assert_eq!(reason.as_deref(), Some("still compromised"));
    let _ = store.with_conn(|c| {
        redis::pipe()
            .atomic()
            .del(format!("{DENYLIST_PREFIX}{dsub}"))
            .ignore()
            .srem(DENYLIST_INDEX, dsub)
            .ignore()
            .query::<()>(c)
    });

    // Attach an AWS credential so the delete cascade over credentials is actually exercised.
    let cred = AwsCredential {
        access_key_id: "AKIA_REDIS_TEST".into(),
        key_id: "vk_redis".into(),
        secret_access_key: "s3cr3t".into(),
    };
    store.put_aws_credential(&cred).unwrap();
    assert!(store
        .list_aws_credentials()
        .unwrap()
        .iter()
        .any(|c| c.access_key_id == "AKIA_REDIS_TEST"));

    // Delete removes the key, its usage, and its AWS creds - atomically (one MULTI/EXEC).
    store.delete_key("vk_redis").unwrap();
    assert!(store.get_key("vk_redis").unwrap().is_none());
    assert_eq!(
        store.get_usage("vk_redis", 100).unwrap(),
        UsageLedger::default()
    );
    assert!(
        !store
            .list_aws_credentials()
            .unwrap()
            .iter()
            .any(|c| c.access_key_id == "AKIA_REDIS_TEST"),
        "delete_key must cascade to the AWS credentials"
    );
}

/// `delete_key`'s cleanup SCAN builds its MATCH pattern from the caller-supplied id via direct
/// string interpolation. A glob wildcard in the id must NOT let the SCAN over-match another key's
/// usage windows: an id of `*` (or containing `?`/`[`/`]`) must be treated as a LITERAL id, not a
/// pattern.
///
/// RED (pre-fix, unescaped `format!("busbar:usage:{id}:*")`): deleting the glob-id key also wipes
/// the innocent key's usage windows (the `*` in the id matches every bucket for every key).
/// GREEN: only the glob-id key's own usage is removed; the innocent key's usage survives.
#[test]
fn delete_key_does_not_glob_match_other_keys_usage() {
    let Some(store) = live_store() else { return };
    // Clean slate.
    let _ = store.delete_key("*");
    let _ = store.delete_key("vk_glob_innocent");

    store.put_key(&vk("*")).unwrap();
    store.put_key(&vk("vk_glob_innocent")).unwrap();

    let ledger = UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            model: "m".into(),
            tokens: TierTokens {
                input: 1,
                output: 1,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };
    store.put_usage("*", 100, &ledger).unwrap();
    store.put_usage("vk_glob_innocent", 100, &ledger).unwrap();

    store.delete_key("*").unwrap();

    assert_eq!(
        store.get_usage("vk_glob_innocent", 100).unwrap(),
        ledger,
        "deleting a key whose id is a Redis glob wildcard must not wipe an unrelated key's usage"
    );
    store.delete_key("vk_glob_innocent").unwrap();
}

/// v4: `billable_requests` persists and HINCRBY-accumulates INDEPENDENTLY of `requests` on its
/// own hash field (admission count vs the 2xx-only fee base). Gated on a live Redis, same as the
/// other round-trip tests.
#[test]
fn billable_requests_roundtrips_independently_against_live_redis() {
    let Some(store) = live_store() else { return };
    let bucket_id = "vk_redis_billable";
    let window = 1_700_000_200_u64;
    let _ = store.with_conn(|c| c.del::<_, ()>(usage_key(bucket_id, window)));

    // Admission 5, only 3 billable (2 non-2xx refunded off the fee base).
    store
        .put_usage(
            bucket_id,
            window,
            &UsageLedger {
                requests: 5,
                billable_requests: 3,
                models: vec![],
            },
        )
        .unwrap();
    let u = store.get_usage(bucket_id, window).unwrap();
    assert_eq!((u.requests, u.billable_requests), (5, 3));

    // A delta refunding one non-2xx: -2 off both axes, accumulated independently.
    store
        .add_usage(
            bucket_id,
            window,
            &busbar_api::UsageDelta {
                requests: -2,
                billable_requests: -2,
                models: vec![],
            },
        )
        .unwrap();
    let u = store.get_usage(bucket_id, window).unwrap();
    assert_eq!((u.requests, u.billable_requests), (3, 1));

    // An over-refund of the fee base alone clamps billable_requests to 0 on read (a transient
    // negative HINCRBY floors on read - see the crate doc) while requests holds.
    store
        .add_usage(
            bucket_id,
            window,
            &busbar_api::UsageDelta {
                requests: 0,
                billable_requests: -100,
                models: vec![],
            },
        )
        .unwrap();
    let u = store.get_usage(bucket_id, window).unwrap();
    assert_eq!(
        (u.requests, u.billable_requests),
        (3, 0),
        "the fee base clamps to 0 on read without disturbing the admission count"
    );
    let _ = store.with_conn(|c| c.del::<_, ()>(usage_key(bucket_id, window)));
}

/// ATOMIC key+credential publish: `put_key_with_aws_credential` writes both (and all three
/// indexes) in ONE MULTI/EXEC, and the delete cascade removes every trace in ONE MULTI/EXEC -
/// no orphaned SigV4 credential, no dangling index member.
#[test]
fn atomic_key_with_credential_and_cascade_against_live_redis() {
    let Some(store) = live_store() else { return };
    let _ = store.delete_key("vk_atomic");

    let key = vk("vk_atomic");
    let cred = AwsCredential {
        access_key_id: "AKIA_ATOMIC_TEST".into(),
        key_id: "vk_atomic".into(),
        secret_access_key: "sekrit".into(),
    };
    store.put_key_with_aws_credential(&key, &cred).unwrap();
    assert!(store.get_key("vk_atomic").unwrap().is_some());
    assert!(store
        .list_aws_credentials()
        .unwrap()
        .iter()
        .any(|c| c.access_key_id == "AKIA_ATOMIC_TEST"));

    store.delete_key("vk_atomic").unwrap();
    // NOTHING remains: key row, key index, credential row, credential index, id map.
    assert!(store.get_key("vk_atomic").unwrap().is_none());
    assert!(!store
        .list_aws_credentials()
        .unwrap()
        .iter()
        .any(|c| c.access_key_id == "AKIA_ATOMIC_TEST"));
    let leftovers: bool = store
        .with_conn(|c| {
            let a: bool = c.exists(format!("{AWSCRED_PREFIX}AKIA_ATOMIC_TEST"))?;
            let b: bool = c.exists(format!("{AWSCRED_IDS_PREFIX}vk_atomic"))?;
            let idx: bool = c.sismember(AWSCRED_INDEX, "AKIA_ATOMIC_TEST")?;
            Ok(a || b || idx)
        })
        .unwrap();
    assert!(!leftovers, "the atomic cascade leaves zero residue");
}

/// RECONNECT: after the server closes our connection (`QUIT`), the next operation transparently
/// reopens and succeeds instead of failing with a broken-pipe error.
#[test]
fn reconnects_after_dropped_connection_against_live_redis() {
    let Some(store) = live_store() else { return };
    let _ = store.delete_key("vk_reconn");
    store.put_key(&vk("vk_reconn")).unwrap();

    // Ask the server to close OUR connection: QUIT makes the server hang up after replying, so
    // the connection in the pool is dead for the next command.
    {
        let mut guard = store.conn.lock().unwrap();
        if let Some(conn) = guard.as_mut() {
            let _ = redis::cmd("QUIT").query::<String>(conn);
        }
    }
    // The next operation must reconnect-and-retry, not error.
    let got = store
        .get_key("vk_reconn")
        .expect("operation after a dropped connection must transparently reconnect");
    assert!(got.is_some());
    store.delete_key("vk_reconn").unwrap();
}

/// M3 (over-bill): a NON-IDEMPOTENT write cascade (add_usage / add_metering) must NOT auto-retry
/// on a connection error - a lost-reply timeout could have already committed the EXEC server-side,
/// so a retry would DOUBLE-APPLY the delta permanently. We drop the pooled connection (server-side
/// QUIT), then a mutating op must ERROR (no transparent retry) while a subsequent READ reconnects.
#[test]
fn mutating_op_does_not_auto_retry_after_dropped_connection() {
    let Some(store) = live_store() else { return };
    let bucket_id = "vk_m3_noretry";
    let window = 1_700_000_000_u64;
    let _ = store.with_conn(|c| c.del::<_, ()>(usage_key(bucket_id, window)));

    let delta = || busbar_api::UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![busbar_api::ModelTokensDelta {
            model: "gpt-x".into(),
            tokens: busbar_api::TierTokensDelta {
                input: 10,
                output: 0,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };

    // Kill the pooled connection so the very next command hits a dead socket.
    {
        let mut guard = store.conn.lock().unwrap();
        if let Some(conn) = guard.as_mut() {
            let _ = redis::cmd("QUIT").query::<String>(conn);
        }
    }
    // The mutating op must ERROR (a read WOULD have transparently reconnected). If it instead
    // returned Ok, that means a silent reconnect+retry ran - the exact double-apply hazard.
    let res = store.add_usage(bucket_id, window, &delta());
    assert!(
        res.is_err(),
        "a non-idempotent write cascade must NOT auto-retry on a connection error (over-bill \
         hazard); it must surface the error so the flusher re-derives from baseline"
    );

    // A subsequent READ reconnects cleanly (the dropped connection was cleared), and - proof the
    // failed write did NOT apply - the counter is still absent/zero.
    let ledger = store.get_usage(bucket_id, window).expect("read reconnects");
    assert_eq!(
        ledger.requests, 0,
        "the un-retried write must not have applied (exactly-once on error)"
    );

    // A fresh mutating op now succeeds on the healthy connection (baseline re-derive path).
    store
        .add_usage(bucket_id, window, &delta())
        .expect("write succeeds on a healthy connection");
    assert_eq!(store.get_usage(bucket_id, window).unwrap().requests, 1);
    let _ = store.with_conn(|c| c.del::<_, ()>(usage_key(bucket_id, window)));
}

/// M2 (data-loss): busbar:* DATA present + schema marker ABSENT + the data is NOT legacy-shaped
/// (a healthy v2 namespace whose marker was evicted under `maxmemory allkeys-*`) must REFUSE to
/// boot - never silently WIPE. And the inverse: a genuinely legacy-shaped namespace (a
/// `busbar:usage:*` HASH carrying the pre-v2 `spend_cents` field) IS wiped and re-marked.
///
/// `#[ignore]`: this test's SUBJECT is `migrate()`'s destructive wipe path, which SCAN+DELETEs
/// the ENTIRE `busbar:*` namespace on `live_store()` — a real Redis reached via `REDIS_URL`,
/// shared by every test in this crate (no per-test key prefix, no dedicated DB index). Any
/// sibling redis test running concurrently against the same instance has its keys destroyed
/// mid-assertion, and this test's own setup can equally be destroyed by a sibling. Isolating by
/// key-prefix or DB index would require either a production change (`migrate()` hardcodes the
/// `busbar:*` SCAN pattern) or a `SELECT` capability CI's Redis is not guaranteed to have; both
/// are more invasive than the value of default-suite coverage for a test already gated behind an
/// opt-in env var most environments skip. Run explicitly and alone against a REDIS_URL instance
/// safe to wipe: `REDIS_URL=... cargo test -p busbar-store-redis -- --ignored --test-threads=1
/// migrate_refuses_to_wipe_non_legacy_namespace_with_missing_marker`.
#[test]
#[ignore = "wipes the shared live namespace; run alone"]
fn migrate_refuses_to_wipe_non_legacy_namespace_with_missing_marker() {
    let Some(store) = live_store() else { return };
    // Simulate a v2 namespace whose marker was evicted: v2-shaped usage data, no busbar:schema.
    let vk_id = "vk_m2_v2";
    let ukey = usage_key(vk_id, 1_700_000_100);
    store
        .with_conn(|c| {
            redis::pipe()
                .hset(&ukey, "requests", 5_i64)
                .ignore()
                .hset(&ukey, model_field("gpt-x", "input"), 10_i64)
                .ignore()
                .del(SCHEMA_KEY)
                .ignore()
                .query::<()>(c)
        })
        .unwrap();

    // migrate() must REFUSE (Err), leaving the data intact - not wipe it.
    let err = store
        .migrate()
        .expect_err("a non-legacy namespace with a missing marker must refuse to boot");
    assert!(
        err.0.contains("Refusing to wipe"),
        "expected a loud refuse-to-wipe error, got: {}",
        err.0
    );
    let still: i64 = store.with_conn(|c| c.hget(&ukey, "requests")).unwrap();
    assert_eq!(
        still, 5,
        "the v2 data must survive - migrate() must not wipe it"
    );

    // Now make it genuinely LEGACY-shaped (add the pre-v2 spend_cents field) and confirm a wipe.
    store
        .with_conn(|c| c.hset::<_, _, _, ()>(&ukey, "spend_cents", 42_i64))
        .unwrap();
    store.with_conn(|c| c.del::<_, ()>(SCHEMA_KEY)).unwrap();
    store
        .migrate()
        .expect("a legacy-shaped namespace migrates (wipe + re-mark)");
    let gone: Option<i64> = store.with_conn(|c| c.hget(&ukey, "requests")).unwrap();
    assert!(gone.is_none(), "the legacy key must be wiped");
    let marker: Option<i64> = store.with_conn(|c| c.get(SCHEMA_KEY)).unwrap();
    assert_eq!(marker, Some(SCHEMA_VERSION), "re-marked v2 after the wipe");
}

/// `delete_key`'s credential cleanup must WATCH the AccessKeyId index key and re-read it fresh
/// inside a retried transaction (`redis::transaction`), not read it once outside the write phase --
/// otherwise a concurrent `put_aws_credential` landing between the read and the EXEC leaves its new
/// credential orphaned (unindexed by key, but still a live row) after the "deleting" key is gone,
/// violating the crate's own stated invariant that a revoked key's SigV4 credential cannot outlive
/// it. Proves the underlying mechanism DETERMINISTICALLY: WATCH a key, read it, have a SECOND
/// connection modify it, then attempt EXEC on stale data -- Redis's own guarantee is that EXEC
/// returns nil (aborted) whenever a watched key changed since WATCH, which is exactly what makes
/// `redis::transaction`'s retry loop pick up fresh state. A naive SMEMBERS-then-pipe with no WATCH
/// has no such detection at all, and this test's EXEC would then need to succeed (there's nothing
/// to abort it) even though it's building on now-stale data -- so this test also proves the ABSENCE
/// of the bug, not just the presence of the mechanism.
#[test]
fn delete_key_credential_watch_detects_a_concurrent_write() {
    let Some(store) = live_store() else { return };
    let url = std::env::var("REDIS_URL").unwrap();
    let id = "vk_watch_detect_test";
    let cred_key = format!("{AWSCRED_IDS_PREFIX}{id}");
    let _ = store.with_conn(|c| c.del::<_, ()>(&cred_key));

    // Connection A: WATCH, then read -- exactly delete_key's closure shape.
    let mut a = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    redis::cmd("WATCH").arg(&cred_key).exec(&mut a).unwrap();
    let _before: Vec<String> = a.smembers(&cred_key).unwrap();

    // Connection B: a concurrent write to the SAME watched key (what put_aws_credential does).
    let mut b = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = b.sadd(&cred_key, "AKIA_CONCURRENT").unwrap();

    // Connection A: build + EXEC a transaction on the (now stale) data it read. Redis MUST abort it.
    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.set(format!("{cred_key}:touched"), 1).ignore();
    let result: Option<()> = pipe.query::<Option<()>>(&mut a).unwrap();
    assert!(
        result.is_none(),
        "WATCH must cause EXEC to abort (return nil) when the watched key changed between WATCH \
         and EXEC -- a delete_key that reads cred_ids WITHOUT watching this key would never detect \
         this and would proceed to delete based on stale membership, orphaning the concurrently \
         added credential"
    );

    let _: () = b.del(&cred_key).unwrap();
}
