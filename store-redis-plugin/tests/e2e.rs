// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-redis-plugin` cdylib loaded over the REAL loader
//! `load_store` seam against a REAL, live Redis (not a mock, not an in-process fake). This is the
//! exact seam the engine sees when `store: { module: redis }` is configured: a `Box<dyn Store>`
//! indistinguishable from a compiled-in store, backed by `dlopen`'d code running the C ABI.
//!
//! Unlike a file-backed store (see busbarAI's sqlite plugin end-to-end test, which reopens the
//! same file), Redis has no "close and reopen the same file" persistence signal to check. Instead
//! this proves persistence the way that is actually meaningful for a SHARED backend:
//!
//!   1. `dlopen` the plugin, write a key + usage ledger through it over the C ABI, then DROP it
//!      (which runs `busbar_close`, closing the plugin's own Redis connection).
//!   2. Independently connect to the SAME Redis instance via the plain `busbar-store-redis`
//!      library crate — a code path that never touches the cdylib, the C ABI, or the loader at
//!      all — and confirm the data is genuinely present.
//!
//! If the plugin's `put_key`/`put_usage` over the ABI were silent no-ops (or wrote to some
//! in-process cache rather than Redis), step 2 would come back empty even though a same-session
//! read-after-write through the plugin looked fine.
//!
//! Gated on `REDIS_URL` (a docker `redis:7` GitHub Actions service container in this repo's CI —
//! see `.github/workflows/ci.yml`). Skips cleanly when unset locally; under `CI` a missing
//! `REDIS_URL` is a HARD FAILURE, never a silent skip, so the only over-the-ABI coverage of the
//! durable Redis store path cannot quietly vanish.

use busbar_api::{ModelTokens, Store, TierTokens, UsageLedger, VirtualKey};
use busbar_plugin_loader::{load_store, plugin_library_filename};
use busbar_store_redis::RedisStore;

/// Locate the built `busbar_store_redis_plugin` cdylib in the target dir, derived from the test
/// binary's own path (robust to a custom `CARGO_TARGET_DIR`). `None` if it hasn't been built —
/// under `cargo test` (which builds the whole package including the cdylib target before running
/// tests) it is always present, so this only guards against unusual invocations.
fn plugin_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/e2e-<hash>
    let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
    let name = plugin_library_filename("busbar_store_redis_plugin");
    let candidate = profile_dir.join(&name);
    candidate.exists().then_some(candidate)
}

/// The live `REDIS_URL`, mirroring `busbar-store-redis`'s own `live_store()` gating discipline
/// (see busbarAI's `crates/store-redis/src/lib.rs`): skip cleanly when unset LOCALLY, but a
/// missing `REDIS_URL` under `CI` is a hard failure, not a silent skip — CI provisions the
/// `redis:7` service container and must set this env var (see `.github/workflows/ci.yml`).
fn redis_url() -> Option<String> {
    match std::env::var("REDIS_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "REDIS_URL is unset under CI: the redis:7 service container must provision it \
                 (see .github/workflows/ci.yml). Refusing to silently skip the only over-the-ABI \
                 coverage of the durable redis store path."
            );
        }
        Err(_) => {
            eprintln!("skip: set REDIS_URL (a live Redis) to run the redis plugin e2e test");
            None
        }
    }
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "binding:vk_e2e_dlopen:g0".into(),
        name: "e2e-dlopen-key".into(),
        allowed_pools: Some(vec!["p".into()]),
        enabled: true,
        created_at: 42,
        group: Some("infra".into()),
        labels: std::collections::BTreeMap::from([("env".into(), "e2e".into())]),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    }
}

fn ledger() -> UsageLedger {
    UsageLedger {
        requests: 5,
        billable_requests: 5,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            tokens: TierTokens {
                input: 20,
                output: 8,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    }
}

/// END-TO-END PERSISTENCE: dlopen the real redis plugin against a REAL, live Redis, write a key +
/// usage through it over the C ABI, drop the plugin (closing its connection via `RawPlugin`'s
/// `Drop`, which runs `busbar_close`), then verify the data actually landed in Redis two
/// independent ways:
///   1. re-dlopen the SAME cdylib against the SAME `REDIS_URL` — a fresh `busbar_open`/fresh
///      `DynStore` instance, proving the plugin itself doesn't just hold an in-memory cache
///      across calls.
///   2. connect to the SAME Redis with `busbar_store_redis::RedisStore::connect` directly — a
///      totally independent code path that never goes through the cdylib, the C ABI, or the
///      loader at all — proving the plugin actually wrote real Redis keys, not just satisfying
///      its own in-process round-trip.
///
/// This is the proof that `store: redis` operations over the ABI aren't silently no-ops.
#[test]
fn load_and_exercise_redis_plugin_persists_to_real_redis_across_reopen() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: redis plugin cdylib not built (run under `cargo test`)");
        return;
    };
    let Some(url) = redis_url() else {
        return;
    };
    let cfg = serde_json::json!({ "url": url }).to_string();

    // Isolate from any prior run against a persistent (non-CI) Redis instance.
    let direct = RedisStore::connect(&url).expect("connect directly to seed/clean up");
    let _ = Store::delete_key(&direct, "vk_e2e_dlopen");

    let vk = key("vk_e2e_dlopen");

    {
        let store = load_store(&path, &cfg).expect("load redis plugin against a real Redis");
        store.put_key(&vk).expect("put_key over the ABI");
        store
            .put_usage("vk_e2e_dlopen", 200, &ledger())
            .expect("put_usage over the ABI");
        assert_eq!(
            store
                .get_key("vk_e2e_dlopen")
                .expect("get_key over the ABI")
                .expect("present in the same session")
                .id,
            "vk_e2e_dlopen"
        );
        // `store` (and the `RawPlugin` it wraps) drops here, running `busbar_close` and dropping
        // the plugin's own `RedisStore`/connection — the data must be durably in Redis after
        // this, not just an in-process cache inside the plugin.
    }

    // (1) Re-dlopen the SAME cdylib against the SAME `REDIS_URL`: a fresh plugin instance, fresh
    // `busbar_open`, fresh connection inside the plugin — proves the ABI round-trip isn't relying
    // on the first instance still being alive.
    let reopened = load_store(&path, &cfg).expect("re-load redis plugin against the same URL");
    let got = reopened
        .get_key("vk_e2e_dlopen")
        .expect("get_key after reopen")
        .expect("the key must survive a full plugin close + reopen against the same Redis");
    assert_eq!(got.group.as_deref(), Some("infra"));
    assert_eq!(got.labels.get("env").map(String::as_str), Some("e2e"));
    let usage = reopened
        .get_usage("vk_e2e_dlopen", 200)
        .expect("get_usage after reopen");
    assert_eq!(usage.requests, 5, "usage ledger must survive the reopen");
    let t = usage
        .tokens_for("gpt-5")
        .expect("model row survives reopen");
    assert_eq!((t.input, t.output), (20, 8));
    drop(reopened);

    // (2) Read back through a TOTALLY INDEPENDENT connection — the plain `RedisStore`, used
    // directly, never touching the cdylib, the C ABI, or `busbar-plugin-loader` at all. If the
    // plugin's `put_key`/`put_usage` over the ABI were silent no-ops (or wrote somewhere other
    // than the configured Redis), this independent reader would come back empty even though the
    // reopen-via-plugin check above passed.
    let direct_key = Store::get_key(&direct, "vk_e2e_dlopen")
        .expect("get_key via the direct connection")
        .expect("the key must be physically present in Redis, bypassing the plugin");
    assert_eq!(direct_key.name, "e2e-dlopen-key");
    assert_eq!(direct_key.allowed_pools, Some(vec!["p".to_string()]));
    let direct_usage = Store::get_usage(&direct, "vk_e2e_dlopen", 200)
        .expect("get_usage via the direct connection");
    assert_eq!(
        direct_usage.requests, 5,
        "usage must be physically present in Redis, not just cached in-process by the plugin"
    );

    let _ = Store::delete_key(&direct, "vk_e2e_dlopen");
}

/// END-TO-END FAILURE: an `open()` config that cannot produce a usable store — malformed JSON, a
/// config missing `url`, and a `url` Redis itself refuses to parse — surfaces back across the C
/// ABI as a clean `Err`, never a panic or a silently-succeeded load. Needs no live Redis: every
/// case here fails before (or instead of) actually connecting.
#[test]
fn load_and_exercise_redis_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: redis plugin cdylib not built (run under `cargo test`)");
        return;
    };

    let err = load_store(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid valkey plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = load_store(&path, "{}")
        .err()
        .expect("a config missing url must fail to load");
    assert!(
        err.contains("requires a \"url\""),
        "expected the plugin's own missing-url message, got: {err}"
    );

    let err = load_store(&path, r#"{"url":"not-a-redis-url"}"#)
        .err()
        .expect("an unparseable redis url must fail to load, not silently succeed");
    assert!(
        err.contains("valkey plugin: failed to connect"),
        "expected the plugin's own connect-failure context, got: {err}"
    );
}
