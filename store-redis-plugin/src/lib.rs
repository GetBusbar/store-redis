// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Valkey (Redis-protocol compatible) store as a droppable busbar plugin** — a `cdylib`
//! exporting the store C ABI. Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's
//! plugins folder, and set `store: { module: valkey, settings: { url: "redis://..." } }`; the engine
//! loads it in-process at boot. One Valkey instance behind a fleet of busbar nodes means shared
//! virtual keys, credentials, budgets, usage, and audit across the cluster.
//!
//! All the KV modeling lives in the `busbar-store-redis` `lib` crate (renamed on the outside to
//! "Valkey" everywhere it's user-facing; the underlying crate/type names — `RedisStore`, the `redis`
//! driver dependency — are unchanged, since the wire protocol itself is identical between Redis and
//! Valkey and the driver crate is still named `redis`). A custom build can also link the lib crate
//! statically. Here we only adapt the engine's JSON config into a `RedisStore`.

use busbar_api::Store;
use busbar_store_redis::RedisStore;
use std::time::Duration;

/// Construct a Valkey/Redis-protocol store from the JSON config the engine passes through `open`:
///
/// ```json
/// { "url": "redis://:password@host:6379/0", "connect_timeout_ms": 10000 }
/// ```
///
/// The engine passes `store.settings` verbatim as this JSON config (see the boot store-load),
/// mirroring how the Postgres plugin receives its libpq URL. `connect_timeout_ms` is optional
/// (defaults to `busbar-store-redis`'s own default, currently 10s); it bounds the initial connect
/// so a blackholed/firewalled instance fails fast at boot instead of wedging it indefinitely.
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid valkey plugin config: {e}"))?
    };
    let url = v.get("url").and_then(|x| x.as_str()).ok_or_else(|| {
        "valkey plugin config requires a \"url\" (a redis:// connection string)".to_string()
    })?;
    let store = match v.get("connect_timeout_ms").and_then(|x| x.as_u64()) {
        Some(ms) => RedisStore::connect_with_timeout(url, Duration::from_millis(ms)),
        None => RedisStore::connect(url),
    }
    .map_err(|e| format!("valkey plugin: failed to connect: {}", e.0))?;
    Ok(Box::new(store))
}

busbar_plugin_sdk::export_store_plugin!(open);
