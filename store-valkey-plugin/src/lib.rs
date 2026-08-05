// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Valkey store as a droppable busbar plugin** — a `cdylib`
//! exporting the store C ABI. Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's
//! plugins folder, and set `store: { module: valkey, settings: { url: "redis://..." } }`; the engine
//! loads it in-process at boot. One Valkey instance behind a fleet of busbar nodes means shared
//! virtual keys, credentials, budgets, usage, and audit across the cluster.
//!
//! All the KV modeling lives in the `busbar-store-valkey` `lib` crate. A custom build can also link
//! the lib crate statically. Here we only adapt the engine's JSON config into a `ValkeyStore`. (The
//! one non-Valkey spelling left in the tree is the upstream RESP driver crate, still published under
//! its pre-fork crates.io name, and the `redis://`/`rediss://` URL schemes that driver parses.)

use busbar_api::Store;
use busbar_store_valkey::ValkeyStore;
use std::time::Duration;

/// Construct a Valkey-protocol store from the JSON config the engine passes through `open`:
///
/// ```json
/// { "url": "redis://:password@host:6379/0", "connect_timeout_ms": 10000 }
/// ```
///
/// The engine passes `store.settings` verbatim as this JSON config (see the boot store-load),
/// mirroring how the Postgres plugin receives its libpq URL. `connect_timeout_ms` is optional
/// (defaults to `busbar-store-valkey`'s own default, currently 10s); it bounds the initial connect
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
        Some(ms) => ValkeyStore::connect_with_timeout(url, Duration::from_millis(ms)),
        None => ValkeyStore::connect(url),
    }
    .map_err(|e| format!("valkey plugin: failed to connect: {}", e.0))?;
    Ok(Box::new(store))
}

busbar_plugin_sdk::export_store_plugin!(open);
