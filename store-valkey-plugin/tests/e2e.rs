// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-valkey-plugin` cdylib loaded over the REAL loader
//! `load_store` seam against a REAL, live Valkey (not a mock, not an in-process fake). This is the
//! exact seam the engine sees when `store: { module: valkey }` is configured: a `Box<dyn Store>`
//! indistinguishable from a compiled-in store, backed by `dlopen`'d code running the C ABI.
//!
//! Unlike a file-backed store (see busbarAI's sqlite plugin end-to-end test, which reopens the
//! same file), Valkey has no "close and reopen the same file" persistence signal to check. Instead
//! this proves persistence the way that is actually meaningful for a SHARED backend:
//!
//!   1. `dlopen` the plugin, write a key + usage ledger through it over the C ABI, then DROP it
//!      (which runs `busbar_close`, closing the plugin's own Valkey connection).
//!   2. Independently connect to the SAME Valkey instance via the plain `busbar-store-valkey`
//!      library crate — a code path that never touches the cdylib, the C ABI, or the loader at
//!      all — and confirm the data is genuinely present.
//!
//! If the plugin's `put_key`/`put_usage` over the ABI were silent no-ops (or wrote to some
//! in-process cache rather than Valkey), step 2 would come back empty even though a same-session
//! read-after-write through the plugin looked fine.
//!
//! Gated on `VALKEY_URL` (a docker `valkey:7` GitHub Actions service container in this repo's CI —
//! see `.github/workflows/ci.yml`). Skips cleanly when unset locally; under `CI` a missing
//! `VALKEY_URL` is a HARD FAILURE, never a silent skip, so the only over-the-ABI coverage of the
//! durable Valkey store path cannot quietly vanish.

use busbar_api::{ModelTokens, Store, TierTokens, UsageLedger, VirtualKey};
use busbar_plugin_loader::{load_store, plugin_library_filename};
use busbar_store_valkey::ValkeyStore;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Locate the built `busbar_store_valkey_plugin` cdylib in the target dir, derived from the test
/// binary's own path (robust to a custom `CARGO_TARGET_DIR`). `None` if it hasn't been built —
/// under `cargo test` (which builds the whole package including the cdylib target before running
/// tests) it is always present, so this only guards against unusual invocations.
fn plugin_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/e2e-<hash>
    let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
    let name = plugin_library_filename("busbar_store_valkey_plugin");
    let candidate = profile_dir.join(&name);
    candidate.exists().then_some(candidate)
}

/// The live `VALKEY_URL`, mirroring `busbar-store-valkey`'s own `live_store()` gating discipline
/// (see busbarAI's `crates/store-valkey/src/lib.rs`): skip cleanly when unset LOCALLY, but a
/// missing `VALKEY_URL` under `CI` is a hard failure, not a silent skip — CI provisions the
/// `valkey:7` service container and must set this env var (see `.github/workflows/ci.yml`).
fn valkey_url() -> Option<String> {
    match std::env::var("VALKEY_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "VALKEY_URL is unset under CI: the valkey:7 service container must provision it \
                 (see .github/workflows/ci.yml). Refusing to silently skip the only over-the-ABI \
                 coverage of the durable valkey store path."
            );
        }
        Err(_) => {
            eprintln!("skip: set VALKEY_URL (a live Valkey) to run the valkey plugin e2e test");
            None
        }
    }
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "binding:vk_e2e_dlopen:g0".into(),
        name: "e2e-dlopen-key".into(),
        allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
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

/// END-TO-END PERSISTENCE: dlopen the real valkey plugin against a REAL, live Valkey, write a key +
/// usage through it over the C ABI, drop the plugin (closing its connection via `RawPlugin`'s
/// `Drop`, which runs `busbar_close`), then verify the data actually landed in Valkey two
/// independent ways:
///   1. re-dlopen the SAME cdylib against the SAME `VALKEY_URL` — a fresh `busbar_open`/fresh
///      `DynStore` instance, proving the plugin itself doesn't just hold an in-memory cache
///      across calls.
///   2. connect to the SAME Valkey with `busbar_store_valkey::ValkeyStore::connect` directly — a
///      totally independent code path that never goes through the cdylib, the C ABI, or the
///      loader at all — proving the plugin actually wrote real Valkey keys, not just satisfying
///      its own in-process round-trip.
///
/// This is the proof that `store: valkey` operations over the ABI aren't silently no-ops.
#[test]
fn load_and_exercise_valkey_plugin_persists_to_real_valkey_across_reopen() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: valkey plugin cdylib not built (run under `cargo test`)");
        return;
    };
    let Some(url) = valkey_url() else {
        return;
    };
    let cfg = serde_json::json!({ "url": url }).to_string();

    // Isolate from any prior run against a persistent (non-CI) Valkey instance.
    let direct = ValkeyStore::connect(&url).expect("connect directly to seed/clean up");
    let _ = Store::delete_key(&direct, "vk_e2e_dlopen");

    let vk = key("vk_e2e_dlopen");

    {
        let store = load_store(&path, &cfg).expect("load valkey plugin against a real Valkey");
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
        // the plugin's own `ValkeyStore`/connection — the data must be durably in Valkey after
        // this, not just an in-process cache inside the plugin.
    }

    // (1) Re-dlopen the SAME cdylib against the SAME `VALKEY_URL`: a fresh plugin instance, fresh
    // `busbar_open`, fresh connection inside the plugin — proves the ABI round-trip isn't relying
    // on the first instance still being alive.
    let reopened = load_store(&path, &cfg).expect("re-load valkey plugin against the same URL");
    let got = reopened
        .get_key("vk_e2e_dlopen")
        .expect("get_key after reopen")
        .expect("the key must survive a full plugin close + reopen against the same Valkey");
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

    // (2) Read back through a TOTALLY INDEPENDENT connection — the plain `ValkeyStore`, used
    // directly, never touching the cdylib, the C ABI, or `busbar-plugin-loader` at all. If the
    // plugin's `put_key`/`put_usage` over the ABI were silent no-ops (or wrote somewhere other
    // than the configured Valkey), this independent reader would come back empty even though the
    // reopen-via-plugin check above passed.
    let direct_key = Store::get_key(&direct, "vk_e2e_dlopen")
        .expect("get_key via the direct connection")
        .expect("the key must be physically present in Valkey, bypassing the plugin");
    assert_eq!(direct_key.name, "e2e-dlopen-key");
    assert_eq!(
        direct_key.allowed_scopes,
        Some(vec![busbar_api::ScopeRef::pool("p")])
    );
    let direct_usage = Store::get_usage(&direct, "vk_e2e_dlopen", 200)
        .expect("get_usage via the direct connection");
    assert_eq!(
        direct_usage.requests, 5,
        "usage must be physically present in Valkey, not just cached in-process by the plugin"
    );

    let _ = Store::delete_key(&direct, "vk_e2e_dlopen");
}

/// END-TO-END FAILURE: an `open()` config that cannot produce a usable store — malformed JSON, a
/// config missing `url`, and a `url` Valkey itself refuses to parse — surfaces back across the C
/// ABI as a clean `Err`, never a panic or a silently-succeeded load. Needs no live Valkey: every
/// case here fails before (or instead of) actually connecting.
#[test]
fn load_and_exercise_valkey_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: valkey plugin cdylib not built (run under `cargo test`)");
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

    let err = load_store(&path, r#"{"url":"not-a-valkey-url"}"#)
        .err()
        .expect("an unparseable valkey url must fail to load, not silently succeed");
    assert!(
        err.contains("valkey plugin: failed to connect"),
        "expected the plugin's own connect-failure context, got: {err}"
    );
}

// ── THE REAL "prod ready" bar: install over the real admin HTTP API, exercise it, verify ──────
//
// Everything above loads the plugin via `busbar_plugin_loader::load_store()` — a direct Rust
// function call no real end user ever makes. `admin_api_installs_the_valkey_plugin_and_writes_land_in_real_valkey`
// instead drives an ACTUAL `busbar` binary the way an operator (or CI's own INSTALL-AND-SERVE
// step, see busbarAI's `.github/workflows/plugin-ci.yml`) does:
//
//   1. Pack the built cdylib into a real tarball with the real `busbar-plugin-pack` tool.
//   2. Boot a real `busbar` process (admin listener up, no valkey plugin loaded yet).
//   3. POST the base64 tarball to `POST /api/v1/admin/plugins` — the real runtime-install path
//      (`crates/busbar/src/admin/v1/json/handlers.rs::install_plugin`) — and confirm 201.
//   4. `PUT /api/v1/admin/config/settings` to set `store.module` to the freshly-installed plugin,
//      persisted; `POST /api/v1/admin/restart` to apply it (store-module changes are documented
//      restart-to-apply, never a hot swap) — then actually restart the process, since busbar's own
//      restart deliberately does not self-respawn (a supervisor's job, which this test plays).
//   5. Confirm the restarted process picked up the plugin as its active store module.
//   6. Do REAL WORK through the running instance: `POST /api/v1/admin/keys` with
//      `issue_aws_credential: true` — the one and only admin-HTTP path that mints BOTH a virtual
//      key AND a credential in one call (there is no separate `/keys/{id}/credentials` endpoint;
//      confirmed by reading `crates/busbar/src/admin/v1/json/mod.rs`'s full route table).
//   7. INDEPENDENTLY verify both rows physically landed in the real Valkey two ways: (a) the typed
//      `ValkeyStore`/`Store` trait — a code path that never touches the plugin, the C ABI, the
//      loader, or the HTTP admin surface at all; and (b) a raw `redis::Client` GET of the exact
//      key bytes (`busbar:key:<id>`) — proof independent even of `busbar-store-valkey`'s own
//      encode/decode path, the strongest verification available short of `valkey-cli` itself.
//
// This is the first test of this shape in either sibling plugin repo (store-postgres's own
// `load_and_exercise_postgres_plugin_via_file_drop` uses the FILE-DROP mechanism, not the admin
// API — see that file's own module doc) — there is no existing pattern to mirror beyond CI's own
// bash INSTALL-AND-SERVE script, which this ports into a real, CI-gated Rust test.

/// RAII guard for a spawned child process: kills and reaps it on drop, including when a panic
/// unwinds partway through the test.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The sibling busbarAI checkout's root — same convention this repo's Cargo.toml path deps and
/// store-postgres's own `e2e.rs` already use.
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

/// Build (once, cached by cargo) the real `busbar` and `busbar-plugin-pack` binaries from the
/// sibling busbarAI checkout — never a fixture, never a stub.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbarai_root();
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(
        status.success(),
        "building the real busbar + busbar-plugin-pack binaries must succeed"
    );
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// A free-at-the-moment localhost port (bind-then-drop; a TOCTOU race is possible in principle
/// but is the standard, accepted pattern for test port allocation and hasn't been a problem for
/// the sibling repos' own equivalents).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn poll_admin_up(admin: &str, token: &str, client: &reqwest::blocking::Client) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(resp) = client
            .get(format!("{admin}/plugins?type=store"))
            .bearer_auth(token)
            .send()
        {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Point at a DIFFERENT logical Valkey database (index 15, the conventional "spare" db a lot of
/// Valkey tooling reserves for tests) than [`valkey_url`]'s own `/0`, which every OTHER test in this
/// file/crate shares. A real `busbar` boot (unlike a plain `Store` call) HYDRATES every existing
/// virtual key at startup and validates its `group` against the config's own `groups:` block —
/// this test's config intentionally defines none, so ANY leftover key from another test sharing
/// db 0 (e.g. the dlopen persistence test above, which mints a key with `group: "infra"`) makes
/// boot fail outright with an unrelated "group does not exist" error. Same server, same
/// `VALKEY_URL` host/port, just an isolated `SELECT`ed database — proven the strongest fix short of
/// a second Valkey container (confirmed necessary: this test failed with exactly that pollution
/// before being pointed at its own db).
fn admin_test_valkey_url(base: &str) -> String {
    let without_path = match base.rfind('/') {
        Some(i) if base[..i].contains("://") => &base[..i],
        _ => base,
    };
    format!("{without_path}/15")
}

#[test]
fn admin_api_installs_the_valkey_plugin_and_writes_land_in_real_valkey() {
    let Some(base_url) = valkey_url() else { return };
    let url = admin_test_valkey_url(&base_url);
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: valkey plugin cdylib not built");
        return;
    };

    // Isolate from any prior run against a persistent (non-CI) Valkey instance.
    let direct = ValkeyStore::connect(&url).expect("connect directly to seed/clean up");

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-valkey-admin-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    // Pack the real cdylib into a real signed-shape tarball, exactly as CI's own SIGNOFF step
    // does — unsigned locally, same fallback CI's release jobs use without BUSBAR_SIGN_KEY.
    let tarball = work.join("store-valkey.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-valkey-plugin",
            "--alias",
            "valkey",
            "--kind",
            "store",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "e2e admin-api install proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    let admin_token = format!("e2e-admin-{}-{}", std::process::id(), free_port());
    let port = free_port();
    // The admin plane ALWAYS runs on its own listener, separate from `listen` (defaults to
    // loopback 127.0.0.1:8081 — see `crates/busbar/src/main.rs`'s `admin_listen`/
    // `build_split_routers_with_limits` doc comments: "production always serves admin on its OWN
    // listener ... admin and data never share a listener at runtime"). Must be configured
    // explicitly to an independently-allocated free port, both to avoid colliding with anything
    // else already bound to 8081 and so concurrent test runs never collide with each other.
    let admin_port = free_port();
    let admin = format!("http://127.0.0.1:{admin_port}/api/v1/admin");

    let providers = work.join("providers.yaml");
    let config = work.join("config.yaml");
    let overlay = work.join("overlay.json");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    // No `store:` block at first boot — proves the plugin isn't already active some other way;
    // the whole point of this test is the RUNTIME install path. `admin_auth` grants Full scope
    // via a static bearer token (mirrors CI's INSTALL-AND-SERVE step exactly).
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:{port}\"\n\
             admin_listen: \"127.0.0.1:{admin_port}\"\n\
             auth:\n  chain: [keys]\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth:\n    - admin-tokens: {{ token: {{ env: E2E_ADMIN_TOKEN }} }}\n\
             plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            plugins_dir.display()
        ),
    )
    .unwrap();

    let client = reqwest::blocking::Client::new();

    // Both boots' stdout+stderr are captured to real files (never left as an unread pipe, which
    // risks the child stalling if it ever writes enough to fill the OS pipe buffer) so a failure
    // can quote the actual boot log rather than a bare timeout.
    let spawn = |label: &str| {
        let log = std::fs::File::create(work.join(format!("busbar-{label}.log")))
            .expect("create boot log file");
        let mut cmd = Command::new(&busbar_bin);
        cmd.env("BUSBAR_CONFIG", &config)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("E2E_ADMIN_TOKEN", &admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("BUSBAR_STATE_FILE", "")
            .env("BUSBAR_CONFIG_OVERLAY", &overlay)
            .stdout(Stdio::from(log.try_clone().expect("clone log fd")))
            .stderr(Stdio::from(log));
        cmd.spawn().expect("spawn a real busbar boot")
    };
    let boot_log = |label: &str| {
        std::fs::read_to_string(work.join(format!("busbar-{label}.log"))).unwrap_or_default()
    };

    // Boot #1: no valkey plugin loaded yet.
    let mut guard = ChildGuard(spawn("1"));
    assert!(
        poll_admin_up(&admin, &admin_token, &client),
        "busbar (boot #1) must come up with the admin listener responsive; log:\n{}",
        boot_log("1")
    );

    // THE REAL INSTALL: POST the signed tarball's base64 bytes to /api/v1/admin/plugins.
    let tarball_bytes = std::fs::read(&tarball).unwrap();
    use base64::Engine as _;
    let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(&tarball_bytes);
    let install_resp = client
        .post(format!("{admin}/plugins"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "file": "busbar-store-valkey-plugin-0.0.0-e2e.tar.gz",
            "tarball_b64": tarball_b64,
        }))
        .send()
        .expect("POST /api/v1/admin/plugins");
    let install_status = install_resp.status();
    let install_body: serde_json::Value = install_resp.json().unwrap_or(serde_json::Value::Null);
    assert_eq!(
        install_status.as_u16(),
        201,
        "expected 201 from POST /api/v1/admin/plugins, got {install_status}: {install_body}"
    );
    assert_eq!(
        install_body.get("name").and_then(|v| v.as_str()),
        Some("busbar-store-valkey-plugin"),
        "install response must name the installed plugin: {install_body}"
    );

    // Activate it as the store module, persisted, then restart to apply (store-module changes
    // are documented restart-to-apply, never a hot swap — confirmed by reading
    // crates/busbar/src/admin/mod.rs / docs/admin-api.md).
    let settings_resp = client
        .put(format!("{admin}/config/settings"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "store": { "module": "busbar-store-valkey-plugin", "settings": { "url": url } },
            "persist": true,
        }))
        .send()
        .expect("PUT /api/v1/admin/config/settings");
    assert!(
        settings_resp.status().is_success(),
        "PUT /api/v1/admin/config/settings must succeed: {}",
        settings_resp.status()
    );

    let _ = client
        .post(format!("{admin}/restart"))
        .bearer_auth(&admin_token)
        .send();

    // busbar's restart deliberately does not self-respawn — drains and exits, expecting a
    // supervisor to relaunch it. Play that role: wait for the real exit, then boot #2.
    let exit_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_)) = guard.0.try_wait() {
            break;
        }
        if Instant::now() >= exit_deadline {
            let _ = guard.0.kill();
            let _ = guard.0.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Boot #2: same config, now with the persisted overlay naming the valkey plugin as the store
    // module — the real dlopen + Store::connect/migrate path executes here, before the listener
    // ever answers a request.
    let guard2 = ChildGuard(spawn("2"));
    assert!(
        poll_admin_up(&admin, &admin_token, &client),
        "busbar (boot #2, with the valkey plugin persisted as store.module) must come back up; \
         log:\n{}",
        boot_log("2")
    );
    assert!(
        !boot_log("2").contains("does not match any plugin"),
        "the valkey plugin persisted as store.module must resolve to the installed plugin, not \
         be rejected as unmatched: {}",
        boot_log("2")
    );

    let list_resp = client
        .get(format!("{admin}/plugins?type=store"))
        .bearer_auth(&admin_token)
        .send()
        .expect("GET /api/v1/admin/plugins?type=store");
    let list_body = list_resp.text().unwrap_or_default();
    assert!(
        list_body.contains("busbar-store-valkey-plugin"),
        "the restarted instance must list the installed valkey plugin: {list_body}"
    );

    // REAL WORK: mint a virtual key AND a credential in one admin call (the only admin-HTTP path
    // that writes a CredentialSecret row — there is no separate /keys/{id}/credentials endpoint).
    let mint_resp = client
        .post(format!("{admin}/keys"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "e2e-admin-install-verify",
            "issue_aws_credential": true,
        }))
        .send()
        .expect("POST /api/v1/admin/keys");
    let mint_status = mint_resp.status();
    let mint_body: serde_json::Value = mint_resp.json().expect("mint response must be JSON");
    assert_eq!(
        mint_status.as_u16(),
        201,
        "expected 201 from POST /api/v1/admin/keys, got {mint_status}: {mint_body}"
    );
    let key_id = mint_body
        .get("id")
        .and_then(|v| v.as_str())
        .expect("mint response must carry an id")
        .to_string();
    assert!(
        key_id.starts_with("vk_"),
        "unexpected key id shape: {key_id}"
    );
    let access_key_id = mint_body
        .get("aws_access_key_id")
        .and_then(|v| v.as_str())
        .expect("issue_aws_credential:true must return aws_access_key_id")
        .to_string();

    // Confirm the API's own view sees it (same process, same request path).
    let get_resp = client
        .get(format!("{admin}/keys/{key_id}"))
        .bearer_auth(&admin_token)
        .send()
        .expect("GET /api/v1/admin/keys/{id}");
    assert!(
        get_resp.status().is_success(),
        "GET /api/v1/admin/keys/{{id}} must find the just-minted key: {}",
        get_resp.status()
    );

    // Now stop the real busbar process before independent verification, so there is no
    // possibility of racing its own connection/cache.
    drop(guard2);
    drop(guard);

    // INDEPENDENT VERIFICATION #1: the typed Store trait, via the plain busbar-store-valkey crate
    // — a code path that never touches the plugin cdylib, the C ABI, the loader, or the admin
    // HTTP surface at all.
    let vk = Store::get_key(&direct, &key_id)
        .expect("get_key via the direct connection")
        .expect("the virtual key minted through the real admin API must be physically in Valkey");
    assert_eq!(vk.id, key_id);
    assert_eq!(vk.name, "e2e-admin-install-verify");
    let creds = Store::list_credentials(&direct, &key_id)
        .expect("list_credentials via the direct connection");
    let cred = creds
        .iter()
        .find(|c| c.public_id == access_key_id)
        .expect("the sigv4 credential minted alongside the key must be physically in Valkey");
    assert_eq!(cred.kind, "sigv4");
    assert_eq!(cred.key_id, key_id);

    // INDEPENDENT VERIFICATION #2: a RAW redis::Client GET of the exact row bytes — proof
    // independent even of busbar-store-valkey's own encode/decode path.
    let mut raw = redis::Client::open(url.as_str())
        .and_then(|c| c.get_connection())
        .expect("raw valkey connection for the strongest independent check");
    let raw_key_row: Option<String> =
        redis::Commands::get(&mut raw, format!("busbar:key:{key_id}")).unwrap();
    let raw_key_row = raw_key_row.expect("busbar:key:<id> must be physically present in Valkey");
    assert!(
        raw_key_row.contains(&key_id) && raw_key_row.contains("e2e-admin-install-verify"),
        "raw Valkey row must contain the minted key's own id and name: {raw_key_row}"
    );

    let _ = Store::delete_key(&direct, &key_id);
    let _ = std::fs::remove_dir_all(&work);
}
