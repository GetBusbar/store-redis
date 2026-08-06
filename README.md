# store-valkey

**This plugin's version: v1.0.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/store-valkey/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/store-valkey/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GetBusbar/store-valkey)](https://github.com/GetBusbar/store-valkey/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: store` plugin for
[busbar](https://getbusbar.com): the Valkey backend for busbar's durable
governance store, packaged as a droppable `cdylib`. Build it, drop the
resulting `.so`/`.dylib`/`.dll` into the engine's plugins folder, and set
`store: { module: valkey, settings: { url: "redis://..." } }`; the engine
loads it in-process at boot. One
Valkey behind a fleet of busbar nodes means shared virtual keys, budgets,
usage, and audit across the cluster — the multi-node story a single-file
SQLite store cannot offer.

## Renamed: `redis` → `valkey` (BREAKING)

This plugin, its repository, its crates, and its published artifact are now
named for **Valkey** — the Linux-Foundation-governed, BSD-licensed store this
plugin has always actually targeted. Two of those renames are user-visible
breaking changes, and neither is silently compatible:

- **The config alias changed**: `store: { module: redis }` is now
  `store: { module: valkey }`. Busbar core ships a config migrator entry that
  retires the old spelling — but pinned/vendored configs should be updated.
- **The published artifact / signed manifest name changed**:
  `busbar-store-redis-plugin` is now `busbar-store-valkey-plugin`, and the
  release asset is `busbar-store-valkey-<ver>-<target>.tar.gz`. That manifest
  name is the plugin's **trust identity** and the key its anti-downgrade
  version floor is recorded under, so the renamed plugin is a *new* identity to
  the loader: it must be installed fresh, and the old floor does not carry
  over. Uninstall `busbar-store-redis-plugin` before installing this.

Internally, the lib/plugin crates are `busbar-store-valkey` /
`busbar-store-valkey-plugin`, the store type is `ValkeyStore`, and the test
env var is `VALKEY_URL`. The only pre-fork spellings left in this tree are
things upstream owns and we cannot rename: the RESP driver crate on crates.io
(still published under its pre-fork name) and the `redis://` / `rediss://` URL
schemes that driver parses. Nothing busbar-owned says "redis" any more.

## Versioning

This plugin is versioned **independently of busbar** — `v1.0.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.5.0+** (the release that ships the
signed hybrid plugin ABI this crate loads over). Pin both versions
explicitly in production; do not assume they move together.

It is a `cdylib` that implements busbar's `Store` trait (via
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbar/tree/main/crates/plugin-sdk))
and is loaded in-process by busbar over the signed store ABI —
`dlopen`'d, not spawned as a separate process.

## What it is for

- **Multi-node deployments**: a fleet of busbar nodes sharing one Valkey
  instance share virtual keys, per-key/per-group budgets, token usage
  ledgers, and metering/audit rows — the store is the durability layer
  behind the engine's in-memory enforcement counters (boot-hydrate +
  periodic write-behind flush), not a request-hot-path dependency.
- **Fleet-honest accrual**: `add_usage` uses Valkey `HINCRBY` for a real
  atomic accumulate, so N nodes each flushing their own delta-since-last
  sum to the true fleet total (an absolute `put_usage` overwrite would be
  last-writer-wins across nodes).

This crate (`busbar-store-valkey-plugin`) is intentionally a thin
adapter: all the Valkey schema/serialization/retry/TLS logic lives in the
`busbar-store-valkey` library crate it wraps, in the `store-valkey/` directory of
this repository; here we only translate the engine's JSON `open` config into a
live `ValkeyStore`.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbarAI](https://github.com/GetBusbar/busbar) ships publicly —
a sibling checkout of `busbarAI` at `../busbarAI` (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_store_valkey_plugin.{so,dylib}
cargo test                 # unit tests + the real-ABI/real-Valkey end-to-end test (see tests/e2e.rs)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

`busbar-store-valkey`, the KV-modeling logic crate this plugin thinly adapts,
lives in this repository. `busbar-api` and `busbar-plugin-sdk`, and the
`busbar-plugin-loader` dev-dependency the end-to-end test uses, come from the
[busbarAI](https://github.com/GetBusbar/busbar) monorepo.
Because busbarAI is not yet public, `Cargo.toml` points at these as
**local path dependencies** (`../busbarAI/crates/...`), which means this
repo expects to be checked out as a sibling of `busbarAI`:

```
some-parent-dir/
├── busbarAI/
└── store-valkey/
```

This is an interim measure — once busbarAI ships publicly, these should
become git (pinned rev/tag) or crates.io dependencies instead. Grep
`Cargo.toml` for the `INTERIM` comments when doing that migration.

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbarAI for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_store_valkey_plugin.so \
    --name busbar-store-valkey-plugin --alias valkey --kind store \
    --version 1.0.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-store-valkey-plugin-1.0.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
set:

```yaml
store:
  module: valkey
  settings: { url: "redis://:password@host:6379/0" }
```

— see [`docs/configuration.md`](https://github.com/GetBusbar/busbar/blob/main/docs/configuration.md)
for the full store config reference.

## Config

The engine passes `store.settings` through as this plugin's `open`
config, mirroring how the Postgres store plugin receives its libpq URL:

```json
{ "url": "redis://:password@host:6379/0", "connect_timeout_ms": 10000 }
```

| Setting | Required | Notes |
|---|---|---|
| `url` | yes | A `redis://` or `rediss://` (TLS) connection string — the URL scheme is the upstream RESP driver's, not a busbar name; a Valkey server is what it points at. TLS is backed by `rustls` (`ring` provider) — no OpenSSL dependency. |
| `connect_timeout_ms` | no | Bounds the initial connect (unlike libpq's DSN-level `connect_timeout`, the upstream driver crate has no URL-level escape hatch, so this crate adds one). Defaults to 10s. A blackholed/firewalled Valkey host fails fast at boot instead of wedging the engine indefinitely. |

## Tests

`cargo test` runs the pure unit tests (config parsing) and the real-ABI
end-to-end test in [`tests/e2e.rs`](tests/e2e.rs), which `dlopen`s the
*built* cdylib over the real `busbar-plugin-loader` ABI seam — the same
seam busbar's engine uses — against a **real, live Valkey** (not a mock
or an in-process fake).

Unlike a file-backed store, Valkey has no "reopen the same file"
persistence check available — so this crate's coverage proves
persistence the way that's actually meaningful for a shared backend:
write a key/usage through the `dlopen`'d plugin over the C ABI, drop the
plugin (closing its connection), then read the SAME Valkey instance back
through a **totally independent connection** — the plain
`busbar-store-valkey` library crate, used directly, never touching the
cdylib, the C ABI, or the loader at all. That is the proof that
`store: valkey` operations over the ABI actually land in Valkey, not just
in an in-process cache.

The live-Valkey coverage is gated on the `VALKEY_URL` environment
variable: it skips cleanly when unset locally (no server needed for a
default `cargo test`), but under CI (`CI` set) a missing `VALKEY_URL` is
a **hard failure**, never a silent skip — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), which runs a
real `valkey/valkey:8` GitHub Actions service container on every push and PR.
CI also separately runs `busbar-store-valkey`'s own live-Valkey
integration tests (from the sibling `busbarAI` checkout) against that
same service container — the coverage that crate's tests were written
for but had never actually been wired into a CI job before this repo's
workflow.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
