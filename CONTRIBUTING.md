# Contributing to store-redis

Thanks for your interest in improving `store-redis`. This document covers how
to build, test, and submit changes.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Development setup

`store-redis` is a Rust `cdylib` plugin. You need a recent stable toolchain
(`rustup` recommended), and — until [busbarAI](https://github.com/GetBusbar/busbarAI)
ships publicly — a sibling checkout of it at `../busbarAI`, since this crate's
`Cargo.toml` points at busbar's crates as local path dependencies. See the
README's [Dependencies](README.md#dependencies) section for the exact layout;
CI checks out `GetBusbar/busbar` at the branch named in the reusable
`plugin-ci.yml` workflow reference in [`ci.yml`](.github/workflows/ci.yml).

The meaningful test coverage here needs a **live Redis** — see the README's
[Tests](README.md#tests) section. Locally, `cargo test` skips that coverage
cleanly if `REDIS_URL` is unset; set it to point at a real Redis to exercise it:

```bash
export REDIS_URL=redis://localhost:6379/0
cargo build --release                       # cdylib
cargo test                                   # unit tests + the e2e dlopen/live-Redis test
cargo clippy --all-targets -- -D warnings    # lints must be clean
cargo fmt --all -- --check                   # format before committing
```

## Before you open a pull request

1. **`cargo fmt --all`** — code must be rustfmt-clean.
2. **`cargo clippy --all-targets -- -D warnings`** — no warnings.
3. **`cargo build && cargo test`** — green, including the live-Redis end-to-end
   test in `tests/e2e.rs` (it hard-fails under `CI=1` rather than silently
   skipping — never let that coverage quietly vanish).
4. Add or update tests for any behavior change.
5. Update documentation (`README.md`, doc comments) when you change behavior or config.

## Architecture

This repo is deliberately a thin adapter (`src/lib.rs`): it turns the engine's
JSON `open` config into a `RedisStore` and hands the trait object to
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbarAI/tree/main/crates/plugin-sdk),
which emits the C ABI symbols the loader resolves. All the Redis schema,
serialization, and retry/TLS logic lives in the `busbar-store-redis` library
crate this plugin wraps, in the `busbarAI` monorepo — most substantive changes
belong there, not here.

## Commit & PR conventions

- Keep commits focused; squash noisy WIP commits before opening the PR.
- Write a clear PR description: what changed, why, and how it was verified.
- Reference any related issue.
- Stage files by name; avoid sweeping `git add -A` that pulls in unrelated changes.

## Questions

Open a discussion or issue. We're happy to help you get oriented.
