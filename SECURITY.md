# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/store-redis/security/advisories/new)
  (the **Security** tab on this repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/store-redis/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

`store-redis` is a `kind: store` busbar plugin: it persists busbar's governance
data — virtual keys, budgets, usage, and audit rows — in a shared Redis instance
behind a fleet of busbar nodes. Issues of particular interest include:

- Connection-string (`url`/`rediss://`) handling that could leak credentials
  into logs or error strings.
- TLS validation gaps in the `rustls`-backed `rediss://` path.
- Cross-node accrual races: `add_usage` relies on Redis `HINCRBY` for atomic
  accumulation — anything that lets concurrent nodes lose or double-count a
  delta is in scope.
- A load-time config error surfacing as a silent success instead of a clean
  `Err` across the plugin ABI.

See busbar's own [threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md)
for the trust boundaries this plugin operates inside.

## Supported versions

This plugin is versioned independently of busbar (see the README's
[Versioning](README.md#versioning) section). Security fixes are applied to the
latest `main` and the most recent tagged release of **this repository**. Pin to a
tag for production use.
