# Changelog

All notable changes to argus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
does not yet cut versioned releases, so entries are grouped by month until it does.
Every behavior-changing PR must add an entry under **Unreleased**.

## [Unreleased]

### Added
- **Phase 2 (Tier 2) — daily rollups** (`internal/flowstore/rollup.go`). Each
  complete day's 30-min detail is aggregated into `flowstore_daily_*` tables (top
  IPs/prefixes/ports/countries/proto per ASN, plus a per-IP daily total that
  survives even for IPs that never topped an ASN bucket) BEFORE the detail is
  pruned, and kept `daily_retention_days` (default 730 = 2 years, config knob).
  So per-ASN history degrades gracefully instead of vanishing at the 7-day detail
  cliff. Rollup runs at the 24h prune tick and on startup (downtime catch-up), is
  idempotent per complete day, and only rolls fully-ended days. Read via
  `GET /debug/rollup?ip=<ip>` (per-IP daily history) or `?asn=<n>&days=<n>` (ASN
  daily top-IPs). Tests cover aggregation, top-N cut, per-IP totals, idempotency,
  incomplete-day skipping, and retention pruning. UI wiring is Phase 3.

### Fixed
- **flowlog hardening** (from an independent review of the Tier-0 flow log):
  - Prune now measures **live data** (`page_count − freelist_count`), not total
    file size. The old math counted free pages left by earlier deletes as data,
    inflated bytes-per-row, and could delete ~99% of rows after a burst even when
    the live data already fit the cap. (regression test)
  - Shutdown: `Close()` now stops the writer and **waits for it to drain + flush**
    before closing the DB — no lost final batch, no "database is closed" on exit.
    The writer stops on `Close` (not the app context), so flows the batcher flushes
    during its own shutdown are still captured. (regression test)
  - Prune deletes in bounded chunks so one statement can't hold the write lock
    past `busy_timeout` and make the concurrent writer's insert fail.
  - Prune cadence 5m → 1m to bound overshoot between checks; `Stats()` errors are
    surfaced by `/debug/flowlog` instead of reporting an empty log; docs corrected
    so `max_gb: 0` = default (20) and **negative** = unbounded (per the Phase 1
    convention). Documented the remaining soft-cap limits in ROADMAP.

### Added
- **Phase 2 (Tier 0) — optional raw flow log** (`internal/flowlog`, off by default).
  When `flowlog.enabled: true`, every enriched flow (5-tuple + bytes/packets/ifaces/
  ASNs/direction) is appended to a dedicated `flows.sqlite` and pruned **by size**
  (`max_gb`, default 20) rather than age — the forensic store that answers "what did
  IP X do at 03:00?". Write path never blocks ingest (bounded channel + batched
  writer + drop-if-full, counted); its own WAL file so it never contends on the
  detection DB. Config section `flowlog:` (`enabled`, `db_path`, `max_gb`,
  `sample_rate`, `buffer_size`, `batch_size`) with the usual default semantics.
  Read it via `GET /debug/flowlog` (stats) / `?ip=…&since=…&proto=…&port=…&dir=…`
  (filtered flows, JSON, IP-only). Tests cover round-trip/query filters, sampling,
  the drop path, and size-bounding/stabilisation. A Flow Explorer UI comes in Phase 3.
- **Phase 1 — configurable retention & caps.** New config sections `flowstore:`,
  `telemetry:`, and `retention:` expose every aggregation cap and retention window
  that was previously hardcoded (flowstore top-N/track caps + detail retention,
  telemetry bucket retention — which was falsely advertised as configurable — and
  all cleanup-ticker retentions: detections, alert_events, snapshots, risk_events,
  blackhole_events). Unset values keep the exact historical defaults; negative
  values mean unlimited (caps) / keep forever (retentions). Documented in README
  and `etc/config.yaml.example`; first tests for `internal/config`.
- Flowstore's 5-min timeline tables now have their **own retention window**
  (`timeline_retention_days`, default 30d) independent of the 30-min detail tables
  (`retention_days`, default 7d) — the timeline is cheap and worth keeping longer.
- Startup log lines with the effective storage settings and the current SQLite
  footprint, so operators can size retention against disk.

### Fixed
- `detection.PurgeOldRiskEvents` with a non-positive max age now disables pruning
  instead of computing a future cutoff that would delete every row.

### Changed
- Flowstore's misleadingly-named "hourly" internals renamed to "detail"
  (`flushDetail`, `detailKey`, …) — the cadence has been 30 minutes for a long
  time. Table names on disk are unchanged; no migration needed.

## 2026-07

### Added
- `CLAUDE.md` (working rules for AI-assisted development), `ROADMAP.md`
  (plan, storage decision ADR-001: stay on SQLite, tiered-rollup strategy),
  and `CHANGELOG.md`. (#18)
- CI (`.github/workflows/ci.yml`): gofmt, `go vet`, `go build`, `go test`
  on push to `main` and all PRs. New `make` targets: `fmt`, `vet`, `test`,
  `check`, `lint`. (#20)
- First tests for `internal/detection`: `runDetection` rule matching + a regression
  test proving the ingest path (`AddFlow`) is not blocked while a detection action
  runs. (#21)
- `internal/flowdir`: shared flow direction classifier (3-tier: upstream interface →
  my-prefix match → NetFlow DIRECTION) with full test coverage. (#22)

### Changed
- Unbounded tables are now pruned on the 1-minute cleanup ticker: `detections`
  (by `last_seen`, 90d), `alert_events` (90d, cascades to `alert_deliveries`), and
  `snapshots` (period-aware — daily pruned at 400d; weekly/monthly/yearly/manual
  kept forever). New tests cover flowstore prune, snapshot period-aware prune, and
  blackhole TTL escalation. (#23)
- `detection` `slack` rule action no longer silently no-ops — it logs a one-time
  "not implemented" warning. Real Slack wiring stays in Phase 4 (Alerting v2). (#23)
- Direction classification unified: `telemetry.classifyDirection` and
  `flowstore.classifyInbound` — previously duplicated and hand-synced — now both
  delegate to `internal/flowdir`. The duplicated `isMyIP` prefix helper is unified
  there too. No behaviour change (the `inbound` result was already identical). (#22)
- Ran `gofmt -w` across the tree (62 files) and flipped the CI gofmt check from
  advisory to a hard `make fmt` gate — formatting is now enforced on every PR.
  No functional change. (#24)
- ROADMAP reorganized: Phase 4 "Detection & mitigation depth", Phase 5 "Visibility
  & business value", Phase 6 "Ops & platform"; BGP FlowSpec parked last, pending
  RouterOS support. (#19)

### Fixed
- **Detection engine no longer stalls flow ingest while acting.** `runDetection`
  held `e.mu` across the entire rule loop — including `HandleBlackhole` (BGP announce
  + PTR DNS + SQLite + CFM) — so a slow blackhole blocked `AddFlow` on the ingest hot
  path, precisely under attack. The lock is now held only to prune + snapshot the
  flow cache; rule evaluation and all actions run lock-free. (#21)
- `go vet` failure: `collectors.Netflow.Start` had a value receiver copying the
  struct's embedded `sync.Once`; changed to a pointer receiver. (#20)
- Renamed `internal/telemetry/peristence.go` → `persistence.go`. (#20)
- Removed the accidentally committed 39 MB `argus` build artifact from git tracking;
  expanded `.gitignore` to cover binaries, logs, and SQLite databases. (#18)

## 2026-06

### Added
- MFA: goauth encryption key wired through config (`auth.mfa_encryption_key`).

### Fixed
- `/blackhole-list` no longer times out under SQLite contention.

## 2026-05

### Added
- `blackhole_events` history table — full announce/withdraw/expire audit trail.
- Blackhole history API endpoints and a History tab on the detection page.

## 2026-04

Initial public development burst — most of the current system landed this month.

### Added
- BGP speaker (embedded GoBGP): full RIB ingestion over eBGP, blackhole
  announcements with communities, TTL escalation, restore-on-restart.
- Routewatch module (RouterOS REST API integration, path quality watching).
- Authentication: session auth with SQLite store, rate limiting, logout, optional
  separate session DB, auth CLI.
- flowstore: per-ASN aggregates persisted to SQLite — 5-min timeline plus 30-min
  detail tables (top IPs, prefixes, ports, protocols, countries, TCP flags),
  7-day retention, permanent per-ASN lifetime totals.
- Dedicated IP profile page (`ip.html`) with blackhole/detection history, linked
  from all telemetry UIs; `ip_profile` enrichment cache table.
- ASN profile endpoint + page with flowstore/BGP fallback and external ASN
  intelligence enrichment layer (SWR cache, provider circuit breakers).
- Reusable ASN/IP nav search across static pages (`nav-search.js`).
- Risk API; detection & dashboard page refactors.

### Fixed
- infoip AS-path hop enrichment (with regression tests).
- IPv6 blackhole history prefix matching.
- ASN profile degrades gracefully when the flow DB is unavailable.
