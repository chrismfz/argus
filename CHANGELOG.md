# Changelog

All notable changes to argus are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
does not yet cut versioned releases, so entries are grouped by month until it does.
Every behavior-changing PR must add an entry under **Unreleased**.

## [Unreleased]

### Changed
- ROADMAP reorganized: Phase 4 split into "Detection & mitigation depth"
  (attack incidents, egress detection presets, threat feeds, ML feedback loop,
  time-of-day baselines), Phase 5 "Visibility & business value" (peering
  candidates report, 95th-percentile reports, RPKI/hijack watch), and Phase 6
  "Ops & platform" (multi-exporter, sFlow, backup/restore, action audit trail).
  BGP FlowSpec parked last, pending RouterOS support.

## 2026-07

### Added
- `CLAUDE.md` (working rules for AI-assisted development), `ROADMAP.md`
  (plan, storage decision ADR-001: stay on SQLite, tiered-rollup strategy),
  and `CHANGELOG.md`. (#18)

### Fixed
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
