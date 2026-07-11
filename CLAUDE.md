# CLAUDE.md — working rules for AI-assisted development on argus

Guidance for Claude (and any other agent/contributor) working in this repository.
Read this before touching code. See `ROADMAP.md` for direction and `CHANGELOG.md` for history.

## What argus is

Real-time NetFlow/IPFIX enrichment, detection, and BGP mitigation engine for a small AS,
written in Go. It was built to replace a pmacctd+Grafana / ELK+Elastiflow / ClickHouse
stack with **one self-contained binary**.

**The prime directive: no external runtime dependencies.** No MariaDB, no ClickHouse,
no Redis, no Grafana, no Node build step. Storage is SQLite (embedded), the UI is
static HTML embedded in the binary, BGP is embedded GoBGP. Any change that adds an
external service a user must install/operate breaks the reason this project exists.
If more storage capability is ever needed, prefer embedded options (better SQLite
usage, tiered rollups, size-capped archives) over external daemons — see
`ROADMAP.md` § Storage decision.

## Build, run, test

```bash
make build          # → bin/argus (version ldflags)
make run            # build + run with etc/config.yaml
go vet ./...        # keep clean
go test ./...       # keep green (coverage is thin — add tests as you touch code)
go build ./...      # quick compile check
```

- Go ≥ 1.25, single module `argus`. No CI yet (planned — see ROADMAP Phase 0).
- Never commit build artifacts. `bin/`, the root `argus` binary, `*.log`, `*.db`,
  `*.sqlite*`, `blackholes.txt` are gitignored — keep it that way.
- Runtime deployment target is `/opt/argus` with systemd (`etc/systemd/system/argus.service`).

## Architecture map

```
cmd/argus/            entrypoint + auth CLI
internal/collectors/  NetFlow v9 / IPFIX UDP listener (port 2055)
internal/flow/        FlowRecord type + batcher → fans out to consumers
internal/enrich/      GeoIP (MaxMind), rDNS/PTR, SNMP iface names, ASN intel
internal/bgp/         embedded GoBGP speaker: receives full RIB, announces blackholes
internal/bgpstate/    RIB state + AS-path lookups        internal/rib/  RIB watcher
internal/telemetry/   in-memory 1440-min ring buffers + snapshots → SQLite
internal/flowstore/   per-ASN aggregates → SQLite (5-min timeline, 30-min detail tables)
internal/detection/   rules engine + anomaly ML (iForest/HBOS/eHBOS) + EWMA memory layer
internal/alerter/     alert contacts/events + smtp/slack/log backends
internal/api/         HTTP API (:9600) + embedded dashboard (internal/api/static/*.html)
internal/sqlite/      detection-side schema           internal/config/  YAML config
internal/pathfinder/, internal/routeros/, internal/bgpmon/  path/route quality tooling
```

Flow of data: collector → enrichment → (telemetry aggregator | flowstore | detection
engine) → SQLite + dashboard + BGP blackhole actions.

## Conventions and rules

1. **Don't lose information silently.** The aggregation pipeline already discards a
   lot (top-N caps, 7-day retention). When you add a limit, cap, or prune, make it a
   config knob with the current value as default, and document it in README + CHANGELOG.
2. **Config over constants.** New thresholds, paths, intervals, and retention windows
   go in `internal/config` + `etc/config.yaml.example`, not hardcoded.
3. **Update `CHANGELOG.md`** (Unreleased section) in every PR that changes behavior.
4. **Hot paths must not block.** `flow.Batcher` fan-out, `flowstore.Accumulate`, and
   `detection.Engine.AddFlow` are on the ingest path. No network I/O, no DNS, no
   synchronous SQLite writes while holding their locks. `detection.runDetection`
   now holds `e.mu` only to prune + snapshot the flow cache, then evaluates rules
   and runs actions (BGP/DNS/SQLite/CFM) lock-free — keep it that way.
5. **SQLite discipline.** WAL mode, batched transactions on tickers (existing pattern
   in `flowstore/persist.go`), `busy_timeout`, and prune every table you create —
   unbounded tables are bugs (`snapshots`, `alert_events`, `detections` currently lack pruning).
6. **UI pages are self-contained HTML** in `internal/api/static/`, embedded via
   `embed.go`. No frameworks, no build step. Shared bits go in small plain JS/CSS files
   (like `nav-search.js`). Match the existing dark dashboard style.
7. **Direction classification is sacred.** The 3-tier logic (upstream iface index →
   my_prefixes match → FlowDirection field) exists in `telemetry/aggregator.go` and is
   mirrored in `flowstore/store.go`. If you touch one, fix both — or better, unify them
   (ROADMAP Phase 0).
8. **Safety around blackholing.** Anything that announces BGP routes must respect the
   protection list (`etc/exclude.detections.conf`), TTL escalation, and write to
   `blackhole_events`. Never widen a blackhole beyond /32 (v4) / /128 (v6) without an
   explicit, reviewed feature.
9. **Secrets.** Never commit real tokens, SNMP communities, or passwords — examples use
   obvious placeholders. Alerter currently stores SMTP/Slack creds plaintext in SQLite;
   don't extend that pattern to new backends (encrypt like the auth TOTP secrets).
10. **Greek in comments is fine**, English preferred for new code and all docs.

## Known gotchas (verified, as of 2026-07)

- flowstore "hourly" tables actually flush every **30 minutes** (`tick1h` = 30m,
  buckets aligned to 1800s). Naming is misleading.
- Telemetry bucket retention is hardcoded to 30 days in `telemetry/persistence.go`
  despite the function taking a parameter.
- `detection/engine.go` has empty TODO stubs: `slack` action is a silent no-op.
- Test coverage is thin: `internal/api` and now `internal/detection` (engine lock +
  rule matching) have tests; flowstore/telemetry cores are still untested — be extra
  careful there and add tests when you touch them.
- Package-level singletons everywhere (`flowstore.Global`, `telemetry.Global`,
  `enrich.Global`, `config.AppConfig`, API package globals). Prefer passing deps;
  don't add new globals.
