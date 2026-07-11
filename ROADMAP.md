# argus — plan & roadmap

Living document. Priorities can shift; the storage decision below should not be
reopened without new evidence.

## Where we are (honest assessment, 2026-07)

argus succeeded at its founding goal: it replaced pmacctd+Grafana / ELK+Elastiflow
with one Go binary, and the detection engine (rules + iForest/HBOS anomaly + EWMA
memory + BGP blackholing) genuinely works in production.

The cost of that success: **the aggregation pipeline throws away too much, too early.**
Concretely (verified in code):

- Nothing stores raw flows. Every consumer pre-aggregates; no 5-tuple flow log exists.
- Per 30-min bucket, only **top-50 IP pairs**, **top-20 prefixes**, **top-10 ports**
  per (ASN, direction) survive to SQLite. Everything below the cut is silently dropped
  at write time. The caps are compile-time constants.
- After **7 days**, all per-ASN detail (IPs, prefixes, ports, countries, TCP flags,
  5-min timeline) is pruned. Only lifetime totals per ASN survive (`flowstore_asn_meta`).
- Telemetry minute-buckets keep 30 days — a hardcoded value falsely advertised as
  configurable.
- So questions like *"what did IP X do last Tuesday at 03:00?"* or *"show me all
  traffic to port 3389 last month"* are unanswerable today. That is the lost
  information we want back.

Meanwhile some tables never prune at all (`snapshots`, `alert_events`, `detections`) —
we lose what we want and keep what we don't.

## Storage decision: stay on SQLite (ADR-001)

**Decision:** do **not** migrate to MariaDB (or any external DB). Fix granularity,
retention, and query capability *inside* SQLite; if a real per-flow archive is ever
needed, add an embedded columnar option (DuckDB/Parquet sidecar files) as an
**optional** feature — still zero external services.

**Why MariaDB is the wrong axis:**
1. The information is lost **before** storage — in the top-N caps and prune windows.
   Swapping the storage engine while keeping the same pipeline recovers nothing.
2. It kills the project's identity. argus exists because ClickHouse/ELK were too
   heavy; "install and operate MariaDB" reintroduces exactly that class of burden.
3. It's the wrong shape anyway: flow analytics are columnar scans/aggregations.
   A row-store OLTP database is worse than SQLite-with-rollups for this workload
   *and* worse than ClickHouse for big archives — worst of both worlds.
4. SQLite is nowhere near its limits here. With WAL, batched inserts (already the
   pattern), proper indexes, and per-concern DB files, it comfortably handles tens
   of GB and hundreds of millions of rows. Our past `/blackhole-list` contention
   issue was a locking/connection pattern, not an engine ceiling.

**What we do instead:** keep more, longer, with graceful degradation (RRD-style
tiered rollups) and a size-capped optional flow log. Details in Phase 2.

## Phase 0 — Hygiene & guardrails (small, do first)

- [x] Remove committed 39 MB `argus` ELF binary from the tree; expand `.gitignore`
      (`*.log`, `*.db`, `*.sqlite*`, `blackholes.txt`, root binary). *(this PR)*
- [x] Add CLAUDE.md, ROADMAP.md, CHANGELOG.md. *(this PR)*
- [x] `make test`, `make vet`, `make lint`, `make check` targets + GitHub Actions CI
      (build + vet + test on push/PR). *(PR: phase-0 hygiene)*
- [x] Fix the `go vet` failure: `collectors.Netflow.Start` value receiver copies an
      embedded `sync.Once` (`internal/collectors/netflow.go`). *(PR: phase-0 hygiene)*
- [x] Rename `internal/telemetry/peristence.go` → `persistence.go`. *(PR: phase-0 hygiene)*
- [ ] Tree-wide `gofmt -w ./...` in a dedicated formatting-only PR (62 files are not
      gofmt-clean today), then flip the CI gofmt check from advisory to a hard
      `make fmt` gate. Kept separate so the diff is reviewable as "formatting only".
- [x] Unify the duplicated direction classifier (`telemetry.classifyDirection` /
      `flowstore.classifyInbound`) into one shared package (`internal/flowdir`) with
      tests — the most load-bearing logic in the system. Both now delegate; the
      duplicated `isMyIP` prefix helper is unified there too. *(PR: phase-0 flowdir)*
- [x] Fix the detection engine lock hazard: `runDetection` held `e.mu` across the
      whole rule loop incl. `HandleBlackhole` (BGP announce + DNS + SQLite), stalling
      `AddFlow` on the ingest path. Now holds the lock only to prune + snapshot the
      flow cache; rule evaluation and actions run lock-free. Regression test included.
      *(PR: phase-0 detection lock)*
- [ ] Implement or remove the no-op `slack` rule action (silent no-op today).
- [ ] Prune the unbounded tables: `snapshots`, `alert_events`/`alert_deliveries`,
      `detections` (configurable retention each).
- [ ] Tests for: rule evaluation (`filters.go`) — partial: `runDetection` matching +
      lock behaviour covered — plus direction classification, flowstore flush/prune,
      blackhole TTL escalation.

## Phase 1 — Stop the bleeding: configurable retention & caps

Everything below exists today as a constant; promote to config with current values
as defaults (backward compatible, zero migration):

```yaml
flowstore:
  retention_days: 7        # per-ASN detail tables
  timeline_retention_days: 30
  top_ips: 50
  top_prefixes: 20
  top_ports: 10
telemetry:
  bucket_retention_days: 30   # currently hardcoded
```

- [ ] Wire flowstore consts + telemetry retention into config.
- [ ] Startup disk-budget log line: estimate DB growth/day at current settings so
      operators can size retention consciously.
- [ ] Rename/clarify the "hourly" tables (they flush every 30 min).

## Phase 2 — Get the information back (the big one)

Tiered rollups — degrade gracefully instead of falling off a cliff:

- [ ] **Tier 0 (optional, default off): size-capped raw flow log.** Enriched 5-tuple
      flow records appended to a dedicated SQLite DB file (or hourly-partitioned
      files), pruned **by size** (`max_gb: 20`), not by age. This single feature
      answers the forensic "what did X do at 03:00?" question. Include src/dst IP,
      ports, proto, flags, bytes, packets, ifaces, ASNs, timestamps.
- [ ] **Tier 1: 5-min detail** (current tables) — retention e.g. 14–30 days.
- [ ] **Tier 2: daily rollups** of the detail tables (top IPs/prefixes/ports/countries
      per ASN per day) — retention 1–2 years. Cheap: computed at prune time from
      Tier 1 before deletion.
- [ ] **Tier 3: forever** — `flowstore_asn_meta` lifetime totals (already exists).
- [ ] Per-IP daily rollup independent of ASN top-N (so a quiet IP's history is not
      lost just because it never made a top-50 bucket) — feeds the `ip.html` profile page.
- [ ] Evaluate DuckDB/Parquet sidecar for Tier 0 **only if** SQLite shows real limits
      at target volumes. Not before.

## Phase 3 — UI: filters, drill-downs, better graphs

The backend query API (`flowstore/query.go`, telemetry handlers) already exists;
the UI barely exposes it. After Phases 1–2 there will be much more to show.

- [ ] Global **time-range picker** (last hour / 24h / 7d / 30d / custom) on dashboard,
      ASN, and IP pages — today most views are "now"-centric.
- [ ] **Flow explorer page** over the Tier-0 flow log: filter by IP/prefix/ASN/port/
      proto/flags/direction + time range, sortable, CSV/JSON export.
- [ ] Per-ASN and per-IP **history charts** from Tier 1/2 (traffic over days/weeks,
      port mix evolution, country mix) — replaces "History snapshots" comparisons
      with real time series.
- [ ] Extract shared CSS + chart helpers from the ~6.5k lines of duplicated inline
      style/script across the 10 static pages (keep the no-build-step rule).
- [ ] Detection UX: timeline of detections/blackholes over time, rule hit-rate chart,
      anomaly score history per IP (data already in `risk_events`).

## Phase 4 — Detection & mitigation depth

- [ ] **Attack incidents.** Group detections into incidents with start/end, peak
      bps/pps, vector classification (NTP/DNS/CLDAP/SSDP/memcached amplification is
      trivially identifiable from src port + proto), affected prefixes, and the
      actions argus took. Deliverables: an incident timeline in the UI and an
      auto-generated incident report (the document you hand to a customer, upstream,
      or abuse desk). Mostly aggregation + UI — the raw material already exists in
      `detections`, `blackhole_events`, and `risk_events`.
- [ ] **Egress detection presets.** All current rules watch ingress; the reverse
      protects our own reputation: customer turned reflector (mass outbound UDP from
      123/53/389), infected host scanning outward, outbound :25 spam bursts. The
      engine already supports `direction: egress` — needs curated preset rules and a
      separate alerting path (you notify the customer, you don't blackhole them).
- [ ] **Threat-feed enrichment.** Ingest Spamhaus DROP / Team Cymru fullbogons on a
      timer; tag flows and detections touching known-bad space, alert on
      bogon-sourced ingress. Cheap enrichment, large signal boost.
- [ ] **ML feedback loop.** True/false-positive marking on risk events in the UI,
      feeding threshold tuning; per-rule **shadow mode** (log-only) to trial rules
      before they can blackhole. Without this, tuning stays guesswork forever.
- [ ] **Time-of-day baselines** for the anomaly layer: a per-hour-of-day baseline
      (30 days of minute buckets already exist) so 04:00 traffic is not judged
      against a 21:00 norm — should cut false positives materially.
- [ ] Anomaly explainability: store the feature vector alongside each risk event so
      the UI can show *why* an IP scored high.
- [ ] Alerting v2: finish Slack action, add webhook/Telegram backends, alert on
      anomaly-engine events (not just rules), digest mode.
- [ ] Blackhole hygiene: dry-run mode, per-rule TTL overrides UI, RTBH community
      per-upstream mapping.

## Phase 5 — Visibility & business value

Turning data argus already collects into operator decisions:

- [ ] **Peering candidates report** — "which ASNs do I exchange the most transit
      bytes with while they sit on the IX I'm already connected to?"
      `flowstore_asn_meta` + the per-interface split almost answer this today.
      For a network paying for transit, this feature pays for the project.
- [ ] **95th-percentile / capacity report** per upstream interface, monthly,
      billing-style — the minute buckets exist; this is a query and a page.
- [ ] **RPKI validation** of the received RIB (flag invalid/unknown), plus
      hijack/leak watch on `my_prefixes` — from the local RIB first, optionally a
      RIPE RIS Live feed later. Fits naturally next to bgpmon/routewatch.
- [ ] **Prometheus `/metrics` endpoint** — flows/sec, enrichment latency, detection
      counts, BGP session state. Cheap, huge operational value, optional for users.
- [ ] Scheduled **reports** (daily/weekly email: top talkers, detections, blackholes).

## Phase 6 — Ops & platform

- [ ] **Multi-exporter support** — accept NetFlow from >1 router, tag flows by
      exporter, per-exporter direction config. (Architecture mostly allows it;
      config assumes one router today.)
- [ ] **sFlow support** — opens the door to switches and other vendors.
- [ ] **`argus backup` / `argus restore`** — consistent snapshot of all SQLite DBs
      (`VACUUM INTO`) + config into one tarball. A single-binary, single-server
      tool owes its operator a single-command disaster recovery.
- [ ] **Audit trail for manual actions** — record which authenticated user ran
      announce/withdraw/flush and when (`blackhole_events.source` already exists;
      thread the username through).
- [ ] Config validation command (`argus check-config`) + live config diff view in UI.

## Parked — blocked on vendor support

- [ ] **BGP FlowSpec (RFC 8955).** The right long-term evolution of mitigation:
      instead of RTBH completing the DoS by dropping all traffic to the victim /32,
      announce granular match/drop rules (e.g. "drop UDP src-port 123 toward X").
      GoBGP already supports FlowSpec, but **RouterOS does not** — the feature
      request has been open since ~2012
      (https://forum.mikrotik.com/t/feature-request-bgp-flowspec-rfc5575/71256),
      so this stays parked until MikroTik ships it (or a non-RouterOS edge exists).
      Interim alternative if granular mitigation becomes urgent: generate MikroTik
      raw firewall rules via the existing routewatch REST-API path — same concept,
      no FlowSpec dependency.

## Non-goals

- External databases, message queues, or JS build toolchains.
- Full ClickHouse-class ad-hoc analytics over unlimited history — the size-capped
  flow log + tiered rollups is the deliberate trade.
- Multi-tenant / SaaS anything.
