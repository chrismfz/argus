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

## Phase 0 — Hygiene & guardrails ✅ complete

- [x] Remove committed 39 MB `argus` ELF binary from the tree; expand `.gitignore`
      (`*.log`, `*.db`, `*.sqlite*`, `blackholes.txt`, root binary). *(this PR)*
- [x] Add CLAUDE.md, ROADMAP.md, CHANGELOG.md. *(this PR)*
- [x] `make test`, `make vet`, `make lint`, `make check` targets + GitHub Actions CI
      (build + vet + test on push/PR). *(PR: phase-0 hygiene)*
- [x] Fix the `go vet` failure: `collectors.Netflow.Start` value receiver copies an
      embedded `sync.Once` (`internal/collectors/netflow.go`). *(PR: phase-0 hygiene)*
- [x] Rename `internal/telemetry/peristence.go` → `persistence.go`. *(PR: phase-0 hygiene)*
- [x] Tree-wide `gofmt -w ./...` (62 files) in a formatting-only PR, and flipped the
      CI gofmt check from advisory to a hard `make fmt` gate. *(PR: phase-0 gofmt)*
- [x] Unify the duplicated direction classifier (`telemetry.classifyDirection` /
      `flowstore.classifyInbound`) into one shared package (`internal/flowdir`) with
      tests — the most load-bearing logic in the system. Both now delegate; the
      duplicated `isMyIP` prefix helper is unified there too. *(PR: phase-0 flowdir)*
- [x] Fix the detection engine lock hazard: `runDetection` held `e.mu` across the
      whole rule loop incl. `HandleBlackhole` (BGP announce + DNS + SQLite), stalling
      `AddFlow` on the ingest path. Now holds the lock only to prune + snapshot the
      flow cache; rule evaluation and actions run lock-free. Regression test included.
      *(PR: phase-0 detection lock)*
- [x] `slack` rule action is no longer a silent no-op — it logs a one-time
      "not implemented" warning; real wiring deferred to Phase 4 (Alerting v2).
      *(PR: phase-0 cleanup)*
- [x] Prune the unbounded tables: `detections` (by last_seen), `alert_events`
      (cascades to `alert_deliveries`), and `snapshots` (period-aware: daily pruned,
      weekly/monthly/yearly/manual kept). Wired into the cleanup ticker with retention
      parameters (hardcoded defaults for now; Phase 1 lifts all retentions to config).
      *(PR: phase-0 cleanup)*
- [x] Tests: rule evaluation + `runDetection` lock behaviour, direction classification
      (`flowdir`), flowstore flush/prune, blackhole TTL escalation (`escalationTTL` +
      `BlackholeDurations`), period-aware snapshot pruning. *(PRs: phase-0 lock / flowdir / cleanup)*

## Phase 1 — Stop the bleeding: configurable retention & caps ✅ complete

Every previously hardcoded cap/retention is now a config knob with the historical
value as default (backward compatible, zero migration). See the `flowstore:`,
`telemetry:`, and `retention:` sections in `etc/config.yaml.example`.
Semantics: unset/0 = default, negative = unlimited (caps) / keep forever (retentions).

- [x] Wire flowstore caps + retention into config (`flowstore:` — top-N, RAM track
      caps, detail retention, and a new independent `timeline_retention_days` so the
      cheap 5-min timeline outlives the detail tables). *(PR: phase-1 retention)*
- [x] Wire telemetry bucket retention into config (`telemetry:` — was hardcoded 30d
      despite claiming to be configurable). *(PR: phase-1 retention)*
- [x] Lift the cleanup-ticker retentions (detections, alert_events, snapshots_daily,
      risk_events, blackhole_events + row cap) into the `retention:` section.
      *(PR: phase-1 retention)*
- [x] Startup log lines: effective storage settings + current SQLite footprint so
      operators can size retention against disk. (A true growth/day estimator needs
      two points in time — revisit alongside Phase 2's flow log sizing.)
      *(PR: phase-1 retention)*
- [x] Rename/clarify the "hourly" internals → "detail" (they flush every 30 min);
      DB table names unchanged. *(PR: phase-1 retention)*

## Phase 2 — Get the information back (the big one)

Tiered rollups — degrade gracefully instead of falling off a cliff:

- [x] **Tier 0 (optional, default off): size-capped raw flow log.** `internal/flowlog`
      appends every enriched 5-tuple (src/dst IP, ports, proto, flags, bytes, packets,
      ifaces, ASNs, direction, ts) to a dedicated `flows.sqlite`, pruned **by size**
      (`max_gb`, default 20) not age — the file stabilises at a high-water mark by
      reusing freed pages. Non-blocking write path (bounded channel, batched writer,
      drop-if-full+counted). Config `flowlog:`, `GET /debug/flowlog?ip=…` JSON endpoint,
      tests (round-trip, sampling, size-bounding, drop path). *(PR: phase-2 flowlog)*
      Hardened after an independent review — prune keys off live data not file size,
      shutdown drains before close, chunked deletes. *(PR: phase-2 flowlog review-fixes)*
      **Next:** the Flow Explorer UI page (Phase 3) to surface it.
      Known soft-cap limits (acceptable): the size bound is main-file-only and lags
      the 1-min prune tick (transient overshoot under bursts + WAL on top); prune
      deletes by insertion order not strictly by timestamp; IPv6 lookups are exact
      string matches (no canonicalisation) — revisit if they bite.
- [x] **Tier 1: 5-min detail** (current tables) — retention now configurable
      (`retention_days` / `timeline_retention_days`, Phase 1).
- [x] **Tier 2: daily rollups** of the detail tables (top IPs/prefixes/ports/countries/
      proto per ASN per day) — `internal/flowstore/rollup.go`, kept `daily_retention_days`
      (default 730). Rolled at the 24h tick (and startup catch-up) BEFORE the detail
      prune, idempotent per complete day. `GET /debug/rollup?asn=…`. *(PR: phase-2 rollups)*
- [x] **Tier 3: forever** — `flowstore_asn_meta` lifetime totals (already existed).
- [x] Per-IP daily rollup independent of ASN top-N (`flowstore_daily_ip_totals`) so a
      quiet IP's history survives even if it never made a top-N bucket. Query
      `GET /debug/rollup?ip=…`; ready to feed the `ip.html` profile page (Phase 3 UI).
      *(PR: phase-2 rollups)*
- [ ] Evaluate DuckDB/Parquet sidecar for Tier 0 **only if** SQLite shows real limits
      at target volumes. Not before.

## Phase 3 — UI: filters, drill-downs, better graphs

The backend query API (`flowstore/query.go`, telemetry handlers) already exists;
the UI barely exposes it. After Phases 1–2 there will be much more to show.

- [x] **Flow explorer page** (`/flows`) over the Tier-0 flow log: filters (IP /
      src / dst / port / proto / direction), time-range chips (15m–7d), traffic-over-
      time chart (in/out stacked), top-talkers chart (click-to-filter), results table,
      client-side CSV export. Palette validated with the dataviz six-checks against
      the dark surface. *(PR: phase-3 flows-ui)*
- [x] Per-IP and per-ASN **daily history charts** from the Tier-2 rollups, on the
      `/flows` Daily History tab: per-IP daily in/out bars and per-ASN stacked
      top-5-IPs+other — deep-linkable (`?hip=…`, `?asn=…`) so `ip.html`/`asn.html`
      can link in. *(PR: phase-3 flows-ui)*
- [ ] Global **time-range picker** (last hour / 24h / 7d / 30d / custom) on dashboard,
      ASN, and IP pages — today most views are "now"-centric. (`/flows` has its own
      range chips; the global rollout across existing pages remains.)
- [ ] Port/country mix evolution charts on `asn.html` from the daily rollup tables
      (`flowstore_daily_ports` / `_country` / `_proto` are populated and waiting).
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
