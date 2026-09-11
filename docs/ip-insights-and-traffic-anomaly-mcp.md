# Design: IP insights, traffic-anomaly detection, and an argus MCP

Status: **proposal / plan** (2026-09-11). Living doc — update as phases land.
Owner discussion origin: the `virgo.myip.gr` "strange traffic" investigation.

## 1. Why this exists (the incident that started it)

An operator saw a large, bursty **outbound** spike for `virgo.myip.gr` in
LibreNMS (interface `eno1`: Out avg ~9 Mbps, **max 73 Mbps, 195 GB / 48h** vs
only 18 GB in), and could not tell *what* it was. LibreNMS shows **bytes on an
interface** — not who/where/which service.

We drilled the fleet's CFM MCP proxy (`cfm-web` → node embedded MCP) to see how
far the existing tooling gets. Findings, verbatim from the node:

- **`mail_traffic` / `whats_wrong`** — a real mail anomaly:
  `appointment@physiopluspilates.gr` at ~17× its 7-day baseline (hitting the
  cPanel 200/h cap), a 333-frozen bounce backlog (sender `<>`), heavy
  deferred/bounced. **Real and worth fixing — but byte-tiny** (~2k msgs/24h ≈
  a few hundred MB; it does not explain 195 GB).
- **`nft_counters`** — `total_bytes: 186060` = **186 KB**. These are only the
  firewall *rule* counters (synrate/newrate/connlimit/portflood). **CFM has no
  total-interface / per-host byte counter at all.** For a 195 GB question, CFM's
  byte view is 186 KB.
- **`process_health`** — `jetbackupd` running (3 procs + children). The
  periodic, deep outbound bursts are almost certainly **JetBackup offsite
  backups**, plus normal HTTP content delivery (argus shows the AS's outbound is
  dominated by OTEnet — Greek eyeballs). But CFM can only say the process
  *exists*; not how many bytes it sent, or to where.

**Conclusion:** CFM answers the *application* layer (mail, WAF, HTTP request
patterns, "is a process running"). It structurally **cannot measure or
attribute raw bandwidth**. That is a flow-data question, and argus already
ingests the flows — it just can't yet answer it conveniently.

## 1a. Root cause found — the whitelist blind spot (case study)

The virgo egress was traced (the hard way) to **`94.131.146.168` draining a
mailbox on the `adamidis` (adamidisatebe.gr) account over POP3** — repeated
RETR of a large mailbox is exactly the sustained outbound byte shape. Why it
escaped every layer, confirmed against the live fleet + the code:

- **It was whitelisted — permanently, globally, protocol-blind.** `check_ip`:
  on the `whitelist`, permanent, added **manually on 2025-10-23 from virgo** with
  reason `SECURITY/RCPT_AUTH_REQUIRED | exim_security`. `ip_locate` on virgo: it
  sits in the nft **ALLOW** sets `allow_ext_v4_hosts` + `allow_ext_v4_hosts_myallow`
  (the MYALLOW feed) → the firewall **fail-opens** for it, fleet-wide. A whitelist
  added to silence one *SMTP* false-positive a year ago silently exempted the IP
  for *every* protocol, including POP3, forever.
- **Allow-list suppresses visibility, not just enforcement.** `detection_history`
  for the IP is **empty**. In `cfm/internal/detectors/ignore.go`, ignored/allow
  IPs are skipped and, with `LOG_IGNORED` defaulting to **false**, are **not even
  recorded to the sink**. So the abuse left no trace to alert on.
- **No detector models POP3 *volume*.** The `dovecot_auth` detector keys only on
  auth *failures* (`auth failed|authentication failure|aborted login|password
  mismatch`). A compromised login with **valid credentials** produces zero
  failures → invisible. There is no bytes/RETR/volume signal on IMAP/POP3 at all.
- **The one signal that could see bandwidth is the unused one.** CFM's `health`
  detector computes `TX_THRU_SPIKE` / `CONN_TOTAL_SPIKE` / `CPU_HIGH`, but it is
  noisy (fires at x≈1.9 via email, no dedup) and — critically — has **no
  attribution** (no peer/port), so even when it fires it can't name the culprit.
- **argus saw the bytes but you couldn't ask it.** NetFlow does not care about
  CFM allow-lists; the flow to `94.131.146.168:110/995` was in argus the whole
  time. The missing piece was a per-local-host view + a volume anomaly + a way to
  query it — i.e. this document.
- **Confirmed from the account too.** cPanel's per-account bandwidth-by-service
  shows the account at **~500 GB / 1 TB monthly (49%)**, essentially **all POP3**
  (bursts to ~1.2 GB/min in 24h; HTTP/FTP/IMAP/SMTP ≈ 0) — matching the LibreNMS
  outbound spikes exactly. This per-account, per-protocol byte breakdown is a
  signal CFM could read directly (see §4.2a) — it attributes to the *account*, not
  just the IP.

**Principles this bakes in:**
1. **An allow-list must suppress enforcement, not visibility.** Abnormal volume
   from a trusted IP must still be *recorded and alertable*.
2. **Flow-layer detection is the backstop for app-layer blind spots.** argus is
   immune to the CFM whitelist and to "valid credentials", so a volume anomaly
   catches exfil/drain that every credential/rule-based detector misses.
3. **Whitelists need scope + TTL.** A permanent, global, protocol-blind IP allow
   is a landmine; scope it to a plane/protocol and expire it.

## 2. The gap in argus today

argus receives NetFlow for the whole AS, and `84.54.49.0/24` (which contains
virgo, `.202`) is in `my_prefixes` — **so argus already sees virgo's traffic.**
The problems are shape and access, not missing data:

1. **Aggregation is by *remote* ASN / interface, not by *our* host.** The
   dashboard's "Traffic by AS" and the per-IP rollups
   (`flowstore_daily_ip_totals`, keyed by `peer_ip`) answer "which remote ASN /
   remote IP", never "how much did *our* `84.54.49.202` send, to whom, on what
   port". The per-IP profile page (`/infoip`) is enrichment only
   (GeoIP/ASN/BGP/detections) — no volume.
2. **The raw flow log is off by default.** `flowlog.enabled: false`, so the only
   store that can answer "what did X do at 03:00" (`/debug/flowlog`) is empty
   until switched on.
3. **No MCP.** Unlike every CFM node, argus can't be queried programmatically
   from the same place the operator already asks the fleet. Hence "δεν έχω
   οπτική στο argus εύκολη".

**Good news — the data is already captured.** `flowstore_daily_ips` and the
30-minute detail tables already store `local_ip` alongside
`peer_ip/asn/proto/dst_port/country/dir/bytes` (see
`internal/flowstore/rollup.go` schema and `query.go`). A per-local-host view is
therefore mostly **read-side + UI**, not a new pipeline.

## 3. Goals / non-goals

**Goals**
- Answer, for any of *our* IPs (a `my_prefixes` address): bytes in/out over
  time, and the top remote peers / ASNs / ports / protocols / countries behind
  it — the direct follow-up to a LibreNMS spike.
- Detect **traffic/volume anomalies** (a host or interface or ASN whose bytes
  are N× its own baseline) — turn "I noticed a spike" into "argus already
  flagged host X → ASN Y on port Z at 07:12, 16× baseline".
- Expose all of it through **three surfaces: CLI, UI, and MCP**, the last one
  reachable through the existing `cfm-web` proxy so it lives next to the CFM
  fleet tools.

**Non-goals**
- No new external runtime dependency (ADR-001 stands — SQLite + embedded only).
- The MCP is **read-only**. No blackhole/announce/withdraw via MCP (those stay
  on the authenticated HTTP API with its allow-list + token).
- Not replacing LibreNMS/SNMP — complementing it with per-flow attribution.

## 4. Design

### 4.1 IP insights — per-local-host traffic (`internal/flowstore` + API + UI)

Add read helpers keyed on `local_ip` (mirroring the existing `peer_ip`/`asn`
ones), so no ingest change is needed:

- `QueryLocalIPDaily(db, localIP, days)` → per-day in/out totals for one of our
  hosts. Backed by a new `flowstore_daily_local_ip_totals` (mirror of
  `flowstore_daily_ip_totals` but keyed by `local_ip`) so a host's total
  survives even below any ASN top-N. Small rollup addition in `rollup.go`.
- `QueryLocalIPBreakdown(db, localIP, days)` → top remote peers / ASNs / ports /
  protocols / countries for that host, from `flowstore_daily_ips WHERE
  local_ip = ?`. Add `CREATE INDEX idx_fsdips_local ON
  flowstore_daily_ips(local_ip, day DESC)` (the column exists; only the index is
  missing).
- `QueryTopLocalTalkers(db, window)` → our busiest hosts by bytes in/out — the
  "which of our servers is hot right now / today" list.
- Intraday (< 7 days) uses the 30-minute detail tables (already carry
  `local_ip`); exact 5-tuple/timestamp forensic uses `flowlog` (§4.4).

**API** (IP-only `/debug/*`, consistent with existing handlers):
- `GET /debug/host?ip=<local-ip>&days=N` → totals + breakdown for one host.
- `GET /debug/hosts?window=...` → top local talkers.

**UI**: a new **"My Hosts"** dashboard tab (self-contained HTML in
`internal/api/static/`, dark theme, no build step per CLAUDE.md §6): pick/enter a
`my_prefixes` IP → in/out throughput over time + top peers/ASN/ports tables +
in/out Sankey, reusing the existing chart helpers.

### 4.2 Traffic / bandwidth anomaly detection

argus already has an anomaly stack (`internal/detection`: iForest/HBOS/eHBOS +
EWMA memory) but it is **per-source-IP feature-vector scoring aimed at DDoS
shapes** (pps, syn ratio, unique dsts…), not **volume baselining of our own
egress/ingress**. Add a distinct, cheap **volume-anomaly** layer:

- Per (local_ip, dir) and per (interface, dir) and per (asn, dir): maintain a
  rolling baseline (EWMA of bytes/min, plus hour-of-day/day-of-week seasonal
  buckets so nightly backups aren't false-positived). Flag when the current
  window exceeds `k × baseline` (config knob) for a sustained period.
- Emit to a new `traffic_anomalies` table (pruned by the existing retention
  ticker — CLAUDE.md §5) and to a log, with enrichment (top peer/ASN/port for
  the offending window) so the alert is self-explaining:
  `host=84.54.49.202 out 16× baseline, 07:00–07:40, top peer AS6799 OTEnet,
  port 443` or `… top peer <offsite-backup-IP>, port 22`.
- Config under a new `traffic_anomaly:` section (defaults = current behaviour;
  unset/0 = default, negative = off — the repo's knob convention). Reuses the
  `exclude.detections.conf` idea for "known heavy & fine" hosts (e.g. the backup
  target), so JetBackup egress can be whitelisted instead of alerting nightly.
- Optional (later): route a flagged anomaly to the existing `alerter`
  (smtp/log) backends.
- **Allow-list-independent by construction.** argus scores flows; it has no
  concept of the CFM whitelist, so a "trusted" IP draining a mailbox is scored
  like any other. This is the deliberate backstop for the §1a blind spot — the
  anomaly must fire on volume regardless of any upstream allow decision.
- **Peer + port in every alert.** Because the flow carries the 5-tuple, an alert
  can say `…top peer 94.131.146.168, port 995 (POP3S)` — the attribution CFM's
  `TX_THRU_SPIKE` structurally lacks. A per-(local_ip, dst_port) egress view also
  gives a cheap "mailbox drain" signal (sustained :110/:143/:993/:995 egress to
  one peer) without argus needing to parse dovecot at all.

This is the piece that would have turned the virgo incident into a one-line
answer instead of an investigation.

### 4.2a Companion CFM-side hardening (tracked in the `cfm` repo)

Out of argus's scope but part of the same lesson, to be raised as separate `cfm`
/ `cfm-web` changes:
- **`dovecot_auth` gains a volume signal** (bytes/session or bytes/mailbox/IP),
  not just auth-failure — catch valid-credential drains.
- **Allow-listed IPs stay visible**: default `LOG_IGNORED` on (or an
  "alert-even-if-allowed" path) so a whitelisted IP behaving abnormally is still
  recorded — an allow decision must not blank `detection_history`.
- **Whitelist hygiene**: scope allow entries to a plane/protocol and give them a
  TTL; a permanent global IP allow added for one SMTP FP should never have
  exempted POP3 for a year.
- **Read cPanel's per-account bandwidth-by-service** (HTTP/FTP/IMAP/POP3/SMTP) —
  cPanel already computes it (the incident showed one account at 500 GB/mo, ~all
  POP3). A detector that flags "account X: N× its own baseline, or ≥K% of quota,
  concentrated in one protocol" is a cheap, account-attributed catch for exactly
  this drain — complementary to argus's IP/flow view. A candidate "base" for
  CLI/UI/MCP alongside the (de-noised) `health` signals.

> **As-built (P2, landed):** `internal/mcpserver` uses go-sdk v1.7.0 streamable
> HTTP (stateless + JSON, `DisableLocalhostProtection` like CFM) mounted at
> `/mcp`. Auth reuses argus's existing `WithAuth` (bearer from `api.tokens`, or
> `allow_ips`) rather than a dedicated `mcp_token` — a fleet gateway already
> holds an api token, so this is one fewer secret to manage and still exactly
> what cfm-web's `FleetMcpClient` presents. Kill switch: `api.mcp_enabled:false`.
> Tools shipped: `host_traffic`, `top_local_talkers`, `infoip`, `interfaces`,
> `flow_search`. `bgp_status`/`blackhole_*` and a light `whats_wrong` remain
> follow-ups.

### 4.3 argus embedded MCP server (`internal/mcpserver`, new)

Mirror the CFM daemon's MCP exactly so it is **drop-in for the `cfm-web`
proxy** (which is what makes it appear next to the fleet tools):

- Use the **same SDK the cfm daemon uses**: `github.com/modelcontextprotocol/
  go-sdk v1.7.0` (argus is Go 1.25 — just add the dep). Mount the go-sdk
  **streamable HTTP handler in STATELESS + JSON mode at `/mcp`**, bearer-auth
  (a new `mcp_token` config knob, like the daemon's `MCP_TOKEN`). This is
  exactly the contract `cfm-web`'s `FleetMcpClient` speaks (JSON-RPC
  `tools/list` / `tools/call`, `Accept: application/json, text/event-stream`,
  TLS with SNI matching the host cert). See `cfm` repo
  `internal/apiserver/mcp_wire.go` + `internal/mcpserver/` as the template.
- Serve it on the transport `cfm-web` expects (see §4.5 for the port decision).

**Read-only tool surface** (thin wrappers over §4.1/§4.2 and existing
endpoints):

| Tool | Backed by | Answers |
|---|---|---|
| `host_traffic(ip, days?)` | §4.1 local-host query | "how much did *our* host send/recv, to whom, on what port" |
| `top_local_talkers(window?)` | §4.1 | "which of our servers is hottest" |
| `traffic_anomalies(hours?)` | §4.2 table | "what volume anomalies fired, with the offending peer/port" |
| `flow_search(ip?, peer_ip?, port?, proto?, dir?, since?, until?, limit?)` | `/debug/flowlog` | exact 5-tuple forensic ("what at 03:00") |
| `interfaces()` | `/snmp/interfaces` | live SNMP per-interface throughput (the LibreNMS-equivalent, in one call) |
| `infoip(ip)` | `/infoip` | GeoIP/ASN/PTR/BGP path for any IP |
| `bgp_status()` / `blackhole_list()` / `blackhole_search(ip)` | existing endpoints | RIB/peer state, active blackholes (read-only) |
| `whats_wrong()` | new light triage | flow ingest alive? BGP session up? anomalies firing? disk? |

### 4.4 flowlog

Ship the per-host view working on the rollups (no flowlog needed for
30-min/day granularity), but **document turning `flowlog.enabled: true` on** for
exact forensic (`flow_search`). It is size-capped (`max_gb`, default 20) and
never blocks ingest, so it's safe to enable on watchdog. The MCP `flow_search`
tool returns the "set flowlog.enabled" hint when it's off (the handler already
does).

### 4.5 Wiring into cfm-web (the "κουμπώνει στο cfm-web" part)

`cfm-web`'s `NodeCallTool` / `NodeToolsTool` are **generic passthroughs**: they
resolve an `Agent` by `server_name` and forward `tools/call` / `tools/list` to
`<apiBaseUrl>/mcp` with the agent's bearer (`FleetMcpClient`). So if argus
speaks the §4.3 protocol, **integration is mostly a DB row, not proxy code**:

1. Register argus as an `Agent` (e.g. `server_name = argus.myip.gr` on
   watchdog, `116.203.217.190`) with a `Token`. `node_tools`/`node_call` then
   reach it with zero new code — `node_call(node="argus.myip.gr",
   tool="host_traffic", arguments={ip:"84.54.49.202"})`.
2. **Transport decision.** `Agent::apiBaseUrl()` is `https://<host>:6061` with a
   *global* scheme/port from `config/fleet.php`. Two options:
   - **MVP (no cfm-web code):** argus serves the MCP on **6061** with a cert
     valid for its `server_name` (SNI must match — see cfm-web CLAUDE.md §5) and
     a bearer. Register the Agent; done.
   - **Cleaner (small cfm-web change):** add per-agent `mcp_scheme/mcp_port/
     mcp_path` columns and read them in `apiBaseUrl()` — `config/fleet.php`
     already anticipates this ("If a deployment mixes both, add columns …").
     Lets argus keep its own port (e.g. reuse :9600 vhost with `/mcp`).
3. **`node="all"` fan-out.** `handleFleet` fans a tool across all `is_down=false`
   agents. A CFM tool sent to argus (or vice-versa) returns a harmless per-node
   tool-error. To keep fleet-wide calls clean, add an `Agent.kind`
   (`cfm` | `argus`) and default `node="all"` (and `list_nodes`) to `kind=cfm`,
   with argus addressable explicitly. Small, optional.

Standalone use ("να έχει και δικό του") comes for free: the same `/mcp` can be
added as its own MCP connector independent of cfm-web.

## 5. Phasing

1. **P1 — IP insights (argus):** `local_ip` index + queries + `/debug/host[s]` +
   "My Hosts" UI tab. (Data already captured; highest value, lowest risk.)
2. **P2 — argus MCP (argus):** `internal/mcpserver` with `host_traffic`,
   `top_local_talkers`, `interfaces`, `infoip`, `flow_search`, bgp/blackhole
   reads; bearer + `/mcp`. Standalone-usable.
3. **P3 — cfm-web wiring:** register argus Agent (+ optional per-agent transport
   columns and `Agent.kind`). Now reachable via the fleet proxy.
4. **P4 — traffic-anomaly engine (argus):** volume baselining + `traffic_anomalies`
   table + `traffic_anomalies` MCP tool + CLI + optional alerter route.
5. **CLI throughout:** extend `flow-cli.sh` / an `argus insights` subcommand to
   hit the new `/debug/host[s]` + anomaly endpoints, so the same answers exist on
   the box without the UI or MCP.

Each phase is a focused PR with a CHANGELOG entry (argus CLAUDE.md §3) and, for
the runtime-behaviour ones, an adversarial self-review. cfm-web changes follow
its own CLAUDE.md (Filament assets / `clear-caches.sh`, manual CHANGELOG).

## 6. Security notes

- MCP is **read-only**; mutating endpoints (`/announce`, `/withdraw`, `/flush`)
  are **not** exposed as tools.
- Bearer required on `/mcp`; argus keeps its existing `allow_ips` + token model
  for the HTTP API. cfm-web holds the bearer server-side and scrubs it from
  results (`FleetMcpClient::scrub`) — same guarantee as CFM nodes.
- TLS/SNI must match the registered `server_name` or the daemon-style handshake
  fails before auth (cfm-web CLAUDE.md §5) — applies to argus too.

## 7. Open questions

- Port for argus `/mcp`: reuse 6061 (MVP) vs per-agent columns in cfm-web?
- Should `top_local_talkers` be live (needs a small per-local-host ring in
  `telemetry`) or is 30-min/daily granularity enough for v1? (v1: rollups.)
- Anomaly seasonality: hour-of-day + day-of-week buckets vs a simpler EWMA with
  a manual backup-window/whitelist. Start simple; iterate on real FPs (the LSM
  and WAF history says budget for a tuning pass).

### P1 follow-ups (from the code review of #35)

- **Service-port view needs `src_port`.** `flowstore_top_ips` stores only
  `dst_port`, so the response/egress half of a served connection carries the
  client's *ephemeral* port, not the service port — the "Destination ports"
  table is caveated in the UI meanwhile. A proper service-port breakdown needs
  `src_port` added to the detail table + accumulate + rollup (a hot-path change,
  hence deferred).
- **Config-backed "My Hosts" query defaults.** The window/top-N defaults and the
  168h max are named constants in `host_handlers.go` for now; per CLAUDE.md rule
  2 they should move to `internal/config` (+ `etc/config.yaml.example`), with the
  max window derived from the configured detail retention so a longer retention
  widens the window automatically.
- **Exact per-local-host totals.** Add a `flowstore_daily_local_ip_totals`
  rollup (mirror of the `peer_ip` one) so a host's in/out total is complete
  rather than top-N-derived (`partial:true`).
