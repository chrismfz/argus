# argus panoptes

Real-time NetFlow/IPFIX enrichment, detection, and mitigation engine for autonomous systems. Written in Go.

Processes live traffic from MikroTik (and other) routers, enriches flows with ASN, GeoIP, BGP paths, reverse DNS, and SNMP interface data, then feeds a built-in telemetry dashboard and detection engine — with no external databases required.

---

## Architecture

```
MikroTik CCR / Router
        │
        │  NetFlow v9 / IPFIX (UDP 2055)
        ▼
┌─────────────────────────────────────────────────────┐
│                      argus                          │
│                                                     │
│  ┌─────────────┐   ┌──────────────────────────┐    │
│  │  Collector  │──▶│  Enrichment Pipeline     │    │
│  │  (NetFlow)  │   │  GeoIP · BGP · SNMP      │    │
│  └─────────────┘   └──────────┬───────────────┘    │
│                               │                     │
│              ┌────────────────┼────────────────┐    │
│              ▼                ▼                ▼    │
│  ┌───────────────┐  ┌──────────────┐  ┌─────────┐  │
│  │   Telemetry   │  │  Detection   │  │   BGP   │  │
│  │  Aggregator   │  │   Engine     │  │ Speaker │  │
│  │  (in-memory)  │  │  Rules + ML  │  │(GoBGP)  │  │
│  └──────┬────────┘  └──────┬───────┘  └────┬────┘  │
│         │                  │               │        │
│         ▼                  ▼               ▼        │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐   │
│  │  Dashboard  │  │  SQLite DB   │  │ Blackhole │   │
│  │  (embedded) │  │  detections  │  │  BGP ann. │   │
│  │  :9600      │  │  blackholes  │  │           │   │
│  └─────────────┘  └──────────────┘  └──────────┘   │
└─────────────────────────────────────────────────────┘
        │
        │  eBGP session (port 179)
        ▼
  MikroTik CCR2004
  (full RIB → argus, blackhole routes ← argus)
```

---

## Features

### Enrichment
- **ASN + name** via MaxMind GeoLite2-ASN (auto-downloaded, auto-updated)
- **Country + city** via MaxMind GeoLite2-City
- **BGP AS path** from full RIB received over eBGP session to the router
- **SNMP interface names** — maps `INPUT_SNMP`/`OUTPUT_SNMP` field indices to real names (e.g. `sfp1-Synapsecom`, `sfp2-GRIX`)
- **Reverse DNS (PTR)** — on-demand via detection engine and `/infoip` API

### Telemetry dashboard
Self-contained, embedded HTML served directly from the argus binary. No Grafana, no ClickHouse, no external dependencies required.

- **Overview** — total in/out bytes, throughput chart (bytes/min), top 10 inbound/outbound ASNs
- **Traffic by AS** — ranked ASN tables with traffic bars and "via" interface column, AS Sankey charts
- **Hosts & Ports** — top destination/source IPs, destination port heatmap
- **History** — per-ASN historical comparison across daily/weekly/monthly/yearly snapshots
- **Snapshots** — manual snapshots with notes; automatic midnight snapshots stored in SQLite
- **Upstreams** — per-upstream-interface throughput charts (Synapsecom, GR-IX, failover), upstream × ASN Sankey
- **⚡ Live Flows** — real-time flow debug table with direction analysis, IP/ASN filter, mismatch highlighting
- **🔬 Raw Fields** — raw NetFlow field inspector (field ID → raw value), freeze-on-hover, sample rate control

**Direction classification** (MikroTik sends `FlowDirection=0` for all flows — confirmed):
1. `INPUT_SNMP` / `OUTPUT_SNMP` interface index matched against `upstream_interfaces` config list
2. IP prefix matching against `my_prefixes`
3. Raw `FlowDirection` field (last resort, always 0 from MikroTik)

### Detection engine
Rule-based detection with configurable actions and automatic BGP blackholing.

**Actions:** `alert` (writes to `detections.log`), `blackhole` (BGP announces /32 with community)

**Rule conditions:** `proto`, `tcp_flags`, `dst_port`/`src_port` (single, list, or range), `direction` (ingress/egress), `same_dst_ip`, `same_dst_port`, `same_src_ip`, `unique_dst_ips`, `unique_dst_ports`, `min_flows`, `min_unique_src_ips`, `min_avg_pps`, `min_bytes`, `min_total_bytes`, `nat_present`, `ttl_min`/`ttl_max`, `only_prefixes`, `exclude_src_ips`, `exclude_dst_ips`

**Escalating blackhole TTLs** — each repeated offense gets a longer block:
```
blackhole_time: [14400, 28800, 57600, 86400, 0]
# offense 1→4h, 2→8h, 3→16h, 4→24h, 5+→permanent
```

**Protection list** (`etc/exclude.detections.conf`) — IPs and CIDRs never blackholed, hot-reloaded via fsnotify

**SQLite persistence** — detection counts, active blackholes, and blackhole history survive restarts; active blackholes are re-announced on startup

### ML anomaly detection
Unsupervised scoring pipeline running alongside rules, catching unknown threat patterns:

- **Isolation Forest** — trained on rolling baseline of per-source feature vectors
- **HBOS** — Histogram-Based Outlier Score, per-feature density estimation  
- **eHBOS** — ensemble HBOS over random feature subspaces
- **Fusion** — configurable weighted combination: `fused = w_iforest·if + w_hbos·hbos_norm + w_ehbos·ehbos_norm`
- **Memory layer (EWMA)** — per-IP risk accumulation with debt tracking and spike flags, writes to `risk.log`
- **Hot-reloadable config** — change thresholds, weights, and allowlists without restart

Feature vector per source: `packets/sec, bytes/sec, mean_pkt_size, unique_dst_ips, unique_dst_ports, tcp_syn_ratio, icmp_share`

### BGP control
- Embedded GoBGP speaker with full eBGP session to the router
- Receives full RIB on startup (used for AS path enrichment of all flows)
- Announces /32 blackhole routes with BGP communities on detection
- Auto-withdraws after configurable TTL with CFM reporting support
- Restores active blackholes on restart from SQLite

---

## Configuration

```yaml
# etc/config.yaml

collectors:
  netflow:
    config:
      bindaddr: 0.0.0.0
      bindport: 2055

bgp:
  bgp_listener:
    enabled:      true
    listen_ip:    "116.203.217.190"   # argus server IP
    peer_ip:      "84.54.49.1"        # router IP
    asn:          65001               # argus internal ASN
    local_asn:    65001
    remote_asn:   216285              # router ASN
    store_aspath: true

maxmind:
  enabled:     true
  account_id:  "000000"
  license_key: "YOUR_KEY"
  db_path:     "/opt/argus/data/geoip"
  editions:    [GeoLite2-ASN, GeoLite2-City]
  check_every: 24h
  min_age:     72h

my_asn: 216285
my_prefixes:
  - 84.54.49.0/24
  - 194.153.116.0/24
  - 2a14:4280::/29

# Interface indices from /snmp/interfaces — primary direction signal
upstream_interfaces:
  - 2    # sfp1-Synapsecom (transit)
  - 3    # sfp2-GRIX (IX)
  - 9    # sfp8-failover

snmp:
  enabled:   true
  target:    "84.54.49.1"
  community: "public"
  port:      161
  timeout:   2
  retries:   3

dns:
  nameserver: "1.1.1.1"

timezone: "Europe/Athens"
enrich: "geoip, bgp, snmp"

detection:
  enable_detection_engine: true
  rules_config: /opt/argus/etc/detection.yml
  flow_cache_max_window: 60s

  anomaly:
    enabled:        true
    window:         60s
    interval:       10s
    retrain_every:  40m
    trees:          256
    sample_size:    1024
    contamination:  0.012
    weights:        { iforest: 0.20, ehbos: 0.50, hbos: 0.40 }
    allow_asns:     [13335, 216285, 8075, 15169]  # suppress known-good ASNs
    print_above_mean_percent: 25

  memory:
    enabled:   true
    interval:  10s
    log_path:  /opt/argus/risk.log
    alpha:     0.30    # EWMA smoothing (higher = shorter memory)
    theta:     0.65    # debt accumulation pivot
    tau_risk:  0.85    # threshold for risk.log entry (higher = quieter)

api:
  listen_address: "0.0.0.0"
  port: 9600
  tokens:
    - "your-secret-token"
  allow_ips:
    - "127.0.0.1"
    - "84.54.49.0/24"

debug_api:
  enabled:        true
  listen_address: "127.0.0.1"
  port:           9601
  require_token:  false
```

---

## Detection rules

```yaml
# etc/detection.yml
rules:
  - name: syn_flood
    proto: tcp
    tcp_flags: SYN
    direction: ingress
    same_dst_ip: true
    min_flows: 5000
    min_avg_pps: 1000
    time_window: 20s
    action: alert,blackhole
    blackhole_count: 30
    blackhole_next_hop: 192.0.2.1
    blackhole_communities: ["65001:666"]
    blackhole_time: [14400, 28800, 57600, 86400, 0]

  - name: horizontal_scan
    proto: tcp
    direction: ingress
    same_dst_port: true
    unique_dst_ips: 80
    min_flows: 150
    time_window: 20s
    action: alert,blackhole
    blackhole_count: 30
    blackhole_next_hop: 192.0.2.1
    blackhole_communities: ["65001:666"]
    blackhole_time: [14400, 28800, 57600, 86400, 0]
```

Add IPs and CIDRs that should never be blackholed to `etc/exclude.detections.conf` (one per line, comments with `#`, hot-reloaded on change).

---

## Building and running

```bash
# Build
make build

# Run (config auto-detected relative to binary location)
./bin/argus

# Explicit config path
./bin/argus --config /opt/argus/etc/config.yaml

# Install as systemd service
cp etc/systemd/system/argus.service /etc/systemd/system/
systemctl enable --now argus
```

**MikroTik setup:**
```
# Blackhole next-hop route (required for BGP blackholing)
/ip route add dst-address=192.0.2.1/32 blackhole comment="BGP Blackhole Nexthop"

# NetFlow v9 export to argus
/ip traffic-flow set enabled=yes interfaces=all
/ip traffic-flow target add dst-address=<argus-ip> port=2055 version=9

# eBGP peer
/routing bgp peer add name=argus remote-address=<argus-ip> \
    remote-as=65001 multihop=yes ttl=default
```

---

## API reference

All endpoints require `Authorization: Bearer <token>` header and source IP in `allow_ips`. Telemetry and dashboard endpoints (`/tel/*`, `/dashboard`, `/debug/*`) are IP-only (no token required).

| Endpoint | Method | Description |
|---|---|---|
| `/infoip?ip=x` | GET | GeoIP, ASN, PTR, BGP AS path for any IP |
| `/status` | GET | Enrichment subsystem health |
| `/bgpstatus` | GET | Peer state, uptime, message counters |
| `/bgpannouncements` | GET | Full adj-in RIB from the router |
| `/announce` | POST | Manually announce a prefix |
| `/withdraw` | POST | Manually withdraw a prefix |
| `/announcements` | GET | Currently announced prefixes |
| `/blackhole-list` | GET | Active blackholes with enrichment metadata |
| `/blackhole-search?ip=x` | GET | Check if a specific IP is blackholed |
| `/snmp/interfaces` | GET | Live interface traffic via SNMP |
| `/flush` | POST | Withdraw all BGP announcements + clear DB |
| `/dashboard` | GET | Embedded telemetry dashboard |
| `/debug/flows` | GET | Live flow debug page |
| `/debug/rawflows` | GET | Raw NetFlow field inspector |

---

## Storage and logs

**SQLite** (`detections.sqlite`) — single file, no setup required:
- `detections` — rule hit counts per IP, persistent across restarts
- `blackholes` — active blackhole records with TTL and enrichment metadata
- `snapshots` — telemetry snapshots (daily/weekly/monthly/yearly + manual)

**In-memory ring buffer** — 1440 one-minute buckets (24h) for telemetry metrics. Snapshots persist to SQLite at midnight automatically.

**Log files:**
| File | Contents |
|---|---|
| `detections.log` | Rule-based detection alerts with enrichment |
| `blackholes.txt` | Blackhole announce/withdraw audit trail |
| `anomalies.log` | ML anomaly engine scored events |
| `risk.log` | EWMA memory layer risk tracking |
| `/var/log/argus/output.log` | Main process log (systemd) |

---

## CLI

```bash
./flow-cli.sh
# Interactive menu:
#  /infoip        — look up any IP (ASN, PTR, BGP path, communities)
#  /bgpstatus     — peer state and message counters
#  /blackhole-list — active blackholes with metadata
#  /snmp/interfaces — live interface stats from router
#  /announce      — manually blackhole a prefix
#  /withdraw      — remove a blackhole
#  /flush         — emergency: withdraw everything, clear all detections
```


## Nginx 

 1. place the config
sudo cp argus.example.tld.conf /etc/nginx/sites-available/argus.example.tld
sudo ln -s /etc/nginx/sites-available/argus.example.tld /etc/nginx/sites-enabled/

 2. create htpasswd
sudo htpasswd -c /etc/nginx/.htpasswd chris

 3. test + reload
sudo nginx -t && sudo systemctl reload nginx

 4. when DNS is pointed, get the cert (modifies the config automatically)
sudo certbot --nginx -d argus.example.tld

