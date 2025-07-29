# flowenricher

`flowenricher` is a real-time NetFlow/IPFIX enrichment, detection, and mitigation engine written in Go.
It processes live traffic or JSON flow logs, enriches them with ASN, GeoIP, BGP AS paths, reverse DNS, and SNMP interface data — then stores them in ClickHouse for blazing-fast analytics.

In addition to enrichment, `flowenricher` includes a built-in detection engine that can trigger alerts or take automated action such as BGP blackholing based on customizable flow rules.

---

## ✨ Features

- ✅ **Enriches flows with:**
  - Autonomous System Numbers (ASN)
  - ASN organization names
  - BGP AS Path from prefix table
  - Country & city (GeoIP2)
  - Reverse DNS (PTR) — *ptr hammers the system, be careful!*
  - SNMP interfaces — *know which interface traffic came in from!*
- ✅ High-performance enrichment with in-memory caching
- ✅ **NetFlow v9/IPFIX collector** included
- ✅ **Detection engine with alerting & auto-blackhole**
- ✅ Modular `action` support: `alert`, `blackhole`, `clickhouse`, `slack`
- ✅ **Timed auto-withdrawal** of blackholed prefixes
- ✅ JSON rule configuration (`detection.yml`) + clean YAML app config
- ✅ ClickHouse batch insertion

---

## 📦 Architecture Overview

New:
[Netflow v9/IPFIX] → [flowenricher] → [BGP/GeoIP/PTR] → [ClickHouse]

---

## 🔥 Detection + Blackhole Engine

### Detection rules (`detection.yml`)
Each rule defines:
- Matching conditions: proto, min_flows, unique IPs, same dst port/IP
- Action(s): `alert`, `blackhole`, etc.
- Optional blackhole configuration:
  - Threshold (`blackhole_count`)
  - BGP next-hop and community
  - Auto-expire (`blackhole_time` in seconds)

Example:
```yaml
- name: slow_horizontal_scan
  proto: tcp
  same_dst_port: true
  unique_dst_ips: 50
  min_flows: 70
  time_window: 60s
  action: alert,blackhole
  blackhole_count: 50
  blackhole_next_hop: 192.0.2.1
  blackhole_communities: ["65001:666"]
  blackhole_time: 3600
```

📄 Alerts are written to `detections.log`, and blackholes to `blackholes.txt`.

---

## 🌐 Blackhole API (BGP Announcement Control)

### `POST /announce`
Announce a prefix with optional next-hop and communities:
```bash
curl -X POST http://127.0.0.1:9600/announce \
  -H 'Content-Type: application/json' \
  -d '{
    "prefix": "149.202.68.236/32",
    "next_hop": "192.0.2.1",
    "communities": ["216285:666"]
  }'
```

### `POST /withdraw`
Withdraw a previously announced prefix:
```bash
curl -X POST http://127.0.0.1:9600/withdraw \
  -H 'Content-Type: application/json' \
  -d '{ "prefix": "149.202.68.236/32" }'
```

### `GET /announcements`
List active BGP blackhole announcements:
```json
{
  "149.202.68.236/32": {
    "prefix": "149.202.68.236/32",
    "next_hop": "192.0.2.1",
    "communities": ["216285:666"],
    "timestamp": "2025-07-29T19:04:56.624057128+03:00"
  }
}
```

---

## ⚙️ Configuration

### `config.yaml`
```yaml
collectors:
  netflow:
    config:
      bindaddr: 0.0.0.0
      bindport: 2055
      debug: false

bgp:
  bgp_listener:
    enabled:    true
    listen_ip:  "116.203.217.190"   # your VM’s IP (used for binding & source of TCP)
    router_id:  "116.203.217.190"   # optional: leave empty to default to listen_ip
    peer_ip:    "84.54.49.1"        # MikroTik’s IP
    asn:        65001               # your 4-byte ASN
    local_asn:  65001
    remote_asn: 216285              # MikroTik’s ASN
    max_peers:  2

clickhouse:
  host: "localhost"
  user: "default"
  password: ""
  database: "pmacct"
  table: "flows"

geoip:
  asn_db: "/etc/pmacct/GeoLite2-ASN.mmdb"
  city_db: "/etc/pmacct/GeoLite2-City.mmdb"

kafka:
  enabled: false
  brokers:
    - "localhost:9092"
  topic: "netflow"
  group_id: "flowenricher-group"

dns:
  nameserver: "1.1.1.1"

timezone: "Europe/Athens"

debug: false

enrich: "geoip, bgp, snmp, ptr"
# could be geoip, bgp, ptr, smtp or none #
# surely, none fucks the purpose of doing all this program :-) #
# ptr hammers the system be careful

insert:
  batch_size: 200
  flush_interval_ms: 1000

my_asn: 216285
my_prefixes:
  - 84.54.49.0/24
  - 194.153.116.0/24
  - 2a14:4280::/29

snmp:
  enabled: true
  target: "84.54.49.1"
  community: "systemworx"
  port: 161
  timeout: 2
  retries: 3

detection:
  enable_detection_engine: true
  rules_config: /opt/flowenricher/etc/detection.yml
  flow_cache_max_window: 60s
  debug_detection: false

# To enable blackhole in routers like Mikrotik please add a blackhole IP like this
# /ip route add dst-address=192.0.2.1/32 blackhole comment="BGP Blackhole Nexthop"
```

---

## 🧠 Enrichment Logic

- **GeoIP** → uses MaxMind ASN & City DBs
- **BGP** → loaded from JSON prefix table
- **PTR** → reverse DNS lookup
- **Cache** → sync.Map for everything

Because why enrich the same scanner twice? 😏

---

## 🧪 Sample Query (ClickHouse)

```sql
SELECT
  timestamp_start,
  src_host,
  dst_host,
  peer_src_as,
  peer_dst_as,
  as_path,
  dst_as,
  src_host_country,
  peer_dst_as_name
FROM pmacct.flows
ORDER BY ingested_at DESC
LIMIT 10;
```

---

## 🗃 ClickHouse Schema

```sql
CREATE TABLE pmacct.flows (
    timestamp_start DateTime,
    proto UInt8,
    tcpflags UInt8,
    tos UInt8,
    src_host String,
    src_port UInt16,
    src_host_country String,
    dst_host String,
    dst_port UInt16,
    dst_host_country String,
    peer_src_as UInt32,
    peer_dst_as UInt32,
    as_path Array(String),
    packets UInt64,
    bytes UInt64,
    peer_dst_as_name String DEFAULT '',
    peer_src_as_name String DEFAULT '',
    dst_as UInt32,
    ingested_at DateTime DEFAULT now(),
    local_pref UInt32 DEFAULT 0,
    input_interface UInt32,
    output_interface UInt32,
    input_interface_name String,
    output_interface_name String,
    flow_direction UInt8,
    ip_protocol UInt8
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp_start)
ORDER BY timestamp_start
TTL timestamp_start + toIntervalMonth(3)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ptr_cache (
    ip String,
    ptr String,
    updated_at DateTime DEFAULT now(),
    asn UInt32 DEFAULT 0,
    asn_name String DEFAULT '',
    country String DEFAULT ''
) ENGINE = MergeTree
ORDER BY ip
SETTINGS index_granularity = 8192;
```

---

## 🚀 Running

```bash
go build -o flowenricher
./flowenricher --config config.yaml --rules detection.yml
```
