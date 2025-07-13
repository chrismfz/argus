# flowenricher

`flowenricher` is a real-time NetFlow/IPFIX enrichment and ingestion engine written in Go. It processes JSON-formatted flow logs (typically from `nfacctd`), enriches them with GeoIP, ASN, BGP AS paths, and PTR (reverse DNS), and inserts them into a ClickHouse database for lightning-fast analytics.

---

## ✨ Features

- ✅ **Enriches flows with:**
  - Autonomous System Numbers (ASN)
  - ASN organization names
  - BGP AS Path from prefix table
  - Country & city (GeoIP2)
  - Reverse DNS (PTR)
- ✅ **High-performance** batching and parallel processing
- ✅ Built-in **Kafka consumer** for real-time stream processing
- ✅ Automatic BGP prefix table reload (JSON format)
- ✅ ClickHouse batch insertion
- ✅ Modular enrichment (enable/disable via config)
- ✅ Supports caching of expensive lookups

---

## 📦 Architecture Overview

[nfacctd] → [Kafka] → [flowenricher] → [Enrich (GeoIP + BGP + PTR)] → [ClickHouse]


---

## ⚙️ Configuration

All configuration is stored in `config.yaml`. Example:

```yaml
clickhouse:
  host: "localhost"
  port: 9000
  username: "default"
  password: ""
  database: "pmacct"
  table: "flows"

geoip:
  asn_db: "/etc/pmacct/GeoLite2-ASN.mmdb"
  city_db: "/etc/pmacct/GeoLite2-City.mmdb"

dns:
  nameserver: "1.1.1.1"

bgp:
  table_file: "/var/log/nfacctd/bgp_table.json"

kafka:
  brokers:
    - "localhost:9092"
  topic: "netflow"
  group_id: "flowenricher-group"

insert:
  batch_size: 500
  flush_interval_ms: 1000

timezone: "Europe/Athens"

enrich: "geoip,bgp,ptr"

debug: false
```

🚀 Running
go build -o flowenricher
./flowenricher [--debug] [--show-flows] [config.yaml] [--help]

🧠 Enrichment Logic

    GeoIP: uses MaxMind GeoLite2 ASN & City databases.

    BGP: loads prefix-to-AS path mapping from JSON file exported by nfacctd.

    PTR: uses a DNS resolver (e.g., 1.1.1.1) to look up reverse hostnames.

    Caching: All enrichment lookups are cached in memory using sync.Map.

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


🗃 Schema (ClickHouse Table)

Make sure your ClickHouse table matches:
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
    peer_dst_as_name String,
    peer_src_as_name String,
    dst_as UInt32,
    src_host_ptr String,
    dst_host_ptr String,
    ingested_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (timestamp_start, src_host, dst_host);


---> nfacctd.conf Example:

```yaml
 
! nfacctd configuration
daemonize: false
pidfile: /var/run/nfacctd.pid
syslog: daemon
logfile: /var/log/nfacctd/daemon.log

nfacctd_ip: 0.0.0.0
nfprobe_receiver: true
nfacctd_port: 2055

! Enable BGP enrichment
bgp_daemon: true
bgp_daemon_ip: 0.0.0.0
bgp_daemon_max_peers: 4
bgp_daemon_as: 65000
nfacctd_as: bgp
bgp_agent_map: /etc/pmacct/agent_map.map
pmacctd_as: bgp

geoipv2_file: /etc/pmacct/GeoLite2-Country.mmdb
as_path_encode_as_array: true

aggregate: timestamp_start, proto, tcpflags, tos, src_host, src_port, src_host_country, dst_host, dst_port, dst_host_country, peer_src_as, peer_dst_as, as_path

plugins: kafka
kafka_broker_host: 127.0.0.1
kafka_broker_port: 9092
kafka_topic: netflow
kafka_format: json
kafka_refresh_time: 2
kafka_history: 5
kafka_partition_key: src_host
kafka_async: true
kafka_debug: false

bgp_table_dump_file: /var/log/nfacctd/bgp_table.json
bgp_table_dump_refresh_time: 120
 </details> 
 

```
:-)
