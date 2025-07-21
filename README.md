# flowenricher

`flowenricher` is a real-time NetFlow/IPFIX enrichment and ingestion engine written in Go. 
It works as standalone app but can also process JSON-formatted flow logs (typically from `nfacctd`), enriches them with GeoIP, ASN, BGP AS paths, and PTR (reverse DNS), and inserts them into a ClickHouse database for lightning-fast analytics. It also supports Kafka.




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
- ✅ **New** Integrated netflow collector


---

## 📦 Architecture Overview

New Structure:
[flowenricher] → [ClickHouse]

Old structure:
[nfacctd] → [Kafka] → [flowenricher] → [Enrich (GeoIP + BGP + PTR)] → [ClickHouse]


flowenricher now accepts Netflow v9 and enriches realtime with BGP + GeoIP + ASN + PTR

---

## ⚙️ Configuration

Left my (working) configuration for reference/example

All configuration is stored in `config.yaml`. Example:

```yaml

collectors:
  netflow:
    config:
      bindaddr: 0.0.0.0
      bindport: 2055
      debug: false


bgp:
  bgp_listener:
    enabled: true
    listen_ip: "0.0.0.0"
    asn: 216285
    router_id: "84.54.49.1"
    max_peers: 2


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

enrich: "geoip, bgp"
# could be geoip, bgp, ptr or none #
# surely, "none" beats the purpose of doing all this program :-) #
# ptr hammers the system be careful

insert:
  batch_size: 200
  flush_interval_ms: 1000


my_asn: 216285
my_prefixes:
  - 84.54.49.0/24
  - 194.153.116.0/24
  - 2a14:4280::/29



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
  

```
:-)
