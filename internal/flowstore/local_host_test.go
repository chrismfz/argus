package flowstore

import (
	"database/sql"
	"testing"
)

// insTopIPFull inserts one 30-min detail row with an explicit local_ip, so the
// per-local-host queries can be exercised across hosts/dirs/peers/ports.
func insTopIPFull(t *testing.T, db *sql.DB, ts int64, asn uint32, dir, peerIP, localIP string, port int, country string, bytes int64) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO flowstore_top_ips
		(ts, asn, dir, peer_ip, local_ip, proto, dst_port, country, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, 6, ?, ?, ?, 1, 1)`,
		ts, asn, dir, peerIP, localIP, port, country, bytes)
	if err != nil {
		t.Fatalf("insert top_ip: %v", err)
	}
}

func TestQueryLocalHostInsights(t *testing.T) {
	db := openRollupDB(t)

	const A = "84.54.49.202" // the host under investigation
	const B = "84.54.49.203" // a different local host — must not leak into A
	base := int64(1_000_000_000)
	since, until := base, base+7200 // 2h window

	// A: egress to peer .1 on POP3S (995) across two buckets, plus .2 on 443,
	// and a small ingress from .9 on 443.
	insTopIPFull(t, db, base+0, 6799, "out", "203.0.113.1", A, 995, "GR", 1000)
	insTopIPFull(t, db, base+1800, 6799, "out", "203.0.113.1", A, 995, "GR", 500)
	insTopIPFull(t, db, base+0, 6799, "out", "203.0.113.2", A, 443, "GR", 200)
	insTopIPFull(t, db, base+0, 13335, "in", "198.51.100.9", A, 443, "US", 300)
	// B's traffic must be isolated from A.
	insTopIPFull(t, db, base+0, 6799, "out", "203.0.113.9", B, 25, "GR", 9999)
	// Out of window — must be excluded (ts >= until).
	insTopIPFull(t, db, until+10, 6799, "out", "203.0.113.1", A, 995, "GR", 7777)

	ins, err := QueryLocalHostInsights(db, A, since, until, 15)
	if err != nil {
		t.Fatalf("QueryLocalHostInsights: %v", err)
	}

	if ins.OutBytes != 1700 { // 1000 + 500 + 200
		t.Fatalf("OutBytes = %d, want 1700", ins.OutBytes)
	}
	if ins.InBytes != 300 {
		t.Fatalf("InBytes = %d, want 300", ins.InBytes)
	}
	if !ins.Partial {
		t.Fatalf("Partial should be true (top-N-derived)")
	}

	// Series: bucket @base = out 1200 (1000+200) / in 300; bucket @base+1800 = out 500.
	if len(ins.Series) != 2 {
		t.Fatalf("series len = %d, want 2", len(ins.Series))
	}
	if ins.Series[0].TS != base || ins.Series[0].OutBytes != 1200 || ins.Series[0].InBytes != 300 {
		t.Fatalf("series[0] = %+v, want ts=%d out=1200 in=300", ins.Series[0], base)
	}
	if ins.Series[1].TS != base+1800 || ins.Series[1].OutBytes != 500 {
		t.Fatalf("series[1] = %+v, want ts=%d out=500", ins.Series[1], base+1800)
	}

	// Top peers, ranked by total bytes: .1 (1500 out) > .9 (300 in) > .2 (200 out).
	if len(ins.TopPeers) != 3 {
		t.Fatalf("top peers len = %d, want 3 (B must not leak in)", len(ins.TopPeers))
	}
	if ins.TopPeers[0].Key != "203.0.113.1" || ins.TopPeers[0].OutBytes != 1500 || ins.TopPeers[0].InBytes != 0 {
		t.Fatalf("top peer[0] = %+v, want .1 out=1500 in=0", ins.TopPeers[0])
	}

	// Top ports: 995 (1500) > 443 (200 out + 300 in = 500).
	if ins.TopPorts[0].Key != "995" || ins.TopPorts[0].Bytes != 1500 {
		t.Fatalf("top port[0] = %+v, want 995/1500", ins.TopPorts[0])
	}
	if ins.TopPorts[1].Key != "443" || ins.TopPorts[1].Bytes != 500 ||
		ins.TopPorts[1].InBytes != 300 || ins.TopPorts[1].OutBytes != 200 {
		t.Fatalf("top port[1] = %+v, want 443 total=500 in=300 out=200", ins.TopPorts[1])
	}

	// Top ASNs: 6799 (1700) > 13335 (300).
	if ins.TopASNs[0].Key != "6799" || ins.TopASNs[0].Bytes != 1700 {
		t.Fatalf("top asn[0] = %+v, want 6799/1700", ins.TopASNs[0])
	}
}

func TestQueryTopLocalHosts(t *testing.T) {
	db := openRollupDB(t)
	base := int64(1_000_000_000)
	insTopIPFull(t, db, base, 6799, "out", "203.0.113.1", "84.54.49.202", 995, "GR", 1700)
	insTopIPFull(t, db, base, 6799, "out", "203.0.113.9", "84.54.49.203", 25, "GR", 500)
	insTopIPFull(t, db, base, 13335, "in", "198.51.100.9", "84.54.49.202", 443, "US", 300)

	top, err := QueryTopLocalHosts(db, base-10, base+10, 10)
	if err != nil {
		t.Fatalf("QueryTopLocalHosts: %v", err)
	}
	if len(top) != 2 {
		t.Fatalf("top hosts len = %d, want 2", len(top))
	}
	if top[0].LocalIP != "84.54.49.202" || top[0].Bytes != 2000 || top[0].OutBytes != 1700 || top[0].InBytes != 300 {
		t.Fatalf("top[0] = %+v, want .202 total=2000 out=1700 in=300", top[0])
	}
	if top[1].LocalIP != "84.54.49.203" || top[1].Bytes != 500 {
		t.Fatalf("top[1] = %+v, want .203 total=500", top[1])
	}
}
