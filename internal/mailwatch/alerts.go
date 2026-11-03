package mailwatch

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sort"
	"time"
)

// AlertConfig controls the baseline alerts evaluated after every bucket flush.
// They see the sender's whole history, which the 60s detection rules cannot.
type AlertConfig struct {
	Enabled          bool
	LearningPeriod   time.Duration // no new-sender alerts until the history is this old
	NewSenderMinDsts int           // new sender alerts at this many distinct destinations in one bucket
	SpikeMinDsts     int           // spike floor: never alert below this many distinct destinations
	SpikeFactor      float64       // spike = distinct destinations >= factor × the sender's own p95
	BaselineWindow   time.Duration // how far back the p95 looks
	Cooldown         time.Duration // per (sender, port, kind)
}

// Alert kinds.
const (
	AlertNewSender = "new_sender"
	AlertSpike     = "spike"
)

// Alert is one baseline alert, stored in mail_egress_alerts and handed to the
// notifier (alerter dispatcher in main).
type Alert struct {
	ID        int64    `json:"id,omitempty"`
	Ts        int64    `json:"ts"` // bucket start
	IP        string   `json:"ip"`
	Port      int      `json:"port"`
	Kind      string   `json:"kind"`
	Severity  string   `json:"severity"` // warning | critical
	UniqDsts  int      `json:"uniq_dsts"`
	Flows     uint64   `json:"flows"`
	Baseline  float64  `json:"baseline_p95"` // sender's p95 distinct destinations per active bucket
	Threshold int      `json:"threshold"`
	TopDsts   []TopDst `json:"top_dsts"`
	TopASNs   []TopASN `json:"top_asns"`
}

// Summary is a one-line human description.
func (a Alert) Summary() string {
	switch a.Kind {
	case AlertNewSender:
		return fmt.Sprintf("new mail sender %s:%d — %d distinct destinations, %d flows in one bucket (never sent mail before)",
			a.IP, a.Port, a.UniqDsts, a.Flows)
	default:
		return fmt.Sprintf("mail spike from %s:%d — %d distinct destinations, %d flows in one bucket (threshold %d, own p95 %.1f)",
			a.IP, a.Port, a.UniqDsts, a.Flows, a.Threshold, a.Baseline)
	}
}

// SetAlerts enables baseline alerts. notify may be nil (log + table only).
// Call before Run.
func (t *Tracker) SetAlerts(cfg AlertConfig, notify func(Alert)) {
	t.alerts = cfg
	t.notify = notify
	t.lastAlert = map[string]time.Time{}
}

type preContext struct {
	known        map[string]bool // senders with a memory row before this bucket
	historyStart int64           // oldest first_seen of any sender (0 = no history)
}

func (t *Tracker) alertContext(db *sql.DB, cur map[key]*agg) preContext {
	pc := preContext{known: map[string]bool{}}
	if !t.alerts.Enabled || db == nil {
		return pc
	}
	_ = db.QueryRow(`SELECT COALESCE(min(first_seen), 0) FROM mail_egress_senders`).Scan(&pc.historyStart)
	seen := map[string]bool{}
	for k := range cur {
		if seen[k.src] {
			continue
		}
		seen[k.src] = true
		var one int
		if err := db.QueryRow(`SELECT 1 FROM mail_egress_senders WHERE src_ip = ?`, k.src).Scan(&one); err == nil {
			pc.known[k.src] = true
		}
	}
	return pc
}

// p95 of the sender's distinct destinations over its active buckets in
// [from, before). Returns the value and how many buckets it came from.
func p95Dsts(db *sql.DB, ip string, port uint16, from, before int64) (float64, int) {
	rows, err := db.Query(`SELECT uniq_dsts FROM mail_egress_buckets
		WHERE src_ip = ? AND port = ? AND ts >= ? AND ts < ?`, ip, port, from, before)
	if err != nil {
		return 0, 0
	}
	defer rows.Close()
	var v []int
	for rows.Next() {
		var n int
		if rows.Scan(&n) == nil {
			v = append(v, n)
		}
	}
	if len(v) == 0 {
		return 0, 0
	}
	sort.Ints(v)
	return float64(v[int(math.Ceil(0.95*float64(len(v))))-1]), len(v)
}

func (t *Tracker) evaluate(db *sql.DB, start time.Time, cur map[key]*agg, pc preContext) {
	ac := t.alerts
	if !ac.Enabled || db == nil {
		return
	}
	ts := start.Unix()
	learned := pc.historyStart > 0 && ts-pc.historyStart >= int64(ac.LearningPeriod.Seconds())
	minDsts := ac.SpikeMinDsts
	if ac.NewSenderMinDsts < minDsts {
		minDsts = ac.NewSenderMinDsts
	}

	var fired []Alert
	for k, a := range cur {
		n := len(a.dsts)
		if n < minDsts {
			continue
		}
		mk := func(kind string, base float64, thr int) Alert {
			sev := "warning"
			if n >= 4*ac.SpikeMinDsts {
				sev = "critical"
			}
			return Alert{Ts: ts, IP: k.src, Port: int(k.port), Kind: kind, Severity: sev,
				UniqDsts: n, Flows: a.flows, Baseline: base, Threshold: thr,
				TopDsts: topDsts(a.dsts, t.cfg.TopN), TopASNs: topASNs(a.asns, t.cfg.TopN)}
		}
		if learned && !pc.known[k.src] && n >= ac.NewSenderMinDsts {
			fired = append(fired, mk(AlertNewSender, 0, ac.NewSenderMinDsts))
			continue
		}
		base, _ := p95Dsts(db, k.src, k.port, ts-int64(ac.BaselineWindow.Seconds()), ts)
		thr := int(math.Ceil(ac.SpikeFactor * base))
		if thr < ac.SpikeMinDsts {
			thr = ac.SpikeMinDsts
		}
		if n >= thr {
			fired = append(fired, mk(AlertSpike, base, thr))
		}
	}

	for _, al := range fired {
		ck := fmt.Sprintf("%s|%d|%s", al.IP, al.Port, al.Kind)
		if last, ok := t.lastAlert[ck]; ok && start.Sub(last) < ac.Cooldown {
			continue
		}
		t.lastAlert[ck] = start
		log.Printf("[mailwatch] ALERT %s: %s", al.Severity, al.Summary())
		if err := insertAlert(db, &al); err != nil {
			log.Printf("[mailwatch] store alert %s: %v", al.IP, err)
		}
		if t.notify != nil {
			t.notify(al)
		}
	}
	// Forget expired cooldowns so the map stays bounded.
	for ck, last := range t.lastAlert {
		if start.Sub(last) >= ac.Cooldown {
			delete(t.lastAlert, ck)
		}
	}
}

func insertAlert(db *sql.DB, a *Alert) error {
	td, _ := json.Marshal(a.TopDsts)
	ta, _ := json.Marshal(a.TopASNs)
	res, err := db.Exec(`INSERT INTO mail_egress_alerts
		(ts, src_ip, port, kind, severity, uniq_dsts, flows, baseline, threshold, top_dsts, top_asns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Ts, a.IP, a.Port, a.Kind, a.Severity, a.UniqDsts, a.Flows, a.Baseline, a.Threshold, string(td), string(ta))
	if err != nil {
		return err
	}
	a.ID, _ = res.LastInsertId()
	return nil
}

// Alerts lists stored alerts since `since`, newest first; ip "" = all.
func Alerts(db *sql.DB, since time.Time, ip string, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT id, ts, src_ip, port, kind, severity, uniq_dsts, flows, baseline, threshold, top_dsts, top_asns
		FROM mail_egress_alerts WHERE ts >= ?`
	args := []any{since.Unix()}
	if ip != "" {
		q += ` AND src_ip = ?`
		args = append(args, ip)
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var td, ta string
		if err := rows.Scan(&a.ID, &a.Ts, &a.IP, &a.Port, &a.Kind, &a.Severity, &a.UniqDsts, &a.Flows,
			&a.Baseline, &a.Threshold, &td, &ta); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(td), &a.TopDsts)
		_ = json.Unmarshal([]byte(ta), &a.TopASNs)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PruneAlerts deletes alerts older than maxAge; <= 0 keeps them forever.
func PruneAlerts(db *sql.DB, maxAge time.Duration) error {
	if db == nil || maxAge <= 0 {
		return nil
	}
	res, err := db.Exec(`DELETE FROM mail_egress_alerts WHERE ts < ?`, time.Now().Add(-maxAge).Unix())
	if err != nil {
		return fmt.Errorf("prune mail_egress_alerts: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[mailwatch] pruned %d alerts older than %s", n, maxAge)
	}
	return nil
}
