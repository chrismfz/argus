package detection

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"argus/internal/bgp"
)

// BHSourceExclude marks blackholes withdrawn because an exclusion now covers them.
const BHSourceExclude = "exclude"

// prefixIP returns the address part of "1.2.3.4/32" (or a bare IP unchanged).
func prefixIP(prefix string) string {
	if i := strings.IndexByte(prefix, '/'); i != -1 {
		return prefix[:i]
	}
	return prefix
}

// WithdrawProtectedBlackholes withdraws every stored blackhole whose address is
// now on the protection list (detection_excludes / exclude.detections.conf).
//
// An exclusion only stops *new* blackholes in HandleBlackhole; without this, a
// blackhole announced before the exclusion was added — permanent ones above
// all — stays announced, and RestoreActiveBlackholes would not bring it back
// but its row would linger. Call it after the protection list is (re)loaded.
// reporter may be nil (CFM disabled). Returns how many were withdrawn.
func WithdrawProtectedBlackholes(db *sql.DB, reporter Reporter) (int, error) {
	return withdrawProtectedBlackholes(db, reporter, func(prefix string) error {
		// Already gone from GoBGP (e.g. restore skipped it): just drop the row.
		if _, ok := bgp.ListAnnouncements()[prefix]; !ok {
			return nil
		}
		return bgp.WithdrawPrefix(prefix)
	})
}

func withdrawProtectedBlackholes(db *sql.DB, reporter Reporter, withdraw func(prefix string) error) (int, error) {
	if db == nil {
		return 0, nil
	}
	// All rows, expired or not: an expired-but-uncleaned protected row is
	// withdrawn here just the same, which the cleanup ticker would do anyway.
	rows, err := db.Query(`SELECT prefix, COALESCE(rule, '') FROM blackholes`)
	if err != nil {
		return 0, fmt.Errorf("query blackholes: %w", err)
	}
	type bhRow struct{ prefix, rule string }
	var protected []bhRow
	for rows.Next() {
		var r bhRow
		if err := rows.Scan(&r.prefix, &r.rule); err != nil {
			continue
		}
		if IsProtected(prefixIP(r.prefix)) {
			protected = append(protected, r)
		}
	}
	rows.Close()

	n := 0
	for _, r := range protected {
		if err := withdraw(r.prefix); err != nil {
			// Keep the row so the next reload retries.
			log.Printf("[SAFEGUARD] failed to withdraw protected blackhole %s: %v", r.prefix, err)
			continue
		}
		if _, err := db.Exec(`DELETE FROM blackholes WHERE prefix = ?`, r.prefix); err != nil {
			log.Printf("[SAFEGUARD] failed to delete protected blackhole %s: %v", r.prefix, err)
		}
		RecordBlackholeEvent(db, BlackholeEvent{
			IP:     prefixIP(r.prefix),
			Prefix: r.prefix,
			Event:  BHEventWithdrawn,
			Source: BHSourceExclude,
			Rule:   r.rule,
			Reason: "covered by detection exclusion",
		})
		if reporter != nil {
			if err := reporter.ReportUnblock(prefixIP(r.prefix), "auto", "detection exclusion"); err != nil {
				log.Printf("[CFM] report unblock failed ip=%s err=%v", prefixIP(r.prefix), err)
			}
		}
		log.Printf("[SAFEGUARD] withdrew blackhole %s (rule=%s): covered by a detection exclusion", r.prefix, r.rule)
		n++
	}
	return n, nil
}
