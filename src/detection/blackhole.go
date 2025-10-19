package detection

import (
	"fmt"
	"log"
	"time"
	"flowenricher/config"
	"flowenricher/bgp"
        "flowenricher/enrich"

)

//helper functions
func GetASN(ip string) uint32 {
	return enrich.Global.Geo.GetASNNumber(ip)
}

func GetASNName(ip string) string {
	return enrich.Global.Geo.GetASNName(ip)
}

func GetCountry(ip string) string {
	return enrich.Global.Geo.GetCountry(ip)
}

func GetPTR(ip string) string {
	return enrich.Global.DNS.LookupPTR(ip)
}

// helper functions end


func (e *Engine) HandleBlackhole(rule DetectionRule, flows []Flow, count int) {
	srcIP := flows[0].SrcIP
	prefix := fmt.Sprintf("%s/32", srcIP)

	// Αποφυγή διπλής ανακοίνωσης
	if _, already := bgp.ListAnnouncements()[prefix]; already {
		return
	}

	// Next-hop
	nextHop := rule.BlackholeNextHop
	if nextHop == "" {
		nextHop = bgp.LocalBGPAddress
		if nextHop == "" {
			nextHop = "192.0.2.1"
		}
	}

	// Communities
	communities := rule.BlackholeCommunities
	if len(communities) == 0 {
		communities = []string{"65001:666"} // default fallback
	}

	// Ανακοίνωση
	if err := bgp.AnnouncePrefix(prefix, nextHop, communities, []uint32{config.GetLocalASN()}); err != nil {
		log.Printf("[BLACKHOLE] Failed to announce %s: %v", prefix, err)
		return
	}

	// ── Escalation TTL: επιλέγουμε διάρκεια με βάση πόσες φορές έχει φάει blackhole αυτή η IP για αυτόν τον κανόνα
	durations := rule.BlackholeDurations() // από rules.go helper
	// πόσες blackhole-ανακοινώσεις έχουμε ήδη κάνει για την IP στον κανόνα αυτό;
	times := 1
	if e.store != nil {
		if t, err := e.store.IncrementCount("bh-escalate:"+rule.Name, srcIP); err == nil && t > 0 {
			times = t
		}
	}
	ttl := 0 // default = permanent
	if len(durations) > 0 {
		idx := times - 1
		if idx >= len(durations) {
			idx = len(durations) - 1
		}
		ttl = durations[idx]
	}

	reason := buildReason(rule)
	timestamp := time.Now().Format(time.RFC3339)

	if ttl == 0 {
		log.Printf("[BLACKHOLE] Announced %s (rule: %s) PERMANENT (escalation #%d)", prefix, rule.Name, times)
	} else {
		log.Printf("[BLACKHOLE] Announced %s (rule: %s) ttl=%ds (escalation #%d)", prefix, rule.Name, ttl, times)
	}
	LogBlackhole(fmt.Sprintf("[%s] BLACKHOLE: Rule='%s' | SRC: %s", timestamp, rule.Name, srcIP))

	// Enrichment
	ptr := e.DNS.LookupPTR(srcIP)
	asn := e.Geo.GetASNNumber(srcIP)
	asnName := e.Geo.GetASNName(srcIP)
	country := e.Geo.GetCountry(srcIP)

	if ptr == "" {
		ptr = "NoPTR"
	}
	if asnName == "" {
		asnName = "Unknown"
	}
	if country == "" {
		country = "Unknown"
	}

	LogBlackhole(fmt.Sprintf("         SRC: %-15s | PTR: %-30s | ASN: AS%d (%s) | Country: %s",
		srcIP, ptr, asn, asnName, country))

	// ✅ SQLite insert (αν χρησιμοποιείται SQLiteStore)
	if s, ok := e.store.(*SQLiteStore); ok {
		const farFuture = "9999-12-31T00:00:00Z" // marker για permanent
		expires := farFuture
		if ttl > 0 {
			expires = time.Now().Add(time.Duration(ttl) * time.Second).Format(time.RFC3339)
		}
		if err := s.InsertBlackhole(
			prefix,
			timestamp,
			expires,
			rule.Name,
			reason,
			fmt.Sprintf("AS%d", asn),
			asnName,
			country,
			ptr,
		); err != nil {
			log.Printf("[BLACKHOLE] Failed to insert %s into SQLite: %v", prefix, err)
		}
	}

//cfm api reporter
if e.reporter != nil {
    if err := e.reporter.ReportBlock(srcIP, fmt.Sprintf("Rule=%s; %s", rule.Name, reason), ttl); err != nil {
        log.Printf("[CFM] report block failed ip=%s err=%v", srcIP, err)
    }
}


if e.reporter != nil {
    if err := e.reporter.ReportUnblock(srcIP, "auto", "TTL expired"); err != nil {
        log.Printf("[CFM] report unblock failed ip=%s err=%v", srcIP, err)
    }
}


	// Auto-withdraw μόνο όταν ttl > 0 (όχι για permanent)
	if ttl > 0 {
		duration := time.Duration(ttl) * time.Second
		go func(prefix string, duration time.Duration, ruleName, srcIP string) {
			<-time.After(duration)
			err := bgp.WithdrawPrefix(prefix)
			timestamp := time.Now().Format(time.RFC3339)
			if err != nil {
				log.Printf("[BLACKHOLE] Withdraw failed for %s: %v", prefix, err)
			} else {
				log.Printf("[BLACKHOLE] Withdrawn %s after %v", prefix, duration)
				LogBlackhole(fmt.Sprintf("[%s] WITHDRAW: Rule='%s' | SRC: %s", timestamp, ruleName, srcIP))
			}
		}(prefix, duration, rule.Name, srcIP)
	}
}

