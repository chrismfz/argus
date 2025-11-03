package detection

import (
	"fmt"
	"log"
	"time"
	"strings"
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

        // Decide target (default "src", optional "dst")
        targetIP := flows[0].SrcIP
        if strings.ToLower(rule.BlackholeTarget) == "dst" {
                targetIP = flows[0].DstIP
        }

        // Safeguard 1: file-based protection list
        if ok, why := ShouldExecuteBlackhole(rule.Name, targetIP); !ok {
                log.Printf("[SAFEGUARD] skipping blackhole for %s (rule=%s reason=%s); logging only", targetIP, rule.Name, why)
                // Still log an 'ALERT-like' line to blackholes.txt for audit
                timestamp := time.Now().Format(time.RFC3339)
                LogBlackhole(fmt.Sprintf("[%s] BLACKHOLE-SKIPPED: Rule='%s' | SRC: %s | Reason=%s",
                        timestamp, rule.Name, targetIP, why))
                return
        }


        // Safeguard 2: treat myNets as protected (auto-skip)
        if isMyPrefix(targetIP, e.myNets) {
                log.Printf("[SAFEGUARD] skipping blackhole for %s (rule=%s reason=myNets)", targetIP, rule.Name)
                timestamp := time.Now().Format(time.RFC3339)
                LogBlackhole(fmt.Sprintf("[%s] BLACKHOLE-SKIPPED: Rule='%s' | TARGET: %s | Reason=myNets",
                        timestamp, rule.Name, targetIP))
                return
        }


        prefix := fmt.Sprintf("%s/32", targetIP)


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
		if t, err := e.store.IncrementCount("bh-escalate:"+rule.Name, targetIP); err == nil && t > 0 {
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

        LogBlackhole(fmt.Sprintf("[%s] BLACKHOLE: Rule='%s' | SRC: %s", timestamp, rule.Name, targetIP))

	// Enrichment
        ptr := e.DNS.LookupPTR(targetIP)
        asn := e.Geo.GetASNNumber(targetIP)
        asnName := e.Geo.GetASNName(targetIP)
        country := e.Geo.GetCountry(targetIP)


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
		targetIP, ptr, asn, asnName, country))

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
    if err := e.reporter.ReportBlock(targetIP, fmt.Sprintf("Rule=%s; %s", rule.Name, reason), ttl); err != nil {
        log.Printf("[CFM] report block failed ip=%s err=%v", targetIP, err)
    }
}




	// Auto-withdraw μόνο όταν ttl > 0 (όχι για permanent)
	if ttl > 0 {
		duration := time.Duration(ttl) * time.Second
		go func(prefix string, duration time.Duration, ruleName, targetIP string) {
			<-time.After(duration)
			err := bgp.WithdrawPrefix(prefix)
			timestamp := time.Now().Format(time.RFC3339)
			if err != nil {
				log.Printf("[BLACKHOLE] Withdraw failed for %s: %v", prefix, err)
			} else {
				log.Printf("[BLACKHOLE] Withdrawn %s after %v", prefix, duration)
				LogBlackhole(fmt.Sprintf("[%s] WITHDRAW: Rule='%s' | SRC: %s", timestamp, ruleName, targetIP))
if e.reporter != nil {
    if err := e.reporter.ReportUnblock(targetIP, "auto", "TTL expired"); err != nil {
        log.Printf("[CFM] report unblock failed ip=%s err=%v", targetIP, err)
    }
}


			}
		}(prefix, duration, rule.Name, targetIP)
	}
}

