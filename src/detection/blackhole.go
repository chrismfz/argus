package detection

import (
	"fmt"
	"log"
	"time"
	"flowenricher/config"
	"flowenricher/bgp"
        "flowenricher/enrich"

)


func (e *Engine) HandleBlackhole(rule DetectionRule, flows []Flow, count int) {
	srcIP := flows[0].SrcIP
	prefix := fmt.Sprintf("%s/32", srcIP)

	// avoid duplicate announce
	if _, already := bgp.ListAnnouncements()[prefix]; already {
		return
	}

	nextHop := rule.BlackholeNextHop
	if nextHop == "" {
		nextHop = bgp.LocalBGPAddress
		if nextHop == "" {
			nextHop = "192.0.2.1"
		}
	}

	communities := rule.BlackholeCommunities
	if len(communities) == 0 {
		communities = []string{"65001:666"} // default fallback
	}

	err := bgp.AnnouncePrefix(prefix, nextHop, communities, []uint32{config.GetLocalASN()})
	if err != nil {
		log.Printf("[BLACKHOLE] Failed to announce %s: %v", prefix, err)
		return
	}

	reason := buildReason(rule)
	timestamp := time.Now().Format(time.RFC3339)
	log.Printf("[BLACKHOLE] Announced %s (rule: %s)", prefix, rule.Name)
	LogBlackhole(fmt.Sprintf("[%s] BLACKHOLE: Rule='%s' | SRC: %s", timestamp, rule.Name, srcIP))

	// enrichment
	ptr := e.DNS.LookupPTR(srcIP)
	asn := e.Geo.GetASNNumber(srcIP)
	asnName := e.Geo.GetASNName(srcIP)
	country := e.Geo.GetCountry(srcIP)

	if ptr == "" {
		ptr = "-"
	}
	if asnName == "" {
		asnName = "Unknown"
	}
	if country == "" {
		country = "--"
	}

	LogBlackhole(fmt.Sprintf("         SRC: %-15s | PTR: %-30s | ASN: AS%d (%s) | Country: %s",
		srcIP, ptr, asn, asnName, country))

	// ✅ SQLite insert only if using SQLiteStore
	if s, ok := e.store.(*SQLiteStore); ok {
		expires := time.Now().Add(time.Duration(rule.BlackholeTime) * time.Second).Format(time.RFC3339)
		err := s.InsertBlackhole(
			prefix,
			timestamp,
			expires,
			rule.Name,
			reason,
			fmt.Sprintf("AS%d", asn),
			asnName,
			country,
			ptr,
		)
		if err != nil {
			log.Printf("[BLACKHOLE] Failed to insert %s into SQLite: %v", prefix, err)
		}
	}

	// Optional auto-withdraw (only relevant if SQLite cleanup is disabled)
	if rule.BlackholeTime > 0 {
		duration := time.Duration(rule.BlackholeTime) * time.Second
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
