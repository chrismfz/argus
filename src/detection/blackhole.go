package detection

import (
	"fmt"
	"log"
	"time"

	"flowenricher/bgp"
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

	err := bgp.AnnouncePrefix(prefix, nextHop, communities)
	if err != nil {
		log.Printf("[BLACKHOLE] Failed to announce %s: %v", prefix, err)
		return
	}

	timestamp := time.Now().Format(time.RFC3339)
	log.Printf("[BLACKHOLE] Announced %s (rule: %s)", prefix, rule.Name)
	LogBlackhole(fmt.Sprintf("[%s] BLACKHOLE: Rule='%s' | SRC: %s", timestamp, rule.Name, srcIP))

	// Optional auto-withdraw
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
