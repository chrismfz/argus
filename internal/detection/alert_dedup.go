package detection

import (
	"sync"
	"time"
)

// alertDeduper turns the per-second rule matches into incidents for the
// "alert" action. Rules are evaluated every second over a sliding window, so a
// scanner that matches for ten minutes used to write ~600 identical alert
// blocks (143k/day in production). Now an (rule, src) incident is logged when
// it starts, then at most once per cooldown while it keeps matching (with the
// number of matches suppressed in between). When it has not matched for a
// cooldown, a closing summary line is written, so no match is lost silently.
//
// It only affects logging: detection counts and the blackhole action still see
// every match.
type alertDeduper struct {
	cooldown time.Duration

	mu   sync.Mutex
	seen map[alertKey]*alertState
}

type alertKey struct{ rule, src string }

type alertState struct {
	firstSeen, lastSeen, lastLogged time.Time
	matches                         int // every match since firstSeen
	suppressed                      int // matches since lastLogged that were not logged
}

// endedIncident is an incident that stopped matching, reported once.
type endedIncident struct {
	Rule, Src           string
	FirstSeen, LastSeen time.Time
	Matches, Suppressed int
}

func newAlertDeduper(cooldown time.Duration) *alertDeduper {
	return &alertDeduper{cooldown: cooldown, seen: make(map[alertKey]*alertState)}
}

// observe records one match and says whether to log it. suppressed is how many
// matches were swallowed since the previous logged alert of this incident.
// cooldown <= 0 disables deduplication (every match is logged).
func (d *alertDeduper) observe(rule, src string, now time.Time) (log bool, suppressed int) {
	if d == nil || d.cooldown <= 0 {
		return true, 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	k := alertKey{rule, src}
	st, ok := d.seen[k]
	if !ok {
		d.seen[k] = &alertState{firstSeen: now, lastSeen: now, lastLogged: now, matches: 1}
		return true, 0
	}
	st.lastSeen = now
	st.matches++
	if now.Sub(st.lastLogged) >= d.cooldown {
		suppressed = st.suppressed
		st.suppressed = 0
		st.lastLogged = now
		return true, suppressed
	}
	st.suppressed++
	return false, 0
}

// expire forgets incidents that have not matched for a cooldown and returns
// those that ended, for a closing summary line.
func (d *alertDeduper) expire(now time.Time) []endedIncident {
	if d == nil || d.cooldown <= 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var ended []endedIncident
	for k, st := range d.seen {
		if now.Sub(st.lastSeen) < d.cooldown {
			continue
		}
		delete(d.seen, k)
		ended = append(ended, endedIncident{
			Rule: k.rule, Src: k.src,
			FirstSeen: st.firstSeen, LastSeen: st.lastSeen,
			Matches: st.matches, Suppressed: st.suppressed,
		})
	}
	return ended
}
