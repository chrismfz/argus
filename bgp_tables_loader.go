package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
)

type BGPEntry struct {
	Prefix *net.IPNet
	ASPath []string
}

type BGPTable struct {
	sync.RWMutex
	Path       string
	LastMtime  time.Time
	Entries    []BGPEntry
	Cache      map[string][]string
	Ranger     cidranger.Ranger
	PrefixMap  map[string][]string // NEW: prefix string → AS path
}

func NewBGPTable(path string) *BGPTable {
	t := &BGPTable{
		Path:      path,
		Cache:     make(map[string][]string),
		Ranger:    cidranger.NewPCTrieRanger(),
		PrefixMap: make(map[string][]string),
	}
	t.Reload()
	go t.WatchForChanges()
	return t
}

func (b *BGPTable) WatchForChanges() {
	for {
		time.Sleep(15 * time.Minute)
		b.Reload()
	}
}

func (b *BGPTable) Reload() {
	info, err := os.Stat(b.Path)
	if err != nil {
		dlog("Failed to stat BGP table: %v", err)
		return
	}
	if !info.ModTime().After(b.LastMtime) {
		dlog("BGP table unchanged")
		return
	}
	dlog("Reloading BGP table from: %s", b.Path)

	f, err := os.Open(b.Path)
	if err != nil {
		log.Printf("[ERROR] Cannot open BGP file: %v", err)
		return
	}
	defer f.Close()

	var entries []BGPEntry
	tempRanger := cidranger.NewPCTrieRanger()
	tempMap := make(map[string][]string)

	decoder := json.NewDecoder(f)
	for {
		var line map[string]interface{}
		if err := decoder.Decode(&line); err != nil {
			break
		}

		if line["event_type"] != "dump" {
			continue
		}

		prefixStr, ok := line["ip_prefix"].(string)
		if !ok {
			continue
		}
		_, ipNet, err := net.ParseCIDR(prefixStr)
		if err != nil {
			continue
		}

		var path []string
		switch v := line["as_path"].(type) {
		case string:
			path = splitASPath(v)
		case []interface{}:
			for _, p := range v {
				if s, ok := p.(string); ok {
					path = append(path, s)
				}
			}
		}

		entry := BGPEntry{
			Prefix: ipNet,
			ASPath: path,
		}
		tempRanger.Insert(cidranger.NewBasicRangerEntry(*ipNet))
		entries = append(entries, entry)
		tempMap[ipNet.String()] = path // save to PrefixMap
	}

	b.Lock()
	b.Entries = entries
	b.LastMtime = info.ModTime()
	b.Cache = make(map[string][]string)
	b.Ranger = tempRanger
	b.PrefixMap = tempMap
	b.Unlock()

	dlog("Loaded %d BGP entries", len(entries))
	dlog("Reloaded BGP table: %d entries at %s", len(entries), b.LastMtime.Format("2006-01-02 15:04:05"))
}

func (b *BGPTable) FindASPath(ipStr string) []string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Cache check
	b.RLock()
	if cached, ok := b.Cache[ipStr]; ok {
		b.RUnlock()
		return cached
	}
	b.RUnlock()

	var asPath []string

	// Find best match via cidranger
	b.RLock()
	entries, err := b.Ranger.ContainingNetworks(ip)
	b.RUnlock()

	if err == nil && len(entries) > 0 {
		bestMask := -1
		var bestPrefix string

		for _, entry := range entries {
			ipnet := entry.Network()
			mask, _ := ipnet.Mask.Size()
			if mask > bestMask {
				bestMask = mask
				bestPrefix = ipnet.String()
			}
		}

		// Direct map lookup
		b.RLock()
		asPath = b.PrefixMap[bestPrefix]
		b.RUnlock()

		dlog("Matched %s with best prefix %s => %v", ipStr, bestPrefix, asPath)
	} else {
		dlog("No BGP match for %s", ipStr)
	}

	// Save to cache
	b.Lock()
	b.Cache[ipStr] = asPath
	b.Unlock()

	return asPath
}

func splitASPath(path string) []string {
	var result []string
	for _, s := range splitSpace(path) {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func splitSpace(s string) []string {
	var out []string
	curr := ""
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if curr != "" {
				out = append(out, curr)
				curr = ""
			}
		} else {
			curr += string(c)
		}
	}
	if curr != "" {
		out = append(out, curr)
	}
	return out
}




func (b *BGPTable) FindASPathBatch(ips []string) map[string][]string {
    results := make(map[string][]string, len(ips))
    var wg sync.WaitGroup
    var lock sync.Mutex

    for _, ipStr := range ips {
        ipStr := ipStr // capture loop var
        wg.Add(1)
        go func() {
            defer wg.Done()
            ip := net.ParseIP(ipStr)
            if ip == nil {
                return
            }

            b.RLock()
            if cached, ok := b.Cache[ipStr]; ok {
                b.RUnlock()
                lock.Lock()
                results[ipStr] = cached
                lock.Unlock()
                return
            }
            b.RUnlock()

            var bestPrefix string
            var bestPath []string
            var bestMask int = -1

            b.RLock()
            entries, err := b.Ranger.ContainingNetworks(ip)
            b.RUnlock()
            if err == nil {
                for _, entry := range entries {
                    ipnet := entry.Network()
                    mask, _ := ipnet.Mask.Size()
                    if mask > bestMask {
                        bestMask = mask
                        bestPrefix = ipnet.String()
                    }
                }
            }

            if bestPrefix != "" {
                b.RLock()
                for _, bgpEntry := range b.Entries {
                    if bgpEntry.Prefix.String() == bestPrefix {
                        bestPath = bgpEntry.ASPath
                        break
                    }
                }
                b.RUnlock()
            }

            b.Lock()
            b.Cache[ipStr] = bestPath
            b.Unlock()

            lock.Lock()
            results[ipStr] = bestPath
            lock.Unlock()
        }()
    }

    wg.Wait()
    return results
}
