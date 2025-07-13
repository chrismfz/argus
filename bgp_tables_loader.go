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
}

func NewBGPTable(path string) *BGPTable {
	t := &BGPTable{
		Path:  path,
		Cache: make(map[string][]string),
		Ranger: cidranger.NewPCTrieRanger(),
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
	}

	b.Lock()
	b.Entries = entries
	b.LastMtime = info.ModTime()
	b.Cache = make(map[string][]string)
	b.Ranger = tempRanger
	b.Unlock()

	dlog("Loaded %d BGP entries", len(entries))
	dlog("Reloaded BGP table: %d entries at %s", len(entries), b.LastMtime.Format("2006-01-02 15:04:05"))
}

func (b *BGPTable) FindASPath(ipStr string) []string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Check cache
	b.RLock()
	if cached, ok := b.Cache[ipStr]; ok {
		b.RUnlock()
		return cached
	}
	b.RUnlock()

	var asPath []string

	// Lookup prefix matches
	b.RLock()
	entries, err := b.Ranger.ContainingNetworks(ip)
	b.RUnlock()

	if err == nil && len(entries) > 0 {
		bestMask := -1
		var bestPrefix string

		for _, entry := range entries {
			ipnet := entry.Network() // returns only *net.IPNet

			mask, _ := ipnet.Mask.Size()
			if mask > bestMask {
				bestMask = mask
				bestPrefix = ipnet.String()
			}
		}

		// find BGPEntry by prefix string
		if bestMask > -1 {
			b.RLock()
			for _, bgpEntry := range b.Entries {
				if bgpEntry.Prefix.String() == bestPrefix {
					asPath = bgpEntry.ASPath
					break
				}
			}
			b.RUnlock()
			dlog("Matched %s with best prefix %s => %v", ipStr, bestPrefix, asPath)
		}
	} else {
		dlog("No BGP match for %s", ipStr)
	}

	// Cache result
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
