package asnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL       = "https://api.bgpview.io"
	defaultTTL           = 15 * time.Minute
	defaultReqTimeout    = 3 * time.Second
	defaultRetryBudget   = 2 // extra attempts after first try
	defaultMaxListValues = 30
)

type OptionalField[T any] struct {
	Present bool   `json:"present"`
	Source  string `json:"source,omitempty"`
	Value   T      `json:"value,omitempty"`
}

type ObservedPathsMetadata struct {
	PathCount  int        `json:"path_count"`
	UniqueHops int        `json:"unique_hops"`
	MinHops    int        `json:"min_hops"`
	MaxHops    int        `json:"max_hops"`
	Samples    [][]uint32 `json:"samples,omitempty"`
}

type Profile struct {
	ASN                    uint32                               `json:"asn"`
	Source                 string                               `json:"source"`
	FetchedAt              time.Time                            `json:"fetched_at"`
	Name                   OptionalField[string]                `json:"name"`
	Country                OptionalField[string]                `json:"country"`
	AnnouncedPrefixesCount OptionalField[int]                   `json:"announced_prefixes_count"`
	AnnouncedPrefixes      OptionalField[[]string]              `json:"announced_prefixes"`
	PeersCount             OptionalField[int]                   `json:"peers_count"`
	Peers                  OptionalField[[]uint32]              `json:"peers"`
	IXPresence             OptionalField[[]string]              `json:"ix_presence"`
	ObservedPaths          OptionalField[ObservedPathsMetadata] `json:"observed_paths"`
}

type cacheEntry struct {
	profile Profile
	expires time.Time
}

type Client struct {
	httpClient *http.Client
	baseURL    string
	ttl        time.Duration
	timeout    time.Duration
	retries    int

	mu    sync.RWMutex
	cache map[uint32]cacheEntry
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: defaultReqTimeout + time.Second},
		baseURL:    defaultBaseURL,
		ttl:        defaultTTL,
		timeout:    defaultReqTimeout,
		retries:    defaultRetryBudget,
		cache:      make(map[uint32]cacheEntry),
	}
}

func (c *Client) GetProfile(ctx context.Context, asn uint32, observed [][]uint32) (Profile, bool, error) {
	now := time.Now().UTC()
	if p, ok := c.getFromCache(asn, now); ok {
		if meta := buildObservedPaths(observed); meta.PathCount > 0 {
			p.ObservedPaths = OptionalField[ObservedPathsMetadata]{Present: true, Source: "flowstore:pathfinder", Value: meta}
		}
		return p, true, nil
	}

	profile := Profile{ASN: asn, Source: "bgpview", FetchedAt: now}

	baseData, err := c.fetchJSON(ctx, fmt.Sprintf("%s/asn/%d", c.baseURL, asn))
	if err != nil {
		if meta := buildObservedPaths(observed); meta.PathCount > 0 {
			profile.ObservedPaths = OptionalField[ObservedPathsMetadata]{Present: true, Source: "flowstore:pathfinder", Value: meta}
		}
		return profile, false, err
	}
	fillBaseFields(&profile, baseData)

	if prefixesData, err := c.fetchJSON(ctx, fmt.Sprintf("%s/asn/%d/prefixes", c.baseURL, asn)); err == nil {
		fillPrefixes(&profile, prefixesData)
	}
	if peersData, err := c.fetchJSON(ctx, fmt.Sprintf("%s/asn/%d/peers", c.baseURL, asn)); err == nil {
		fillPeers(&profile, peersData)
	}
	if ixsData, err := c.fetchJSON(ctx, fmt.Sprintf("%s/asn/%d/ixs", c.baseURL, asn)); err == nil {
		fillIXPresence(&profile, ixsData)
	}

	if meta := buildObservedPaths(observed); meta.PathCount > 0 {
		profile.ObservedPaths = OptionalField[ObservedPathsMetadata]{Present: true, Source: "flowstore:pathfinder", Value: meta}
	}
	profile.FetchedAt = time.Now().UTC()
	c.storeCache(profile)
	return profile, false, nil
}

func (c *Client) getFromCache(asn uint32, now time.Time) (Profile, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[asn]
	if !ok || now.After(entry.expires) {
		return Profile{}, false
	}
	return entry.profile, true
}

func (c *Client) storeCache(p Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[p.ASN] = cacheEntry{profile: p, expires: time.Now().Add(c.ttl)}
}

func (c *Client) fetchJSON(ctx context.Context, url string) (map[string]interface{}, error) {
	var lastErr error
	attempts := c.retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := c.httpClient.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 120 * time.Millisecond)
			continue
		}
		var payload map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&payload); err != nil {
			_ = resp.Body.Close()
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return payload, nil
		}
		lastErr = fmt.Errorf("status %d", resp.StatusCode)
		if resp.StatusCode < 500 {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 120 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown fetch error")
	}
	return nil, lastErr
}

func fillBaseFields(out *Profile, payload map[string]interface{}) {
	data := mapValue(payload, "data")
	if name, ok := stringValue(data, "name"); ok && name != "" {
		out.Name = OptionalField[string]{Present: true, Source: "bgpview", Value: name}
	}
	if cc, ok := stringValue(data, "country_code"); ok && cc != "" {
		out.Country = OptionalField[string]{Present: true, Source: "bgpview", Value: strings.ToUpper(cc)}
	}
	if n, ok := intValue(data, "num_prefixes"); ok {
		out.AnnouncedPrefixesCount = OptionalField[int]{Present: true, Source: "bgpview", Value: n}
	}
	if n, ok := intValue(data, "num_peers"); ok {
		out.PeersCount = OptionalField[int]{Present: true, Source: "bgpview", Value: n}
	}
}

func fillPrefixes(out *Profile, payload map[string]interface{}) {
	data := mapValue(payload, "data")
	all := make([]string, 0, defaultMaxListValues)
	all = append(all, extractPrefixes(data, "ipv4_prefixes")...)
	all = append(all, extractPrefixes(data, "ipv6_prefixes")...)
	all = uniqStrings(all)
	if len(all) > 0 {
		if len(all) > defaultMaxListValues {
			all = all[:defaultMaxListValues]
		}
		out.AnnouncedPrefixes = OptionalField[[]string]{Present: true, Source: "bgpview", Value: all}
		if !out.AnnouncedPrefixesCount.Present {
			out.AnnouncedPrefixesCount = OptionalField[int]{Present: true, Source: "bgpview", Value: len(all)}
		}
	}
}

func fillPeers(out *Profile, payload map[string]interface{}) {
	data := mapValue(payload, "data")
	peers := make([]uint32, 0, defaultMaxListValues)
	peers = append(peers, extractPeerASNs(data, "ipv4_peers")...)
	peers = append(peers, extractPeerASNs(data, "ipv6_peers")...)
	peers = uniqUint32s(peers)
	if len(peers) > 0 {
		if len(peers) > defaultMaxListValues {
			peers = peers[:defaultMaxListValues]
		}
		out.Peers = OptionalField[[]uint32]{Present: true, Source: "bgpview", Value: peers}
		if !out.PeersCount.Present {
			out.PeersCount = OptionalField[int]{Present: true, Source: "bgpview", Value: len(peers)}
		}
	}
}

func fillIXPresence(out *Profile, payload map[string]interface{}) {
	data := mapValue(payload, "data")
	items, ok := data["ixs"].([]interface{})
	if !ok {
		return
	}
	names := make([]string, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := stringValue(item, "name"); ok && name != "" {
			names = append(names, name)
		}
	}
	names = uniqStrings(names)
	if len(names) > defaultMaxListValues {
		names = names[:defaultMaxListValues]
	}
	if len(names) > 0 {
		out.IXPresence = OptionalField[[]string]{Present: true, Source: "bgpview", Value: names}
	}
}

func buildObservedPaths(paths [][]uint32) ObservedPathsMetadata {
	if len(paths) == 0 {
		return ObservedPathsMetadata{}
	}
	seenHop := make(map[uint32]struct{})
	meta := ObservedPathsMetadata{PathCount: len(paths), MinHops: -1}
	for _, p := range paths {
		hops := len(p)
		if meta.MinHops == -1 || hops < meta.MinHops {
			meta.MinHops = hops
		}
		if hops > meta.MaxHops {
			meta.MaxHops = hops
		}
		for _, hop := range p {
			seenHop[hop] = struct{}{}
		}
		if len(meta.Samples) < 5 {
			meta.Samples = append(meta.Samples, p)
		}
	}
	meta.UniqueHops = len(seenHop)
	if meta.MinHops < 0 {
		meta.MinHops = 0
	}
	return meta
}

func extractPrefixes(data map[string]interface{}, key string) []string {
	items, ok := data[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if pfx, ok := stringValue(item, "prefix"); ok && pfx != "" {
			out = append(out, pfx)
		}
	}
	return out
}

func extractPeerASNs(data map[string]interface{}, key string) []uint32 {
	items, ok := data[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]uint32, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		asn, ok := intValue(item, "asn")
		if !ok || asn <= 0 {
			continue
		}
		out = append(out, uint32(asn))
	}
	return out
}

func mapValue(m map[string]interface{}, key string) map[string]interface{} {
	raw, ok := m[key]
	if !ok {
		return map[string]interface{}{}
	}
	mv, ok := raw.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return mv
}

func stringValue(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	if ok {
		return strings.TrimSpace(s), true
	}
	return "", false
}

func intValue(m map[string]interface{}, key string) (int, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func uniqStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func uniqUint32s(in []uint32) []uint32 {
	if len(in) == 0 {
		return in
	}
	seen := make(map[uint32]struct{}, len(in))
	out := make([]uint32, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
