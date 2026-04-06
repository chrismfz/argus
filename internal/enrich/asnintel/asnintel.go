package asnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL       = "https://api.bgpview.io"
	defaultFreshTTL      = 15 * time.Minute
	defaultStaleTTL      = 2 * time.Hour
	defaultReqTimeout    = 3 * time.Second
	defaultRetryBudget   = 2 // extra attempts after first try
	defaultMaxListValues = 30
	defaultOpenFor       = 45 * time.Second
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
	profile    Profile
	freshUntil time.Time
	expiresAt  time.Time
}

type CacheState struct {
	Hit   bool `json:"hit"`
	Stale bool `json:"stale"`
}

type ProviderStatus struct {
	Provider    string `json:"provider"`
	OK          bool   `json:"ok"`
	LatencyMS   int64  `json:"latency_ms"`
	Error       string `json:"error,omitempty"`
	Timeout     bool   `json:"timeout,omitempty"`
	CircuitOpen bool   `json:"circuit_open,omitempty"`
	FromCache   bool   `json:"from_cache,omitempty"`
	Stale       bool   `json:"stale,omitempty"`
}

type circuitState struct {
	consecutiveFailures int
	openUntil           time.Time
}

type Client struct {
	httpClient *http.Client
	baseURL    string
	freshTTL   time.Duration
	staleTTL   time.Duration
	timeout    time.Duration
	retries    int
	openFor    time.Duration

	mu         sync.RWMutex
	cache      map[uint32]cacheEntry
	breakers   map[string]*circuitState
	refreshing map[uint32]bool
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: defaultReqTimeout + time.Second},
		baseURL:    defaultBaseURL,
		freshTTL:   defaultFreshTTL,
		staleTTL:   defaultStaleTTL,
		timeout:    defaultReqTimeout,
		retries:    defaultRetryBudget,
		openFor:    defaultOpenFor,
		cache:      make(map[uint32]cacheEntry),
		breakers:   make(map[string]*circuitState),
		refreshing: make(map[uint32]bool),
	}
}

func (c *Client) GetProfile(ctx context.Context, asn uint32, observed [][]uint32) (Profile, CacheState, map[string]ProviderStatus, error) {
	now := time.Now().UTC()
	if p, cacheState, ok := c.getFromCache(asn, now); ok {
		if meta := buildObservedPaths(observed); meta.PathCount > 0 {
			p.ObservedPaths = OptionalField[ObservedPathsMetadata]{Present: true, Source: "flowstore:pathfinder", Value: meta}
		}
		status := map[string]ProviderStatus{
			"cache": {
				Provider:  "cache",
				OK:        true,
				FromCache: true,
				Stale:     cacheState.Stale,
			},
		}
		if cacheState.Stale {
			c.refreshAsync(asn, observed)
		}
		return p, cacheState, status, nil
	}

	profile := Profile{ASN: asn, Source: "bgpview", FetchedAt: now}
	sourceStatus := make(map[string]ProviderStatus, 5)

	baseData, baseStatus, err := c.fetchProviderJSON(ctx, "bgpview:base", fmt.Sprintf("%s/asn/%d", c.baseURL, asn))
	sourceStatus["base"] = baseStatus
	if err != nil {
		if meta := buildObservedPaths(observed); meta.PathCount > 0 {
			profile.ObservedPaths = OptionalField[ObservedPathsMetadata]{Present: true, Source: "flowstore:pathfinder", Value: meta}
		}
		return profile, CacheState{}, sourceStatus, err
	}
	fillBaseFields(&profile, baseData)

	if prefixesData, status, err := c.fetchProviderJSON(ctx, "bgpview:prefixes", fmt.Sprintf("%s/asn/%d/prefixes", c.baseURL, asn)); err == nil {
		fillPrefixes(&profile, prefixesData)
		sourceStatus["prefixes"] = status
	} else {
		sourceStatus["prefixes"] = status
	}
	if peersData, status, err := c.fetchProviderJSON(ctx, "bgpview:peers", fmt.Sprintf("%s/asn/%d/peers", c.baseURL, asn)); err == nil {
		fillPeers(&profile, peersData)
		sourceStatus["peers"] = status
	} else {
		sourceStatus["peers"] = status
	}
	if ixsData, status, err := c.fetchProviderJSON(ctx, "bgpview:ixs", fmt.Sprintf("%s/asn/%d/ixs", c.baseURL, asn)); err == nil {
		fillIXPresence(&profile, ixsData)
		sourceStatus["ixs"] = status
	} else {
		sourceStatus["ixs"] = status
	}

	if meta := buildObservedPaths(observed); meta.PathCount > 0 {
		profile.ObservedPaths = OptionalField[ObservedPathsMetadata]{Present: true, Source: "flowstore:pathfinder", Value: meta}
	}
	profile.FetchedAt = time.Now().UTC()
	c.storeCache(profile)
	sourceStatus["cache"] = ProviderStatus{Provider: "cache", OK: true}
	return profile, CacheState{Hit: false, Stale: false}, sourceStatus, nil
}

func (c *Client) getFromCache(asn uint32, now time.Time) (Profile, CacheState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[asn]
	if !ok || now.After(entry.expiresAt) {
		return Profile{}, CacheState{}, false
	}
	state := CacheState{Hit: true, Stale: now.After(entry.freshUntil)}
	return entry.profile, state, true
}

func (c *Client) refreshAsync(asn uint32, observed [][]uint32) {
	c.mu.Lock()
	if c.refreshing[asn] {
		c.mu.Unlock()
		return
	}
	c.refreshing[asn] = true
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			delete(c.refreshing, asn)
			c.mu.Unlock()
		}()
		refreshCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, _, _, err := c.GetProfile(refreshCtx, asn, observed); err != nil {
			log.Printf(`{"component":"asnintel","event":"async_refresh","asn":%d,"ok":false,"error":%q}`, asn, err.Error())
		}
	}()
}

func (c *Client) storeCache(p Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.cache[p.ASN] = cacheEntry{
		profile:    p,
		freshUntil: now.Add(c.freshTTL),
		expiresAt:  now.Add(c.staleTTL),
	}
}

func (c *Client) fetchProviderJSON(ctx context.Context, provider string, url string) (map[string]interface{}, ProviderStatus, error) {
	var lastErr error
	attempts := c.retries + 1
	start := time.Now()
	status := ProviderStatus{Provider: provider}
	if c.isCircuitOpen(provider, start) {
		status.CircuitOpen = true
		status.Error = "circuit_open"
		status.LatencyMS = time.Since(start).Milliseconds()
		c.logProviderMetric(provider, status, 0)
		return nil, status, fmt.Errorf("provider %s circuit open", provider)
	}

	for attempt := 0; attempt < attempts; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			status.Error = err.Error()
			status.LatencyMS = time.Since(start).Milliseconds()
			c.logProviderMetric(provider, status, attempt+1)
			return nil, status, err
		}
		resp, err := c.httpClient.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			if reqCtx.Err() == context.DeadlineExceeded {
				status.Timeout = true
			}
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
			status.OK = true
			status.LatencyMS = time.Since(start).Milliseconds()
			c.markProviderSuccess(provider)
			c.logProviderMetric(provider, status, attempt+1)
			return payload, status, nil
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
	status.Error = lastErr.Error()
	status.LatencyMS = time.Since(start).Milliseconds()
	c.markProviderFailure(provider, time.Now())
	c.logProviderMetric(provider, status, attempts)
	return nil, status, lastErr
}

func (c *Client) isCircuitOpen(provider string, now time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state, ok := c.breakers[provider]
	return ok && now.Before(state.openUntil)
}

func (c *Client) markProviderSuccess(provider string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.breakers[provider] = &circuitState{}
}

func (c *Client) markProviderFailure(provider string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.breakers[provider]
	if !ok {
		state = &circuitState{}
		c.breakers[provider] = state
	}
	state.consecutiveFailures++
	if state.consecutiveFailures >= 3 {
		state.openUntil = now.Add(c.openFor)
	}
}

func (c *Client) logProviderMetric(provider string, status ProviderStatus, attempts int) {
	log.Printf(
		`{"component":"asnintel","event":"provider_call","provider":%q,"ok":%t,"latency_ms":%d,"attempts":%d,"timeout":%t,"circuit_open":%t,"error":%q}`,
		provider,
		status.OK,
		status.LatencyMS,
		attempts,
		status.Timeout,
		status.CircuitOpen,
		status.Error,
	)
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
