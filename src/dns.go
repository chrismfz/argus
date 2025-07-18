package main

import (
	"context"
//	"log" // Added for logging errors within queryPTR
	"strings"
	"sync"
	"time"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight" // New import
)

const (
	// Cache expiration time for successful DNS lookups
	defaultCacheTTL = 60 * time.Minute
	// Cache expiration time for failed DNS lookups (e.g., no PTR record)
	defaultNegativeCacheTTL = 60 * time.Minute
)

// cacheEntry holds the PTR record and its expiration time
type cacheEntry struct {
	ptr        string
	expiration time.Time
}

type DNSResolver struct {
	nameserver string
	cache      sync.Map // Map[string]*cacheEntry
	group      singleflight.Group // Used to deduplicate concurrent requests for the same IP
	// context and client are not strictly needed here as they are created per query
}

func NewDNSResolver(nameserver string) *DNSResolver {
	// Ensure it ends with port
	if !strings.Contains(nameserver, ":") {
		nameserver += ":53"
	}
	dlog("Initializing DNS resolver with nameserver: %s", nameserver)
	return &DNSResolver{nameserver: nameserver}
}

// LookupPTR performs a PTR lookup for the given IP address,
// utilizing a cache and singleflight to prevent redundant queries.
func (r *DNSResolver) LookupPTR(ip string) string {
	// 1. Check cache first
	if val, ok := r.cache.Load(ip); ok {
		entry := val.(*cacheEntry)
		if time.Now().Before(entry.expiration) {
			// Cache hit and not expired
			dlog("Cache hit for %s: %s (expires %s)", ip, entry.ptr, entry.expiration.Format(time.RFC3339))
			return entry.ptr
		}
		// Cache entry expired, remove it to allow re-querying
		dlog("Cache expired for %s. Removing and re-querying.", ip)
		r.cache.Delete(ip)
	}

	// 2. Use singleflight for concurrent requests to the same IP
	// Do takes a key (the IP) and a function to execute if no flight is in progress for that key.
	// The result (v) will be either the result of a new flight or a shared result from an ongoing flight.
	v, err, _ := r.group.Do(ip, func() (interface{}, error) {
		ptr, queryErr := r.queryPTR(ip)
		if queryErr != nil {
			// For errors, cache an empty string but with a shorter TTL (negative cache)
			dlog("Error querying PTR for %s: %v. Caching empty string for %s.", ip, queryErr, defaultNegativeCacheTTL)
			r.cache.Store(ip, &cacheEntry{
				ptr:        "", // Store empty string on error
				expiration: time.Now().Add(defaultNegativeCacheTTL),
			})
			return "", queryErr // Return error, singleflight will still cache the ""
		}

		// On success, cache the result with a normal TTL
		dlog("Successfully queried PTR for %s: %s. Caching for %s.", ip, ptr, defaultCacheTTL)
		r.cache.Store(ip, &cacheEntry{
			ptr:        ptr,
			expiration: time.Now().Add(defaultCacheTTL),
		})
		return ptr, nil
	})

	// If the singleflight operation itself returned an error, return an empty string.
	// The error here indicates a problem during the lookup (e.g., DNS server down),
	// but the `queryPTR` already handled caching the empty string with a short TTL for such cases.
	if err != nil {
		return ""
	}

	// The `v` returned by singleflight.Do is an `interface{}`. Cast it back to string.
	return v.(string)
}

func (r *DNSResolver) queryPTR(ip string) (string, error) {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		// Log specific IP parsing error, as ReverseAddr can fail for invalid IP formats
		dlog("[ERROR] DNS ReverseAddr failed for IP '%s': %v", ip, err)
		return "", err
	}

	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)

	c := new(dns.Client)
	c.Timeout = 2 * time.Second // Use a reasonable timeout

	// Use context.Background() for the DNS query itself,
	// as the LookupPTR is called from within the batcher's flush loop
	// which might have its own context, but the DNS lookup should be isolated.
	resp, _, err := c.ExchangeContext(context.Background(), m, r.nameserver)
	if err != nil {
		// Log DNS exchange errors (e.g., server unreachable, timeout)
		dlog("[ERROR] DNS exchange failed for %s (%s): %v", ip, arpa, err)
		return "", err
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		// Log if response is nil or not successful (e.g., NXDOMAIN, SERVFAIL)
		rcodeStr := "nil_response"
		if resp != nil {
			rcodeStr = dns.RcodeToString[resp.Rcode]
		}
		dlog("[DEBUG] DNS query for %s (%s) failed or returned non-success Rcode: %s", ip, arpa, rcodeStr)
		return "", fmt.Errorf("DNS query non-successful: %s", rcodeStr)
	}

	for _, a := range resp.Answer {
		if ptr, ok := a.(*dns.PTR); ok {
			// Trim the trailing dot from the PTR record
			return strings.TrimSuffix(ptr.Ptr, "."), nil
		}
	}
	// No PTR record found in the answer section, but query was successful
	dlog("No PTR record found for %s (%s)", ip, arpa)
	return "", nil
}
