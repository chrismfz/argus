package enrich

import (
    "context"
    "fmt"
    "strings"
    "sync"
    "time"
    "log"
    "github.com/miekg/dns"
    "golang.org/x/sync/singleflight"
)

const (
    defaultCacheTTL        = 60 * time.Minute
    defaultNegativeCacheTTL = 60 * time.Minute
    NoPTR                  = "NoPTR"
)

type cacheEntry struct {
    ptr        string
    expiration time.Time
}

type DNSResolver struct {
    nameserver string
    cache      sync.Map // map[string]*cacheEntry
    group      singleflight.Group
}

func NewDNSResolver(nameserver string) *DNSResolver {
    if !strings.Contains(nameserver, ":") {
        nameserver += ":53"
    }
    log.Printf("Initializing DNS resolver with nameserver: %s", nameserver)
    return &DNSResolver{nameserver: nameserver}
}

func (r *DNSResolver) LookupPTR(ip string) string {
    if val, ok := r.cache.Load(ip); ok {
        entry := val.(*cacheEntry)
        if time.Now().Before(entry.expiration) {
            //log.Printf("Cache hit for %s: %s", ip, entry.ptr)
            if entry.ptr == NoPTR {
                return ""
            }
            return entry.ptr
        }
        //log.Printf("Cache expired for %s", ip)
        r.cache.Delete(ip)
    }

    v, err, _ := r.group.Do(ip, func() (interface{}, error) {
        ptr, err := r.queryPTR(ip)
        ttl := defaultCacheTTL
        if err != nil || ptr == "" {
            ptr = NoPTR
            ttl = defaultNegativeCacheTTL
            //log.Printf("PTR lookup failed for %s: %v", ip, err)
        } else {
            //log.Printf("PTR lookup success for %s: %s", ip, ptr)
        }

        r.cache.Store(ip, &cacheEntry{
            ptr:        ptr,
            expiration: time.Now().Add(ttl),
        })

        return ptr, err
    })

    if err != nil || v == NoPTR {
        return ""
    }
    return v.(string)
}

func (r *DNSResolver) queryPTR(ip string) (string, error) {
    arpa, err := dns.ReverseAddr(ip)
    if err != nil {
        //log.Printf("[ERROR] Invalid IP for PTR: %s", ip)
        return "", err
    }

    msg := new(dns.Msg)
    msg.SetQuestion(arpa, dns.TypePTR)

    client := new(dns.Client)
    client.Timeout = 2 * time.Second

    resp, _, err := client.ExchangeContext(context.Background(), msg, r.nameserver)
    if err != nil {
        return "", err
    }

    if resp == nil || resp.Rcode != dns.RcodeSuccess {
        return "", fmt.Errorf("PTR lookup failed: %v", resp)
    }

    for _, a := range resp.Answer {
        if ptr, ok := a.(*dns.PTR); ok {
            return strings.TrimSuffix(ptr.Ptr, "."), nil
        }
    }

    return "", nil
}

// ✅ (Προαιρετικό για μελλοντική χρήση)
// LookupBatch returns a map[ip]ptr (empty string if no PTR)
func (r *DNSResolver) LookupBatch(ips []string) map[string]string {
    results := make(map[string]string)
    for _, ip := range ips {
        results[ip] = r.LookupPTR(ip)
    }
    return results
}



func (r *DNSResolver) Lookup(ip string) (string, bool) {
    ptr := r.LookupPTR(ip)
    if ptr == "" {
        return "", false
    }
    return ptr, true
}
