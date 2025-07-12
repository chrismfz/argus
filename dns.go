package main

import (
	"context"
//	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSResolver struct {
	nameserver string
	cache      sync.Map
}

func NewDNSResolver(nameserver string) *DNSResolver {
	// Ensure it ends with port
	if !strings.Contains(nameserver, ":") {
		nameserver += ":53"
	}
	return &DNSResolver{nameserver: nameserver}
}

func (r *DNSResolver) LookupPTR(ip string) string {
	if v, ok := r.cache.Load(ip); ok {
		return v.(string)
	}

	ptr, err := r.queryPTR(ip)
	if err != nil {
		ptr = ""
	}
	r.cache.Store(ip, ptr)
	return ptr
}

func (r *DNSResolver) queryPTR(ip string) (string, error) {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", err
	}

	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)

	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	resp, _, err := c.ExchangeContext(context.Background(), m, r.nameserver)
	if err != nil {
		return "", err
	}
	for _, a := range resp.Answer {
		if ptr, ok := a.(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, "."), nil
		}
	}
	return "", nil
}
