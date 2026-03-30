package pathfinder

import (
	"context"
	"fmt"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	bgppkt "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v3/pkg/server"
)

// Resolver queries GoBGP's in-memory global RIB to resolve paths.
// It is safe for concurrent use — ListPath is read-only.
type Resolver struct {
	server *gobgpserver.BgpServer
	myASN  uint32
}

// NewResolver creates a Resolver backed by the given GoBGP server instance.
func NewResolver(s *gobgpserver.BgpServer, myASN uint32) *Resolver {
	return &Resolver{server: s, myASN: myASN}
}

// ResolvePrefix returns the best path (and alt paths if ADD-PATH is enabled)
// for the given CIDR prefix, e.g. "62.103.0.0/16".
func (r *Resolver) ResolvePrefix(prefix string) (*PrefixPaths, error) {
	result := &PrefixPaths{Prefix: prefix}

	err := r.server.ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Prefixes: []*api.TableLookupPrefix{
			{Prefix: prefix},
		},
	}, func(d *api.Destination) {
		for _, p := range d.Paths {
			parsed := r.parsePath(d.Prefix, p)
			if p.Best {
				cp := parsed
				result.BestPath = &cp
			} else {
				result.AltPaths = append(result.AltPaths, parsed)
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("ListPath prefix %q: %w", prefix, err)
	}
	return result, nil
}

// ResolveASN returns all prefixes in the RIB where the origin AS matches asn.
// asnName is optional enrichment from MaxMind / telemetry.
func (r *Resolver) ResolveASN(asn uint32, asnName string) (*ASNResult, error) {
	result := &ASNResult{ASN: asn, Name: asnName}
	byPrefix := map[string]*PrefixPaths{}

	err := r.server.ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
	}, func(d *api.Destination) {
		for _, p := range d.Paths {
			parsed := r.parsePath(d.Prefix, p)
			if parsed.OriginAS != asn {
				continue
			}
			pp, ok := byPrefix[d.Prefix]
			if !ok {
				pp = &PrefixPaths{Prefix: d.Prefix}
				byPrefix[d.Prefix] = pp
			}
			if p.Best {
				cp := parsed
				pp.BestPath = &cp
			} else {
				pp.AltPaths = append(pp.AltPaths, parsed)
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("ListPath ASN %d: %w", asn, err)
	}

	for _, pp := range byPrefix {
		result.Prefixes = append(result.Prefixes, *pp)
	}
	return result, nil
}


// parsePath extracts a strongly-typed Path from a raw api.Path.
func (r *Resolver) parsePath(prefix string, p *api.Path) Path {
	out := Path{
		Prefix: prefix,
		IsBest: p.Best,
	}

	attrs, err := apiutil.UnmarshalPathAttributes(p.Pattrs)
	if err != nil {
		return out
	}

	for _, attr := range attrs {
		switch v := attr.(type) {

		case *bgppkt.PathAttributeAsPath:
			for _, seg := range v.Value {
				switch s := seg.(type) {
				case *bgppkt.As4PathParam:
					out.ASPath = append(out.ASPath, s.AS...)
				case *bgppkt.AsPathParam:
					for _, a := range s.AS {
						out.ASPath = append(out.ASPath, uint32(a))
					}
				}
			}
			if len(out.ASPath) > 0 {
				out.OriginAS = out.ASPath[len(out.ASPath)-1]
			}

		case *bgppkt.PathAttributeNextHop:
			out.NextHop = v.Value.String()

		case *bgppkt.PathAttributeMpReachNLRI:
			if v.Nexthop != nil {
				out.NextHop = v.Nexthop.String()
			}

		case *bgppkt.PathAttributeLocalPref:
			out.LocalPref = v.Value

		case *bgppkt.PathAttributeCommunities:
			for _, c := range v.Value {
				out.Communities = append(out.Communities, fmt.Sprintf("%d:%d", c>>16, c&0xFFFF))
			}

		case *bgppkt.PathAttributeLargeCommunities:
			for _, c := range v.Values {
				out.Communities = append(out.Communities,
					fmt.Sprintf("%d:%d:%d", c.ASN, c.LocalData1, c.LocalData2))
			}
		}
	}

	out.PeerASN = firstExternalASN(out.ASPath, r.myASN)

	return out
}








func firstExternalASN(path []uint32, myASN uint32) uint32 {
	for _, asn := range path {
		if asn != 0 && asn != myASN {
			return asn
		}
	}
	return 0
}
