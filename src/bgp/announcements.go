package bgp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"log"
	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
	"flowenricher/config"
)

var AnnounceServer *gobgpserver.BgpServer
var announcedPrefixes = make(map[string]AnnouncedPrefix)
var announceMu sync.RWMutex
var LocalBGPAddress string
var MyASN uint32

func SetMyASN(asn uint32) {
    MyASN = asn
}


type AnnouncedPrefix struct {
	Prefix      string     `json:"prefix"`
	NextHop     string     `json:"next_hop"`
	Communities []string   `json:"communities"`
	Timestamp   time.Time  `json:"timestamp"`
	ASPath      []uint32   `json:"as_path,omitempty"` // ✅ NEW
}

func SetAnnounceServer(s *gobgpserver.BgpServer) {
	AnnounceServer = s
}




func AnnouncePrefix(prefix, nextHop string, communities []string, asPath []uint32) error {
    if AnnounceServer == nil {
        return fmt.Errorf("BGP server not set")
    }

    // Convert communities
    coms := []uint32{}
    for _, c := range communities {
        parts := strings.Split(c, ":")
        if len(parts) != 2 {
            return fmt.Errorf("invalid community: %s", c)
        }
        var high, low uint32
        fmt.Sscanf(parts[0], "%d", &high)
        fmt.Sscanf(parts[1], "%d", &low)
        coms = append(coms, (high<<16)|low)
    }

    // Default AS path if empty
    if len(asPath) == 0 {
        asPath = []uint32{config.GetLocalASN()}
    }

    // NLRI
    prefixParts := strings.Split(prefix, "/")
    if len(prefixParts) != 2 {
        return fmt.Errorf("invalid prefix format: %s", prefix)
    }
    ipPrefix := prefixParts[0]
    maskLen := 0
    fmt.Sscanf(prefixParts[1], "%d", &maskLen)

    nlri := &api.IPAddressPrefix{
        Prefix:    ipPrefix,
        PrefixLen: uint32(maskLen),
    }
    nlriAny, _ := anypb.New(nlri)

    if nextHop == "" {
        if LocalBGPAddress != "" {
            nextHop = LocalBGPAddress
        } else {
            nextHop = "127.0.0.1"
        }
    }

    attrs := []bgp.PathAttributeInterface{
        bgp.NewPathAttributeOrigin(0),
        bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
            &bgp.As4PathParam{
                Num:  uint8(len(asPath)),
                AS:   asPath,
                Type: bgp.BGP_ASPATH_ATTR_TYPE_SEQ,
            },
        }),
        bgp.NewPathAttributeNextHop(nextHop),
    }

    if len(coms) > 0 {
        attrs = append(attrs, bgp.NewPathAttributeCommunities(coms))
    }

    // Logging
    log.Printf("[BGP] Announcing prefix: %s via %s with communities: %s", prefix, nextHop, strings.Join(communities, ", "))
    log.Printf("[BGP] Communities (uint32): %v", coms)
    for _, attr := range attrs {
        log.Printf("[BGP] Attribute: %T = %+v", attr, attr)
    }

    // Marshal and send
    attrsAny, _ := apiutil.MarshalPathAttributes(attrs)
    _, err := AnnounceServer.AddPath(context.Background(), &api.AddPathRequest{
        Path: &api.Path{
            Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
            Nlri:   nlriAny,
            Pattrs: attrsAny,
        },
    })
    if err != nil {
        return err
    }

    // Store
    announceMu.Lock()
    announcedPrefixes[prefix] = AnnouncedPrefix{
        Prefix:      prefix,
        NextHop:     nextHop,
        Communities: communities,
        Timestamp:   time.Now(),
        ASPath:      asPath, // ✅ Χρήση πραγματικού path
    }
    announceMu.Unlock()

    return nil
}






func WithdrawPrefix(prefix string) error {
	if AnnounceServer == nil {
		return fmt.Errorf("BGP server not set")
	}

	announceMu.RLock()
	entry, ok := announcedPrefixes[prefix]
	announceMu.RUnlock()
	if !ok {
		return fmt.Errorf("prefix not announced: %s", prefix)
	}

	prefixParts := strings.Split(prefix, "/")
	if len(prefixParts) != 2 {
		return fmt.Errorf("invalid prefix format: %s", prefix)
	}
	ipPrefix := prefixParts[0]
	maskLen := 0
	fmt.Sscanf(prefixParts[1], "%d", &maskLen)

	nlri := &api.IPAddressPrefix{
		Prefix:    ipPrefix,
		PrefixLen: uint32(maskLen),
	}
	nlriAny, _ := anypb.New(nlri)

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(entry.NextHop),
	}
	attrsAny, _ := apiutil.MarshalPathAttributes(attrs)

	err := AnnounceServer.DeletePath(context.Background(), &api.DeletePathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlriAny,
			Pattrs: attrsAny,
		},
	})
	if err == nil {
		announceMu.Lock()
		delete(announcedPrefixes, prefix)
		announceMu.Unlock()
	}
	return err
}

func ListAnnouncements() map[string]AnnouncedPrefix {
	announceMu.RLock()
	defer announceMu.RUnlock()
	copy := make(map[string]AnnouncedPrefix, len(announcedPrefixes))
	for k, v := range announcedPrefixes {
		copy[k] = v
	}
	return copy
}
