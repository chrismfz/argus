package bgp

import (
	"context"
	"fmt"
	"strings"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

var AnnounceServer *gobgpserver.BgpServer

func SetAnnounceServer(s *gobgpserver.BgpServer) {
	AnnounceServer = s
}

func AnnouncePrefix(prefix, nextHop string, communities []string) error {
	if AnnounceServer == nil {
		return fmt.Errorf("BGP server not set")
	}

	// Convert communities to uint32 format
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

	// NLRI
	prefixParts := strings.Split(prefix, "/")
	if len(prefixParts) != 2 {
		return fmt.Errorf("invalid prefix format: %s", prefix)
	}
	ipPrefix := prefixParts[0]
	maskLen := 0
	fmt.Sscanf(prefixParts[1], "%d", &maskLen)

	// Use gobgp api NLRI
	nlri := &api.IPAddressPrefix{
		Prefix:    ipPrefix,
		PrefixLen: uint32(maskLen),
	}
	nlriAny, _ := anypb.New(nlri)

	// Attributes
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nextHop),
	}
	if len(coms) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeCommunities(coms))
	}
	attrsAny, _ := apiutil.MarshalPathAttributes(attrs)

	// Send
	_, err := AnnounceServer.AddPath(context.Background(), &api.AddPathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlriAny,
			Pattrs: attrsAny,
		},
	})
	return err
}

func WithdrawPrefix(prefix string) error {
	if AnnounceServer == nil {
		return fmt.Errorf("BGP server not set")
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

	err := AnnounceServer.DeletePath(context.Background(), &api.DeletePathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlriAny,
		},
	})
	return err
}
