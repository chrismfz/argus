package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/yl2chen/cidranger"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
        bgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
)

// Optional: debug logging toggle
var debugLog = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)

// BGPListener handles the embedded BGP server
type BGPListener struct {
	Server *server.BgpServer
	Ctx    context.Context
	Cfg    BGPListenerConfig
	Ranger cidranger.Ranger
	PathCount int
}

func NewBGPListener(cfg BGPListenerConfig) *BGPListener {
	ctx := context.Background()
	s := server.NewBgpServer()
	go s.Serve()

	return &BGPListener{
		Server: s,
		Ctx:    ctx,
		Cfg:    cfg,
		Ranger: cidranger.NewPCTrieRanger(),
	}
}

func (b *BGPListener) Start() error {
	log.Println("[BGP] Starting embedded BGP listener")

	err := b.Server.StartBgp(b.Ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        b.Cfg.ASN,
			RouterId:   b.Cfg.RouterID,
			ListenPort: 179,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start BGP: %w", err)
	}

	log.Printf("[BGP] Listening for peers at %s (ASN %d)", b.Cfg.ListenIP, b.Cfg.ASN)

	err = b.Server.AddPeer(b.Ctx, &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: b.Cfg.RouterID,
				PeerAsn:         b.Cfg.ASN,
			},
			Transport: &api.Transport{
				PassiveMode: true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add BGP peer: %w", err)
	}
	log.Printf("[BGP] Peer added: %s (ASN %d)", b.Cfg.RouterID, b.Cfg.ASN)

	go b.watchUpdates()
	go b.watchPeers()

	return nil
}



func (b *BGPListener) watchUpdates() {
	log.Println("[BGP] Starting update watcher")

	var totalInitialPaths int

	err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{
					Type: api.WatchEventRequest_Table_Filter_ADJIN,
					Init: true,
				},
			},
		},
	}, func(res *api.WatchEventResponse) {
		if table := res.GetTable(); table != nil {
			for _, path := range table.Paths {
				nlri := path.GetNlri()
				if nlri == nil {
					continue
				}

				prefix, err := getPrefixFromNlri(nlri)
				if err != nil {
					continue
				}

				// Decode BGP path attributes
				var asPath []string
				var localPref uint32

				attrs, err := apiutil.UnmarshalPathAttributes(path.Pattrs)
				if err != nil {
					log.Printf("[BGP] Failed to decode path attributes: %v", err)
					continue
				}

				for _, attr := range attrs {
					switch v := attr.(type) {
					case *bgp.PathAttributeAsPath:
						for _, seg := range v.Value {
							if as4, ok := seg.(*bgp.As4PathParam); ok {
								for _, asn := range as4.AS {
									asPath = append(asPath, fmt.Sprintf("%d", asn))
								}
							}
						}
					case *bgp.PathAttributeLocalPref:
						localPref = v.Value
					}
				}

				entry := BGPEnrichedEntry{
					network:   *prefix,
					ASPath:    asPath,
					LocalPref: localPref,
				}
				_ = b.Ranger.Insert(entry)

				totalInitialPaths++
				b.PathCount = totalInitialPaths
				if totalInitialPaths%100000 == 0 {
					log.Printf("[BGP] Initial sync progress: %d prefixes...", totalInitialPaths)
				}
			}
		}
	})

	if err != nil {
		log.Printf("[BGP] WatchEvent error (updates): %v", err)
		return
	}

	log.Printf("[BGP] Initial table sync complete. Total prefixes received: %d", totalInitialPaths)
}



func getPrefixFromNlri(nlri *anypb.Any) (*net.IPNet, error) {
	var prefix api.IPAddressPrefix
	if err := proto.Unmarshal(nlri.Value, &prefix); err != nil {
		return nil, fmt.Errorf("failed to unmarshal NLRI: %w", err)
	}

	ip := net.IP(prefix.Prefix)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %v", prefix.Prefix)
	}

	ones := int(prefix.PrefixLen)
	mask := net.CIDRMask(ones, 8*len(ip))

	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}

func (b *BGPListener) watchPeers() {
	log.Println("[BGP] Starting peer event watcher")

	err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
	}, func(res *api.WatchEventResponse) {
		if peerEvent := res.GetPeer(); peerEvent != nil && peerEvent.Peer != nil {
			p := peerEvent.Peer

			log.Printf("[BGP] Peer event: ASN %d, Address %s, State %s",
				p.Conf.PeerAsn,
				p.Conf.NeighborAddress,
				p.State.SessionState,
			)
		}
	})

	if err != nil {
		log.Printf("[BGP] WatchEvent error (peers): %v", err)
	}
}

