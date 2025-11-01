package bgp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	// "io" // REMOVED: "io" imported and not used
	"flowenricher/config"
	"github.com/yl2chen/cidranger"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	_ "google.golang.org/protobuf/encoding/protojson"
)

// Optional: debug logging toggle
var debugLog = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)
var PathCount int

// BGPListener handles the embedded BGP server
type BGPListener struct {
	Server    *server.BgpServer
	Ctx       context.Context
	Cfg       config.BGPListenerConfig
	Ranger    cidranger.Ranger
	PathCount int
	LocalAddress string
}

func NewBGPListener(cfg config.BGPListenerConfig) *BGPListener {
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

    // 1) Determine our BGP Identifier: use RouterID if set, otherwise ListenIP
    routerID := b.Cfg.RouterID
    if routerID == "" {
        routerID = b.Cfg.ListenIP
    }

    // 2) Start GoBGP itself
    if err := b.Server.StartBgp(b.Ctx, &api.StartBgpRequest{
        Global: &api.Global{
            Asn:        b.Cfg.LocalASN,  // your 4-byte ASN
            RouterId:   routerID,        // BGP Identifier
            ListenPort: 179,
        },
    }); err != nil {
        return fmt.Errorf("failed to start BGP: %w", err)
    }
    log.Printf("[BGP] Listening for peers at %s (ASN: %d, Router-ID: %s)",
        b.Cfg.ListenIP, b.Cfg.LocalASN, routerID)

    // 3) Add the MikroTik as an eBGP peer
    if err := b.Server.AddPeer(b.Ctx, &api.AddPeerRequest{
        Peer: &api.Peer{
            Conf: &api.PeerConf{
                NeighborAddress: b.Cfg.PeerIP,   // MikroTik’s IP from config
                PeerAsn:         b.Cfg.RemoteASN,// MikroTik’s ASN
                LocalAsn:        b.Cfg.LocalASN, // your ASN
            },
            Transport: &api.Transport{
                PassiveMode:  false,            // GoBGP will actively dial out
                LocalAddress: b.Cfg.ListenIP,   // bind from your VM’s IP
            },
            EbgpMultihop: &api.EbgpMultihop{
                Enabled:     true,
                MultihopTtl: 26,
            },
            AfiSafis: []*api.AfiSafi{
                {
                    Config: &api.AfiSafiConfig{
                        Family: &api.Family{
                            Afi:  api.Family_AFI_IP,
                            Safi: api.Family_SAFI_UNICAST,
                        },
                    },
                },
                {
                    Config: &api.AfiSafiConfig{
                        Family: &api.Family{
                            Afi:  api.Family_AFI_IP6,
                            Safi: api.Family_SAFI_UNICAST,
                        },
                    },
                },
            },
        },
    }); err != nil {
        return fmt.Errorf("failed to add BGP peer: %w", err)
    }
    log.Printf("[BGP] Added eBGP peer %s (remote ASN: %d) from local ASN %d",
        b.Cfg.PeerIP, b.Cfg.RemoteASN, b.Cfg.LocalASN)

    go b.watchUpdates()
    go b.watchPeers()
    return nil
}







// getPrefixFromNlri now uses proto.Unmarshal for API Any with extensive debugging
func getPrefixFromNlri(nlri *anypb.Any) (*net.IPNet, error) {
	//debugLog.Printf("Entering getPrefixFromNlri for TypeUrl: %s", nlri.TypeUrl)
	switch nlri.TypeUrl {
	case "type.googleapis.com/apipb.IPAddressPrefix":
		var pfx api.IPAddressPrefix
		if err := proto.Unmarshal(nlri.Value, &pfx); err != nil {
			//debugLog.Printf("Failed to proto.Unmarshal API IPAddressPrefix (TypeUrl: %s): %v", nlri.TypeUrl, err)
			return nil, fmt.Errorf("failed to proto.Unmarshal API IPAddressPrefix: %w", err)
		}
		//debugLog.Printf("Successfully unmarshaled IPAddressPrefix. Raw Prefix Bytes: %x, PrefixLen: %d", pfx.Prefix, pfx.PrefixLen)

		// --- CORRECTED LOGIC REVISION START ---
		// pfx.Prefix is a byte slice representation of the IP address string (e.g., []byte("192.0.2.1"))
		ipStr := string(pfx.Prefix) // Convert the byte slice containing the IP string to a Go string
		ip := net.ParseIP(ipStr)    // Parse the IP string into a net.IP object

		if ip == nil {
			//debugLog.Printf("net.ParseIP(\"%s\") returned nil. Raw pfx.Prefix was: %x", ipStr, pfx.Prefix)
			return nil, fmt.Errorf("invalid IP string for prefix: \"%s\"", ipStr)
		}
		//debugLog.Printf("net.IP conversion successful: %s", ip.String())

		// Determine address family and calculate mask
		var maxBits int
		if ip.To4() != nil { // Check if it's an IPv4 address (or IPv6-mapped IPv4)
			maxBits = 32
			ip = ip.To4() // Ensure it's a 4-byte IPv4 representation
			//debugLog.Printf("Identified as IPv4. IP after To4: %s (Raw: %x)", ip.String(), ip)
		} else if len(ip) == 16 { // If not IPv4, check if it's a 16-byte IPv6 address
			maxBits = 128
			//debugLog.Printf("Identified as IPv6. IP: %s (Raw: %x)", ip.String(), ip)
		} else {
			//debugLog.Printf("Unexpected IP length after ParseIP: %d bytes. Raw IP: %x", len(ip), ip)
			return nil, fmt.Errorf("unexpected IP address length after parsing: %d", len(ip))
		}

		mask := net.CIDRMask(int(pfx.PrefixLen), maxBits)
		// ip.Mask(mask) will create a new IP slice with the network address
		calculatedNet := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
		//debugLog.Printf("Calculated IPNet: %s/%d (%s)", calculatedNet.IP.String(), pfx.PrefixLen, calculatedNet.String())
		return calculatedNet, nil
		// --- CORRECTED LOGIC REVISION END ---

	default:
		// Keep your existing fallback logic for other NLRI types
		//debugLog.Printf("Falling back to apiutil.UnmarshalNLRI for unknown TypeUrl: %s", nlri.TypeUrl)
		nlriIntf, err := apiutil.UnmarshalNLRI(bgp.RF_IPv4_UC, nlri)
		if err != nil {
			//debugLog.Printf("Attempting IPv4 unmarshal failed: %v. Trying IPv6...", err)
			nlriIntf, err = apiutil.UnmarshalNLRI(bgp.RF_IPv6_UC, nlri)
			if err != nil {
				//debugLog.Printf("Failed to unmarshal NLRI with fallback (IPv4 & IPv6 failed) for TypeUrl %s: %v", nlri.TypeUrl, err)
				return nil, fmt.Errorf("failed to unmarshal NLRI (TypeUrl: %s): %w", nlri.TypeUrl, err)
			}
		}
		//debugLog.Printf("UnmarshalNLRI successful using fallback, type: %T", nlriIntf)

		switch v := nlriIntf.(type) {
		case *bgp.IPAddrPrefix:
			ip := net.IP(v.Prefix) // This `v.Prefix` from `bgp.IPAddrPrefix` *is* raw bytes, so this is correct here.
			mask := net.CIDRMask(int(v.Length), 32)
			calculatedNet := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
			//debugLog.Printf("Fallback success: Parsed IPv4 prefix: %s/%d -> %s", ip.String(), v.Length, calculatedNet.String())
			return calculatedNet, nil
		case *bgp.IPv6AddrPrefix:
			ip := net.IP(v.Prefix) // This `v.Prefix` from `bgp.IPv6AddrPrefix` *is* raw bytes, so this is correct here.
			mask := net.CIDRMask(int(v.Length), 128)
			calculatedNet := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
			//debugLog.Printf("Fallback success: Parsed IPv6 prefix: %s/%d -> %s", ip.String(), v.Length, calculatedNet.String())
			return calculatedNet, nil
		default:
			debugLog.Printf("Unsupported NLRI type in fallback handler: %T", v)
			return nil, fmt.Errorf("unsupported NLRI type in fallback: %T", v)
		}
	}
}

func (b *BGPListener) watchUpdates() {
    var f *os.File
    if config.AppConfig != nil && config.AppConfig.BGP.DumpEnabled {
        var err error
        f, err = os.Create("bgp_dump.jsonl")
        if err != nil {
            log.Fatalf("cannot open dump file: %v", err)
        }
        defer f.Close()
    }

    log.Println("[BGP] Starting update watcher")
    var totalPaths int

    err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
        Table: &api.WatchEventRequest_Table{
            Filters: []*api.WatchEventRequest_Table_Filter{{
                Type: api.WatchEventRequest_Table_Filter_BEST,
                Init: true, // fetch current RIB
            }},
        },
    }, func(res *api.WatchEventResponse) {
        if table := res.GetTable(); table != nil {
            for _, path := range table.Paths {
                nlriAny := path.GetNlri()
                if nlriAny == nil {
                    continue
                }

                prefix, err := getPrefixFromNlri(nlriAny)
                if err != nil {
                    continue
                }

                // --- decode attributes (AS path gated by config) ---
                var (
                    asPath      []string
                    localPref   uint32
                    communities []uint32
                )

                attrs, aerr := apiutil.UnmarshalPathAttributes(path.Pattrs)
                if aerr == nil {
                    for _, attr := range attrs {
                        switch v := attr.(type) {
                        case *bgp.PathAttributeCommunities:
                            for _, c := range v.Value {
                                communities = append(communities, c)
                            }
                        case *bgp.PathAttributeAsPath:
                            if config.AppConfig != nil && config.AppConfig.BGP.StoreASPath {
                                for _, seg := range v.Value {
                                    switch p := seg.(type) {
                                    case *bgp.AsPathParam:
                                        for _, asn := range p.AS {
                                            asPath = append(asPath, fmt.Sprintf("%d", asn))
                                        }
                                    case *bgp.As4PathParam:
                                        for _, asn := range p.AS {
                                            asPath = append(asPath, fmt.Sprintf("%d", asn))
                                        }
                                    }
                                }
                            }
                        case *bgp.PathAttributeLocalPref:
                            localPref = v.Value
                        default:
                            // ignore others
                        }
                    }
                }

                // origin ASN from last AS in path (if present)
                var originASN uint32
                if len(asPath) > 0 {
                    fmt.Sscanf(asPath[len(asPath)-1], "%d", &originASN)
                }

                entry := BGPEnrichedEntry{
                    Net:       *prefix,
                    LocalPref: localPref,
                    ASN:       originASN,
                }
                if config.AppConfig != nil && config.AppConfig.BGP.StoreASPath {
                    entry.ASPath = asPath
                }

                if err := b.Ranger.Insert(entry); err == nil {
                    totalPaths++
                    b.PathCount = totalPaths
                    PathCount = totalPaths
                }

                // optional dump
                if f != nil {
                    rawPattrs := make([]string, len(path.Pattrs))
                    for i, attrAny := range path.Pattrs {
                        rawPattrs[i] = hex.EncodeToString(attrAny.Value)
                    }
                    dump := struct {
                        NLRI      string   `json:"nlri"`
                        RawPattrs []string `json:"raw_pattrs"`
                        ASPath    []string `json:"as_path"`
                        LocalPref uint32   `json:"local_pref"`
                    }{
                        NLRI:      prefix.String(),
                        RawPattrs: rawPattrs,
                        ASPath:    asPath,
                        LocalPref: localPref,
                    }
                    if line, jerr := json.Marshal(dump); jerr == nil {
                        _, _ = f.Write(append(line, '\n'))
                    }
                }
            }
        }
    })
    if err != nil {
        log.Printf("[BGP] WatchEvent error (updates): %v", err)
    }

    log.Printf("[BGP] Initial table sync complete. Total prefixes received: %d", totalPaths)
}








func (b *BGPListener) watchPeers() {
	log.Println("[BGP] Starting peer event watcher")
	if err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
	}, func(res *api.WatchEventResponse) {
		if pe := res.GetPeer(); pe != nil && pe.Peer != nil {
			p := pe.Peer
			log.Printf("[BGP] Peer event: ASN %d, Addr %s, State %s",
				p.Conf.PeerAsn, p.Conf.NeighborAddress, p.State.SessionState)

            // Trigger the detailed logging when the peer becomes ESTABLISHED
            if p.State.SessionState == api.PeerState_ESTABLISHED {
                log.Printf("[BGP] Peer %s ESTABLISHED. Logging detailed info...", p.Conf.NeighborAddress)
                b.logEstablishedPeerDetails(p.Conf.NeighborAddress)
		b.LocalAddress = p.Transport.LocalAddress
	        log.Printf("[BGP]   Local Address (our IP): %s", b.LocalAddress)
            }
		}
	}); err != nil {
		log.Printf("[BGP] WatchEvent error (peers): %v", err)
	}
}

//////////////////////////////

// Helper function to log detailed peer information
func (b *BGPListener) logEstablishedPeerDetails(peerAddress string) {
	log.Printf("[BGP] Attempting to list detailed info for peer: %s", peerAddress)

	ctx, cancel := context.WithTimeout(b.Ctx, 5*time.Second)
	defer cancel()

	req := &api.ListPeerRequest{
		Address: peerAddress,
	}

	err := b.Server.ListPeer(ctx, req, func(peer *api.Peer) {
		if peer == nil {
			log.Printf("[BGP] Received nil peer detail for %s in callback.", peerAddress)
			return
		}

		// --- Keep this for now, it's very useful! ---
		//log.Printf("[BGP] Raw Peer Protobuf Message for %s:", peerAddress)
		//marshaler := protojson.MarshalOptions{
		//	Multiline:     true,
		//	Indent:        "  ",
		//	UseProtoNames: true,
		//}
		//peerJSON, marshalErr := marshaler.Marshal(peer)
		//if marshalErr != nil {
		//	log.Printf("[BGP] Error marshalling peer to JSON: %v", marshalErr)
		//} else {
		//	log.Printf("[BGP] %s", string(peerJSON))
		//}
		// --- END DEBUGGING CODE ---

		p := peer // The actual Peer object from the callback

		log.Printf("[BGP] --- Detailed Peer Information for %s ---", p.Conf.NeighborAddress)
		log.Printf("[BGP]   Remote AS: %d", p.Conf.PeerAsn)
		log.Printf("[BGP]   Remote ID: %s", p.State.RouterId)

		// Corrected field access for Local AS
		log.Printf("[BGP]   Local AS: %d", p.State.LocalAsn)

		// Uptime and Downtime are *timestamppb.Timestamp and need to be converted to time.Time
		if p.Timers != nil && p.Timers.State != nil {
			// Uptime
			if p.Timers.State.Uptime != nil { // Check if the Timestamp pointer is not nil
				uptimeTime := p.Timers.State.Uptime.AsTime() // Convert to time.Time
				log.Printf("[BGP]   Uptime: %s", time.Since(uptimeTime).Round(time.Second)) // Calculate duration since uptime
			} else {
				log.Printf("[BGP]   Uptime: Not available (or nil)")
			}

			// Downtime
			if p.Timers.State.Downtime != nil { // Check if the Timestamp pointer is not nil
				downtimeTime := p.Timers.State.Downtime.AsTime() // Convert to time.Time
				log.Printf("[BGP]   Last Downtime: %s", downtimeTime.Local().Format("2006-01-02 15:04:05 MST")) // Format for readability
			} else {
				log.Printf("[BGP]   Last Downtime: Not available (or nil)")
			}
		} else {
			log.Printf("[BGP]   Timers State information not available.")
		}


if p.Transport != nil {
    b.LocalAddress = p.Transport.LocalAddress
    log.Printf("[BGP]   Local Address (our IP): %s", b.LocalAddress)
}



		// Capabilities are in p.State.RemoteCap and p.State.LocalCap
		remoteCaps := make([]string, 0)
		for _, capAny := range p.State.RemoteCap {
			remoteCaps = append(remoteCaps, capAny.TypeUrl)
		}
		//log.Printf("[BGP]   Remote Capabilities: %v", remoteCaps)

		localCaps := make([]string, 0)
		for _, capAny := range p.State.LocalCap {
			localCaps = append(localCaps, capAny.TypeUrl)
		}
		//log.Printf("[BGP]   Local Capabilities: %v", localCaps)

		// AfiSafis are a top-level field of Peer
		negotiatedAfiSafis := []string{}
		for _, afiSafi := range p.AfiSafis {
			if afiSafi != nil && afiSafi.Config != nil && afiSafi.Config.Family != nil {
				negotiatedAfiSafis = append(negotiatedAfiSafis, fmt.Sprintf("%s/%s", afiSafi.Config.Family.Afi.String(), afiSafi.Config.Family.Safi.String()))
			}
		}
		log.Printf("[BGP]   Negotiated AFI/SAFIs: %v", negotiatedAfiSafis)

		// Messages Sent/Received are nested under p.State.Messages
		// Note: The JSON showed these as strings. The Go struct generated by protobuf
		// for 'total', 'open', 'keepalive' fields within BgpMessage is actually `uint64`.
		// So we can use them directly as numbers.
		if p.State.Messages != nil {
			if p.State.Messages.Sent != nil {
				log.Printf("[BGP]   Messages Sent: %d (Open: %d, Keepalive: %d)",
					p.State.Messages.Sent.Total, p.State.Messages.Sent.Open, p.State.Messages.Sent.Keepalive)
			}
			if p.State.Messages.Received != nil {
				log.Printf("[BGP]   Messages Received: %d (Open: %d, Keepalive: %d)",
					p.State.Messages.Received.Total, p.State.Messages.Received.Open, p.State.Messages.Received.Keepalive)
			}
		} else {
			log.Printf("[BGP]   Message counters not available.")
		}

		// BytesSent/Received and Prefixes Received are NOT present in the provided JSON for ListPeer
		log.Printf("[BGP]   Bytes Sent/Received: Not directly available via ListPeer in this version.")
		log.Printf("[BGP]   Prefixes Received: Not directly available via ListPeer in this version. (See watchUpdates for total paths)")

		log.Printf("[BGP] --- End Peer Information ---")
	})

	if err != nil {
		log.Printf("[BGP] Error listing peer %s details: %v", peerAddress, err)
	}
}



func GetPathCount() int {
	return PathCount
}
