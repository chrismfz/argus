package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/yl2chen/cidranger"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Optional: debug logging toggle
var debugLog = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)

// BGPListener handles the embedded BGP server
type BGPListener struct {
	Server    *server.BgpServer
	Ctx       context.Context
	Cfg       BGPListenerConfig
	Ranger    cidranger.Ranger
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
	if err := b.Server.StartBgp(b.Ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        b.Cfg.ASN,
			RouterId:   b.Cfg.RouterID,
			ListenPort: 179,
		},
	}); err != nil {
		return fmt.Errorf("failed to start BGP: %w", err)
	}
	log.Printf("[BGP] Listening for peers at %s (ASN %d)", b.Cfg.ListenIP, b.Cfg.ASN)
	if err := b.Server.AddPeer(b.Ctx, &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: b.Cfg.RouterID, // Assuming RouterID is the neighbor IP for self-peering testing
				PeerAsn:         b.Cfg.ASN,
			},
			Transport: &api.Transport{PassiveMode: true}, // Listen for incoming connections
		},
	}); err != nil {
		return fmt.Errorf("failed to add BGP peer: %w", err)
	}
	log.Printf("[BGP] Peer added: %s (ASN %d)", b.Cfg.RouterID, b.Cfg.ASN)
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
	f, err := os.Create("bgp_dump.jsonl")
	if err != nil {
		log.Fatalf("cannot open dump file: %v", err)
	}
	defer f.Close()

	log.Println("[BGP] Starting update watcher")
	var totalPaths int

	if err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{{
				Type: api.WatchEventRequest_Table_Filter_BEST, Init: true, // Init: true fetches current RIB
			}},
		},
	}, func(res *api.WatchEventResponse) {
		if table := res.GetTable(); table != nil {
			debugLog.Printf("[BGP] Received table event with %d paths.", len(table.Paths))
			for _, path := range table.Paths {
				nlriAny := path.GetNlri()
				if nlriAny == nil {
					debugLog.Println("[BGP] Skipping nil NLRI from path.")
					continue
				}
				debugLog.Printf("[BGP] Processing path with NLRI TypeUrl: %s", nlriAny.TypeUrl)

				prefix, err := getPrefixFromNlri(nlriAny)
				if err != nil {
					debugLog.Printf("[BGP] Error getting prefix from NLRI (TypeUrl %s): %v", nlriAny.TypeUrl, err)
					continue
				}
				debugLog.Printf("[BGP] Successfully parsed prefix: %s", prefix.String())

				// Decode attributes
				var asPath []string
				var localPref uint32
				if attrs, err := apiutil.UnmarshalPathAttributes(path.Pattrs); err == nil {
					debugLog.Printf("[BGP] Unmarshaled %d path attributes.", len(attrs))
					for _, attr := range attrs {
						debugLog.Printf("[BGP] Processing attribute type: %T", attr)
						switch v := attr.(type) {
						case *bgp.PathAttributeAsPath:
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
							debugLog.Printf("[BGP] Parsed ASPath: %v", asPath)
						case *bgp.PathAttributeLocalPref:
							localPref = v.Value
							debugLog.Printf("[BGP] Parsed LocalPref: %d", localPref)
						default:
							debugLog.Printf("[BGP] Skipping unknown BGP attribute type: %T", v)
						}
					}
				} else {
					debugLog.Printf("[BGP] Error unmarshaling path attributes: %v", err)
				}

				// The 'rawPattrs' part is for debugging raw attribute bytes, good for seeing what's there
				rawPattrs := make([]string, len(path.Pattrs))
				for i, attrAny := range path.Pattrs {
					rawPattrs[i] = hex.EncodeToString(attrAny.Value)
				}
				debugLog.Printf("[BGP] Raw Path Attributes: %v", rawPattrs)

				entry := BGPEnrichedEntry{network: *prefix, ASPath: asPath, LocalPref: localPref}
				if err := b.Ranger.Insert(entry); err != nil {
					debugLog.Printf("[BGP] Ranger insert error for %s: %v", prefix.String(), err)
				} else {
					totalPaths++
					b.PathCount = totalPaths
					if totalPaths%1000 == 0 { // Changed to 1000 for more frequent updates if many routes
						log.Printf("[BGP] Progress: %d prefixes...", totalPaths)
					}
				}

				dump := struct {
					NLRI      string   `json:"nlri"`
					RawPattrs []string `json:"raw_pattrs"`
					ASPath    []string `json:"as_path"`
					LocalPref uint32   `json:"local_pref"`
				}{prefix.String(), rawPattrs, asPath, localPref}

				if line, err := json.Marshal(dump); err == nil {
					f.Write(line)
					f.Write([]byte("\n"))
				} else {
					debugLog.Printf("[BGP] Error marshalling dump to JSON: %v", err)
				}
			}
		}
	}); err != nil {
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
		}
	}); err != nil {
		log.Printf("[BGP] WatchEvent error (peers): %v", err)
	}
}
