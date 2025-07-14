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
    "github.com/osrg/gobgp/v3/pkg/server"
    bgp "github.com/osrg/gobgp/v3/pkg/packet/bgp"
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
                NeighborAddress: b.Cfg.RouterID,
                PeerAsn:         b.Cfg.ASN,
            },
            Transport: &api.Transport{PassiveMode: true},
        },
    }); err != nil {
        return fmt.Errorf("failed to add BGP peer: %w", err)
    }
    log.Printf("[BGP] Peer added: %s (ASN %d)", b.Cfg.RouterID, b.Cfg.ASN)
    go b.watchUpdates()
    go b.watchPeers()
    return nil
}

// Fixed NLRI parsing function
func getPrefixFromNlri(nlri *anypb.Any) (*net.IPNet, error) {
    // Check the type URL to determine how to handle this NLRI
    switch nlri.TypeUrl {
    case "type.googleapis.com/apipb.IPAddressPrefix":
        var pfx api.IPAddressPrefix
        if err := nlri.UnmarshalTo(&pfx); err != nil {
            return nil, fmt.Errorf("failed to unmarshal API IPAddressPrefix: %w", err)
        }
        ip := net.IP(pfx.Prefix)
        if ip == nil {
            return nil, fmt.Errorf("invalid IP bytes: %v", pfx.Prefix)
        }
        // Determine if IPv4 or IPv6
        var maxBits int
        if len(ip) == 4 || (len(ip) == 16 && ip.To4() != nil) {
            maxBits = 32
            if len(ip) == 16 {
                ip = ip.To4()
            }
        } else {
            maxBits = 128
        }
        mask := net.CIDRMask(int(pfx.PrefixLen), maxBits)
        return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil

    default:
        // Try to unmarshal as BGP packet NLRI
        nlriIntf, err := apiutil.UnmarshalNLRI(bgp.RF_IPv4_UC, nlri)
        if err != nil {
            nlriIntf, err = apiutil.UnmarshalNLRI(bgp.RF_IPv6_UC, nlri)
            if err != nil {
                return nil, fmt.Errorf("failed to unmarshal NLRI (TypeUrl: %s): %w", nlri.TypeUrl, err)
            }
        }
        switch v := nlriIntf.(type) {
        case *bgp.IPAddrPrefix:
            ip := net.IP(v.Prefix)
            if ip == nil {
                return nil, fmt.Errorf("invalid IPv4 prefix: %v", v.Prefix)
            }
            mask := net.CIDRMask(int(v.Length), 32)
            return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
        case *bgp.IPv6AddrPrefix:
            ip := net.IP(v.Prefix)
            if ip == nil {
                return nil, fmt.Errorf("invalid IPv6 prefix: %v", v.Prefix)
            }
            mask := net.CIDRMask(int(v.Length), 128)
            return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
        default:
            return nil, fmt.Errorf("unsupported NLRI type: %T (TypeUrl: %s)", v, nlri.TypeUrl)
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
    var totalInitialPaths int

    if err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
        Table: &api.WatchEventRequest_Table{
            Filters: []*api.WatchEventRequest_Table_Filter{
                {
                    Type: api.WatchEventRequest_Table_Filter_BEST,
                    Init: true,
                },
            },
        },
    }, func(res *api.WatchEventResponse) {
        if table := res.GetTable(); table != nil {
            for _, path := range table.Paths {
                nlriAny := path.GetNlri()
                if nlriAny == nil {
                    debugLog.Printf("[BGP] Skipping path with nil NLRI")
                    continue
                }
                debugLog.Printf("[BGP] Processing NLRI TypeUrl: %s", nlriAny.TypeUrl)

                prefix, err := getPrefixFromNlri(nlriAny)
                if err != nil {
                    debugLog.Printf("[BGP] getPrefix error: %v", err)
                    continue
                }
                debugLog.Printf("[BGP] Parsed prefix: %s", prefix.String())

                // Decode attributes
                var asPath []string
                var localPref uint32
                if attrs, err := apiutil.UnmarshalPathAttributes(path.Pattrs); err == nil {
                    for _, attr := range attrs {
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
                        case *bgp.PathAttributeLocalPref:
                            localPref = v.Value
                        }
                    }
                }

                // raw attrs in hex
                rawPattrs := make([]string, len(path.Pattrs))
                for i, attrAny := range path.Pattrs {
                    rawPattrs[i] = hex.EncodeToString(attrAny.Value)
                }

                // Enrich in Ranger
                entry := BGPEnrichedEntry{
                    network:   *prefix,
                    ASPath:    asPath,
                    LocalPref: localPref,
                }
                if err := b.Ranger.Insert(entry); err != nil {
                    debugLog.Printf("[BGP] Ranger insert error for %s: %v", prefix.String(), err)
                } else {
                    totalInitialPaths++
                    b.PathCount = totalInitialPaths
                    if totalInitialPaths%100000 == 0 {
                        log.Printf("[BGP] Initial sync progress: %d prefixes...", totalInitialPaths)
                    }
                }

                // JSONL dump
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
                if line, err := json.Marshal(dump); err == nil {
                    f.Write(line)
                    f.Write([]byte("\n"))
                }
            }
        }
    }); err != nil {
        log.Printf("[BGP] WatchEvent error (updates): %v", err)
        return
    }

    log.Printf("[BGP] Initial table sync complete. Total prefixes received: %d", totalInitialPaths)
}

func (b *BGPListener) watchPeers() {
    log.Println("[BGP] Starting peer event watcher")
    if err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
        Peer: &api.WatchEventRequest_Peer{},
    }, func(res *api.WatchEventResponse) {
        if peerEvt := res.GetPeer(); peerEvt != nil && peerEvt.Peer != nil {
            p := peerEvt.Peer
            log.Printf("[BGP] Peer event: ASN %d, Address %s, State %s",
                p.Conf.PeerAsn, p.Conf.NeighborAddress, p.State.SessionState)
        }
    }); err != nil {
        log.Printf("[BGP] WatchEvent error (peers): %v", err)
    }
}
