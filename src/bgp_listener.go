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

func (b *BGPListener) watchUpdates() {
    // Άνοιγμα JSONL dump
    f, err := os.Create("bgp_dump.jsonl")
    if err != nil {
        log.Fatalf("cannot open dump file: %v", err)
    }
    // Δεν κάνουμε defer f.Close() γιατί θέλουμε το αρχείο ανοιχτό όσο τρέχει ο watcher
    log.Println("[BGP] Starting update watcher")

    // Για να μετράμε πόσες εισαγωγές κάναμε
    var totalInitialPaths int

    // Ξεκινάμε να παρακολουθούμε το RIB
    if err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
        Table: &api.WatchEventRequest_Table{
            Filters: []*api.WatchEventRequest_Table_Filter{{
                Type: api.WatchEventRequest_Table_Filter_ADJIN,
                Init: true,
            }},
        },
    }, func(res *api.WatchEventResponse) {
        if table := res.GetTable(); table != nil {
            for _, path := range table.Paths {
                // 1) Πάρε το NLRI Any
                nlriAny := path.GetNlri()
                if nlriAny == nil {
                    continue
                }
                prefix, err := getPrefixFromNlri(nlriAny)
                if err != nil {
                    debugLog.Printf("[BGP] getPrefix error: %v", err)
                    continue
                }

                // 2) Decode path attributes
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

                // 3) Μετέτρεψε τα raw Pattrs σε hex
                rawPattrs := make([]string, len(path.Pattrs))
                for i, attrAny := range path.Pattrs {
                    rawPattrs[i] = hex.EncodeToString(attrAny.Value)
                }

                // 4) Enrichment: insert στον ranger
                entry := BGPEnrichedEntry{
                    network:   *prefix,
                    ASPath:    asPath,
                    LocalPref: localPref,
                }
                if err := b.Ranger.Insert(entry); err != nil {
                    debugLog.Printf("[BGP] Ranger insert error: %v", err)
                } else {
                    totalInitialPaths++
                    b.PathCount = totalInitialPaths
                    if totalInitialPaths%100000 == 0 {
                        log.Printf("[BGP] Initial sync progress: %d prefixes...", totalInitialPaths)
                    }
                }

                // 5) Γράψε το dump
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

func getPrefixFromNlri(nlri *anypb.Any) (*net.IPNet, error) {
    var pfx api.IPAddressPrefix
    if err := proto.Unmarshal(nlri.Value, &pfx); err != nil {
        return nil, fmt.Errorf("failed to unmarshal NLRI: %w", err)
    }
    ip := net.IP(pfx.Prefix)
    if ip == nil {
        return nil, fmt.Errorf("invalid IP bytes: %v", pfx.Prefix)
    }
    mask := net.CIDRMask(int(pfx.PrefixLen), 8*len(ip))
    return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}

func (b *BGPListener) watchPeers() {
    log.Println("[BGP] Starting peer event watcher")
    if err := b.Server.WatchEvent(b.Ctx, &api.WatchEventRequest{
        Peer: &api.WatchEventRequest_Peer{},
    }, func(res *api.WatchEventResponse) {
        if peerEvt := res.GetPeer(); peerEvt != nil && peerEvt.Peer != nil {
            p := peerEvt.Peer
            log.Printf("[BGP] Peer event: ASN %d, Address %s, State %s",
                p.Conf.PeerAsn,
                p.Conf.NeighborAddress,
                p.State.SessionState,
            )
        }
    }); err != nil {
        log.Printf("[BGP] WatchEvent error (peers): %v", err)
    }
}
