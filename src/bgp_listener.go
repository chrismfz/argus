package main

import (
        "context"
        "fmt"
        "log"
        "os"

        api "github.com/osrg/gobgp/v3/api"
        "github.com/osrg/gobgp/v3/pkg/server"
        "google.golang.org/protobuf/encoding/protojson"
)

// Optional: debug logging toggle
var debugLog = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)

// BGPListener handles the embedded BGP server
type BGPListener struct {
        Server *server.BgpServer
        Ctx    context.Context
        Cfg    BGPListenerConfig
}

func NewBGPListener(cfg BGPListenerConfig) *BGPListener {
        ctx := context.Background()
        s := server.NewBgpServer()
        go s.Serve()

        return &BGPListener{
                Server: s,
                Ctx:    ctx,
                Cfg:    cfg,
        }
}

func (b *BGPListener) Start() error {
        log.Println("[BGP] Starting embedded BGP listener")

        err := b.Server.StartBgp(b.Ctx, &api.StartBgpRequest{
                Global: &api.Global{
                        Asn:        b.Cfg.ASN,
                        RouterId:   b.Cfg.RouterID,
                        ListenPort: -1, // passive mode
                },
        })
        if err != nil {
                return fmt.Errorf("failed to start BGP: %w", err)
        }

        log.Printf("[BGP] Listening for peers at %s (ASN %d)", b.Cfg.ListenIP, b.Cfg.ASN)

        go b.watchUpdates()
        go b.watchPeers()

        return nil
}

func (b *BGPListener) watchUpdates() {
        log.Println("[BGP] Starting update watcher")

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
                        log.Printf("[BGP] Received %d path(s) from peer", len(table.Paths))
                        for _, path := range table.Paths {
                                jsonPath, _ := protojson.Marshal(path)
                                debugLog.Printf("UPDATE PATH: %s", jsonPath)
                        }
                }
        })

        if err != nil {
                log.Printf("[BGP] WatchEvent error (updates): %v", err)
        }
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
