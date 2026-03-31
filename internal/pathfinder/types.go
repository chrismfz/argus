package pathfinder

import (
"time"
//"argus/internal/routeros"
)


// Path represents a single BGP path for a prefix.
type Path struct {
	Prefix      string   `json:"prefix"`
	OriginAS    uint32   `json:"origin_as"`
	PeerASN     uint32   `json:"peer_asn,omitempty"`   // first external ASN
	ASPath      []uint32 `json:"as_path"`
	NextHop     string   `json:"next_hop"`
	Upstream    string   `json:"upstream,omitempty"`
	LocalPref   uint32   `json:"local_pref"`
	Communities []string `json:"communities,omitempty"`
	IsBest      bool     `json:"is_best"`
}

// PrefixPaths holds the best path and any alternative paths for a prefix.
  type PrefixPaths struct {
      Prefix        string          `json:"prefix"`
      BestPath      *Path           `json:"best_path,omitempty"`
      AltPaths      []Path          `json:"alt_paths,omitempty"`
      AllPaths      []RouteSummary  `json:"all_paths,omitempty"`  // from RouterOS
  }


type ASNResult struct {
	ASN      uint32        `json:"asn"`
	Name     string        `json:"name,omitempty"`
	Prefixes []PrefixPaths `json:"prefixes"`
}

type RIBSnapshot struct {
	Timestamp time.Time       `json:"timestamp"`
	Paths     map[string]Path `json:"paths"`
}

type ChangeKind string

const (
	ChangeWithdrawn ChangeKind = "withdrawn"
	ChangeNewPrefix ChangeKind = "new_prefix"
	ChangeNextHop   ChangeKind = "nexthop_changed"
	ChangeASPath    ChangeKind = "aspath_changed"
	ChangeLocalPref ChangeKind = "localpref_changed"
)

type PathChange struct {
	Prefix     string     `json:"prefix"`
	ChangeType ChangeKind `json:"change_type"`
	Before     *Path      `json:"before,omitempty"`
	After      *Path      `json:"after,omitempty"`
}

  // RouteSummary is a simplified multi-path entry from RouterOS.
  // It avoids importing the routeros package into pathfinder.
  type RouteSummary struct {
      Gateway      string `json:"gateway"`
      Interface    string `json:"interface"`
      Distance     int    `json:"distance"`
      Active       bool   `json:"active"`
      Upstream     string `json:"upstream,omitempty"` // auto-resolved label
  }

