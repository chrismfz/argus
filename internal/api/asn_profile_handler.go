package api

import (
	"argus/internal/flowstore"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

var asnProfileWindows = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"48h": 48 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

type asnProfileResponse struct {
	ASN          uint32                 `json:"asn"`
	Window       string                 `json:"window"`
	Dir          string                 `json:"dir"`
	HasLocalData bool                   `json:"has_local_data"`
	HasBGPData   bool                   `json:"has_bgp_data"`
	Local        asnProfileLocalData    `json:"local"`
	BGP          asnProfileBGPData      `json:"bgp"`
	External     asnProfileExternalData `json:"external"`
	Links        []asnProfileLink       `json:"links"`
}

type asnProfileLocalData struct {
	Meta      *flowstore.ASNMeta        `json:"meta"`
	Timeline  []flowstore.TimelinePoint `json:"timeline"`
	Ifaces    []flowstore.IfaceSplit    `json:"ifaces"`
	TopIPs    []flowstore.IPPair        `json:"top_ips"`
	Prefixes  []flowstore.PrefixStat    `json:"prefixes"`
	Proto     []flowstore.ProtoStat     `json:"proto"`
	Countries []flowstore.CountryStat   `json:"countries"`
	Ports     []flowstore.PortStat      `json:"ports"`
	TCPFlags  *flowstore.TCPFlagsStat   `json:"tcp_flags"`
}

type asnProfileBGPData struct {
	Available bool        `json:"available"`
	Error     string      `json:"error,omitempty"`
	Result    interface{} `json:"result"`
}

type asnProfileExternalData struct {
	ASN            uint32 `json:"asn"`
	DisplayName    string `json:"display_name"`
	NameSource     string `json:"name_source"`
	Summary        string `json:"summary"`
	FallbackActive bool   `json:"fallback_active"`
}

type asnProfileLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// GET /asn/{asn}/profile?window=24h&dir=both
func handleASNProfile(w http.ResponseWriter, r *http.Request) {
	if DB == nil {
		jsonErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	asn, err := parseProfileASN(r)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}

	windowLabel, window := parseProfileWindow(r)
	dir := parseProfileDir(r)

	meta, err := flowstore.QueryMeta(DB, asn)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	timeline, err := flowstore.QueryTimeline(DB, asn, window)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ifaces, err := flowstore.QueryIfaceSplit(DB, asn, window)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	topIPs, err := flowstore.QueryTopIPs(DB, asn, window, dir)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	prefixes, err := flowstore.QueryTopPrefixes(DB, asn, window)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	proto, err := flowstore.QueryProto(DB, asn, window)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	countries, err := flowstore.QueryCountry(DB, asn, window)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ports, err := flowstore.QueryPorts(DB, asn, window)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tcpFlags, err := flowstore.QueryTCPFlags(DB, asn, window)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	displayName := fmt.Sprintf("AS%d", asn)
	nameSource := "fallback"
	if meta != nil && meta.ASNName != "" {
		displayName = meta.ASNName
		nameSource = "flowstore"
	}

	local := asnProfileLocalData{
		Meta:      meta,
		Timeline:  nonNilTimeline(timeline),
		Ifaces:    nonNilIfaces(ifaces),
		TopIPs:    nonNilTopIPs(topIPs),
		Prefixes:  nonNilPrefixes(prefixes),
		Proto:     nonNilProto(proto),
		Countries: nonNilCountries(countries),
		Ports:     nonNilPorts(ports),
		TCPFlags:  ensureTCPFlags(tcpFlags),
	}

	hasLocalData := meta != nil || len(local.Timeline) > 0 || len(local.Ifaces) > 0 ||
		len(local.TopIPs) > 0 || len(local.Prefixes) > 0 || len(local.Proto) > 0 ||
		len(local.Countries) > 0 || len(local.Ports) > 0

	bgp := asnProfileBGPData{Available: PathfinderResolver != nil, Result: map[string]interface{}{}}
	hasBGPData := false
	if PathfinderResolver != nil {
		result, resolveErr := PathfinderResolver.ResolveASN(asn, displayName)
		if resolveErr != nil {
			bgp.Error = resolveErr.Error()
		} else {
			bgp.Result = result
			hasBGPData = result != nil && len(result.Prefixes) > 0
		}
	}

	resp := asnProfileResponse{
		ASN:          asn,
		Window:       windowLabel,
		Dir:          dir,
		HasLocalData: hasLocalData,
		HasBGPData:   hasBGPData,
		Local:        local,
		BGP:          bgp,
		External: asnProfileExternalData{
			ASN:            asn,
			DisplayName:    displayName,
			NameSource:     nameSource,
			Summary:        fmt.Sprintf("ASN profile for AS%d", asn),
			FallbackActive: !hasLocalData,
		},
		Links: []asnProfileLink{
			{Label: "Pathfinder", URL: fmt.Sprintf("/pathfinder/asn?asn=%d", asn)},
			{Label: "BGP HE", URL: fmt.Sprintf("https://bgp.he.net/AS%d", asn)},
			{Label: "Hurricane Electric Toolkit", URL: fmt.Sprintf("https://bgp.he.net/AS%d#_prefixes", asn)},
		},
	}

	jsonOK(w, resp)
}

func parseProfileASN(r *http.Request) (uint32, error) {
	seg := r.PathValue("asn")
	if seg == "" {
		seg = r.URL.Query().Get("asn")
	}
	v, err := strconv.ParseUint(seg, 10, 32)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("invalid or missing ASN")
	}
	return uint32(v), nil
}

func parseProfileWindow(r *http.Request) (string, time.Duration) {
	windowLabel := r.URL.Query().Get("window")
	if d, ok := asnProfileWindows[windowLabel]; ok {
		return windowLabel, d
	}
	return "24h", 24 * time.Hour
}

func parseProfileDir(r *http.Request) string {
	dir := r.URL.Query().Get("dir")
	if dir == "in" || dir == "out" || dir == "both" {
		return dir
	}
	return "both"
}

func ensureTCPFlags(flags *flowstore.TCPFlagsStat) *flowstore.TCPFlagsStat {
	if flags != nil {
		return flags
	}
	return &flowstore.TCPFlagsStat{}
}

func nonNilTimeline(in []flowstore.TimelinePoint) []flowstore.TimelinePoint {
	if in == nil {
		return []flowstore.TimelinePoint{}
	}
	return in
}

func nonNilIfaces(in []flowstore.IfaceSplit) []flowstore.IfaceSplit {
	if in == nil {
		return []flowstore.IfaceSplit{}
	}
	return in
}

func nonNilTopIPs(in []flowstore.IPPair) []flowstore.IPPair {
	if in == nil {
		return []flowstore.IPPair{}
	}
	return in
}

func nonNilPrefixes(in []flowstore.PrefixStat) []flowstore.PrefixStat {
	if in == nil {
		return []flowstore.PrefixStat{}
	}
	return in
}

func nonNilProto(in []flowstore.ProtoStat) []flowstore.ProtoStat {
	if in == nil {
		return []flowstore.ProtoStat{}
	}
	return in
}

func nonNilCountries(in []flowstore.CountryStat) []flowstore.CountryStat {
	if in == nil {
		return []flowstore.CountryStat{}
	}
	return in
}

func nonNilPorts(in []flowstore.PortStat) []flowstore.PortStat {
	if in == nil {
		return []flowstore.PortStat{}
	}
	return in
}
