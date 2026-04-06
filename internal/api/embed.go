package api

import _ "embed"

// dashboardHTML is the single-file admin dashboard, served at /dashboard.
// It is compiled into the binary — no separate web server or static files needed.
//
//go:embed static/dashboard.html
var dashboardHTML []byte

//go:embed static/detection.html
var detectionHTML []byte

//go:embed static/alerts.html
var alertsHTML []byte

//go:embed static/pathfinder.html
var pathfinderHTML []byte

//go:embed static/bgp.html
var bgpHTML []byte

//go:embed static/routewatch.html
var routewatchHTML []byte


//go:embed static/asn.html
var asnHTML []byte

//go:embed static/ip.html
var ipHTML []byte

//go:embed static/nav-search.js
var navSearchJS []byte
