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
