package api

import _ "embed"

// dashboardHTML is the single-file admin dashboard, served at /dashboard.
// It is compiled into the binary — no separate web server or static files needed.
//
//go:embed static/dashboard.html
var dashboardHTML []byte
var detectionHTML []byte

