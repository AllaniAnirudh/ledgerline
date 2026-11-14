package gateway

import _ "embed"

//go:embed approvals.html
var approvalsHTML []byte

// ApprovalsHTML returns the human approval page served at /approvals.
// It is dependency-free HTML+JS. It talks to the gateway's own API.
func ApprovalsHTML() []byte { return approvalsHTML }

//go:embed dashboard.html
var dashboardHTML []byte

// DashboardHTML returns the admin dashboard served at /dashboard.
// It is dependency-free HTML+JS. It talks to the gateway's own API.
func DashboardHTML() []byte { return dashboardHTML }
