package gateway

import _ "embed"

//go:embed approvals.html
var approvalsHTML []byte

// ApprovalsHTML returns the human approval page served at /approvals.
// It is dependency-free HTML+JS that talks to the gateway's own API.
func ApprovalsHTML() []byte { return approvalsHTML }
