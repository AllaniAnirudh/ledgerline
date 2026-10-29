package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// RedactURL strips credentials from a URL for display: logs, errors,
// and the control plane never show an embedded userinfo. The URL
// itself is still used verbatim for the actual upstream request;
// only displayed copies are redacted.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable upstream URL]"
	}
	u.User = nil
	return u.String()
}

// UpstreamPin identifies a configured upstream MCP server: the SHA-256
// of its base URL after the same trailing-slash normalization New
// applies. The pin file holds only this hash, never credentials, so
// an upstream URL carrying embedded credentials stays hidden.
func UpstreamPin(upstream string) string {
	sum := sha256.Sum256([]byte(strings.TrimSuffix(upstream, "/")))
	return hex.EncodeToString(sum[:])
}

// CheckUpstreamPin enforces the pin for one gateway start. It returns
// one of "ok", "created", or "reapproved":
//
//   - No pin file yet: the current upstream becomes the pin, and the
//     file is written. First run establishes the pin.
//   - Pin matches: nothing changes.
//   - Pin mismatches without reapprove: an error, and the gateway
//     must refuse to start. A changed upstream is a changed trust
//     root, and it needs a human to say so.
//   - Pin mismatches with reapprove: the pin file is overwritten
//     with the new upstream's pin. The caller witnesses the
//     re-approval in the ledger.
func CheckUpstreamPin(pinFile, upstream string, reapprove bool) (string, error) {
	want := UpstreamPin(upstream)
	// Exclusive create: two gateways starting at once cannot both
	// believe they created the pin. The loser falls through to the
	// read-and-compare path below. The pin file holds only a hash,
	// but it is still written 0600: it is a trust record, and a
	// same-user process can rewrite it regardless, so its content
	// is only as trustworthy as the operator's machine (see
	// SECURITY.md). First run is trust-on-first-use: "created"
	// enshrines whatever --upstream was passed.
	f, err := os.OpenFile(pinFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		if _, err := f.WriteString(want + "\n"); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return "created", nil
	}
	if !errors.Is(err, os.ErrExist) {
		return "", err
	}
	raw, err := os.ReadFile(pinFile)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(raw)) == want {
		return "ok", nil
	}
	if !reapprove {
		return "", fmt.Errorf("upstream pin mismatch: configured upstream %s does not match the pinned upstream; refusing to start (pass --reapprove-upstream to accept the new upstream)", RedactURL(upstream))
	}
	if err := os.WriteFile(pinFile, []byte(want+"\n"), 0600); err != nil {
		return "", err
	}
	return "reapproved", nil
}
